use std::{
    io,
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};

use thiserror::Error;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::JoinSet,
    time::{Instant, sleep_until, timeout},
};
use tracing::{debug, info, warn};

use crate::config::{AuthSkipPrefix, Config, ConfigError};
use crate::outbound::ProxyOutbound;
use crate::routing::{RequestTarget, RouteAction, RuleSet, TargetHost};

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_USERNAME_PASSWORD: u8 = 0x02;
const METHOD_NO_ACCEPTABLE: u8 = 0xff;
const AUTH_VERSION: u8 = 0x01;
const CMD_CONNECT: u8 = 0x01;
const REP_SUCCEEDED: u8 = 0x00;
const REP_GENERAL_FAILURE: u8 = 0x01;
const REP_CONNECTION_NOT_ALLOWED: u8 = 0x02;
const REP_NETWORK_UNREACHABLE: u8 = 0x03;
const REP_HOST_UNREACHABLE: u8 = 0x04;
const REP_CONNECTION_REFUSED: u8 = 0x05;
const REP_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const REP_ADDRESS_TYPE_NOT_SUPPORTED: u8 = 0x08;
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Clone, Copy)]
struct ConnectionTimeouts {
    connect: Duration,
    handshake: Duration,
}

#[derive(Clone)]
struct ConnectionContext {
    timeouts: ConnectionTimeouts,
    routing: watch::Receiver<Arc<RuleSet>>,
    outbounds: Arc<Vec<ProxyOutbound>>,
    authentication: Arc<Vec<(String, String)>>,
    skip_auth_prefixes: Arc<Vec<AuthSkipPrefix>>,
}

#[derive(Debug, Error)]
pub enum ServerError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error(transparent)]
    Io(#[from] io::Error),
}

/// Bind the configured loopback listener and serve until Ctrl-C.
pub async fn run(config: Config) -> Result<(), ServerError> {
    let listen_addr = config.listen_addr()?;
    let (routing_sender, routing) = watch::channel(Arc::new(config.routing_rules()?));
    let outbounds = Arc::new(config.proxy_outbounds().to_vec());
    let authentication = Arc::new(config.authentication_credentials());
    let skip_auth_prefixes = Arc::new(config.skip_auth_prefixes()?);
    let listener = TcpListener::bind(listen_addr).await?;
    let connection_limit = Arc::new(Semaphore::new(config.max_connections()));
    let timeouts = ConnectionTimeouts {
        connect: Duration::from_millis(config.connect_timeout_ms()),
        handshake: HANDSHAKE_TIMEOUT,
    };
    let connection_context = ConnectionContext {
        timeouts,
        routing,
        outbounds,
        authentication,
        skip_auth_prefixes,
    };
    let mut tasks: JoinSet<io::Result<()>> = JoinSet::new();
    let refreshes = config.rule_provider_refreshes();
    if !refreshes.is_empty() {
        let refresh_config = config.clone();
        let refresh_sender = routing_sender.clone();
        tasks.spawn(async move {
            refresh_rule_provider_loop(refresh_config, refreshes, refresh_sender).await;
            Ok(())
        });
    }
    let shutdown_signal = tokio::signal::ctrl_c();
    tokio::pin!(shutdown_signal);

    info!(
        listen = %listen_addr,
        max_connections = config.max_connections(),
        "SOCKS5 loopback listener started"
    );

    loop {
        tokio::select! {
            result = listener.accept() => {
                let (stream, peer) = result?;
                if !try_spawn_connection(
                    &mut tasks,
                    &connection_limit,
                    stream,
                    peer,
                    &connection_context,
                ) {
                    debug!("connection limit reached; dropping accepted connection");
                }
            }
            result = tasks.join_next(), if !tasks.is_empty() => {
                match result {
                    Some(Ok(Ok(()))) => {}
                    Some(Ok(Err(error))) => debug!(error = %error, "connection ended with an I/O error"),
                    Some(Err(error)) => warn!(error = %error, "connection task failed"),
                    None => {}
                }
            }
            signal = &mut shutdown_signal => {
                signal?;
                info!("shutdown requested");
                break;
            }
        }
    }

    tasks.shutdown().await;
    Ok(())
}

fn try_spawn_connection(
    tasks: &mut JoinSet<io::Result<()>>,
    connection_limit: &Arc<Semaphore>,
    stream: TcpStream,
    peer: SocketAddr,
    context: &ConnectionContext,
) -> bool {
    let Ok(permit) = connection_limit.clone().try_acquire_owned() else {
        drop(stream);
        return false;
    };
    let context = context.clone();
    tasks.spawn(async move {
        let _permit = permit;
        handle_connection_with_rules(
            stream,
            context.timeouts,
            context.routing,
            context.outbounds,
            context.authentication,
            context.skip_auth_prefixes,
            peer,
        )
        .await
    });
    true
}

async fn refresh_rule_provider_loop(
    mut config: Config,
    refreshes: Vec<(String, Duration)>,
    routing: watch::Sender<Arc<RuleSet>>,
) {
    if refreshes.is_empty() {
        return;
    }
    let now = Instant::now();
    let mut deadlines = refreshes
        .iter()
        .map(|(_, interval)| now + *interval)
        .collect::<Vec<_>>();

    loop {
        let deadline = *deadlines.iter().min().expect("non-empty refresh schedule");
        sleep_until(deadline).await;
        let now = Instant::now();
        for (index, (name, interval)) in refreshes.iter().enumerate() {
            if deadlines[index] > now {
                continue;
            }
            match config.refresh_rule_provider(name).await {
                Ok(()) => match config.routing_rules() {
                    Ok(updated_rules) => {
                        routing.send_replace(Arc::new(updated_rules));
                        info!(provider = %name, "rule-provider refreshed");
                    }
                    Err(error) => {
                        warn!(provider = %name, error = %error, "refreshed rules are invalid; keeping previous routing table")
                    }
                },
                Err(error) => {
                    warn!(provider = %name, error = %error, "rule-provider refresh failed; keeping previous routing table")
                }
            }
            deadlines[index] = Instant::now() + *interval;
        }
    }
}

/// Handle one SOCKS5 TCP stream with the default direct-only routing table.
/// Exposed for local integration tests and embedding.
pub async fn handle_connection(client: TcpStream, connect_timeout: Duration) -> io::Result<()> {
    let peer = client.peer_addr()?;
    handle_connection_with_rules(
        client,
        ConnectionTimeouts {
            connect: connect_timeout,
            handshake: HANDSHAKE_TIMEOUT,
        },
        watch::channel(Arc::new(RuleSet::default())).1,
        Arc::new(Vec::new()),
        Arc::new(Vec::new()),
        Arc::new(Vec::new()),
        peer,
    )
    .await
}

async fn handle_connection_with_rules(
    mut client: TcpStream,
    timeouts: ConnectionTimeouts,
    routing: watch::Receiver<Arc<RuleSet>>,
    outbounds: Arc<Vec<ProxyOutbound>>,
    authentication: Arc<Vec<(String, String)>>,
    skip_auth_prefixes: Arc<Vec<AuthSkipPrefix>>,
    peer: SocketAddr,
) -> io::Result<()> {
    let require_authentication = !authentication.is_empty()
        && !skip_auth_prefixes
            .iter()
            .any(|prefix| prefix.contains(peer.ip()));
    let target = match timeout(
        timeouts.handshake,
        negotiate(&mut client, &authentication, require_authentication),
    )
    .await
    {
        Err(_) => return Ok(()),
        Ok(Ok(Some(target))) => target,
        Ok(Ok(None)) => return Ok(()),
        Ok(Err(ProtocolError::Reply(code))) => {
            send_reply(&mut client, code, None).await?;
            return Ok(());
        }
        Ok(Err(ProtocolError::Io(error))) => return Err(error),
    };

    let routing_table = Arc::clone(&routing.borrow());
    let action = routing_table.route_with_source(&target, Some(peer));
    if action == RouteAction::Reject {
        send_reply(&mut client, REP_CONNECTION_NOT_ALLOWED, None).await?;
        return Ok(());
    }

    let connect_result = timeout(timeouts.connect, async {
        match action {
            RouteAction::Direct => connect_target(&target).await,
            RouteAction::Proxy(name) => {
                let proxy = outbounds
                    .iter()
                    .find(|proxy| proxy.name == name)
                    .ok_or_else(|| {
                        io::Error::new(io::ErrorKind::InvalidInput, "configured proxy not found")
                    })?;
                proxy.connect(&target).await
            }
            RouteAction::Reject => unreachable!("REJECT returns before dialing"),
        }
    })
    .await;
    let mut upstream = match connect_result {
        Ok(Ok(upstream)) => upstream,
        Ok(Err(error)) => {
            let _ = send_reply(&mut client, reply_for_io_error(&error), None).await;
            return Err(error);
        }
        Err(_) => {
            send_reply(&mut client, REP_GENERAL_FAILURE, None).await?;
            return Ok(());
        }
    };

    let bound_address = upstream.local_addr()?;
    send_reply(&mut client, REP_SUCCEEDED, Some(bound_address)).await?;
    copy_bidirectional(&mut client, &mut upstream).await?;
    Ok(())
}

#[derive(Debug)]
enum ProtocolError {
    Io(io::Error),
    Reply(u8),
}

impl From<io::Error> for ProtocolError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

async fn negotiate<S>(
    stream: &mut S,
    authentication: &[(String, String)],
    require_authentication: bool,
) -> Result<Option<RequestTarget>, ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut greeting = [0u8; 2];
    stream.read_exact(&mut greeting).await?;
    if greeting[0] != SOCKS_VERSION || greeting[1] == 0 {
        stream
            .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
            .await?;
        return Ok(None);
    }

    let mut methods = vec![0u8; usize::from(greeting[1])];
    stream.read_exact(&mut methods).await?;
    let selected_method = if require_authentication {
        METHOD_USERNAME_PASSWORD
    } else {
        METHOD_NO_AUTH
    };
    if !methods.contains(&selected_method) {
        stream
            .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
            .await?;
        return Ok(None);
    }
    stream.write_all(&[SOCKS_VERSION, selected_method]).await?;
    if selected_method == METHOD_USERNAME_PASSWORD
        && !authenticate_user(stream, authentication).await?
    {
        return Ok(None);
    }

    read_connect_request(stream).await.map(Some)
}

async fn authenticate_user<S>(
    stream: &mut S,
    authentication: &[(String, String)],
) -> Result<bool, ProtocolError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut header = [0u8; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != AUTH_VERSION || header[1] == 0 {
        stream.write_all(&[AUTH_VERSION, 0x01]).await?;
        return Ok(false);
    }
    let mut username = vec![0u8; usize::from(header[1])];
    stream.read_exact(&mut username).await?;
    let password_len = stream.read_u8().await?;
    if password_len == 0 {
        stream.write_all(&[AUTH_VERSION, 0x01]).await?;
        return Ok(false);
    }
    let mut password = vec![0u8; usize::from(password_len)];
    stream.read_exact(&mut password).await?;
    let authenticated = authentication
        .iter()
        .any(|(expected_user, expected_password)| {
            expected_user.as_bytes() == username && expected_password.as_bytes() == password
        });
    stream
        .write_all(&[AUTH_VERSION, if authenticated { 0x00 } else { 0x01 }])
        .await?;
    Ok(authenticated)
}

async fn read_connect_request<S>(stream: &mut S) -> Result<RequestTarget, ProtocolError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;

    let host = match header[3] {
        0x01 => {
            let mut octets = [0u8; 4];
            stream.read_exact(&mut octets).await?;
            TargetHost::Ip(IpAddr::V4(octets.into()))
        }
        0x04 => {
            let mut octets = [0u8; 16];
            stream.read_exact(&mut octets).await?;
            TargetHost::Ip(IpAddr::V6(octets.into()))
        }
        0x03 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            if length[0] == 0 {
                return Err(ProtocolError::Reply(REP_ADDRESS_TYPE_NOT_SUPPORTED));
            }
            let mut bytes = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut bytes).await?;
            let domain = String::from_utf8(bytes)
                .map_err(|_| ProtocolError::Reply(REP_ADDRESS_TYPE_NOT_SUPPORTED))?;
            TargetHost::Domain(domain)
        }
        _ => return Err(ProtocolError::Reply(REP_ADDRESS_TYPE_NOT_SUPPORTED)),
    };

    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    let port = u16::from_be_bytes(port_bytes);
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        return Err(ProtocolError::Reply(REP_GENERAL_FAILURE));
    }
    if header[1] != CMD_CONNECT {
        return Err(ProtocolError::Reply(REP_COMMAND_NOT_SUPPORTED));
    }
    Ok(RequestTarget { host, port })
}

async fn connect_target(target: &RequestTarget) -> io::Result<TcpStream> {
    match &target.host {
        TargetHost::Ip(address) => TcpStream::connect(SocketAddr::new(*address, target.port)).await,
        TargetHost::Domain(domain) => TcpStream::connect((domain.as_str(), target.port)).await,
    }
}

async fn send_reply<S>(
    stream: &mut S,
    reply: u8,
    bound_address: Option<SocketAddr>,
) -> io::Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut bytes = vec![SOCKS_VERSION, reply, 0];
    match bound_address.unwrap_or_else(|| SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)) {
        SocketAddr::V4(address) => {
            bytes.push(0x01);
            bytes.extend_from_slice(&address.ip().octets());
            bytes.extend_from_slice(&address.port().to_be_bytes());
        }
        SocketAddr::V6(address) => {
            bytes.push(0x04);
            bytes.extend_from_slice(&address.ip().octets());
            bytes.extend_from_slice(&address.port().to_be_bytes());
        }
    }
    stream.write_all(&bytes).await
}

fn reply_for_io_error(error: &io::Error) -> u8 {
    match error.kind() {
        io::ErrorKind::ConnectionRefused => REP_CONNECTION_REFUSED,
        io::ErrorKind::NetworkUnreachable => REP_NETWORK_UNREACHABLE,
        io::ErrorKind::HostUnreachable => REP_HOST_UNREACHABLE,
        io::ErrorKind::TimedOut => REP_GENERAL_FAILURE,
        _ => REP_GENERAL_FAILURE,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn start_one_connection() -> (TcpStream, tokio::task::JoinHandle<io::Result<()>>) {
        start_one_connection_with_rules(RuleSet::default()).await
    }

    async fn start_one_connection_with_rules(
        rules: RuleSet,
    ) -> (TcpStream, tokio::task::JoinHandle<io::Result<()>>) {
        start_one_connection_with_rules_and_outbounds(rules, Vec::new()).await
    }

    async fn start_one_connection_with_rules_and_outbounds(
        rules: RuleSet,
        outbounds: Vec<ProxyOutbound>,
    ) -> (TcpStream, tokio::task::JoinHandle<io::Result<()>>) {
        start_one_connection_with_authentication(rules, outbounds, Vec::new()).await
    }

    async fn start_one_connection_with_authentication(
        rules: RuleSet,
        outbounds: Vec<ProxyOutbound>,
        authentication: Vec<(String, String)>,
    ) -> (TcpStream, tokio::task::JoinHandle<io::Result<()>>) {
        start_one_connection_with_auth_policy(rules, outbounds, authentication, Vec::new()).await
    }

    async fn start_one_connection_with_auth_policy(
        rules: RuleSet,
        outbounds: Vec<ProxyOutbound>,
        authentication: Vec<(String, String)>,
        skip_auth_prefixes: Vec<AuthSkipPrefix>,
    ) -> (TcpStream, tokio::task::JoinHandle<io::Result<()>>) {
        start_one_connection_with_handshake_timeout(
            rules,
            outbounds,
            authentication,
            skip_auth_prefixes,
            HANDSHAKE_TIMEOUT,
        )
        .await
    }

    async fn start_one_connection_with_handshake_timeout(
        rules: RuleSet,
        outbounds: Vec<ProxyOutbound>,
        authentication: Vec<(String, String)>,
        skip_auth_prefixes: Vec<AuthSkipPrefix>,
        handshake_timeout: Duration,
    ) -> (TcpStream, tokio::task::JoinHandle<io::Result<()>>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (_, routing) = watch::channel(Arc::new(rules));
        let outbounds = Arc::new(outbounds);
        let authentication = Arc::new(authentication);
        let skip_auth_prefixes = Arc::new(skip_auth_prefixes);
        let task = tokio::spawn(async move {
            let (stream, peer) = listener.accept().await?;
            handle_connection_with_rules(
                stream,
                ConnectionTimeouts {
                    connect: Duration::from_secs(2),
                    handshake: handshake_timeout,
                },
                routing,
                outbounds,
                authentication,
                skip_auth_prefixes,
                peer,
            )
            .await
        });
        let client = TcpStream::connect(address).await.unwrap();
        (client, task)
    }

    async fn negotiate_no_auth(client: &mut TcpStream) {
        client
            .write_all(&[SOCKS_VERSION, 1, METHOD_NO_AUTH])
            .await
            .unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [SOCKS_VERSION, METHOD_NO_AUTH]);
    }

    async fn read_reply(client: &mut TcpStream) -> (u8, u8) {
        let mut header = [0u8; 4];
        client.read_exact(&mut header).await.unwrap();
        let address_len = match header[3] {
            0x01 => 4,
            0x04 => 16,
            other => panic!("unexpected reply address type: {other}"),
        };
        let mut rest = vec![0u8; address_len + 2];
        client.read_exact(&mut rest).await.unwrap();
        (header[0], header[1])
    }

    async fn parse_target(request: &[u8]) -> Result<RequestTarget, ProtocolError> {
        let (mut writer, mut reader) = tokio::io::duplex(request.len() + 1);
        writer.write_all(request).await.unwrap();
        drop(writer);
        read_connect_request(&mut reader).await
    }

    async fn start_provider_response_sequence(
        bodies: Vec<Vec<u8>>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            for body in bodies {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") && request.len() < 16 * 1024 {
                    let mut byte = [0u8; 1];
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    request.push(byte[0]);
                }
                let headers = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if stream.write_all(headers.as_bytes()).await.is_err()
                    || stream.write_all(&body).await.is_err()
                {
                    return;
                }
            }
        });
        (address, task)
    }

    #[tokio::test]
    async fn scheduled_provider_refresh_replaces_routing_and_persists_snapshot() {
        let directory = std::env::temp_dir().join(format!(
            "rust-mhm-refresh-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let (address, server) = start_provider_response_sequence(vec![
            b"payload:\n  - .old.example\n".to_vec(),
            b"payload:\n  - .new.example\n".to_vec(),
        ])
        .await;
        let config_path = directory.join("config.yaml");
        std::fs::write(
            &config_path,
            format!(
                "rule-providers:\n  remote:\n    type: http\n    behavior: domain\n    url: 'http://{address}/rules'\n    path: provider.cache\n    interval: 1\nrules:\n  - RULE-SET,remote,REJECT\n  - MATCH,DIRECT\n"
            ),
        )
        .unwrap();

        let config = Config::load_async(&config_path).await.unwrap();
        let refreshes = config.rule_provider_refreshes();
        let (sender, mut routing) = watch::channel(Arc::new(config.routing_rules().unwrap()));
        let refresh_task = tokio::spawn(refresh_rule_provider_loop(config, refreshes, sender));
        let new_target = RequestTarget {
            host: TargetHost::Domain("cdn.new.example".into()),
            port: 443,
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                routing.changed().await.unwrap();
                if routing.borrow().route(&new_target) == RouteAction::Reject {
                    break;
                }
            }
        })
        .await
        .expect("scheduled refresh should publish the new routing table");
        assert_eq!(
            routing.borrow().route(&RequestTarget {
                host: TargetHost::Domain("cdn.old.example".into()),
                port: 443,
            }),
            RouteAction::Direct
        );
        assert_eq!(
            std::fs::read(directory.join("provider.cache")).unwrap(),
            b"payload:\n  - .new.example\n"
        );

        refresh_task.abort();
        let _ = refresh_task.await;
        server.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn file_provider_refresh_swaps_valid_routes_and_keeps_them_on_bad_files() {
        let directory = std::env::temp_dir().join(format!(
            "rust-mhm-file-refresh-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let provider_path = directory.join("provider.rules");
        std::fs::write(&provider_path, "payload:\n  - DOMAIN-SUFFIX,old.example\n").unwrap();
        let config_path = directory.join("config.yaml");
        std::fs::write(
            &config_path,
            "rule-providers:\n  local:\n    type: file\n    behavior: classical\n    path: provider.rules\n    interval: 1\nrules:\n  - RULE-SET,local,REJECT\n  - MATCH,DIRECT\n",
        )
        .unwrap();

        let config = Config::load_async(&config_path).await.unwrap();
        let refreshes = config.rule_provider_refreshes();
        let (sender, mut routing) = watch::channel(Arc::new(config.routing_rules().unwrap()));
        let refresh_task = tokio::spawn(refresh_rule_provider_loop(config, refreshes, sender));
        let old_target = RequestTarget {
            host: TargetHost::Domain("cdn.old.example".into()),
            port: 443,
        };
        let new_target = RequestTarget {
            host: TargetHost::Domain("cdn.new.example".into()),
            port: 443,
        };
        assert_eq!(routing.borrow().route(&old_target), RouteAction::Reject);

        std::fs::write(&provider_path, "payload:\n  - DOMAIN-SUFFIX,new.example\n").unwrap();
        tokio::time::timeout(Duration::from_secs(4), async {
            loop {
                routing.changed().await.unwrap();
                if routing.borrow().route(&new_target) == RouteAction::Reject {
                    break;
                }
            }
        })
        .await
        .expect("a valid file replacement should publish new routes");
        assert_eq!(routing.borrow().route(&old_target), RouteAction::Direct);

        std::fs::write(&provider_path, "payload:\n  - GEOIP,CN\n").unwrap();
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert!(!routing.has_changed().unwrap());
        assert_eq!(routing.borrow().route(&new_target), RouteAction::Reject);

        std::fs::write(&provider_path, vec![b'x'; 4 * 1024 * 1024 + 1]).unwrap();
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert!(!routing.has_changed().unwrap());
        assert_eq!(routing.borrow().route(&new_target), RouteAction::Reject);

        std::fs::remove_file(&provider_path).unwrap();
        tokio::time::sleep(Duration::from_millis(1_200)).await;
        assert!(!routing.has_changed().unwrap());
        assert_eq!(routing.borrow().route(&new_target), RouteAction::Reject);

        refresh_task.abort();
        let _ = refresh_task.await;
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn slow_provider_refresh_waits_full_interval_after_completion() {
        use std::sync::atomic::{AtomicUsize, Ordering};

        let directory = std::env::temp_dir().join(format!(
            "rust-mhm-slow-refresh-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let request_count = Arc::new(AtomicUsize::new(0));
        let server_request_count = Arc::clone(&request_count);
        let server = tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let mut request = Vec::new();
                while !request.ends_with(b"\r\n\r\n") && request.len() < 16 * 1024 {
                    let mut byte = [0u8; 1];
                    if stream.read_exact(&mut byte).await.is_err() {
                        return;
                    }
                    request.push(byte[0]);
                }
                server_request_count.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(500)).await;
                let body = b"payload:\n  - .slow.example\n";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                if stream.write_all(response.as_bytes()).await.is_err()
                    || stream.write_all(body).await.is_err()
                {
                    return;
                }
            }
        });
        let config_path = directory.join("config.yaml");
        std::fs::write(
            &config_path,
            format!(
                "rule-providers:\n  remote:\n    type: http\n    behavior: domain\n    url: 'http://{address}/rules'\n    path: provider.cache\n    interval: 1\nrules:\n  - RULE-SET,remote,REJECT\n  - MATCH,DIRECT\n"
            ),
        )
        .unwrap();
        let config = Config::load_async(&config_path).await.unwrap();
        assert_eq!(request_count.load(Ordering::SeqCst), 1);
        let refreshes = config.rule_provider_refreshes();
        let (sender, mut routing) = watch::channel(Arc::new(config.routing_rules().unwrap()));
        let refresh_task = tokio::spawn(refresh_rule_provider_loop(config, refreshes, sender));

        tokio::time::timeout(Duration::from_secs(4), routing.changed())
            .await
            .expect("first scheduled refresh should finish")
            .unwrap();
        tokio::time::sleep(Duration::from_millis(250)).await;
        assert_eq!(request_count.load(Ordering::SeqCst), 2);

        refresh_task.abort();
        let _ = refresh_task.await;
        server.abort();
        let _ = server.await;
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn parses_domain_target() {
        let mut request = vec![SOCKS_VERSION, CMD_CONNECT, 0, 0x03, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());

        let target = parse_target(&request).await.unwrap();
        assert!(
            matches!(target, RequestTarget { host: TargetHost::Domain(domain), port: 443 } if domain == "example.com")
        );
    }

    #[tokio::test]
    async fn invalid_provider_refresh_keeps_active_routes_and_cached_snapshot() {
        let directory = std::env::temp_dir().join(format!(
            "rust-mhm-invalid-refresh-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&directory).unwrap();
        let initial = b"payload:\n  - DOMAIN-SUFFIX,old.example\n".to_vec();
        let invalid = b"payload:\n  - GEOIP,CN\n".to_vec();
        let (address, server) =
            start_provider_response_sequence(vec![initial.clone(), invalid]).await;
        let config_path = directory.join("config.yaml");
        let cache_path = directory.join("provider.cache");
        std::fs::write(
            &config_path,
            format!(
                "rule-providers:\n  remote:\n    type: http\n    behavior: classical\n    url: 'http://{address}/rules'\n    path: provider.cache\n    interval: 1\nrules:\n  - RULE-SET,remote,REJECT\n  - MATCH,DIRECT\n"
            ),
        )
        .unwrap();
        let config = Config::load_async(&config_path).await.unwrap();
        let refreshes = config.rule_provider_refreshes();
        let (sender, routing) = watch::channel(Arc::new(config.routing_rules().unwrap()));
        let refresh_task = tokio::spawn(refresh_rule_provider_loop(config, refreshes, sender));

        server.await.unwrap();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(!routing.has_changed().unwrap());
        assert_eq!(
            routing.borrow().route(&RequestTarget {
                host: TargetHost::Domain("cdn.old.example".into()),
                port: 443,
            }),
            RouteAction::Reject
        );
        assert_eq!(std::fs::read(&cache_path).unwrap(), initial);

        refresh_task.abort();
        let _ = refresh_task.await;
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn parses_ipv6_target() {
        let mut request = vec![SOCKS_VERSION, CMD_CONNECT, 0, 0x04];
        request.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        request.extend_from_slice(&8443u16.to_be_bytes());

        let target = parse_target(&request).await.unwrap();
        assert!(
            matches!(target, RequestTarget { host: TargetHost::Ip(address), port: 8443 } if address == IpAddr::V6(std::net::Ipv6Addr::LOCALHOST))
        );
    }

    #[tokio::test]
    async fn every_truncated_connect_frame_returns_unexpected_eof() {
        let mut ipv4 = vec![SOCKS_VERSION, CMD_CONNECT, 0, 0x01, 127, 0, 0, 1];
        ipv4.extend_from_slice(&443u16.to_be_bytes());
        let mut ipv6 = vec![SOCKS_VERSION, CMD_CONNECT, 0, 0x04];
        ipv6.extend_from_slice(&std::net::Ipv6Addr::LOCALHOST.octets());
        ipv6.extend_from_slice(&443u16.to_be_bytes());
        let domain = b"example.test";
        let mut domain_frame = vec![SOCKS_VERSION, CMD_CONNECT, 0, 0x03, domain.len() as u8];
        domain_frame.extend_from_slice(domain);
        domain_frame.extend_from_slice(&443u16.to_be_bytes());

        for frame in [ipv4, ipv6, domain_frame] {
            for prefix_length in 0..frame.len() {
                let result = parse_target(&frame[..prefix_length]).await;
                assert!(
                    matches!(result, Err(ProtocolError::Io(ref error)) if error.kind() == io::ErrorKind::UnexpectedEof),
                    "truncated frame with prefix length {prefix_length} must return UnexpectedEof"
                );
            }
        }
    }

    #[tokio::test]
    async fn malformed_connect_fields_return_protocol_errors() {
        for (frame, expected) in [
            (
                vec![SOCKS_VERSION, CMD_CONNECT, 0, 0x02],
                REP_ADDRESS_TYPE_NOT_SUPPORTED,
            ),
            (
                vec![SOCKS_VERSION, CMD_CONNECT, 0, 0x03, 0],
                REP_ADDRESS_TYPE_NOT_SUPPORTED,
            ),
            (
                vec![SOCKS_VERSION, CMD_CONNECT, 0, 0x03, 1, 0xff],
                REP_ADDRESS_TYPE_NOT_SUPPORTED,
            ),
            (
                vec![SOCKS_VERSION, CMD_CONNECT, 1, 0x01, 127, 0, 0, 1, 0, 80],
                REP_GENERAL_FAILURE,
            ),
            (
                vec![0x04, CMD_CONNECT, 0, 0x01, 127, 0, 0, 1, 0, 80],
                REP_GENERAL_FAILURE,
            ),
        ] {
            assert!(matches!(
                parse_target(&frame).await,
                Err(ProtocolError::Reply(reply)) if reply == expected
            ));
        }
    }

    #[tokio::test]
    async fn socks5_connect_relays_tcp_to_local_echo_server() {
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo_listener.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let (mut stream, _) = echo_listener.accept().await.unwrap();
            let mut buffer = [0u8; 1024];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                stream.write_all(&buffer[..count]).await.unwrap();
            }
        });

        let (mut client, server_task) = start_one_connection().await;
        negotiate_no_auth(&mut client).await;

        let mut request = vec![SOCKS_VERSION, CMD_CONNECT, 0, 0x01];
        match echo_address.ip() {
            IpAddr::V4(address) => request.extend_from_slice(&address.octets()),
            IpAddr::V6(_) => unreachable!(),
        }
        request.extend_from_slice(&echo_address.port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            (SOCKS_VERSION, REP_SUCCEEDED)
        );

        let payload = b"rust-mhm-local-relay";
        client.write_all(payload).await.unwrap();
        let mut echoed = vec![0u8; payload.len()];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(echoed, payload);

        client.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();
        echo_task.await.unwrap();
    }

    #[tokio::test]
    async fn incomplete_greeting_times_out_and_closes_slow_client() {
        let (mut client, server_task) = start_one_connection_with_handshake_timeout(
            RuleSet::default(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Duration::from_millis(100),
        )
        .await;
        client.write_all(&[SOCKS_VERSION]).await.unwrap();

        let mut byte = [0u8; 1];
        let received = timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("server should close the timed-out connection")
            .unwrap();
        assert_eq!(received, 0);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn cancelling_a_negotiated_session_closes_the_client_stream() {
        let (mut client, server_task) = start_one_connection().await;
        negotiate_no_auth(&mut client).await;
        server_task.abort();
        assert!(server_task.await.unwrap_err().is_cancelled());

        let mut byte = [0u8; 1];
        let result = timeout(Duration::from_secs(1), client.read(&mut byte))
            .await
            .expect("cancelling the session should close its client stream");
        match result {
            Ok(0) => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ) => {}
            other => panic!("unexpected read after cancelling session: {other:?}"),
        }
    }

    #[tokio::test]
    async fn truncated_connect_frame_closes_without_success_reply() {
        let (mut client, server_task) = start_one_connection().await;
        negotiate_no_auth(&mut client).await;
        client
            .write_all(&[SOCKS_VERSION, CMD_CONNECT, 0, 0x01, 127, 0])
            .await
            .unwrap();
        client.shutdown().await.unwrap();

        let mut byte = [0u8; 1];
        assert_eq!(client.read(&mut byte).await.unwrap(), 0);
        let error = server_task.await.unwrap().unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
    }

    #[tokio::test]
    async fn unsupported_socks_command_is_rejected() {
        let (mut client, server_task) = start_one_connection().await;
        negotiate_no_auth(&mut client).await;
        // UDP ASSOCIATE is deliberately outside this TCP-only phase.
        client
            .write_all(&[SOCKS_VERSION, 0x03, 0, 0x01, 127, 0, 0, 1, 0, 53])
            .await
            .unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            (SOCKS_VERSION, REP_COMMAND_NOT_SUPPORTED)
        );
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn malformed_greetings_are_rejected_with_no_acceptable_method() {
        for greeting in [
            vec![0x04, 1, METHOD_NO_AUTH],
            vec![SOCKS_VERSION, 0],
            vec![SOCKS_VERSION, 1, METHOD_USERNAME_PASSWORD],
        ] {
            let (mut client, mut server) = tokio::io::duplex(64);
            client.write_all(&greeting).await.unwrap();
            assert!(negotiate(&mut server, &[], false).await.unwrap().is_none());
            let mut response = [0u8; 2];
            client.read_exact(&mut response).await.unwrap();
            assert_eq!(response, [SOCKS_VERSION, METHOD_NO_ACCEPTABLE]);
        }
    }

    #[tokio::test]
    async fn connection_limit_bounds_parallel_socks5_sessions() {
        const CONNECTION_LIMIT: usize = 8;
        const CLIENT_COUNT: usize = 20;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let connection_limit = Arc::new(Semaphore::new(CONNECTION_LIMIT));
        let (routing_sender, routing) = watch::channel(Arc::new(RuleSet::default()));
        let outbounds = Arc::new(Vec::new());
        let authentication = Arc::new(Vec::new());
        let skip_auth_prefixes = Arc::new(Vec::new());
        let timeouts = ConnectionTimeouts {
            connect: Duration::from_secs(2),
            handshake: Duration::from_secs(2),
        };
        let connection_context = ConnectionContext {
            timeouts,
            routing,
            outbounds,
            authentication,
            skip_auth_prefixes,
        };
        let mut clients = Vec::with_capacity(CLIENT_COUNT);
        for _ in 0..CLIENT_COUNT {
            clients.push(TcpStream::connect(address).await.unwrap());
        }

        let mut connection_tasks = JoinSet::new();
        let mut started = 0;
        for _ in 0..CLIENT_COUNT {
            let (stream, peer) = listener.accept().await.unwrap();
            started += usize::from(try_spawn_connection(
                &mut connection_tasks,
                &connection_limit,
                stream,
                peer,
                &connection_context,
            ));
        }
        assert_eq!(started, CONNECTION_LIMIT);

        let mut client_tasks = JoinSet::new();
        for mut client in clients {
            client_tasks.spawn(async move {
                client
                    .write_all(&[SOCKS_VERSION, 1, METHOD_NO_AUTH])
                    .await
                    .unwrap();
                let mut method_response = [0u8; 2];
                match timeout(
                    Duration::from_secs(2),
                    client.read_exact(&mut method_response),
                )
                .await
                .expect("accepted session should respond and excess session should close")
                {
                    Ok(_) => {
                        assert_eq!(method_response, [SOCKS_VERSION, METHOD_NO_AUTH]);
                        client
                            .write_all(&[SOCKS_VERSION, 0x03, 0, 0x01, 127, 0, 0, 1, 0, 53])
                            .await
                            .unwrap();
                        assert_eq!(
                            read_reply(&mut client).await,
                            (SOCKS_VERSION, REP_COMMAND_NOT_SUPPORTED)
                        );
                        true
                    }
                    Err(error)
                        if matches!(
                            error.kind(),
                            io::ErrorKind::UnexpectedEof
                                | io::ErrorKind::ConnectionReset
                                | io::ErrorKind::ConnectionAborted
                        ) =>
                    {
                        false
                    }
                    Err(error) => panic!("unexpected read error for handshake: {error}"),
                }
            });
        }
        let mut completed = 0;
        let mut accepted = 0;
        while let Some(result) = client_tasks.join_next().await {
            completed += 1;
            accepted += usize::from(result.unwrap());
        }
        assert_eq!(completed, CLIENT_COUNT);
        assert_eq!(accepted, CONNECTION_LIMIT);

        while let Some(result) = connection_tasks.join_next().await {
            result.unwrap().unwrap();
        }
        drop(routing_sender);
    }

    #[tokio::test]
    async fn unsupported_authentication_is_refused() {
        let (mut client, server_task) = start_one_connection().await;
        client.write_all(&[SOCKS_VERSION, 1, 0x02]).await.unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [SOCKS_VERSION, METHOD_NO_ACCEPTABLE]);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn malformed_username_password_frames_are_rejected_or_closed() {
        let cases = [
            (vec![0x02, 1], false),
            (vec![AUTH_VERSION, 0], false),
            (vec![AUTH_VERSION, 1, b'a', 0], false),
            (vec![AUTH_VERSION], true),
            (vec![AUTH_VERSION, 3, b'a'], true),
            (vec![AUTH_VERSION, 1, b'a', 3, b'x'], true),
        ];
        for (frame, truncated) in cases {
            let users = vec![("alice".to_owned(), "secret".to_owned())];
            let (mut client, server_task) =
                start_one_connection_with_authentication(RuleSet::default(), Vec::new(), users)
                    .await;
            client
                .write_all(&[SOCKS_VERSION, 1, METHOD_USERNAME_PASSWORD])
                .await
                .unwrap();
            let mut method = [0u8; 2];
            client.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [SOCKS_VERSION, METHOD_USERNAME_PASSWORD]);
            client.write_all(&frame).await.unwrap();

            if truncated {
                client.shutdown().await.unwrap();
                let mut byte = [0u8; 1];
                assert_eq!(client.read(&mut byte).await.unwrap(), 0);
                let error = server_task.await.unwrap().unwrap_err();
                assert_eq!(error.kind(), io::ErrorKind::UnexpectedEof);
            } else {
                let mut response = [0u8; 2];
                client.read_exact(&mut response).await.unwrap();
                assert_eq!(response, [AUTH_VERSION, 0x01]);
                server_task.await.unwrap().unwrap();
            }
        }
    }

    #[tokio::test]
    async fn configured_user_must_authenticate_before_connect_commands() {
        let users = vec![("alice".to_owned(), "secret".to_owned())];
        let (mut client, server_task) =
            start_one_connection_with_authentication(RuleSet::default(), Vec::new(), users).await;
        client
            .write_all(&[SOCKS_VERSION, 2, METHOD_NO_AUTH, METHOD_USERNAME_PASSWORD])
            .await
            .unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [SOCKS_VERSION, METHOD_USERNAME_PASSWORD]);
        client.write_all(&[AUTH_VERSION, 5]).await.unwrap();
        client.write_all(b"alice").await.unwrap();
        client.write_all(&[6]).await.unwrap();
        client.write_all(b"secret").await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [AUTH_VERSION, 0x00]);
        client
            .write_all(&[SOCKS_VERSION, 0x03, 0, 0x01, 127, 0, 0, 1, 0, 53])
            .await
            .unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            (SOCKS_VERSION, REP_COMMAND_NOT_SUPPORTED)
        );
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn invalid_user_password_is_rejected_and_connection_closes() {
        let users = vec![("alice".to_owned(), "secret".to_owned())];
        let (mut client, server_task) =
            start_one_connection_with_authentication(RuleSet::default(), Vec::new(), users).await;
        client
            .write_all(&[SOCKS_VERSION, 1, METHOD_USERNAME_PASSWORD])
            .await
            .unwrap();
        let mut method = [0u8; 2];
        client.read_exact(&mut method).await.unwrap();
        assert_eq!(method, [SOCKS_VERSION, METHOD_USERNAME_PASSWORD]);
        client.write_all(&[AUTH_VERSION, 3]).await.unwrap();
        client.write_all(b"bob").await.unwrap();
        client.write_all(&[6]).await.unwrap();
        client.write_all(b"secret").await.unwrap();
        let mut auth_reply = [0u8; 2];
        client.read_exact(&mut auth_reply).await.unwrap();
        assert_eq!(auth_reply, [AUTH_VERSION, 0x01]);
        let mut trailing = [0u8; 1];
        assert_eq!(client.read(&mut trailing).await.unwrap(), 0);
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn skip_auth_prefix_allows_no_auth_method_for_matching_peer() {
        let config = Config::from_yaml_str(
            "authentication:\n  - alice:secret\nskip-auth-prefixes:\n  - 127.0.0.1/32\n",
        )
        .unwrap();
        let (mut client, server_task) = start_one_connection_with_auth_policy(
            RuleSet::default(),
            Vec::new(),
            config.authentication_credentials(),
            config.skip_auth_prefixes().unwrap(),
        )
        .await;
        negotiate_no_auth(&mut client).await;
        client
            .write_all(&[SOCKS_VERSION, 0x03, 0, 0x01, 127, 0, 0, 1, 0, 53])
            .await
            .unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            (SOCKS_VERSION, REP_COMMAND_NOT_SUPPORTED)
        );
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn reject_rule_sends_connection_not_allowed_without_dialing() {
        let rules = RuleSet::parse(&["DST-PORT,80,REJECT".to_owned()]).unwrap();
        let (mut client, server_task) = start_one_connection_with_rules(rules).await;
        negotiate_no_auth(&mut client).await;
        client
            .write_all(&[SOCKS_VERSION, CMD_CONNECT, 0, 0x01, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            (SOCKS_VERSION, REP_CONNECTION_NOT_ALLOWED)
        );
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn source_ip_cidr_rule_uses_inbound_peer_address() {
        let rules = RuleSet::parse(&["SRC-IP-CIDR,127.0.0.1/32,REJECT".to_owned()]).unwrap();
        let (mut client, server_task) = start_one_connection_with_rules(rules).await;
        negotiate_no_auth(&mut client).await;
        client
            .write_all(&[SOCKS_VERSION, CMD_CONNECT, 0, 0x01, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            (SOCKS_VERSION, REP_CONNECTION_NOT_ALLOWED)
        );
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn source_port_rule_uses_inbound_peer_port() {
        let rules = RuleSet::parse(&["SRC-PORT,1-65535,REJECT".to_owned()]).unwrap();
        let (mut client, server_task) = start_one_connection_with_rules(rules).await;
        negotiate_no_auth(&mut client).await;
        client
            .write_all(&[SOCKS_VERSION, CMD_CONNECT, 0, 0x01, 127, 0, 0, 1, 0, 80])
            .await
            .unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            (SOCKS_VERSION, REP_CONNECTION_NOT_ALLOWED)
        );
        server_task.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn named_http_connect_proxy_authenticates_and_relays_tcp() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await.unwrap();
            let mut headers = Vec::new();
            while !headers.ends_with(b"\r\n\r\n") {
                headers.push(stream.read_u8().await.unwrap());
            }
            let headers = String::from_utf8(headers).unwrap();
            assert!(headers.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            assert!(headers.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
            stream
                .write_all(
                    b"HTTP/1.1 200 Connection established\r\nX-Proxy-Extension: \xff\r\n\r\n",
                )
                .await
                .unwrap();
            let mut buffer = [0u8; 256];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                stream.write_all(&buffer[..count]).await.unwrap();
            }
        });
        let proxy = ProxyOutbound {
            name: "upstream".into(),
            kind: "http".into(),
            server: proxy_address.ip().to_string(),
            port: proxy_address.port(),
            username: Some("user".into()),
            password: Some("pass".into()),
        };
        let names = vec!["upstream".to_owned()];
        let rules = RuleSet::parse_with_proxies(&["MATCH,upstream".to_owned()], &names).unwrap();
        let (mut client, server_task) =
            start_one_connection_with_rules_and_outbounds(rules, vec![proxy]).await;
        negotiate_no_auth(&mut client).await;
        client
            .write_all(&[SOCKS_VERSION, CMD_CONNECT, 0, 0x03, 11])
            .await
            .unwrap();
        client.write_all(b"example.com").await.unwrap();
        client.write_all(&443u16.to_be_bytes()).await.unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            (SOCKS_VERSION, REP_SUCCEEDED)
        );
        client.write_all(b"through-http-proxy").await.unwrap();
        let mut echoed = [0u8; 18];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"through-http-proxy");
        client.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();
        proxy_task.await.unwrap();
    }

    #[tokio::test]
    async fn named_socks5_proxy_authenticates_and_relays_tcp() {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = proxy_listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut stream, _) = proxy_listener.accept().await.unwrap();
            let mut greeting = [0u8; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01, 0x02]);
            stream.write_all(&[0x05, 0x02]).await.unwrap();
            let mut auth_header = [0u8; 2];
            stream.read_exact(&mut auth_header).await.unwrap();
            assert_eq!(auth_header[0], 0x01);
            let mut username = vec![0u8; auth_header[1] as usize];
            stream.read_exact(&mut username).await.unwrap();
            let password_len = stream.read_u8().await.unwrap() as usize;
            let mut password = vec![0u8; password_len];
            stream.read_exact(&mut password).await.unwrap();
            assert_eq!(username, b"user");
            assert_eq!(password, b"pass");
            stream.write_all(&[0x01, 0x00]).await.unwrap();
            let mut request_header = [0u8; 5];
            stream.read_exact(&mut request_header).await.unwrap();
            assert_eq!(request_header, [0x05, 0x01, 0x00, 0x03, 11]);
            let mut domain = [0u8; 11];
            stream.read_exact(&mut domain).await.unwrap();
            let mut port = [0u8; 2];
            stream.read_exact(&mut port).await.unwrap();
            assert_eq!(&domain, b"example.com");
            assert_eq!(u16::from_be_bytes(port), 443);
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .await
                .unwrap();
            let mut buffer = [0u8; 256];
            loop {
                let count = stream.read(&mut buffer).await.unwrap();
                if count == 0 {
                    break;
                }
                stream.write_all(&buffer[..count]).await.unwrap();
            }
        });
        let proxy = ProxyOutbound {
            name: "upstream".into(),
            kind: "socks5".into(),
            server: proxy_address.ip().to_string(),
            port: proxy_address.port(),
            username: Some("user".into()),
            password: Some("pass".into()),
        };
        let names = vec!["upstream".to_owned()];
        let rules = RuleSet::parse_with_proxies(&["MATCH,upstream".to_owned()], &names).unwrap();
        let (mut client, server_task) =
            start_one_connection_with_rules_and_outbounds(rules, vec![proxy]).await;
        negotiate_no_auth(&mut client).await;
        client
            .write_all(&[SOCKS_VERSION, CMD_CONNECT, 0, 0x03, 11])
            .await
            .unwrap();
        client.write_all(b"example.com").await.unwrap();
        client.write_all(&443u16.to_be_bytes()).await.unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            (SOCKS_VERSION, REP_SUCCEEDED)
        );
        client.write_all(b"through-socks5-proxy").await.unwrap();
        let mut echoed = [0u8; 20];
        client.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"through-socks5-proxy");
        client.shutdown().await.unwrap();
        server_task.await.unwrap().unwrap();
        proxy_task.await.unwrap();
    }
}
