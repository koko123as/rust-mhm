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
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};
use tracing::{debug, info, warn};

use crate::config::{Config, ConfigError};
use crate::outbound::ProxyOutbound;
use crate::routing::{RequestTarget, RouteAction, RuleSet, TargetHost};

const SOCKS_VERSION: u8 = 0x05;
const METHOD_NO_AUTH: u8 = 0x00;
const METHOD_NO_ACCEPTABLE: u8 = 0xff;
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
    let routing = Arc::new(config.routing_rules()?);
    let outbounds = Arc::new(config.proxy_outbounds().to_vec());
    let listener = TcpListener::bind(listen_addr).await?;
    let connection_limit = Arc::new(Semaphore::new(config.max_connections()));
    let connect_timeout = Duration::from_millis(config.connect_timeout_ms());
    let mut tasks: JoinSet<io::Result<()>> = JoinSet::new();
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
                let (stream, _peer) = result?;
                match connection_limit.clone().try_acquire_owned() {
                    Ok(permit) => {
                        let routing = Arc::clone(&routing);
                        let outbounds = Arc::clone(&outbounds);
                        tasks.spawn(async move {
                            let _permit = permit;
                            handle_connection_with_rules(stream, connect_timeout, routing, outbounds).await
                        });
                    }
                    Err(_) => {
                        debug!("connection limit reached; dropping accepted connection");
                        drop(stream);
                    }
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

/// Handle one SOCKS5 TCP stream with the default direct-only routing table.
/// Exposed for local integration tests and embedding.
pub async fn handle_connection(client: TcpStream, connect_timeout: Duration) -> io::Result<()> {
    handle_connection_with_rules(
        client,
        connect_timeout,
        Arc::new(RuleSet::default()),
        Arc::new(Vec::new()),
    )
    .await
}

async fn handle_connection_with_rules(
    mut client: TcpStream,
    connect_timeout: Duration,
    routing: Arc<RuleSet>,
    outbounds: Arc<Vec<ProxyOutbound>>,
) -> io::Result<()> {
    let target = match timeout(HANDSHAKE_TIMEOUT, negotiate(&mut client)).await {
        Err(_) => return Ok(()),
        Ok(Ok(Some(target))) => target,
        Ok(Ok(None)) => return Ok(()),
        Ok(Err(ProtocolError::Reply(code))) => {
            send_reply(&mut client, code, None).await?;
            return Ok(());
        }
        Ok(Err(ProtocolError::Io(error))) => return Err(error),
    };

    let action = routing.route(&target);
    if action == RouteAction::Reject {
        send_reply(&mut client, REP_CONNECTION_NOT_ALLOWED, None).await?;
        return Ok(());
    }

    let connect_result = timeout(connect_timeout, async {
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

async fn negotiate<S>(stream: &mut S) -> Result<Option<RequestTarget>, ProtocolError>
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
    if !methods.contains(&METHOD_NO_AUTH) {
        stream
            .write_all(&[SOCKS_VERSION, METHOD_NO_ACCEPTABLE])
            .await?;
        return Ok(None);
    }
    stream.write_all(&[SOCKS_VERSION, METHOD_NO_AUTH]).await?;

    read_connect_request(stream).await.map(Some)
}

async fn read_connect_request<S>(stream: &mut S) -> Result<RequestTarget, ProtocolError>
where
    S: AsyncRead + Unpin,
{
    let mut header = [0u8; 4];
    stream.read_exact(&mut header).await?;
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        return Err(ProtocolError::Reply(REP_GENERAL_FAILURE));
    }
    if header[1] != CMD_CONNECT {
        return Err(ProtocolError::Reply(REP_COMMAND_NOT_SUPPORTED));
    }

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
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let routing = Arc::new(rules);
        let outbounds = Arc::new(outbounds);
        let task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await?;
            handle_connection_with_rules(stream, Duration::from_secs(2), routing, outbounds).await
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
        read_connect_request(&mut reader).await
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
    async fn unsupported_authentication_is_refused() {
        let (mut client, server_task) = start_one_connection().await;
        client.write_all(&[SOCKS_VERSION, 1, 0x02]).await.unwrap();
        let mut response = [0u8; 2];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [SOCKS_VERSION, METHOD_NO_ACCEPTABLE]);
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
