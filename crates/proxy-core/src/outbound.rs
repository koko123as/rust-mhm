use std::{io, net::IpAddr};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::Deserialize;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use crate::routing::{RequestTarget, TargetHost, normalize_domain};

const MAX_HTTP_HEADER: usize = 16 * 1024;

/// A named HTTP CONNECT or SOCKS5 TCP proxy endpoint.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProxyOutbound {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    pub server: String,
    pub port: u16,
    #[serde(default)]
    pub username: Option<String>,
    #[serde(default)]
    pub password: Option<String>,
}

impl ProxyOutbound {
    pub(crate) fn validate(&self) -> Result<(), String> {
        if self.name.trim().is_empty()
            || self.name.contains(',')
            || self.name.chars().any(char::is_whitespace)
            || self.name.chars().any(char::is_control)
            || matches!(self.name.as_str(), "DIRECT" | "REJECT")
        {
            return Err("proxy name must be non-empty, non-reserved, and contain no whitespace, commas, or control characters".into());
        }
        if !matches!(self.kind.as_str(), "http" | "socks5") {
            return Err(format!("unsupported proxy type: {}", self.kind));
        }
        if self.server.trim().is_empty()
            || self.server.chars().any(|character| {
                character.is_whitespace()
                    || character.is_control()
                    || matches!(character, '/' | '@')
            })
        {
            return Err("proxy server must be a hostname or IP address, not a URL".into());
        }
        if self.port == 0 {
            return Err("proxy port must be between 1 and 65535".into());
        }
        match (&self.username, &self.password) {
            (None, None) => {}
            (Some(username), Some(password)) => {
                if username.is_empty() || username.len() > 255 || password.len() > 255 {
                    return Err("proxy credentials must have a non-empty username and fit in 255 UTF-8 bytes".into());
                }
                if self.kind == "http" && username.contains(':') {
                    return Err("HTTP proxy usernames cannot contain ':'".into());
                }
            }
            _ => return Err("proxy username and password must be configured together".into()),
        }
        Ok(())
    }

    /// Establish a TCP tunnel to `target` through this proxy.
    pub async fn connect(&self, target: &RequestTarget) -> io::Result<TcpStream> {
        let mut stream = TcpStream::connect((self.server.as_str(), self.port)).await?;
        match self.kind.as_str() {
            "http" => http_connect(&mut stream, target, self).await?,
            "socks5" => socks5_connect(&mut stream, target, self).await?,
            _ => return Err(invalid_data("unsupported proxy type")),
        }
        Ok(stream)
    }

    /// Establish a SOCKS5 UDP association and return its live control stream and relay socket.
    pub(crate) async fn udp_associate(&self) -> io::Result<(TcpStream, tokio::net::UdpSocket)> {
        if self.kind != "socks5" {
            return Err(invalid_data("UDP ASSOCIATE requires a SOCKS5 proxy"));
        }
        let mut control = TcpStream::connect((self.server.as_str(), self.port)).await?;
        let proxy_peer_ip = control.peer_addr()?.ip();
        socks5_negotiate_auth(&mut control, self).await?;
        control
            .write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await?;
        let relay_address = socks5_udp_relay_address(&mut control, proxy_peer_ip).await?;
        let local_bind = match relay_address.ip() {
            IpAddr::V4(_) => "0.0.0.0:0",
            IpAddr::V6(_) => "[::]:0",
        };
        let relay = tokio::net::UdpSocket::bind(local_bind).await?;
        relay.connect(relay_address).await?;
        Ok((control, relay))
    }
}

async fn http_connect(
    stream: &mut TcpStream,
    target: &RequestTarget,
    proxy: &ProxyOutbound,
) -> io::Result<()> {
    let authority = target_authority(target)?;
    let mut request = format!(
        "CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\nProxy-Connection: Keep-Alive\r\n"
    );
    if let (Some(username), Some(password)) = (&proxy.username, &proxy.password) {
        let credential = STANDARD.encode(format!("{username}:{password}"));
        request.push_str(&format!("Proxy-Authorization: Basic {credential}\r\n"));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await?;

    // Read byte-by-byte so a buffered reader cannot consume any initial tunnel payload.
    let mut response = Vec::with_capacity(256);
    while response.len() < MAX_HTTP_HEADER {
        response.push(stream.read_u8().await?);
        if response.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    if !response.ends_with(b"\r\n\r\n") {
        return Err(invalid_data("HTTP proxy response headers exceed the limit"));
    }
    let line_end = response
        .windows(2)
        .position(|window| window == b"\r\n")
        .ok_or_else(|| invalid_data("HTTP proxy response has no status line"))?;
    let status_line = std::str::from_utf8(&response[..line_end])
        .map_err(|_| invalid_data("HTTP proxy returned a non-ASCII status line"))?;
    let mut fields = status_line.split_ascii_whitespace();
    let version = fields.next().unwrap_or_default();
    let status = fields.next().and_then(|value| value.parse::<u16>().ok());
    if !matches!(version, "HTTP/1.0" | "HTTP/1.1")
        || !status.is_some_and(|code| (200..300).contains(&code))
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("HTTP proxy rejected CONNECT request: {status_line}"),
        ));
    }
    Ok(())
}

async fn socks5_connect(
    stream: &mut TcpStream,
    target: &RequestTarget,
    proxy: &ProxyOutbound,
) -> io::Result<()> {
    socks5_negotiate_auth(stream, proxy).await?;

    let mut request = vec![0x05, 0x01, 0x00];
    match &target.host {
        TargetHost::Ip(IpAddr::V4(address)) => {
            request.push(0x01);
            request.extend_from_slice(&address.octets());
        }
        TargetHost::Ip(IpAddr::V6(address)) => {
            request.push(0x04);
            request.extend_from_slice(&address.octets());
        }
        TargetHost::Domain(domain) => {
            let bytes = domain.as_bytes();
            if bytes.is_empty() || bytes.len() > u8::MAX as usize {
                return Err(invalid_data("SOCKS5 target domain must fit in 255 bytes"));
            }
            request.extend_from_slice(&[0x03, bytes.len() as u8]);
            request.extend_from_slice(bytes);
        }
    }
    request.extend_from_slice(&target.port.to_be_bytes());
    stream.write_all(&request).await?;

    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 || response[2] != 0 {
        return Err(invalid_data("malformed SOCKS5 CONNECT response"));
    }
    match response[3] {
        0x01 => {
            let mut address_and_port = [0u8; 6];
            stream.read_exact(&mut address_and_port).await?;
        }
        0x04 => {
            let mut address_and_port = [0u8; 18];
            stream.read_exact(&mut address_and_port).await?;
        }
        0x03 => {
            let length = stream.read_u8().await? as usize;
            let mut address_and_port = vec![0u8; length + 2];
            stream.read_exact(&mut address_and_port).await?;
        }
        _ => {
            return Err(invalid_data(
                "SOCKS5 proxy returned an unknown address type",
            ));
        }
    }
    if response[1] != 0x00 {
        let kind = match response[1] {
            0x03 => io::ErrorKind::NetworkUnreachable,
            0x04 => io::ErrorKind::HostUnreachable,
            0x05 => io::ErrorKind::ConnectionRefused,
            0x02 => io::ErrorKind::PermissionDenied,
            _ => io::ErrorKind::Other,
        };
        return Err(io::Error::new(
            kind,
            format!("SOCKS5 CONNECT failed with reply {}", response[1]),
        ));
    }
    Ok(())
}

async fn socks5_negotiate_auth(stream: &mut TcpStream, proxy: &ProxyOutbound) -> io::Result<()> {
    let wants_auth = proxy.username.is_some();
    if wants_auth {
        stream.write_all(&[0x05, 0x01, 0x02]).await?;
    } else {
        stream.write_all(&[0x05, 0x01, 0x00]).await?;
    }
    let mut method = [0u8; 2];
    stream.read_exact(&mut method).await?;
    if method[0] != 0x05
        || method[1] == 0xff
        || (wants_auth && method[1] != 0x02)
        || (!wants_auth && method[1] != 0x00)
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "SOCKS5 proxy selected an unsupported authentication method",
        ));
    }
    if method[1] == 0x02 {
        let username = proxy.username.as_deref().unwrap_or_default().as_bytes();
        let password = proxy.password.as_deref().unwrap_or_default().as_bytes();
        stream.write_all(&[0x01, username.len() as u8]).await?;
        stream.write_all(username).await?;
        stream.write_all(&[password.len() as u8]).await?;
        stream.write_all(password).await?;
        let mut auth_reply = [0u8; 2];
        stream.read_exact(&mut auth_reply).await?;
        if auth_reply != [0x01, 0x00] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "SOCKS5 proxy authentication failed",
            ));
        }
    }
    Ok(())
}

async fn socks5_udp_relay_address(
    stream: &mut TcpStream,
    proxy_peer_ip: IpAddr,
) -> io::Result<std::net::SocketAddr> {
    let mut response = [0u8; 4];
    stream.read_exact(&mut response).await?;
    if response[0] != 0x05 || response[2] != 0 {
        return Err(invalid_data("malformed SOCKS5 UDP ASSOCIATE response"));
    }

    let host_text = match response[3] {
        0x01 => {
            let mut address = [0u8; 4];
            stream.read_exact(&mut address).await?;
            IpAddr::V4(address.into()).to_string()
        }
        0x04 => {
            let mut address = [0u8; 16];
            stream.read_exact(&mut address).await?;
            IpAddr::V6(address.into()).to_string()
        }
        0x03 => {
            let length = stream.read_u8().await? as usize;
            if length == 0 {
                return Err(invalid_data(
                    "SOCKS5 proxy returned an empty UDP relay domain",
                ));
            }
            let mut domain = vec![0u8; length];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain)
                .map_err(|_| invalid_data("SOCKS5 proxy returned a non-UTF-8 UDP relay domain"))?
        }
        _ => {
            return Err(invalid_data(
                "SOCKS5 proxy returned an unknown UDP relay address type",
            ));
        }
    };
    let port = stream.read_u16().await?;
    if response[1] != 0x00 {
        return Err(io::Error::new(
            io::ErrorKind::ConnectionRefused,
            format!("SOCKS5 UDP ASSOCIATE failed with reply {}", response[1]),
        ));
    }
    if port == 0 {
        return Err(invalid_data("SOCKS5 proxy returned a zero UDP relay port"));
    }

    let parsed_ip = host_text.parse::<IpAddr>().ok().map(|address| {
        if address.is_unspecified() {
            proxy_peer_ip
        } else {
            address
        }
    });
    let ip = match parsed_ip {
        Some(address) => address,
        None => tokio::net::lookup_host((host_text.as_str(), port))
            .await?
            .next()
            .ok_or_else(|| invalid_data("SOCKS5 UDP relay domain resolved to no addresses"))?
            .ip(),
    };
    Ok(std::net::SocketAddr::new(ip, port))
}

fn target_authority(target: &RequestTarget) -> io::Result<String> {
    match &target.host {
        TargetHost::Ip(IpAddr::V4(address)) => Ok(format!("{address}:{}", target.port)),
        TargetHost::Ip(IpAddr::V6(address)) => Ok(format!("[{address}]:{}", target.port)),
        TargetHost::Domain(domain) => normalize_domain(domain)
            .map(|domain| format!("{domain}:{}", target.port))
            .ok_or_else(|| invalid_data("HTTP CONNECT target must be a valid ASCII DNS name")),
    }
}

fn invalid_data(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn formats_ipv6_connect_authority_with_brackets() {
        let target = RequestTarget {
            host: TargetHost::Ip("2001:db8::1".parse().unwrap()),
            port: 443,
        };
        assert_eq!(target_authority(&target).unwrap(), "[2001:db8::1]:443");
    }

    #[test]
    fn rejects_http_authority_with_header_injection_characters() {
        let target = RequestTarget {
            host: TargetHost::Domain("example.com\r\nInjected: yes".into()),
            port: 443,
        };
        assert!(target_authority(&target).is_err());
    }

    #[tokio::test]
    async fn socks5_udp_associate_authenticates_and_keeps_control_stream_open() {
        let proxy_udp_relay = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_address = proxy_udp_relay.local_addr().unwrap();
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let proxy_task = tokio::spawn(async move {
            let (mut control, _) = listener.accept().await.unwrap();
            let mut greeting = [0u8; 2];
            control.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [0x05, 0x01]);
            let mut methods = [0u8; 1];
            control.read_exact(&mut methods).await.unwrap();
            assert_eq!(methods, [0x02]);
            control.write_all(&[0x05, 0x02]).await.unwrap();

            let mut auth_header = [0u8; 2];
            control.read_exact(&mut auth_header).await.unwrap();
            assert_eq!(auth_header, [0x01, 4]);
            let mut username = [0u8; 4];
            control.read_exact(&mut username).await.unwrap();
            assert_eq!(&username, b"user");
            let password_length = control.read_u8().await.unwrap();
            assert_eq!(password_length, 4);
            let mut password = [0u8; 4];
            control.read_exact(&mut password).await.unwrap();
            assert_eq!(&password, b"pass");
            control.write_all(&[0x01, 0x00]).await.unwrap();

            let mut request = [0u8; 10];
            control.read_exact(&mut request).await.unwrap();
            assert_eq!(request, [0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0]);
            let mut response = vec![0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0];
            response.extend_from_slice(&relay_address.port().to_be_bytes());
            control.write_all(&response).await.unwrap();

            let mut byte = [0u8; 1];
            assert_eq!(control.read(&mut byte).await.unwrap(), 0);
        });

        let proxy = ProxyOutbound {
            name: "upstream".into(),
            kind: "socks5".into(),
            server: "127.0.0.1".into(),
            port: proxy_address.port(),
            username: Some("user".into()),
            password: Some("pass".into()),
        };
        let (control, relay) = proxy.udp_associate().await.unwrap();
        assert_eq!(relay.peer_addr().unwrap(), relay_address);
        drop(relay);
        drop(control);
        proxy_task.await.unwrap();
    }
}
