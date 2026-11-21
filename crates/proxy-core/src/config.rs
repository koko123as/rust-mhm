use std::{
    collections::{BTreeMap, HashMap},
    fs::File,
    io::Read,
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
};

use serde::Deserialize;
use thiserror::Error;

use crate::outbound::ProxyOutbound;
use crate::routing::{RuleError, RuleSet};

const DEFAULT_LISTEN: &str = "127.0.0.1:1080";
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_MAX_CONNECTIONS: usize = 256;
const MAX_CONNECTIONS: usize = 4_096;
const MIN_CONNECT_TIMEOUT_MS: u64 = 100;
const MAX_CONNECT_TIMEOUT_MS: u64 = 120_000;
const MAX_RULE_PROVIDER_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    #[serde(default = "default_listen")]
    listen: String,
    #[serde(default = "default_connect_timeout_ms")]
    connect_timeout_ms: u64,
    #[serde(default = "default_max_connections")]
    max_connections: usize,
    #[serde(default = "default_rules")]
    rules: Vec<String>,
    #[serde(default, rename = "rule-providers")]
    rule_providers: BTreeMap<String, RuleProviderConfig>,
    #[serde(skip)]
    config_dir: Option<PathBuf>,
    #[serde(default)]
    proxies: Vec<ProxyOutbound>,
    #[serde(default)]
    authentication: Vec<String>,
    #[serde(default, rename = "skip-auth-prefixes")]
    skip_auth_prefixes: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleProviderConfig {
    #[serde(rename = "type")]
    provider_type: String,
    behavior: String,
    #[serde(default)]
    payload: Vec<String>,
    #[serde(default)]
    path: Option<PathBuf>,
    #[serde(default)]
    url: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            connect_timeout_ms: default_connect_timeout_ms(),
            max_connections: default_max_connections(),
            rules: default_rules(),
            rule_providers: BTreeMap::new(),
            config_dir: None,
            proxies: Vec::new(),
            authentication: Vec::new(),
            skip_auth_prefixes: Vec::new(),
        }
    }
}

impl Config {
    /// Parse this project's intentionally small YAML schema and validate it.
    pub fn from_yaml_str(source: &str) -> Result<Self, ConfigError> {
        let config: Self = yaml_serde::from_str(source)?;
        if config
            .rule_providers
            .values()
            .any(|provider| provider.provider_type == "file")
        {
            return Err(ConfigError::FileProviderRequiresConfigPath);
        }
        if config
            .rule_providers
            .values()
            .any(|provider| provider.provider_type == "http")
        {
            return Err(ConfigError::HttpProviderRequiresAsyncLoad);
        }
        config.validate()?;
        Ok(config)
    }

    /// Load a configuration file without logging its contents.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let source = std::fs::read_to_string(path)?;
        let mut config: Self = yaml_serde::from_str(&source)?;
        if config
            .rule_providers
            .values()
            .any(|provider| provider.provider_type == "http")
        {
            return Err(ConfigError::HttpProviderRequiresAsyncLoad);
        }
        config.config_dir = Some(
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        );
        config.load_file_rule_providers()?;
        config.validate()?;
        Ok(config)
    }

    /// Load configuration and startup snapshots of its local and HTTP rule providers.
    pub async fn load_async(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let path = path.as_ref();
        let source = std::fs::read_to_string(path)?;
        let mut config: Self = yaml_serde::from_str(&source)?;
        config.config_dir = Some(
            path.parent()
                .filter(|parent| !parent.as_os_str().is_empty())
                .unwrap_or_else(|| Path::new("."))
                .to_path_buf(),
        );
        config.load_file_rule_providers()?;
        config.load_http_rule_providers().await?;
        config.validate()?;
        Ok(config)
    }

    pub fn listen_addr(&self) -> Result<SocketAddr, ConfigError> {
        self.listen
            .parse::<SocketAddr>()
            .map_err(|_| ConfigError::InvalidListenAddress(self.listen.clone()))
    }

    pub fn connect_timeout_ms(&self) -> u64 {
        self.connect_timeout_ms
    }

    pub fn max_connections(&self) -> usize {
        self.max_connections
    }

    pub fn routing_rules(&self) -> Result<RuleSet, ConfigError> {
        let names = self
            .proxies
            .iter()
            .map(|proxy| proxy.name.clone())
            .collect::<Vec<_>>();
        let rule_providers = self
            .rule_providers
            .iter()
            .map(|(name, provider)| (name.clone(), provider.normalized_payload()))
            .collect::<HashMap<_, _>>();
        Ok(RuleSet::parse_with_rule_providers(
            &self.rules,
            &names,
            &rule_providers,
        )?)
    }

    pub fn proxy_outbounds(&self) -> &[ProxyOutbound] {
        &self.proxies
    }

    pub(crate) fn authentication_credentials(&self) -> Vec<(String, String)> {
        self.authentication
            .iter()
            .map(|entry| {
                let (username, password) = entry
                    .split_once(':')
                    .expect("validated authentication entry");
                (username.to_owned(), password.to_owned())
            })
            .collect()
    }

    pub(crate) fn skip_auth_prefixes(&self) -> Result<Vec<AuthSkipPrefix>, ConfigError> {
        self.skip_auth_prefixes
            .iter()
            .map(|prefix| {
                AuthSkipPrefix::parse(prefix).ok_or_else(|| {
                    ConfigError::InvalidAuthentication(format!(
                        "invalid skip-auth-prefix: {prefix}"
                    ))
                })
            })
            .collect()
    }

    fn load_file_rule_providers(&mut self) -> Result<(), ConfigError> {
        let config_dir = self
            .config_dir
            .as_ref()
            .expect("file providers are loaded only from a config file")
            .clone();
        for (name, provider) in &mut self.rule_providers {
            if provider.provider_type != "file" {
                continue;
            }
            let path = provider
                .path
                .as_ref()
                .ok_or_else(|| ConfigError::InvalidRuleProvider {
                    name: name.clone(),
                    reason: "type: file requires a path".to_owned(),
                })?;
            if !provider.payload.is_empty() {
                return Err(ConfigError::InvalidRuleProvider {
                    name: name.clone(),
                    reason: "type: file cannot define an inline payload".to_owned(),
                });
            }
            let resolved_path = if path.is_absolute() {
                path.clone()
            } else {
                config_dir.join(path)
            };
            let file =
                File::open(&resolved_path).map_err(|error| ConfigError::RuleProviderLoad {
                    name: name.clone(),
                    path: resolved_path.display().to_string(),
                    reason: error.to_string(),
                })?;
            let size = file
                .metadata()
                .map_err(|error| ConfigError::RuleProviderLoad {
                    name: name.clone(),
                    path: resolved_path.display().to_string(),
                    reason: error.to_string(),
                })?
                .len();
            if size > MAX_RULE_PROVIDER_BYTES {
                return Err(ConfigError::RuleProviderLoad {
                    name: name.clone(),
                    path: resolved_path.display().to_string(),
                    reason: format!("file exceeds {MAX_RULE_PROVIDER_BYTES} bytes"),
                });
            }
            let mut bytes = Vec::with_capacity(size as usize);
            file.take(MAX_RULE_PROVIDER_BYTES + 1)
                .read_to_end(&mut bytes)
                .map_err(|error| ConfigError::RuleProviderLoad {
                    name: name.clone(),
                    path: resolved_path.display().to_string(),
                    reason: error.to_string(),
                })?;
            if bytes.len() as u64 > MAX_RULE_PROVIDER_BYTES {
                return Err(ConfigError::RuleProviderLoad {
                    name: name.clone(),
                    path: resolved_path.display().to_string(),
                    reason: format!("file exceeds {MAX_RULE_PROVIDER_BYTES} bytes"),
                });
            }
            let source =
                String::from_utf8(bytes).map_err(|error| ConfigError::RuleProviderLoad {
                    name: name.clone(),
                    path: resolved_path.display().to_string(),
                    reason: format!("file is not valid UTF-8: {error}"),
                })?;
            provider.payload = parse_rule_provider_file(&source).map_err(|reason| {
                ConfigError::RuleProviderLoad {
                    name: name.clone(),
                    path: resolved_path.display().to_string(),
                    reason,
                }
            })?;
        }
        Ok(())
    }

    async fn load_http_rule_providers(&mut self) -> Result<(), ConfigError> {
        if !self
            .rule_providers
            .values()
            .any(|provider| provider.provider_type == "http")
        {
            return Ok(());
        }
        let client = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::limited(5))
            .build()
            .map_err(|error| ConfigError::RuleProviderHttp {
                name: "<client>".to_owned(),
                reason: error.without_url().to_string(),
            })?;
        let timeout_duration = std::time::Duration::from_millis(self.connect_timeout_ms);
        for (name, provider) in &mut self.rule_providers {
            if provider.provider_type != "http" {
                continue;
            }
            if !provider.payload.is_empty() {
                return Err(ConfigError::InvalidRuleProvider {
                    name: name.clone(),
                    reason: "type: http cannot define an inline payload".to_owned(),
                });
            }
            let url = provider
                .url
                .as_deref()
                .ok_or_else(|| ConfigError::InvalidRuleProvider {
                    name: name.clone(),
                    reason: "type: http requires a url".to_owned(),
                })?;
            let parsed_url =
                reqwest::Url::parse(url).map_err(|_| ConfigError::InvalidRuleProvider {
                    name: name.clone(),
                    reason: "type: http url must be a valid http or https URL".to_owned(),
                })?;
            if !matches!(parsed_url.scheme(), "http" | "https")
                || parsed_url.host_str().is_none()
                || !parsed_url.username().is_empty()
                || parsed_url.password().is_some()
            {
                return Err(ConfigError::InvalidRuleProvider {
                    name: name.clone(),
                    reason: "type: http url must use http/https and contain no user credentials"
                        .to_owned(),
                });
            }
            let download = async {
                let mut response = client
                    .get(parsed_url)
                    .send()
                    .await
                    .map_err(reqwest_error_reason)?;
                if !response.status().is_success() {
                    return Err(format!("server returned HTTP status {}", response.status()));
                }
                if response
                    .content_length()
                    .is_some_and(|length| length > MAX_RULE_PROVIDER_BYTES)
                {
                    return Err(format!("response exceeds {MAX_RULE_PROVIDER_BYTES} bytes"));
                }
                let mut bytes = Vec::new();
                while let Some(chunk) = response.chunk().await.map_err(reqwest_error_reason)? {
                    if bytes.len() as u64 + chunk.len() as u64 > MAX_RULE_PROVIDER_BYTES {
                        return Err(format!("response exceeds {MAX_RULE_PROVIDER_BYTES} bytes"));
                    }
                    bytes.extend_from_slice(&chunk);
                }
                Ok::<_, String>(bytes)
            };
            let bytes = tokio::time::timeout(timeout_duration, download)
                .await
                .map_err(|_| ConfigError::RuleProviderHttp {
                    name: name.clone(),
                    reason: "request exceeded connect_timeout_ms".to_owned(),
                })?
                .map_err(|reason| ConfigError::RuleProviderHttp {
                    name: name.clone(),
                    reason,
                })?;
            let source =
                String::from_utf8(bytes).map_err(|error| ConfigError::RuleProviderHttp {
                    name: name.clone(),
                    reason: format!("response is not valid UTF-8: {error}"),
                })?;
            provider.payload = parse_rule_provider_file(&source).map_err(|reason| {
                ConfigError::RuleProviderHttp {
                    name: name.clone(),
                    reason: format!("could not parse response: {reason}"),
                }
            })?;
        }
        Ok(())
    }

    fn validate(&self) -> Result<(), ConfigError> {
        let listen_addr = self.listen_addr()?;
        if !listen_addr.ip().is_loopback() {
            return Err(ConfigError::NonLoopbackListenAddress(self.listen.clone()));
        }
        if !(MIN_CONNECT_TIMEOUT_MS..=MAX_CONNECT_TIMEOUT_MS).contains(&self.connect_timeout_ms) {
            return Err(ConfigError::InvalidConnectTimeout(self.connect_timeout_ms));
        }
        if !(1..=MAX_CONNECTIONS).contains(&self.max_connections) {
            return Err(ConfigError::InvalidMaxConnections(self.max_connections));
        }
        let mut names = std::collections::HashSet::new();
        for proxy in &self.proxies {
            proxy.validate().map_err(ConfigError::InvalidProxy)?;
            if !names.insert(proxy.name.as_str()) {
                return Err(ConfigError::InvalidProxy(format!(
                    "duplicate proxy name: {}",
                    proxy.name
                )));
            }
        }
        let proxy_names = self
            .proxies
            .iter()
            .map(|proxy| proxy.name.clone())
            .collect::<Vec<_>>();
        for (name, provider) in &self.rule_providers {
            provider.validate(name)?;
        }
        let rule_providers = self
            .rule_providers
            .iter()
            .map(|(name, provider)| (name.clone(), provider.normalized_payload()))
            .collect::<HashMap<_, _>>();
        RuleSet::parse_with_rule_providers(&self.rules, &proxy_names, &rule_providers)?;
        let mut usernames = std::collections::HashSet::new();
        for entry in &self.authentication {
            let Some((username, password)) = entry.split_once(':') else {
                return Err(ConfigError::InvalidAuthentication(
                    "entries must use username:password format".into(),
                ));
            };
            if username.is_empty()
                || password.is_empty()
                || username.len() > 255
                || password.len() > 255
                || !usernames.insert(username)
            {
                return Err(ConfigError::InvalidAuthentication(
                    "usernames must be unique and both fields must fit in 1..=255 UTF-8 bytes"
                        .into(),
                ));
            }
        }
        let mut skip_prefixes = std::collections::HashSet::new();
        for prefix in &self.skip_auth_prefixes {
            if AuthSkipPrefix::parse(prefix).is_none() || !skip_prefixes.insert(prefix) {
                return Err(ConfigError::InvalidAuthentication(
                    "skip-auth-prefixes must contain unique IPv4/IPv6 CIDR ranges".into(),
                ));
            }
        }
        Ok(())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleProviderDocument {
    payload: Vec<String>,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum RuleProviderFile {
    Document(RuleProviderDocument),
    Payload(Vec<String>),
}

fn parse_rule_provider_file(source: &str) -> Result<Vec<String>, String> {
    let trimmed = source.trim();
    if trimmed.is_empty() {
        return Ok(Vec::new());
    }
    if let Ok(document) = yaml_serde::from_str::<RuleProviderFile>(trimmed) {
        return Ok(match document {
            RuleProviderFile::Document(document) => document.payload,
            RuleProviderFile::Payload(payload) => payload,
        });
    }
    Ok(source
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .map(str::to_owned)
        .collect())
}

fn reqwest_error_reason(error: reqwest::Error) -> String {
    let error = error.without_url();
    let mut reason = error.to_string();
    let mut source = std::error::Error::source(&error);
    while let Some(cause) = source {
        reason.push_str(": ");
        reason.push_str(&cause.to_string());
        source = cause.source();
    }
    reason
}

impl RuleProviderConfig {
    fn normalized_payload(&self) -> Vec<String> {
        match self.behavior.as_str() {
            "domain" => self
                .payload
                .iter()
                .map(|domain| {
                    if domain.contains(['*', '?']) {
                        format!("DOMAIN-WILDCARD,{domain}")
                    } else {
                        format!(
                            "DOMAIN-SUFFIX,{}",
                            domain.strip_prefix('.').unwrap_or(domain)
                        )
                    }
                })
                .collect(),
            "ipcidr" => self
                .payload
                .iter()
                .map(|cidr| {
                    let address = cidr.split('/').next().unwrap_or_default();
                    let kind = if address.parse::<std::net::Ipv6Addr>().is_ok() {
                        "IP-CIDR6"
                    } else {
                        "IP-CIDR"
                    };
                    format!("{kind},{cidr}")
                })
                .collect(),
            _ => self.payload.clone(),
        }
    }

    fn validate(&self, name: &str) -> Result<(), ConfigError> {
        let invalid = |reason: String| ConfigError::InvalidRuleProvider {
            name: name.to_owned(),
            reason,
        };
        if name.trim().is_empty() || name != name.trim() || name.contains(',') {
            return Err(invalid(
                "provider name must be non-empty, have no surrounding whitespace, and contain no commas"
                    .to_owned(),
            ));
        }
        match self.provider_type.as_str() {
            "inline" if self.path.is_none() && self.url.is_none() => {}
            "file"
                if self
                    .path
                    .as_ref()
                    .is_some_and(|path| !path.as_os_str().is_empty())
                    && self.url.is_none() => {}
            "http" if self.path.is_none() => {
                let Some(url) = self.url.as_deref() else {
                    return Err(invalid("type: http requires a url".to_owned()));
                };
                let Ok(url) = reqwest::Url::parse(url) else {
                    return Err(invalid("type: http url must be valid".to_owned()));
                };
                if !matches!(url.scheme(), "http" | "https")
                    || url.host_str().is_none()
                    || !url.username().is_empty()
                    || url.password().is_some()
                {
                    return Err(invalid(
                        "type: http url must use http/https and contain no user credentials"
                            .to_owned(),
                    ));
                }
            }
            "inline" => return Err(invalid("type: inline cannot define path or url".to_owned())),
            "file" => return Err(invalid("type: file requires a path".to_owned())),
            "http" => {
                return Err(invalid(
                    "HTTP provider cache paths are not yet supported".to_owned(),
                ));
            }
            _ => {
                return Err(invalid(
                    "supported types are inline, file, and http".to_owned(),
                ));
            }
        }
        if !matches!(self.behavior.as_str(), "classical" | "domain" | "ipcidr") {
            return Err(invalid(
                "supported behaviors are classical, domain, and ipcidr".to_owned(),
            ));
        }
        if self
            .payload
            .iter()
            .any(|rule| rule.trim().is_empty() || rule.contains(['\r', '\n']))
        {
            return Err(invalid(
                "payload entries must be non-empty single-line rules".to_owned(),
            ));
        }

        let validation_rules = self
            .normalized_payload()
            .iter()
            .map(|rule| format!("{rule},DIRECT"))
            .collect::<Vec<_>>();
        RuleSet::parse(&validation_rules)
            .map_err(|error| invalid(format!("invalid provider payload: {error}")))?;
        Ok(())
    }
}

fn default_listen() -> String {
    DEFAULT_LISTEN.to_owned()
}

const fn default_connect_timeout_ms() -> u64 {
    DEFAULT_CONNECT_TIMEOUT_MS
}

const fn default_max_connections() -> usize {
    DEFAULT_MAX_CONNECTIONS
}

fn default_rules() -> Vec<String> {
    vec!["MATCH,DIRECT".to_owned()]
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct AuthSkipPrefix {
    network: IpAddr,
    prefix: u8,
}

impl AuthSkipPrefix {
    fn parse(source: &str) -> Option<Self> {
        let (address, prefix) = source.split_once('/')?;
        let network = address.parse::<IpAddr>().ok()?;
        let prefix = prefix.parse::<u8>().ok()?;
        let max_prefix = if network.is_ipv4() { 32 } else { 128 };
        (prefix <= max_prefix).then_some(Self { network, prefix })
    }

    pub(crate) fn contains(self, candidate: IpAddr) -> bool {
        match (self.network, candidate) {
            (IpAddr::V4(network), IpAddr::V4(candidate)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                (u32::from(network) & mask) == (u32::from(candidate) & mask)
            }
            (IpAddr::V6(network), IpAddr::V6(candidate)) => {
                let mask = if self.prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                (u128::from(network) & mask) == (u128::from(candidate) & mask)
            }
            _ => false,
        }
    }
}

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("configuration file could not be read: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid YAML configuration: {0}")]
    Yaml(#[from] yaml_serde::Error),
    #[error("invalid listen socket address: {0}")]
    InvalidListenAddress(String),
    #[error("listen address must be a loopback IP address: {0}")]
    NonLoopbackListenAddress(String),
    #[error(
        "connect_timeout_ms must be between {MIN_CONNECT_TIMEOUT_MS} and {MAX_CONNECT_TIMEOUT_MS}; got {0}"
    )]
    InvalidConnectTimeout(u64),
    #[error("max_connections must be between 1 and {MAX_CONNECTIONS}; got {0}")]
    InvalidMaxConnections(usize),
    #[error(transparent)]
    Routing(#[from] RuleError),
    #[error("invalid proxy configuration: {0}")]
    InvalidProxy(String),
    #[error("invalid rule provider {name}: {reason}")]
    InvalidRuleProvider { name: String, reason: String },
    #[error("file rule providers require Config::load with a configuration-file path")]
    FileProviderRequiresConfigPath,
    #[error("HTTP rule providers require Config::load_async")]
    HttpProviderRequiresAsyncLoad,
    #[error("could not load rule provider {name} from {path}: {reason}")]
    RuleProviderLoad {
        name: String,
        path: String,
        reason: String,
    },
    #[error("could not download rule provider {name}: {reason}")]
    RuleProviderHttp { name: String, reason: String },
    #[error("invalid SOCKS5 authentication configuration: {0}")]
    InvalidAuthentication(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{RequestTarget, RouteAction, TargetHost};

    fn temporary_directory() -> PathBuf {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("rust-mhm-test-{unique}"));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    async fn start_http_response(
        status: &'static str,
        body: Vec<u8>,
        declared_length: Option<u64>,
    ) -> (SocketAddr, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") && request.len() < 16 * 1024 {
                let mut byte = [0u8; 1];
                if stream.read_exact(&mut byte).await.is_err() {
                    return;
                }
                request.push(byte[0]);
            }
            let length = declared_length.unwrap_or(body.len() as u64);
            let headers = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(headers.as_bytes()).await;
            let _ = stream.write_all(&body).await;
        });
        (address, task)
    }

    #[test]
    fn defaults_are_loopback_and_bounded() {
        let config = Config::from_yaml_str("").expect("empty config uses safe defaults");
        assert_eq!(
            config.listen_addr().unwrap(),
            "127.0.0.1:1080".parse().unwrap()
        );
        assert_eq!(config.connect_timeout_ms(), DEFAULT_CONNECT_TIMEOUT_MS);
        assert_eq!(config.max_connections(), DEFAULT_MAX_CONNECTIONS);
    }

    #[test]
    fn accepts_ipv6_loopback() {
        let config = Config::from_yaml_str("listen: '[::1]:1081'\n").unwrap();
        assert_eq!(config.listen_addr().unwrap(), "[::1]:1081".parse().unwrap());
    }

    #[test]
    fn rejects_non_loopback_listener() {
        let error = Config::from_yaml_str("listen: '0.0.0.0:1080'\n").unwrap_err();
        assert!(matches!(error, ConfigError::NonLoopbackListenAddress(_)));
    }

    #[test]
    fn rejects_unknown_top_level_fields() {
        let error = Config::from_yaml_str("mixed-port: 7890\n").unwrap_err();
        assert!(matches!(error, ConfigError::Yaml(_)));
    }

    #[test]
    fn rejects_out_of_range_resource_limits() {
        let error = Config::from_yaml_str("max_connections: 0\n").unwrap_err();
        assert!(matches!(error, ConfigError::InvalidMaxConnections(0)));

        let error = Config::from_yaml_str("connect_timeout_ms: 10\n").unwrap_err();
        assert!(matches!(error, ConfigError::InvalidConnectTimeout(10)));
    }

    #[test]
    fn parses_rules_and_uses_match_direct_by_default() {
        let config = Config::from_yaml_str("rules:\n  - DOMAIN,ad.example,REJECT\n").unwrap();
        let rules = config.routing_rules().unwrap();
        let blocked = RequestTarget {
            host: TargetHost::Domain("ad.example".to_owned()),
            port: 443,
        };
        let other = RequestTarget {
            host: TargetHost::Domain("other.example".to_owned()),
            port: 443,
        };
        assert_eq!(rules.route(&blocked), RouteAction::Reject);
        assert_eq!(rules.route(&other), RouteAction::Direct);
    }

    #[test]
    fn repository_example_config_parses() {
        let config = Config::from_yaml_str(include_str!("../../../config.example.yaml")).unwrap();
        assert_eq!(config.routing_rules().unwrap().rule_count(), 5);
    }

    #[test]
    fn invalid_or_unsupported_rules_reject_the_configuration() {
        let error = Config::from_yaml_str("rules:\n  - RULE-SET,ads,REJECT\n").unwrap_err();
        assert!(matches!(
            error,
            ConfigError::Routing(RuleError::UnknownRuleProvider { .. })
        ));
    }

    #[test]
    fn inline_classical_rule_provider_expands_in_order_and_overrides_action() {
        let config = Config::from_yaml_str(
            r#"
rule-providers:
  local:
    type: inline
    behavior: classical
    payload:
      - "DOMAIN-SUFFIX,blocked.example"
      - "DST-PORT,8443"
rules:
  - DOMAIN,allow.example,DIRECT
  - RULE-SET,local,REJECT
  - MATCH,DIRECT
"#,
        )
        .unwrap();
        let rules = config.routing_rules().unwrap();
        assert_eq!(
            rules.route(&RequestTarget {
                host: TargetHost::Domain("blocked.example".into()),
                port: 443,
            }),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&RequestTarget {
                host: TargetHost::Domain("other.example".into()),
                port: 8443,
            }),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&RequestTarget {
                host: TargetHost::Domain("allow.example".into()),
                port: 443,
            }),
            RouteAction::Direct
        );
    }

    #[test]
    fn file_rule_providers_load_yaml_and_text_payloads_relative_to_config() {
        let directory = temporary_directory();
        std::fs::write(
            directory.join("domains.yaml"),
            "payload:\n  - .ads.example\n  - '*.tracker.example'\n",
        )
        .unwrap();
        std::fs::write(
            directory.join("networks.txt"),
            "# IPv4 and IPv6 entries\n198.51.100.0/24\n2001:db8::/32\n",
        )
        .unwrap();
        std::fs::write(
            directory.join("config.yaml"),
            r#"
rule-providers:
  domains:
    type: file
    behavior: domain
    path: domains.yaml
  networks:
    type: file
    behavior: ipcidr
    path: networks.txt
rules:
  - RULE-SET,domains,REJECT
  - RULE-SET,networks,REJECT
  - MATCH,DIRECT
"#,
        )
        .unwrap();

        let config = Config::load(directory.join("config.yaml")).unwrap();
        let rules = config.routing_rules().unwrap();
        for target in [
            RequestTarget {
                host: TargetHost::Domain("ads.example".into()),
                port: 443,
            },
            RequestTarget {
                host: TargetHost::Domain("cdn.tracker.example".into()),
                port: 443,
            },
            RequestTarget {
                host: TargetHost::Ip("198.51.100.17".parse().unwrap()),
                port: 443,
            },
            RequestTarget {
                host: TargetHost::Ip("2001:db8::5".parse().unwrap()),
                port: 443,
            },
        ] {
            assert_eq!(rules.route(&target), RouteAction::Reject);
        }
        assert_eq!(
            rules.route(&RequestTarget {
                host: TargetHost::Domain("safe.example".into()),
                port: 443,
            }),
            RouteAction::Direct
        );
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn http_provider_downloads_and_routes_a_startup_snapshot() {
        let body = b"payload:\n  - .remote.example\n  - '*.static.example'\n".to_vec();
        let (address, server) = start_http_response("200 OK", body, None).await;
        let directory = temporary_directory();
        let config_path = directory.join("config.yaml");
        std::fs::write(
            &config_path,
            format!(
                "rule-providers:\n  remote:\n    type: http\n    behavior: domain\n    url: 'http://{address}/rules.yaml'\nrules:\n  - RULE-SET,remote,REJECT\n  - MATCH,DIRECT\n"
            ),
        )
        .unwrap();

        assert!(matches!(
            Config::load(&config_path),
            Err(ConfigError::HttpProviderRequiresAsyncLoad)
        ));
        let config = Config::load_async(&config_path).await.unwrap();
        let rules = config.routing_rules().unwrap();
        for domain in ["remote.example", "a.remote.example", "cdn.static.example"] {
            assert_eq!(
                rules.route(&RequestTarget {
                    host: TargetHost::Domain(domain.into()),
                    port: 443,
                }),
                RouteAction::Reject
            );
        }
        assert_eq!(
            rules.route(&RequestTarget {
                host: TargetHost::Domain("static.example".into()),
                port: 443,
            }),
            RouteAction::Direct
        );
        server.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn file_rule_provider_rejects_missing_and_oversized_files() {
        let directory = temporary_directory();
        std::fs::write(
            directory.join("missing.yaml"),
            "rule-providers:\n  local:\n    type: file\n    behavior: classical\n    path: absent.yaml\n",
        )
        .unwrap();
        assert!(matches!(
            Config::load(directory.join("missing.yaml")),
            Err(ConfigError::RuleProviderLoad { .. })
        ));

        std::fs::write(
            directory.join("large.rules"),
            vec![b'x'; (MAX_RULE_PROVIDER_BYTES + 1) as usize],
        )
        .unwrap();
        std::fs::write(
            directory.join("large.yaml"),
            "rule-providers:\n  local:\n    type: file\n    behavior: classical\n    path: large.rules\n",
        )
        .unwrap();
        assert!(matches!(
            Config::load(directory.join("large.yaml")),
            Err(ConfigError::RuleProviderLoad { .. })
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn http_provider_rejects_error_status_and_oversized_response() {
        let directory = temporary_directory();
        let not_found_path = directory.join("not-found.yaml");
        let (address, server) =
            start_http_response("404 Not Found", b"not found".to_vec(), None).await;
        std::fs::write(
            &not_found_path,
            format!(
                "rule-providers:\n  remote:\n    type: http\n    behavior: classical\n    url: 'http://{address}/missing'\n"
            ),
        )
        .unwrap();
        assert!(matches!(
            Config::load_async(&not_found_path).await,
            Err(ConfigError::RuleProviderHttp { reason, .. }) if reason.contains("404 Not Found")
        ));
        server.await.unwrap();

        let oversized_path = directory.join("oversized.yaml");
        let (address, server) =
            start_http_response("200 OK", Vec::new(), Some(MAX_RULE_PROVIDER_BYTES + 1)).await;
        std::fs::write(
            &oversized_path,
            format!(
                "rule-providers:\n  remote:\n    type: http\n    behavior: classical\n    url: 'http://{address}/too-large'\n"
            ),
        )
        .unwrap();
        assert!(matches!(
            Config::load_async(&oversized_path).await,
            Err(ConfigError::RuleProviderHttp { reason, .. }) if reason.contains("response exceeds")
        ));
        server.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rule_provider_rejects_unsupported_types_and_invalid_payloads() {
        let file_provider = Config::from_yaml_str(
            "rule-providers:\n  remote:\n    type: cloud\n    behavior: classical\n",
        )
        .unwrap_err();
        assert!(matches!(
            file_provider,
            ConfigError::InvalidRuleProvider { .. }
        ));

        let invalid_payload = Config::from_yaml_str(
            "rule-providers:\n  local:\n    type: inline\n    behavior: classical\n    payload:\n      - 'GEOIP,CN'\n",
        )
        .unwrap_err();
        assert!(matches!(
            invalid_payload,
            ConfigError::InvalidRuleProvider { .. }
        ));
    }

    #[test]
    fn empty_rule_provider_still_validates_action_and_match_position() {
        let invalid_action = Config::from_yaml_str(
            "rule-providers:\n  empty:\n    type: inline\n    behavior: classical\nrules:\n  - RULE-SET,empty,not-configured\n",
        )
        .unwrap_err();
        assert!(matches!(
            invalid_action,
            ConfigError::Routing(RuleError::UnsupportedAction { .. })
        ));

        let misplaced_match = Config::from_yaml_str(
            "rule-providers:\n  empty:\n    type: inline\n    behavior: classical\nrules:\n  - MATCH,DIRECT\n  - RULE-SET,empty,REJECT\n",
        )
        .unwrap_err();
        assert!(matches!(
            misplaced_match,
            ConfigError::Routing(RuleError::MatchMustBeLast)
        ));
    }

    #[test]
    fn accepts_named_http_proxy_and_routes_to_it() {
        let config = Config::from_yaml_str(
            "proxies:\n  - name: upstream\n    type: http\n    server: 127.0.0.1\n    port: 8080\nrules:\n  - MATCH,upstream\n",
        )
        .unwrap();
        let rules = config.routing_rules().unwrap();
        let target = RequestTarget {
            host: TargetHost::Domain("example.org".into()),
            port: 443,
        };
        assert_eq!(rules.route(&target), RouteAction::Proxy("upstream".into()));
        assert_eq!(config.proxy_outbounds().len(), 1);
    }

    #[test]
    fn rejects_unknown_proxy_references_and_duplicate_names() {
        let missing = Config::from_yaml_str("rules:\n  - MATCH,not-configured\n").unwrap_err();
        assert!(matches!(
            missing,
            ConfigError::Routing(RuleError::UnsupportedAction { .. })
        ));
        let duplicate = Config::from_yaml_str(
            "proxies:\n  - { name: same, type: http, server: localhost, port: 80 }\n  - { name: same, type: socks5, server: localhost, port: 1080 }\n",
        )
        .unwrap_err();
        assert!(matches!(duplicate, ConfigError::InvalidProxy(_)));
    }

    #[test]
    fn parses_global_authentication_and_rejects_invalid_entries() {
        let config = Config::from_yaml_str("authentication:\n  - alice:secret\n").unwrap();
        assert_eq!(
            config.authentication_credentials(),
            vec![("alice".into(), "secret".into())]
        );
        assert!(matches!(
            Config::from_yaml_str("authentication:\n  - missing-separator\n"),
            Err(ConfigError::InvalidAuthentication(_))
        ));
        assert!(matches!(
            Config::from_yaml_str("authentication:\n  - alice:one\n  - alice:two\n"),
            Err(ConfigError::InvalidAuthentication(_))
        ));
    }

    #[test]
    fn validates_skip_auth_prefixes_for_both_address_families() {
        let config = Config::from_yaml_str(
            "authentication:\n  - alice:secret\nskip-auth-prefixes:\n  - 127.0.0.0/8\n  - ::1/128\n",
        )
        .unwrap();
        let prefixes = config.skip_auth_prefixes().unwrap();
        assert!(prefixes[0].contains("127.0.0.1".parse().unwrap()));
        assert!(!prefixes[0].contains("192.0.2.1".parse().unwrap()));
        assert!(prefixes[1].contains("::1".parse().unwrap()));
        assert!(matches!(
            Config::from_yaml_str("skip-auth-prefixes:\n  - 192.0.2.1/33\n"),
            Err(ConfigError::InvalidAuthentication(_))
        ));
    }
}
