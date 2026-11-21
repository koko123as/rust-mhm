use std::{
    net::{IpAddr, SocketAddr},
    path::Path,
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
    #[serde(default)]
    proxies: Vec<ProxyOutbound>,
    #[serde(default)]
    authentication: Vec<String>,
    #[serde(default, rename = "skip-auth-prefixes")]
    skip_auth_prefixes: Vec<String>,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            connect_timeout_ms: default_connect_timeout_ms(),
            max_connections: default_max_connections(),
            rules: default_rules(),
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
        config.validate()?;
        Ok(config)
    }

    /// Load a configuration file without logging its contents.
    pub fn load(path: impl AsRef<Path>) -> Result<Self, ConfigError> {
        let source = std::fs::read_to_string(path)?;
        Self::from_yaml_str(&source)
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
        Ok(RuleSet::parse_with_proxies(&self.rules, &names)?)
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
        RuleSet::parse_with_proxies(&self.rules, &proxy_names)?;
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
    #[error("invalid SOCKS5 authentication configuration: {0}")]
    InvalidAuthentication(String),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{RequestTarget, RouteAction, TargetHost};

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
            ConfigError::Routing(RuleError::UnsupportedRuleType { .. })
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
