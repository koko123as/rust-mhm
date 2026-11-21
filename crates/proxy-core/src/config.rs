use std::{net::SocketAddr, path::Path};

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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: default_listen(),
            connect_timeout_ms: default_connect_timeout_ms(),
            max_connections: default_max_connections(),
            rules: default_rules(),
            proxies: Vec::new(),
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
}
