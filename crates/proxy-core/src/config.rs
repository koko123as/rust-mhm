use std::{
    collections::{BTreeMap, HashMap},
    fs::{File, OpenOptions},
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    path::{Component, Path, PathBuf},
    time::Duration,
};

use reqwest::header::{HeaderName, HeaderValue};
use serde::Deserialize;
use thiserror::Error;
use tracing::warn;

use crate::outbound::ProxyOutbound;
use crate::routing::{RuleError, RuleSet};

const DEFAULT_LISTEN: &str = "127.0.0.1:1080";
const DEFAULT_CONNECT_TIMEOUT_MS: u64 = 10_000;
const DEFAULT_MAX_CONNECTIONS: usize = 256;
const MAX_CONNECTIONS: usize = 4_096;
const MIN_CONNECT_TIMEOUT_MS: u64 = 100;
const MAX_CONNECT_TIMEOUT_MS: u64 = 120_000;
const MAX_RULE_PROVIDER_BYTES: u64 = 4 * 1024 * 1024;
const DEFAULT_RULE_PROVIDER_INTERVAL_SECS: u64 = 24 * 60 * 60;
const MAX_RULE_PROVIDER_INTERVAL_SECS: u64 = 365 * 24 * 60 * 60;

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
    #[serde(skip)]
    config_path: Option<PathBuf>,
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
    #[serde(default)]
    interval: Option<u64>,
    #[serde(default, rename = "header")]
    headers: BTreeMap<String, ProviderHeaderValues>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
enum ProviderHeaderValues {
    One(String),
    Many(Vec<String>),
}

impl ProviderHeaderValues {
    fn values(&self) -> &[String] {
        match self {
            Self::One(value) => std::slice::from_ref(value),
            Self::Many(values) => values,
        }
    }
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
            config_path: None,
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
        config.config_path = Some(path.to_path_buf());
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
        config.config_path = Some(path.to_path_buf());
        config.validate()?;
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

    pub(crate) fn rule_provider_refreshes(&self) -> Vec<(String, Duration)> {
        self.rule_providers
            .iter()
            .filter(|(_, provider)| matches!(provider.provider_type.as_str(), "http" | "file"))
            .map(|(name, provider)| {
                (
                    name.clone(),
                    Duration::from_secs(
                        provider
                            .interval
                            .unwrap_or(DEFAULT_RULE_PROVIDER_INTERVAL_SECS),
                    ),
                )
            })
            .collect()
    }

    pub(crate) async fn refresh_rule_provider(&mut self, name: &str) -> Result<(), ConfigError> {
        let provider = self
            .rule_providers
            .get(name)
            .filter(|provider| matches!(provider.provider_type.as_str(), "http" | "file"))
            .cloned()
            .ok_or_else(|| ConfigError::InvalidRuleProvider {
                name: name.to_owned(),
                reason: "provider is not an HTTP or file provider".to_owned(),
            })?;
        let is_http = provider.provider_type == "http";
        let (payload, refreshed_bytes) = if is_http {
            let client = build_rule_provider_client(provider.headers.is_empty())?;
            let timeout = Duration::from_millis(self.connect_timeout_ms);
            let bytes = download_rule_provider(&client, name, &provider, timeout)
                .await
                .map_err(|reason| ConfigError::RuleProviderHttp {
                    name: name.to_owned(),
                    reason,
                })?;
            let payload = parse_rule_provider_bytes(&bytes).map_err(|reason| {
                ConfigError::RuleProviderHttp {
                    name: name.to_owned(),
                    reason: format!("could not parse response: {reason}"),
                }
            })?;
            (payload, Some(bytes))
        } else {
            let path = provider
                .path
                .as_deref()
                .expect("file provider path is validated");
            let config_dir = self
                .config_dir
                .as_deref()
                .expect("file providers are loaded only from a config file");
            let resolved_path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                config_dir.join(path)
            };
            (load_file_rule_provider_payload(&resolved_path, name)?, None)
        };
        let mut updated = provider;
        updated.payload = payload;
        updated.validate_payload().map_err(|reason| {
            if is_http {
                ConfigError::RuleProviderHttp {
                    name: name.to_owned(),
                    reason: format!("response contains invalid rules: {reason}"),
                }
            } else {
                ConfigError::InvalidRuleProvider {
                    name: name.to_owned(),
                    reason: format!("file contains invalid rules: {reason}"),
                }
            }
        })?;
        let mut candidate = self.clone();
        candidate
            .rule_providers
            .get_mut(name)
            .expect("provider was found above")
            .payload = updated.payload.clone();
        candidate.routing_rules()?;
        if let Some(bytes) = refreshed_bytes {
            let cache_path = self.rule_provider_cache_path(name, &updated);
            if let Err(error) = write_rule_provider_cache(&cache_path, &bytes) {
                warn!(provider = %name, error = %error, "could not persist refreshed rule-provider cache");
            }
        }
        self.rule_providers
            .get_mut(name)
            .expect("provider was found above")
            .payload = updated.payload;
        Ok(())
    }

    fn rule_provider_cache_path(&self, name: &str, provider: &RuleProviderConfig) -> PathBuf {
        let config_dir = self
            .config_dir
            .as_deref()
            .expect("HTTP providers are loaded only from a config file");
        provider_cache_path(config_dir, name, provider)
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
            provider.payload = load_file_rule_provider_payload(&resolved_path, name)?;
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
        let timeout_duration = Duration::from_millis(self.connect_timeout_ms);
        let config_dir = self
            .config_dir
            .as_deref()
            .expect("HTTP providers are loaded only from a config file")
            .to_path_buf();
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
            let client = build_rule_provider_client(provider.headers.is_empty())?;
            let cache_path = provider_cache_path(&config_dir, name, provider);
            let fetched = match download_rule_provider(&client, name, provider, timeout_duration)
                .await
            {
                Ok(bytes) => match parse_rule_provider_bytes(&bytes) {
                    Ok(parsed) => {
                        let mut updated = provider.clone();
                        updated.payload = parsed;
                        updated
                            .validate_payload()
                            .map(|()| (bytes, updated.payload))
                            .map_err(|reason| format!("response contains invalid rules: {reason}"))
                    }
                    Err(reason) => Err(format!("could not parse response: {reason}")),
                },
                Err(reason) => Err(reason),
            };
            match fetched {
                Ok((bytes, payload)) => {
                    if let Err(error) = write_rule_provider_cache(&cache_path, &bytes) {
                        warn!(provider = %name, error = %error, "could not persist rule-provider cache");
                    }
                    provider.payload = payload;
                }
                Err(network_error) => match read_rule_provider_cache(&cache_path) {
                    Ok(Some(payload)) => {
                        let mut cached = provider.clone();
                        cached.payload = payload;
                        cached.validate_payload().map_err(|reason| {
                            ConfigError::RuleProviderHttp {
                                name: name.clone(),
                                reason: format!(
                                    "download failed ({network_error}); cached snapshot is invalid: {reason}"
                                ),
                            }
                        })?;
                        warn!(provider = %name, "using cached rule-provider snapshot after refresh failed");
                        provider.payload = cached.payload;
                    }
                    Ok(None) => {
                        return Err(ConfigError::RuleProviderHttp {
                            name: name.clone(),
                            reason: network_error,
                        });
                    }
                    Err(cache_error) => {
                        return Err(ConfigError::RuleProviderHttp {
                            name: name.clone(),
                            reason: format!(
                                "download failed ({network_error}); could not read cached snapshot: {cache_error}"
                            ),
                        });
                    }
                },
            }
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
        let mut cache_paths = std::collections::HashSet::new();
        for (name, provider) in &self.rule_providers {
            provider.validate(name)?;
            if provider.provider_type == "http" {
                let cache_path = self.rule_provider_cache_path(name, provider);
                if cache_path.is_dir() {
                    return Err(ConfigError::InvalidRuleProvider {
                        name: name.clone(),
                        reason: "cache path must name a file, not a directory".to_owned(),
                    });
                }
                let cache_path_key = normalized_path_for_comparison(&cache_path);
                if self
                    .config_path
                    .as_deref()
                    .is_some_and(|config_path| paths_refer_to_same_file(config_path, &cache_path))
                {
                    return Err(ConfigError::InvalidRuleProvider {
                        name: name.clone(),
                        reason: "cache path must not overwrite the configuration file".to_owned(),
                    });
                }
                if !cache_paths.insert(cache_path_key) {
                    return Err(ConfigError::InvalidRuleProvider {
                        name: name.clone(),
                        reason: "HTTP providers must use distinct cache paths".to_owned(),
                    });
                }
            }
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

fn load_file_rule_provider_payload(path: &Path, name: &str) -> Result<Vec<String>, ConfigError> {
    let metadata = std::fs::metadata(path).map_err(|error| ConfigError::RuleProviderLoad {
        name: name.to_owned(),
        path: path.display().to_string(),
        reason: error.to_string(),
    })?;
    if !metadata.is_file() {
        return Err(ConfigError::RuleProviderLoad {
            name: name.to_owned(),
            path: path.display().to_string(),
            reason: "path is not a regular file".to_owned(),
        });
    }
    let size = metadata.len();
    if size > MAX_RULE_PROVIDER_BYTES {
        return Err(ConfigError::RuleProviderLoad {
            name: name.to_owned(),
            path: path.display().to_string(),
            reason: format!("file exceeds {MAX_RULE_PROVIDER_BYTES} bytes"),
        });
    }
    let file = File::open(path).map_err(|error| ConfigError::RuleProviderLoad {
        name: name.to_owned(),
        path: path.display().to_string(),
        reason: error.to_string(),
    })?;
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(MAX_RULE_PROVIDER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| ConfigError::RuleProviderLoad {
            name: name.to_owned(),
            path: path.display().to_string(),
            reason: error.to_string(),
        })?;
    if bytes.len() as u64 > MAX_RULE_PROVIDER_BYTES {
        return Err(ConfigError::RuleProviderLoad {
            name: name.to_owned(),
            path: path.display().to_string(),
            reason: format!("file exceeds {MAX_RULE_PROVIDER_BYTES} bytes"),
        });
    }
    let source = String::from_utf8(bytes).map_err(|error| ConfigError::RuleProviderLoad {
        name: name.to_owned(),
        path: path.display().to_string(),
        reason: format!("file is not valid UTF-8: {error}"),
    })?;
    parse_rule_provider_file(&source).map_err(|reason| ConfigError::RuleProviderLoad {
        name: name.to_owned(),
        path: path.display().to_string(),
        reason,
    })
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

fn build_rule_provider_client(allow_redirects: bool) -> Result<reqwest::Client, ConfigError> {
    reqwest::Client::builder()
        .redirect(if allow_redirects {
            reqwest::redirect::Policy::limited(5)
        } else {
            reqwest::redirect::Policy::none()
        })
        .build()
        .map_err(|error| ConfigError::RuleProviderHttp {
            name: "<client>".to_owned(),
            reason: error.without_url().to_string(),
        })
}

async fn download_rule_provider(
    client: &reqwest::Client,
    name: &str,
    provider: &RuleProviderConfig,
    timeout_duration: Duration,
) -> Result<Vec<u8>, String> {
    let url = provider
        .url
        .as_deref()
        .ok_or_else(|| "type: http requires a url".to_owned())?;
    let parsed_url = reqwest::Url::parse(url)
        .map_err(|_| "type: http url must be a valid http or https URL".to_owned())?;
    if !matches!(parsed_url.scheme(), "http" | "https")
        || parsed_url.host_str().is_none()
        || !parsed_url.username().is_empty()
        || parsed_url.password().is_some()
    {
        return Err("type: http url must use http/https and contain no user credentials".into());
    }

    let download = async {
        let mut request = client.get(parsed_url);
        for (key, value) in &provider.headers {
            for value in value.values() {
                request = request.header(key, value);
            }
        }
        let mut response = request.send().await.map_err(reqwest_error_reason)?;
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
    tokio::time::timeout(timeout_duration, download)
        .await
        .map_err(|_| format!("request exceeded connect_timeout_ms for provider {name}"))?
}

fn parse_rule_provider_bytes(bytes: &[u8]) -> Result<Vec<String>, String> {
    let source = std::str::from_utf8(bytes)
        .map_err(|error| format!("response is not valid UTF-8: {error}"))?;
    parse_rule_provider_file(source)
}

fn provider_cache_path(config_dir: &Path, name: &str, provider: &RuleProviderConfig) -> PathBuf {
    if let Some(path) = &provider.path {
        return if path.is_absolute() {
            path.clone()
        } else {
            config_dir.join(path)
        };
    }
    let encoded_name = name
        .as_bytes()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    config_dir
        .join(".rust-mhm-cache")
        .join(format!("provider-{encoded_name}.cache"))
}

fn cache_path_names_file(path: &Path) -> bool {
    let path_text = path.as_os_str().to_string_lossy();
    path.file_name().is_some()
        && !path_text.ends_with(std::path::MAIN_SEPARATOR)
        && !(cfg!(windows) && path_text.ends_with('/'))
}

fn normalized_path_for_comparison(path: &Path) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                if normalized.file_name().is_some() {
                    normalized.pop();
                } else {
                    normalized.push(component.as_os_str());
                }
            }
            _ => normalized.push(component.as_os_str()),
        }
    }

    let mut ancestor = normalized.clone();
    let mut suffix = Vec::new();
    loop {
        let candidate = if ancestor.as_os_str().is_empty() {
            Path::new(".")
        } else {
            &ancestor
        };
        if let Ok(mut canonical) = std::fs::canonicalize(candidate) {
            for component in suffix.iter().rev() {
                canonical.push(component);
            }
            return path_comparison_key(canonical);
        }
        let Some(file_name) = ancestor.file_name() else {
            break;
        };
        suffix.push(file_name.to_os_string());
        if !ancestor.pop() {
            break;
        }
    }

    path_comparison_key(normalized)
}

fn path_comparison_key(path: PathBuf) -> PathBuf {
    #[cfg(windows)]
    {
        PathBuf::from(path.to_string_lossy().to_lowercase())
    }
    #[cfg(not(windows))]
    {
        path
    }
}

fn paths_refer_to_same_file(left: &Path, right: &Path) -> bool {
    normalized_path_for_comparison(left) == normalized_path_for_comparison(right)
}

fn read_rule_provider_cache(path: &Path) -> Result<Option<Vec<String>>, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let size = file.metadata().map_err(|error| error.to_string())?.len();
    if size > MAX_RULE_PROVIDER_BYTES {
        return Err(format!(
            "cached snapshot exceeds {MAX_RULE_PROVIDER_BYTES} bytes"
        ));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(MAX_RULE_PROVIDER_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_RULE_PROVIDER_BYTES {
        return Err(format!(
            "cached snapshot exceeds {MAX_RULE_PROVIDER_BYTES} bytes"
        ));
    }
    parse_rule_provider_bytes(&bytes)
        .map(Some)
        .map_err(|reason| format!("cached snapshot is invalid: {reason}"))
}

fn write_rule_provider_cache(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temporary_name = path
        .file_name()
        .unwrap_or_else(|| std::ffi::OsStr::new("provider-cache"))
        .to_os_string();
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    temporary_name.push(format!(".tmp-{}-{nonce}", std::process::id()));
    let temporary_path = parent.join(temporary_name);
    let result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary_path)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        drop(file);
        replace_rule_provider_cache(&temporary_path, path)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary_path);
    }
    result
}

fn replace_rule_provider_cache(temporary_path: &Path, cache_path: &Path) -> std::io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::ffi::OsStrExt;

        const MOVEFILE_REPLACE_EXISTING: u32 = 0x1;
        const MOVEFILE_WRITE_THROUGH: u32 = 0x8;

        #[link(name = "Kernel32")]
        unsafe extern "system" {
            #[link_name = "MoveFileExW"]
            fn move_file_ex_w(
                existing_file_name: *const u16,
                new_file_name: *const u16,
                flags: u32,
            ) -> i32;
        }

        let existing = temporary_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let destination = cache_path
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        // The temporary file is created beside the cache, so replacement stays on one volume.
        let replaced = unsafe {
            move_file_ex_w(
                existing.as_ptr(),
                destination.as_ptr(),
                MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH,
            )
        };
        if replaced == 0 {
            return Err(std::io::Error::last_os_error());
        }
        Ok(())
    }
    #[cfg(not(windows))]
    {
        std::fs::rename(temporary_path, cache_path)
    }
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
        if self.provider_type == "http"
            && self
                .path
                .as_deref()
                .is_some_and(|path| !cache_path_names_file(path))
        {
            return Err(invalid("type: http path must name a cache file".to_owned()));
        }
        match self.provider_type.as_str() {
            "inline"
                if self.path.is_none()
                    && self.url.is_none()
                    && self.interval.is_none()
                    && self.headers.is_empty() => {}
            "file"
                if self
                    .path
                    .as_ref()
                    .is_some_and(|path| !path.as_os_str().is_empty())
                    && self.url.is_none()
                    && self.headers.is_empty() =>
            {
                if !valid_rule_provider_interval(self.interval) {
                    return Err(invalid(format!(
                        "interval must be between 1 and {MAX_RULE_PROVIDER_INTERVAL_SECS} seconds"
                    )));
                }
            }
            "http"
                if self
                    .path
                    .as_ref()
                    .is_none_or(|path| !path.as_os_str().is_empty()) =>
            {
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
                if !valid_rule_provider_interval(self.interval) {
                    return Err(invalid(format!(
                        "interval must be between 1 and {MAX_RULE_PROVIDER_INTERVAL_SECS} seconds"
                    )));
                }
                if self.headers.len() > 64
                    || self
                        .headers
                        .values()
                        .map(|values| values.values().len())
                        .sum::<usize>()
                        > 64
                {
                    return Err(invalid("at most 64 HTTP headers are allowed".to_owned()));
                }
                let mut header_names = std::collections::HashSet::new();
                for (key, values) in &self.headers {
                    let Ok(header_name) = HeaderName::from_bytes(key.as_bytes()) else {
                        return Err(invalid(format!("invalid HTTP header name: {key}")));
                    };
                    if !header_names.insert(header_name.as_str().to_owned())
                        || values.values().is_empty()
                        || values.values().iter().any(|value| {
                            value.len() > 8 * 1024
                                || HeaderValue::from_bytes(value.as_bytes()).is_err()
                        })
                    {
                        return Err(invalid(format!("invalid or duplicate HTTP header: {key}")));
                    }
                }
            }
            "inline" => {
                return Err(invalid(
                    "type: inline cannot define path, url, interval, or header".to_owned(),
                ));
            }
            "file" => return Err(invalid("type: file requires a path".to_owned())),
            "http" => return Err(invalid("type: http requires a valid url".to_owned())),
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

        self.validate_payload()
            .map_err(|reason| invalid(format!("invalid provider payload: {reason}")))?;
        Ok(())
    }

    fn validate_payload(&self) -> Result<(), String> {
        if self
            .payload
            .iter()
            .any(|rule| rule.trim().is_empty() || rule.contains(['\r', '\n']))
        {
            return Err("payload entries must be non-empty single-line rules".to_owned());
        }
        let validation_rules = self
            .normalized_payload()
            .iter()
            .map(|rule| format!("{rule},DIRECT"))
            .collect::<Vec<_>>();
        if validation_rules.iter().any(|rule| {
            rule.split(',')
                .next()
                .is_some_and(|kind| kind.trim() == "MATCH")
        }) {
            return Err("MATCH cannot appear inside a rule-provider payload".to_owned());
        }
        RuleSet::parse(&validation_rules)
            .map(|_| ())
            .map_err(|error| error.to_string())
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

fn valid_rule_provider_interval(interval: Option<u64>) -> bool {
    interval.is_none_or(|interval| (1..=MAX_RULE_PROVIDER_INTERVAL_SECS).contains(&interval))
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
        static NEXT_TEMP_DIR: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_TEMP_DIR.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!(
            "rust-mhm-test-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        std::fs::create_dir_all(&path).unwrap();
        path
    }

    #[test]
    fn cache_writer_replaces_an_existing_snapshot() {
        let directory = temporary_directory();
        let cache_path = directory.join("provider.cache");
        std::fs::write(&cache_path, b"old snapshot").unwrap();

        write_rule_provider_cache(&cache_path, b"new snapshot").unwrap();

        assert_eq!(std::fs::read(&cache_path).unwrap(), b"new snapshot");
        std::fs::remove_dir_all(directory).unwrap();
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

    async fn start_http_redirect(location: String) -> (SocketAddr, tokio::task::JoinHandle<()>) {
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
            let response = format!(
                "HTTP/1.1 302 Found\r\nLocation: {location}\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
            );
            let _ = stream.write_all(response.as_bytes()).await;
        });
        (address, task)
    }

    async fn start_chunked_http_response(
        body: Vec<u8>,
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
            let _ = stream
                .write_all(
                    b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                )
                .await;
            let chunk_header = format!("{:X}\r\n", body.len());
            let _ = stream.write_all(chunk_header.as_bytes()).await;
            let _ = stream.write_all(&body).await;
            let _ = stream.write_all(b"\r\n0\r\n\r\n").await;
        });
        (address, task)
    }

    async fn start_delayed_http_response(
        delay: std::time::Duration,
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
            tokio::time::sleep(delay).await;
            let body = b"payload:\n  - slow.example\n";
            let headers = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            let _ = stream.write_all(headers.as_bytes()).await;
            let _ = stream.write_all(body).await;
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

    #[test]
    fn file_rule_provider_interval_is_optional_bounded_and_scheduled() {
        let directory = temporary_directory();
        std::fs::write(directory.join("rules.txt"), "old.example\n").unwrap();
        for (interval, expected) in [
            (None, DEFAULT_RULE_PROVIDER_INTERVAL_SECS),
            (Some(3600), 3600),
            (
                Some(MAX_RULE_PROVIDER_INTERVAL_SECS),
                MAX_RULE_PROVIDER_INTERVAL_SECS,
            ),
        ] {
            let interval_config = interval
                .map(|seconds| format!("    interval: {seconds}\n"))
                .unwrap_or_default();
            let config_path = directory.join("config.yaml");
            std::fs::write(
                &config_path,
                format!(
                    "rule-providers:\n  local:\n    type: file\n    behavior: domain\n    path: rules.txt\n{interval_config}rules:\n  - RULE-SET,local,REJECT\n"
                ),
            )
            .unwrap();
            let config = Config::load(&config_path).unwrap();
            assert_eq!(
                config.rule_provider_refreshes(),
                vec![("local".to_owned(), Duration::from_secs(expected))]
            );
        }

        for invalid_interval in [0, MAX_RULE_PROVIDER_INTERVAL_SECS + 1] {
            let config_path = directory.join("invalid-interval.yaml");
            std::fs::write(
                &config_path,
                format!(
                    "rule-providers:\n  local:\n    type: file\n    behavior: domain\n    path: rules.txt\n    interval: {invalid_interval}\n"
                ),
            )
            .unwrap();
            assert!(matches!(
                Config::load(&config_path),
                Err(ConfigError::InvalidRuleProvider { .. })
            ));
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn http_provider_downloads_and_routes_a_startup_snapshot() {
        let body = b"payload:\n  - .remote.example\n  - '*.static.example'\n".to_vec();
        let expected_body = body.clone();
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
        let cache_path = directory
            .join(".rust-mhm-cache")
            .join("provider-72656d6f7465.cache");
        assert_eq!(std::fs::read(cache_path).unwrap(), expected_body);
        server.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn http_provider_uses_a_valid_persistent_cache_when_offline() {
        let directory = temporary_directory();
        let config_path = directory.join("offline.yaml");
        let cache_path = directory.join("snapshots/remote.rules");
        std::fs::create_dir_all(cache_path.parent().unwrap()).unwrap();
        std::fs::write(&cache_path, "payload:\n  - .cached.example\n").unwrap();
        let unavailable = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = unavailable.local_addr().unwrap();
        drop(unavailable);
        std::fs::write(
            &config_path,
            format!(
                "rule-providers:\n  remote:\n    type: http\n    behavior: domain\n    url: 'http://{address}/rules'\n    path: snapshots/remote.rules\nrules:\n  - RULE-SET,remote,REJECT\n  - MATCH,DIRECT\n"
            ),
        )
        .unwrap();

        let config = Config::load_async(&config_path).await.unwrap();
        let rules = config.routing_rules().unwrap();
        assert_eq!(
            rules.route(&RequestTarget {
                host: TargetHost::Domain("cdn.cached.example".into()),
                port: 443,
            }),
            RouteAction::Reject
        );
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
    async fn http_provider_falls_back_when_downloaded_rules_are_invalid() {
        let (address, server) =
            start_http_response("200 OK", b"payload:\n  - GEOIP,CN\n".to_vec(), None).await;
        let directory = temporary_directory();
        let config_path = directory.join("invalid-remote.yaml");
        let cache_path = directory.join("valid-cache.yaml");
        let cached_snapshot = b"payload:\n  - DOMAIN-SUFFIX,cached.example\n";
        std::fs::write(&cache_path, cached_snapshot).unwrap();
        std::fs::write(
            &config_path,
            format!(
                "rule-providers:\n  remote:\n    type: http\n    behavior: classical\n    url: 'http://{address}/rules'\n    path: valid-cache.yaml\nrules:\n  - RULE-SET,remote,REJECT\n  - MATCH,DIRECT\n"
            ),
        )
        .unwrap();

        let config = Config::load_async(&config_path).await.unwrap();
        assert_eq!(
            config.routing_rules().unwrap().route(&RequestTarget {
                host: TargetHost::Domain("cdn.cached.example".into()),
                port: 443,
            }),
            RouteAction::Reject
        );
        assert_eq!(std::fs::read(&cache_path).unwrap(), cached_snapshot);
        server.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn http_provider_sends_configured_headers_and_uses_explicit_cache_path() {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            while !request.ends_with(b"\r\n\r\n") && request.len() < 16 * 1024 {
                let mut byte = [0u8; 1];
                if stream.read_exact(&mut byte).await.is_err() {
                    return;
                }
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap().to_ascii_lowercase();
            assert!(request.contains("x-provider-key: local-test-token\r\n"));
            assert!(request.contains("x-provider-key: second-token\r\n"));
            assert!(request.contains("x-provider-single: scalar-value\r\n"));
            let body = b"payload:\n  - .headered.example\n";
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            stream.write_all(response.as_bytes()).await.unwrap();
            stream.write_all(body).await.unwrap();
        });
        let directory = temporary_directory();
        let config_path = directory.join("headers.yaml");
        std::fs::write(
            &config_path,
            format!(
                "rule-providers:\n  remote:\n    type: http\n    behavior: domain\n    url: 'http://{address}/rules'\n    path: snapshots/header.rules\n    interval: 3600\n    header:\n      X-Provider-Key:\n        - local-test-token\n        - second-token\n      X-Provider-Single: scalar-value\nrules:\n  - RULE-SET,remote,REJECT\n  - MATCH,DIRECT\n"
            ),
        )
        .unwrap();

        let config = Config::load_async(&config_path).await.unwrap();
        assert_eq!(
            config.rule_provider_refreshes(),
            vec![("remote".to_owned(), Duration::from_secs(3600))]
        );
        assert_eq!(
            std::fs::read(directory.join("snapshots/header.rules")).unwrap(),
            b"payload:\n  - .headered.example\n"
        );
        assert_eq!(
            config.routing_rules().unwrap().route(&RequestTarget {
                host: TargetHost::Domain("cdn.headered.example".into()),
                port: 443,
            }),
            RouteAction::Reject
        );
        server.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn invalid_http_refresh_options_are_rejected_before_network_access() {
        let directory = temporary_directory();
        let cases = [
            ("zero-interval", "    interval: 0\n"),
            (
                "bad-header",
                "    header:\n      'Bad Header':\n        - value\n",
            ),
            ("overwrite-config", "    path: overwrite-config.yaml\n"),
        ];
        for (name, extra) in cases {
            let config_path = directory.join(format!("{name}.yaml"));
            std::fs::write(
                &config_path,
                format!(
                    "rule-providers:\n  remote:\n    type: http\n    behavior: classical\n    url: 'http://127.0.0.1:9/rules'\n{extra}"
                ),
            )
            .unwrap();
            assert!(matches!(
                Config::load_async(&config_path).await,
                Err(ConfigError::InvalidRuleProvider { .. })
            ));
        }
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn rejects_noncanonical_plural_provider_header_field() {
        let error = Config::from_yaml_str(
            "rule-providers:\n  remote:\n    type: http\n    behavior: classical\n    url: 'http://example.test/rules'\n    headers:\n      X-Test: value\n",
        )
        .unwrap_err();
        assert!(matches!(error, ConfigError::Yaml(_)));
    }

    #[tokio::test]
    async fn http_provider_follows_redirects_and_routes_the_result() {
        let body = b"payload:\n  - .redirected.example\n".to_vec();
        let (destination, destination_server) = start_http_response("200 OK", body, None).await;
        let (address, redirect_server) =
            start_http_redirect(format!("http://{destination}/rules")).await;
        let directory = temporary_directory();
        let config_path = directory.join("redirect.yaml");
        std::fs::write(
            &config_path,
            format!(
                "rule-providers:\n  remote:\n    type: http\n    behavior: domain\n    url: 'http://{address}/start'\nrules:\n  - RULE-SET,remote,REJECT\n  - MATCH,DIRECT\n"
            ),
        )
        .unwrap();

        let config = Config::load_async(&config_path).await.unwrap();
        assert_eq!(
            config.routing_rules().unwrap().route(&RequestTarget {
                host: TargetHost::Domain("cdn.redirected.example".into()),
                port: 443,
            }),
            RouteAction::Reject
        );
        redirect_server.await.unwrap();
        destination_server.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn http_provider_with_custom_headers_does_not_follow_redirects() {
        let (address, redirect_server) =
            start_http_redirect("http://127.0.0.1:9/untrusted".to_owned()).await;
        let directory = temporary_directory();
        let config_path = directory.join("redirect-with-header.yaml");
        std::fs::write(
            &config_path,
            format!(
                "rule-providers:\n  remote:\n    type: http\n    behavior: classical\n    url: 'http://{address}/start'\n    header:\n      Authorization:\n        - Bearer local-test-token\n"
            ),
        )
        .unwrap();

        assert!(matches!(
            Config::load_async(&config_path).await,
            Err(ConfigError::RuleProviderHttp { reason, .. }) if reason.contains("302 Found")
        ));
        redirect_server.await.unwrap();
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn http_providers_cannot_share_a_cache_path() {
        let directory = temporary_directory();
        let config_path = directory.join("duplicate-cache.yaml");
        std::fs::write(
            &config_path,
            "rule-providers:\n  first:\n    type: http\n    behavior: classical\n    url: 'http://127.0.0.1:9/first'\n    path: shared.cache\n  second:\n    type: http\n    behavior: classical\n    url: 'http://127.0.0.1:9/second'\n    path: nested/../shared.cache\n",
        )
        .unwrap();

        assert!(matches!(
            Config::load_async(&config_path).await,
            Err(ConfigError::InvalidRuleProvider { reason, .. })
                if reason.contains("distinct cache paths")
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[cfg(windows)]
    #[tokio::test]
    async fn http_providers_cannot_share_case_insensitive_cache_paths() {
        let directory = temporary_directory();
        let config_path = directory.join("case-cache.yaml");
        std::fs::write(
            &config_path,
            "rule-providers:\n  first:\n    type: http\n    behavior: classical\n    url: 'http://127.0.0.1:9/first'\n    path: shared.cache\n  second:\n    type: http\n    behavior: classical\n    url: 'http://127.0.0.1:9/second'\n    path: SHARED.CACHE\n",
        )
        .unwrap();

        assert!(matches!(
            Config::load_async(&config_path).await,
            Err(ConfigError::InvalidRuleProvider { reason, .. })
                if reason.contains("distinct cache paths")
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn http_provider_cache_cannot_overwrite_config_through_path_alias() {
        let directory = temporary_directory();
        let config_path = directory.join("protected.yaml");
        std::fs::write(
            &config_path,
            "rule-providers:\n  remote:\n    type: http\n    behavior: classical\n    url: 'http://127.0.0.1:9/remote'\n    path: nested/../protected.yaml\n",
        )
        .unwrap();

        assert!(matches!(
            Config::load_async(&config_path).await,
            Err(ConfigError::InvalidRuleProvider { reason, .. })
                if reason.contains("must not overwrite the configuration file")
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn http_provider_rejects_directory_cache_paths() {
        let directory = temporary_directory();
        let config_path = directory.join("directory-cache.yaml");
        std::fs::write(
            &config_path,
            "rule-providers:\n  remote:\n    type: http\n    behavior: classical\n    url: 'http://127.0.0.1:9/remote'\n    path: .\n",
        )
        .unwrap();

        assert!(matches!(
            Config::load_async(&config_path).await,
            Err(ConfigError::InvalidRuleProvider { reason, .. })
                if reason.contains("path must name a cache file")
        ));
        std::fs::remove_dir_all(directory).unwrap();
    }

    #[tokio::test]
    async fn http_provider_download_obeys_connect_timeout() {
        let (address, server) =
            start_delayed_http_response(std::time::Duration::from_millis(300)).await;
        let directory = temporary_directory();
        let config_path = directory.join("timeout.yaml");
        std::fs::write(
            &config_path,
            format!(
                "connect_timeout_ms: 100\nrule-providers:\n  remote:\n    type: http\n    behavior: classical\n    url: 'http://{address}/slow'\n"
            ),
        )
        .unwrap();

        assert!(matches!(
            Config::load_async(&config_path).await,
            Err(ConfigError::RuleProviderHttp { reason, .. }) if reason.contains("connect_timeout_ms")
        ));
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
            directory.join("directory.yaml"),
            "rule-providers:\n  local:\n    type: file\n    behavior: classical\n    path: .\n",
        )
        .unwrap();
        assert!(matches!(
            Config::load(directory.join("directory.yaml")),
            Err(ConfigError::RuleProviderLoad { reason, .. })
                if reason.contains("not a regular file")
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

        let streamed_path = directory.join("streamed-oversized.yaml");
        let (address, server) =
            start_chunked_http_response(vec![b'x'; (MAX_RULE_PROVIDER_BYTES + 1) as usize]).await;
        std::fs::write(
            &streamed_path,
            format!(
                "rule-providers:\n  remote:\n    type: http\n    behavior: classical\n    url: 'http://{address}/chunked'\n"
            ),
        )
        .unwrap();
        assert!(matches!(
            Config::load_async(&streamed_path).await,
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
