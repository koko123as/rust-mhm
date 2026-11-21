use std::{
    collections::{BTreeMap, HashMap, HashSet},
    fs::File,
    io::{Read, Write},
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::{Arc, RwLock},
};

use regex::Regex;
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use thiserror::Error;
use tracing::warn;

const MAX_PROXY_GROUP_STATE_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ProxyGroupSelectionState {
    version: u8,
    selected: BTreeMap<String, String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RouteAction {
    Direct,
    Reject,
    Proxy(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TargetHost {
    Ip(IpAddr),
    Domain(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RequestTarget {
    pub host: TargetHost,
    pub port: u16,
}

#[derive(Debug, Clone)]
pub(crate) struct ProxyGroupDefinition {
    pub(crate) members: Vec<String>,
    pub(crate) default_selected: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyGroupSnapshot {
    pub name: String,
    pub selected: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone)]
enum RuleAction {
    Fixed(RouteAction),
    ProxyGroup(String),
}

#[derive(Debug, Clone)]
pub struct RuleSet {
    rules: Vec<RoutingRule>,
    proxy_groups: Arc<RwLock<ProxyGroupSelections>>,
}

#[derive(Debug, Clone)]
struct RoutingRule {
    matcher: Matcher,
    action: RuleAction,
}

#[derive(Debug, Clone, Default)]
struct ProxyGroupSelections {
    definitions: HashMap<String, ProxyGroupDefinition>,
    selected: BTreeMap<String, String>,
    persistence_path: Option<PathBuf>,
}

impl ProxyGroupSelections {
    fn from_definitions(definitions: &HashMap<String, ProxyGroupDefinition>) -> Self {
        let selected = definitions
            .iter()
            .map(|(name, definition)| (name.clone(), definition.default_selected.clone()))
            .collect();
        Self {
            definitions: definitions.clone(),
            selected,
            persistence_path: None,
        }
    }

    fn resolve(&self, name: &str, visiting: &mut HashSet<String>) -> Option<RouteAction> {
        if !visiting.insert(name.to_owned()) {
            return None;
        }
        let Some(selected) = self.selected.get(name) else {
            visiting.remove(name);
            return None;
        };
        let action = match selected.as_str() {
            "DIRECT" => Some(RouteAction::Direct),
            "REJECT" => Some(RouteAction::Reject),
            member if self.definitions.contains_key(member) => self.resolve(member, visiting),
            proxy => Some(RouteAction::Proxy(proxy.to_owned())),
        };
        visiting.remove(name);
        action
    }
}

#[derive(Debug, Clone)]
enum Matcher {
    DomainExact(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainWildcard(String),
    DomainRegex(Regex),
    IpCidr { cidr: Cidr, no_resolve: bool },
    SourceIpCidr(Cidr),
    SourcePort(PortMatcher),
    DstPort(PortMatcher),
    Any,
}

#[derive(Debug, Clone, Copy)]
struct Cidr {
    network: IpAddr,
    prefix: u8,
}

#[derive(Debug, Clone, Copy)]
enum PortMatcher {
    Single(u16),
    Range { first: u16, last: u16 },
}

#[derive(Debug, Error)]
pub enum RuleError {
    #[error("invalid routing rule at index {index}: malformed fields")]
    InvalidSyntax { index: usize },
    #[error("unsupported routing rule type at index {index}: {kind}")]
    UnsupportedRuleType { index: usize, kind: String },
    #[error("unknown rule provider at index {index}: {name}")]
    UnknownRuleProvider { index: usize, name: String },
    #[error("unsupported routing action at index {index}: {action}")]
    UnsupportedAction { index: usize, action: String },
    #[error("invalid domain in routing rule at index {index}")]
    InvalidDomain { index: usize },
    #[error("invalid domain keyword in routing rule at index {index}")]
    InvalidDomainKeyword { index: usize },
    #[error("invalid domain wildcard in routing rule at index {index}")]
    InvalidDomainWildcard { index: usize },
    #[error("invalid domain regular expression in routing rule at index {index}")]
    InvalidDomainRegex { index: usize },
    #[error("invalid CIDR in routing rule at index {index}")]
    InvalidCidr { index: usize },
    #[error("invalid destination port or range in routing rule at index {index}")]
    InvalidPort { index: usize },
    #[error("MATCH must appear at most once and must be the final routing rule")]
    MatchMustBeLast,
    #[error("unknown proxy group: {name}")]
    UnknownProxyGroup { name: String },
    #[error("member {member} is not configured in proxy group {group}")]
    InvalidProxyGroupMember { group: String, member: String },
    #[error("could not persist proxy group selection state: {reason}")]
    ProxyGroupStatePersistence { reason: String },
}

impl Default for RuleSet {
    fn default() -> Self {
        Self {
            rules: vec![RoutingRule {
                matcher: Matcher::Any,
                action: RuleAction::Fixed(RouteAction::Direct),
            }],
            proxy_groups: Arc::new(RwLock::new(ProxyGroupSelections::default())),
        }
    }
}

impl RuleSet {
    /// Parse the supported comma-separated Mihomo-style rule subset.
    /// An implicit MATCH,DIRECT is appended when no MATCH rule is supplied.
    pub fn parse(lines: &[String]) -> Result<Self, RuleError> {
        Self::parse_with_proxies(lines, &[])
    }

    /// Parse rules whose actions may also name one of the configured outbounds.
    pub fn parse_with_proxies(lines: &[String], proxy_names: &[String]) -> Result<Self, RuleError> {
        Self::parse_with_rule_providers(lines, proxy_names, &HashMap::new())
    }

    /// Parse rules and expand references to already-validated classical rule-provider payloads.
    pub(crate) fn parse_with_rule_providers(
        lines: &[String],
        proxy_names: &[String],
        rule_providers: &HashMap<String, Vec<String>>,
    ) -> Result<Self, RuleError> {
        Self::parse_with_rule_providers_and_groups(
            lines,
            proxy_names,
            &HashMap::new(),
            rule_providers,
        )
    }

    /// Parse rules with validated provider payloads and proxy-group definitions.
    pub(crate) fn parse_with_rule_providers_and_groups(
        lines: &[String],
        proxy_names: &[String],
        group_definitions: &HashMap<String, ProxyGroupDefinition>,
        rule_providers: &HashMap<String, Vec<String>>,
    ) -> Result<Self, RuleError> {
        let mut expanded_lines = Vec::with_capacity(lines.len());
        for (offset, line) in lines.iter().enumerate() {
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();
            if fields.first().copied() == Some("MATCH")
                && fields.len() == 2
                && offset + 1 != lines.len()
            {
                return Err(RuleError::MatchMustBeLast);
            }
            if fields.first().copied() != Some("RULE-SET") {
                expanded_lines.push(line.clone());
                continue;
            }

            let index = offset + 1;
            if fields.len() != 3 || fields.iter().any(|field| field.is_empty()) {
                return Err(RuleError::InvalidSyntax { index });
            }
            let Some(payload) = rule_providers.get(fields[1]) else {
                return Err(RuleError::UnknownRuleProvider {
                    index,
                    name: fields[1].to_owned(),
                });
            };
            parse_action(fields[2], index, proxy_names, group_definitions)?;
            expanded_lines.extend(payload.iter().map(|rule| format!("{rule},{}", fields[2])));
        }

        Self::parse_expanded_with_proxies(&expanded_lines, proxy_names, group_definitions)
    }

    fn parse_expanded_with_proxies(
        lines: &[String],
        proxy_names: &[String],
        group_definitions: &HashMap<String, ProxyGroupDefinition>,
    ) -> Result<Self, RuleError> {
        if lines.is_empty() {
            let default = Self::default();
            return Ok(Self {
                rules: default.rules,
                proxy_groups: Arc::new(RwLock::new(ProxyGroupSelections::from_definitions(
                    group_definitions,
                ))),
            });
        }

        let mut rules = Vec::with_capacity(lines.len() + 1);
        let mut has_match = false;

        for (offset, line) in lines.iter().enumerate() {
            let index = offset + 1;
            let fields: Vec<&str> = line.split(',').map(str::trim).collect();
            let kind = fields.first().copied().unwrap_or_default();
            if kind != "DOMAIN-REGEX" && fields.iter().any(|field| field.is_empty()) {
                return Err(RuleError::InvalidSyntax { index });
            }

            let (matcher, action_field) = match kind {
                "DOMAIN" if fields.len() == 3 => {
                    let domain =
                        normalize_domain(fields[1]).ok_or(RuleError::InvalidDomain { index })?;
                    (Matcher::DomainExact(domain), fields[2])
                }
                "DOMAIN-SUFFIX" if fields.len() == 3 => {
                    let domain =
                        normalize_domain(fields[1]).ok_or(RuleError::InvalidDomain { index })?;
                    (Matcher::DomainSuffix(domain), fields[2])
                }
                "DOMAIN-KEYWORD" if fields.len() == 3 => {
                    let keyword = fields[1];
                    if keyword.len() > 253
                        || !keyword.is_ascii()
                        || keyword.bytes().any(|byte| byte.is_ascii_whitespace())
                    {
                        return Err(RuleError::InvalidDomainKeyword { index });
                    }
                    (
                        Matcher::DomainKeyword(keyword.to_ascii_lowercase()),
                        fields[2],
                    )
                }
                "DOMAIN-WILDCARD" if fields.len() == 3 => {
                    let pattern = fields[1];
                    if pattern.is_empty()
                        || pattern.len() > 253
                        || !pattern.is_ascii()
                        || pattern.bytes().any(|byte| {
                            !(byte.is_ascii_alphanumeric()
                                || matches!(byte, b'.' | b'-' | b'*' | b'?'))
                        })
                    {
                        return Err(RuleError::InvalidDomainWildcard { index });
                    }
                    (
                        Matcher::DomainWildcard(pattern.to_ascii_lowercase()),
                        fields[2],
                    )
                }
                "DOMAIN-REGEX" => {
                    let (rule, action) = line
                        .rsplit_once(',')
                        .ok_or(RuleError::InvalidDomainRegex { index })?;
                    let (_, pattern) = rule
                        .split_once(',')
                        .ok_or(RuleError::InvalidDomainRegex { index })?;
                    let pattern = pattern.trim();
                    let action = action.trim();
                    if pattern.is_empty() || pattern.len() > 4096 || action.is_empty() {
                        return Err(RuleError::InvalidDomainRegex { index });
                    }
                    let regex =
                        Regex::new(pattern).map_err(|_| RuleError::InvalidDomainRegex { index })?;
                    (Matcher::DomainRegex(regex), action)
                }
                "IP-CIDR" | "IP-CIDR6"
                    if fields.len() == 3
                        || (fields.len() == 4 && fields[3].eq_ignore_ascii_case("no-resolve")) =>
                {
                    let cidr = Cidr::parse(fields[1]).ok_or(RuleError::InvalidCidr { index })?;
                    (
                        Matcher::IpCidr {
                            cidr,
                            no_resolve: fields.len() == 4,
                        },
                        fields[2],
                    )
                }
                "SRC-IP-CIDR" if fields.len() == 3 => {
                    let cidr = Cidr::parse(fields[1]).ok_or(RuleError::InvalidCidr { index })?;
                    (Matcher::SourceIpCidr(cidr), fields[2])
                }
                "SRC-PORT" if fields.len() == 3 => {
                    let port =
                        PortMatcher::parse(fields[1]).ok_or(RuleError::InvalidPort { index })?;
                    (Matcher::SourcePort(port), fields[2])
                }
                "DST-PORT" if fields.len() == 3 => {
                    let port =
                        PortMatcher::parse(fields[1]).ok_or(RuleError::InvalidPort { index })?;
                    (Matcher::DstPort(port), fields[2])
                }
                "MATCH" if fields.len() == 2 => (Matcher::Any, fields[1]),
                "DOMAIN" | "DOMAIN-SUFFIX" | "DOMAIN-KEYWORD" | "DOMAIN-WILDCARD" | "IP-CIDR"
                | "IP-CIDR6" | "SRC-IP-CIDR" | "SRC-PORT" | "DST-PORT" | "MATCH" => {
                    return Err(RuleError::InvalidSyntax { index });
                }
                other => {
                    return Err(RuleError::UnsupportedRuleType {
                        index,
                        kind: other.to_owned(),
                    });
                }
            };

            if matches!(matcher, Matcher::Any) {
                if has_match || offset + 1 != lines.len() {
                    return Err(RuleError::MatchMustBeLast);
                }
                has_match = true;
            }

            rules.push(RoutingRule {
                matcher,
                action: parse_action(action_field, index, proxy_names, group_definitions)?,
            });
        }

        if !has_match {
            rules.push(RoutingRule {
                matcher: Matcher::Any,
                action: RuleAction::Fixed(RouteAction::Direct),
            });
        }

        Ok(Self {
            rules,
            proxy_groups: Arc::new(RwLock::new(ProxyGroupSelections::from_definitions(
                group_definitions,
            ))),
        })
    }

    /// Evaluate rules in source order; the first matching rule wins.
    pub fn route(&self, target: &RequestTarget) -> RouteAction {
        self.route_with_source(target, None)
    }

    pub(crate) fn load_persistent_proxy_group_selections(&self, path: PathBuf) {
        let mut selections = self
            .proxy_groups
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        selections.persistence_path = Some(path.clone());
        match read_proxy_group_selection_state(&path) {
            Ok(Some(state)) => {
                let mut ignored = 0;
                for (group, member) in state.selected {
                    if selections
                        .definitions
                        .get(&group)
                        .is_some_and(|definition| definition.members.contains(&member))
                    {
                        selections.selected.insert(group, member);
                    } else {
                        ignored += 1;
                    }
                }
                if ignored > 0 {
                    warn!(ignored, "ignored stale proxy-group selection entries");
                }
            }
            Ok(None) => {}
            Err(reason) => {
                warn!(error = %reason, "ignoring invalid proxy-group selection state file")
            }
        }
    }

    /// Evaluate rules with the source address of the inbound connection when available.
    pub(crate) fn route_with_source(
        &self,
        target: &RequestTarget,
        source: Option<SocketAddr>,
    ) -> RouteAction {
        self.route_with_resolved_ips(target, source, &[])
    }

    /// Evaluate rules against an already-resolved set of IP addresses for a domain target.
    pub(crate) fn route_with_resolved_ips(
        &self,
        target: &RequestTarget,
        source: Option<SocketAddr>,
        resolved_ips: &[IpAddr],
    ) -> RouteAction {
        self.rules
            .iter()
            .find(|rule| rule.matches(target, source, resolved_ips))
            .map(|rule| self.resolve_action(&rule.action))
            .unwrap_or(RouteAction::Direct)
    }

    /// Whether ordered TCP rule evaluation reaches a CIDR rule that needs a domain lookup.
    pub(crate) fn needs_domain_resolution(
        &self,
        target: &RequestTarget,
        source: Option<SocketAddr>,
    ) -> bool {
        if !matches!(&target.host, TargetHost::Domain(_)) {
            return false;
        }
        for rule in &self.rules {
            match &rule.matcher {
                Matcher::IpCidr {
                    no_resolve: true, ..
                } => continue,
                Matcher::IpCidr {
                    no_resolve: false, ..
                } => return true,
                _ if rule.matches(target, source, &[]) => return false,
                _ => {}
            }
        }
        false
    }

    /// Select a configured member for a group in this ruleset.
    /// Clones of the same ruleset share selections; separate rulesets do not.
    pub fn select_proxy_group_member(&self, group: &str, member: &str) -> Result<(), RuleError> {
        let mut selections = self
            .proxy_groups
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let Some(definition) = selections.definitions.get(group) else {
            return Err(RuleError::UnknownProxyGroup {
                name: group.to_owned(),
            });
        };
        if !definition
            .members
            .iter()
            .any(|candidate| candidate == member)
        {
            return Err(RuleError::InvalidProxyGroupMember {
                group: group.to_owned(),
                member: member.to_owned(),
            });
        }
        let mut updated = selections.selected.clone();
        updated.insert(group.to_owned(), member.to_owned());
        if let Some(path) = selections.persistence_path.as_deref() {
            persist_proxy_group_selection_state(path, &updated).map_err(|error| {
                RuleError::ProxyGroupStatePersistence {
                    reason: error.to_string(),
                }
            })?;
        }
        selections.selected = updated;
        Ok(())
    }

    /// Return the currently selected member for a configured group, if present.
    pub fn selected_proxy_group_member(&self, group: &str) -> Option<String> {
        self.proxy_groups
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .selected
            .get(group)
            .cloned()
    }

    /// Return an owned snapshot of the configured selection groups.
    pub fn proxy_group_snapshots(&self) -> Vec<ProxyGroupSnapshot> {
        let selections = self
            .proxy_groups
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut groups = selections
            .definitions
            .iter()
            .filter_map(|(name, definition)| {
                selections
                    .selected
                    .get(name)
                    .map(|selected| ProxyGroupSnapshot {
                        name: name.clone(),
                        selected: selected.clone(),
                        members: definition.members.clone(),
                    })
            })
            .collect::<Vec<_>>();
        groups.sort_by(|left, right| left.name.cmp(&right.name));
        groups
    }

    /// Return one configured group and its current selection, if it exists.
    pub fn proxy_group_snapshot(&self, group: &str) -> Option<ProxyGroupSnapshot> {
        let selections = self
            .proxy_groups
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let definition = selections.definitions.get(group)?;
        let selected = selections.selected.get(group)?;
        Some(ProxyGroupSnapshot {
            name: group.to_owned(),
            selected: selected.clone(),
            members: definition.members.clone(),
        })
    }

    /// Preserve valid selections and share their lock when replacing rules after refresh.
    pub(crate) fn inherit_proxy_group_selections_from(&mut self, previous: &Self) {
        let new_definitions = self
            .proxy_groups
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .definitions
            .clone();
        let mut previous_state = previous
            .proxy_groups
            .write()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let selected = new_definitions
            .iter()
            .map(|(group, definition)| {
                let member = previous_state
                    .selected
                    .get(group)
                    .filter(|member| definition.members.contains(member))
                    .unwrap_or(&definition.default_selected);
                (group.clone(), member.clone())
            })
            .collect();
        previous_state.definitions = new_definitions;
        previous_state.selected = selected;
        drop(previous_state);
        self.proxy_groups = previous.proxy_groups.clone();
    }

    fn resolve_action(&self, action: &RuleAction) -> RouteAction {
        match action {
            RuleAction::Fixed(action) => action.clone(),
            RuleAction::ProxyGroup(name) => self
                .proxy_groups
                .read()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .resolve(name, &mut HashSet::new())
                .unwrap_or(RouteAction::Reject),
        }
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

fn read_proxy_group_selection_state(
    path: &Path,
) -> Result<Option<ProxyGroupSelectionState>, String> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.to_string()),
    };
    let size = file.metadata().map_err(|error| error.to_string())?.len();
    if size > MAX_PROXY_GROUP_STATE_BYTES {
        return Err(format!(
            "state file exceeds {MAX_PROXY_GROUP_STATE_BYTES} bytes"
        ));
    }
    let mut bytes = Vec::with_capacity(size as usize);
    file.take(MAX_PROXY_GROUP_STATE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|error| error.to_string())?;
    if bytes.len() as u64 > MAX_PROXY_GROUP_STATE_BYTES {
        return Err(format!(
            "state file exceeds {MAX_PROXY_GROUP_STATE_BYTES} bytes"
        ));
    }
    let state: ProxyGroupSelectionState =
        serde_json::from_slice(&bytes).map_err(|error| error.to_string())?;
    if state.version != 1 {
        return Err(format!("unsupported state file version {}", state.version));
    }
    Ok(Some(state))
}

fn persist_proxy_group_selection_state(
    path: &Path,
    selected: &BTreeMap<String, String>,
) -> std::io::Result<()> {
    let state = ProxyGroupSelectionState {
        version: 1,
        selected: selected.clone(),
    };
    let bytes = serde_json::to_vec(&state).map_err(std::io::Error::other)?;
    if bytes.len() as u64 > MAX_PROXY_GROUP_STATE_BYTES {
        return Err(std::io::Error::other(format!(
            "state file exceeds {MAX_PROXY_GROUP_STATE_BYTES} bytes"
        )));
    }
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)?;
    let mut temporary = NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    Ok(())
}

impl RoutingRule {
    fn matches(
        &self,
        target: &RequestTarget,
        source: Option<SocketAddr>,
        resolved_ips: &[IpAddr],
    ) -> bool {
        match &self.matcher {
            Matcher::DomainExact(expected) => match &target.host {
                TargetHost::Domain(domain) => normalize_domain(domain).as_deref() == Some(expected),
                TargetHost::Ip(_) => false,
            },
            Matcher::DomainSuffix(suffix) => match &target.host {
                TargetHost::Domain(domain) => normalize_domain(domain)
                    .is_some_and(|domain| domain == *suffix || has_label_suffix(&domain, suffix)),
                TargetHost::Ip(_) => false,
            },
            Matcher::DomainKeyword(keyword) => match &target.host {
                TargetHost::Domain(domain) => {
                    normalize_domain(domain).is_some_and(|domain| domain.contains(keyword))
                }
                TargetHost::Ip(_) => false,
            },
            Matcher::DomainWildcard(pattern) => match &target.host {
                TargetHost::Domain(domain) => normalize_domain(domain)
                    .is_some_and(|domain| wildcard_matches(pattern, &domain)),
                TargetHost::Ip(_) => false,
            },
            Matcher::DomainRegex(regex) => match &target.host {
                TargetHost::Domain(domain) => {
                    normalize_domain(domain).is_some_and(|domain| regex.is_match(&domain))
                }
                TargetHost::Ip(_) => false,
            },
            Matcher::IpCidr { cidr, no_resolve } => match &target.host {
                TargetHost::Ip(ip) => cidr.contains(*ip),
                TargetHost::Domain(_) if *no_resolve => false,
                TargetHost::Domain(_) => resolved_ips.iter().any(|ip| cidr.contains(*ip)),
            },
            Matcher::SourceIpCidr(cidr) => source.is_some_and(|peer| cidr.contains(peer.ip())),
            Matcher::SourcePort(port) => source.is_some_and(|peer| port.contains(peer.port())),
            Matcher::DstPort(port) => port.contains(target.port),
            Matcher::Any => true,
        }
    }
}

fn parse_action(
    value: &str,
    index: usize,
    proxy_names: &[String],
    group_definitions: &HashMap<String, ProxyGroupDefinition>,
) -> Result<RuleAction, RuleError> {
    match value {
        "DIRECT" => Ok(RuleAction::Fixed(RouteAction::Direct)),
        "REJECT" => Ok(RuleAction::Fixed(RouteAction::Reject)),
        name if proxy_names.iter().any(|proxy_name| proxy_name == name) => {
            Ok(RuleAction::Fixed(RouteAction::Proxy(name.to_owned())))
        }
        name if group_definitions.contains_key(name) => Ok(RuleAction::ProxyGroup(name.to_owned())),
        other => Err(RuleError::UnsupportedAction {
            index,
            action: other.to_owned(),
        }),
    }
}

fn has_label_suffix(domain: &str, suffix: &str) -> bool {
    domain
        .strip_suffix(suffix)
        .is_some_and(|prefix| prefix.ends_with('.'))
}

fn wildcard_matches(pattern: &str, value: &str) -> bool {
    let pattern = pattern.as_bytes();
    let value = value.as_bytes();
    let (mut pattern_index, mut value_index) = (0, 0);
    let mut last_star = None;
    let mut star_value_index = 0;

    while value_index < value.len() {
        if pattern_index < pattern.len()
            && (pattern[pattern_index] == b'?' || pattern[pattern_index] == value[value_index])
        {
            pattern_index += 1;
            value_index += 1;
        } else if pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
            last_star = Some(pattern_index);
            pattern_index += 1;
            star_value_index = value_index;
        } else if let Some(star_index) = last_star {
            star_value_index += 1;
            pattern_index = star_index + 1;
            value_index = star_value_index;
        } else {
            return false;
        }
    }

    while pattern_index < pattern.len() && pattern[pattern_index] == b'*' {
        pattern_index += 1;
    }
    pattern_index == pattern.len()
}

/// Canonicalize the limited ASCII DNS names handled by this rule engine.
/// One terminal root dot is accepted; Unicode IDNs must be supplied as A-labels.
pub fn normalize_domain(value: &str) -> Option<String> {
    let value = value.strip_suffix('.').unwrap_or(value);
    if value.is_empty() || value.len() > 253 || !value.is_ascii() {
        return None;
    }
    if value.parse::<IpAddr>().is_ok() {
        return None;
    }

    let normalized = value.to_ascii_lowercase();
    for label in normalized.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        {
            return None;
        }
    }
    Some(normalized)
}

impl Cidr {
    fn parse(value: &str) -> Option<Self> {
        let (address, prefix) = value.split_once('/')?;
        let network = address.parse::<IpAddr>().ok()?;
        let prefix = prefix.parse::<u8>().ok()?;
        let max_prefix = match network {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        (prefix <= max_prefix).then_some(Self { network, prefix })
    }

    fn contains(self, candidate: IpAddr) -> bool {
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

impl PortMatcher {
    fn parse(value: &str) -> Option<Self> {
        if let Some((first, last)) = value.split_once('-') {
            if last.contains('-') {
                return None;
            }
            let first = parse_port(first)?;
            let last = parse_port(last)?;
            (first <= last).then_some(Self::Range { first, last })
        } else {
            Some(Self::Single(parse_port(value)?))
        }
    }

    fn contains(self, candidate: u16) -> bool {
        match self {
            Self::Single(port) => candidate == port,
            Self::Range { first, last } => (first..=last).contains(&candidate),
        }
    }
}

fn parse_port(value: &str) -> Option<u16> {
    let port = value.parse::<u16>().ok()?;
    (port != 0).then_some(port)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_set(lines: &[&str]) -> RuleSet {
        let lines = lines
            .iter()
            .map(|line| (*line).to_owned())
            .collect::<Vec<_>>();
        RuleSet::parse(&lines).unwrap()
    }

    #[test]
    fn refreshed_rules_keep_valid_selections_and_default_when_a_member_disappears() {
        let lines = vec!["MATCH,selected".to_owned()];
        let definitions = HashMap::from([(
            "selected".to_owned(),
            ProxyGroupDefinition {
                members: vec!["DIRECT".to_owned(), "REJECT".to_owned()],
                default_selected: "DIRECT".to_owned(),
            },
        )]);
        let previous = RuleSet::parse_with_rule_providers_and_groups(
            &lines,
            &[],
            &definitions,
            &HashMap::new(),
        )
        .unwrap();
        previous
            .select_proxy_group_member("selected", "REJECT")
            .unwrap();

        let mut refreshed = RuleSet::parse_with_rule_providers_and_groups(
            &lines,
            &[],
            &definitions,
            &HashMap::new(),
        )
        .unwrap();
        refreshed.inherit_proxy_group_selections_from(&previous);
        assert_eq!(
            refreshed.route(&domain_target("example.org", 443)),
            RouteAction::Reject
        );
        let late_handle = previous.clone();
        late_handle
            .select_proxy_group_member("selected", "DIRECT")
            .unwrap();
        assert_eq!(
            refreshed.route(&domain_target("example.org", 443)),
            RouteAction::Direct
        );
        late_handle
            .select_proxy_group_member("selected", "REJECT")
            .unwrap();

        let changed_definitions = HashMap::from([(
            "selected".to_owned(),
            ProxyGroupDefinition {
                members: vec!["DIRECT".to_owned()],
                default_selected: "DIRECT".to_owned(),
            },
        )]);
        let mut changed = RuleSet::parse_with_rule_providers_and_groups(
            &lines,
            &[],
            &changed_definitions,
            &HashMap::new(),
        )
        .unwrap();
        changed.inherit_proxy_group_selections_from(&previous);
        assert_eq!(
            changed.route(&domain_target("example.org", 443)),
            RouteAction::Direct
        );
    }

    fn domain_target(domain: &str, port: u16) -> RequestTarget {
        RequestTarget {
            host: TargetHost::Domain(domain.to_owned()),
            port,
        }
    }

    fn ip_target(address: &str, port: u16) -> RequestTarget {
        RequestTarget {
            host: TargetHost::Ip(address.parse().unwrap()),
            port,
        }
    }

    #[test]
    fn domain_exact_is_case_insensitive_and_does_not_match_subdomains() {
        let rules = rule_set(&["DOMAIN,Example.com,REJECT", "MATCH,DIRECT"]);
        assert_eq!(
            rules.route(&domain_target("EXAMPLE.COM", 443)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&domain_target("www.example.com", 443)),
            RouteAction::Direct
        );
    }

    #[test]
    fn domain_suffix_respects_label_boundaries_and_matches_apex() {
        let rules = rule_set(&["DOMAIN-SUFFIX,example.com,REJECT", "MATCH,DIRECT"]);
        assert_eq!(
            rules.route(&domain_target("example.com", 443)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&domain_target("www.example.com", 443)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&domain_target("notexample.com", 443)),
            RouteAction::Direct
        );
    }

    #[test]
    fn domain_keyword_matches_case_insensitive_substrings_in_domains_only() {
        let rules = rule_set(&["DOMAIN-KEYWORD,Google,REJECT", "MATCH,DIRECT"]);
        assert_eq!(
            rules.route(&domain_target("mail.GOOGLE.example", 443)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&domain_target("notgoogle.example", 443)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&domain_target("example.org", 443)),
            RouteAction::Direct
        );
        assert_eq!(
            rules.route(&ip_target("192.0.2.1", 443)),
            RouteAction::Direct
        );
    }

    #[test]
    fn domain_wildcard_supports_star_and_single_character_question_mark() {
        let star = rule_set(&["DOMAIN-WILDCARD,*.Google.example,REJECT", "MATCH,DIRECT"]);
        assert_eq!(
            star.route(&domain_target("mail.google.example", 443)),
            RouteAction::Reject
        );
        assert_eq!(
            star.route(&domain_target("google.example", 443)),
            RouteAction::Direct
        );
        assert_eq!(
            star.route(&domain_target("notgoogle.example", 443)),
            RouteAction::Direct
        );

        let question = rule_set(&["DOMAIN-WILDCARD,ab?.example.com,REJECT", "MATCH,DIRECT"]);
        assert_eq!(
            question.route(&domain_target("ab1.example.com", 443)),
            RouteAction::Reject
        );
        assert_eq!(
            question.route(&domain_target("ab12.example.com", 443)),
            RouteAction::Direct
        );
    }

    #[test]
    fn domain_regex_matches_normalized_domains_and_preserves_comma_quantifiers() {
        let rules = rule_set(&[
            r"DOMAIN-REGEX,^api[0-9]{2,4}\.example\.com$,REJECT",
            "MATCH,DIRECT",
        ]);
        assert_eq!(
            rules.route(&domain_target("API12.EXAMPLE.COM", 443)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&domain_target("api.example.com", 443)),
            RouteAction::Direct
        );
        assert_eq!(
            rules.route(&domain_target("xapi12.example.com", 443)),
            RouteAction::Direct
        );
    }

    #[test]
    fn source_ip_cidr_matches_only_the_supplied_peer_address() {
        let rules = rule_set(&[
            "SRC-IP-CIDR,192.0.2.0/24,REJECT",
            "SRC-IP-CIDR,2001:db8::/32,REJECT",
            "MATCH,DIRECT",
        ]);
        let target = domain_target("example.com", 443);
        assert_eq!(
            rules.route_with_source(&target, Some("192.0.2.44:41234".parse().unwrap())),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route_with_source(&target, Some("[2001:db8::44]:41234".parse().unwrap())),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route_with_source(&target, Some("192.0.3.1:41234".parse().unwrap())),
            RouteAction::Direct
        );
        assert_eq!(rules.route_with_source(&target, None), RouteAction::Direct);
        assert_eq!(rules.route(&target), RouteAction::Direct);
    }

    #[test]
    fn source_port_matches_single_ports_and_inclusive_ranges() {
        let rules = rule_set(&["SRC-PORT,40000-40010,REJECT", "MATCH,DIRECT"]);
        let target = domain_target("example.com", 443);
        assert_eq!(
            rules.route_with_source(&target, Some("127.0.0.1:40005".parse().unwrap())),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route_with_source(&target, Some("127.0.0.1:40011".parse().unwrap())),
            RouteAction::Direct
        );
        assert_eq!(rules.route_with_source(&target, None), RouteAction::Direct);
    }

    #[test]
    fn domain_matching_normalizes_ascii_case_and_terminal_root_dot() {
        let rules = rule_set(&["DOMAIN,example.com,REJECT", "MATCH,DIRECT"]);
        assert_eq!(
            rules.route(&domain_target("Example.COM.", 80)),
            RouteAction::Reject
        );
    }

    #[test]
    fn ipv4_cidr_matches_only_its_address_family() {
        let rules = rule_set(&["IP-CIDR,192.0.2.0/24,DIRECT,no-resolve", "MATCH,REJECT"]);
        assert_eq!(
            rules.route(&ip_target("192.0.2.44", 443)),
            RouteAction::Direct
        );
        assert_eq!(
            rules.route(&ip_target("192.0.3.1", 443)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&ip_target("::ffff:192.0.2.44", 443)),
            RouteAction::Reject
        );
    }

    #[test]
    fn ipv6_cidr_supports_zero_and_full_prefixes() {
        let rules = rule_set(&["IP-CIDR6,2001:db8::1/128,REJECT", "MATCH,DIRECT"]);
        assert_eq!(
            rules.route(&ip_target("2001:db8::1", 443)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&ip_target("2001:db8::2", 443)),
            RouteAction::Direct
        );

        let all_ipv6 = rule_set(&["IP-CIDR,::/0,REJECT", "MATCH,DIRECT"]);
        assert_eq!(
            all_ipv6.route(&ip_target("2001:db8::2", 443)),
            RouteAction::Reject
        );
    }

    #[test]
    fn domain_cidr_resolution_respects_rule_order_and_no_resolve() {
        let target = domain_target("example.com", 443);
        let domain_first = rule_set(&[
            "DOMAIN,example.com,REJECT",
            "IP-CIDR,127.0.0.0/8,REJECT",
            "MATCH,DIRECT",
        ]);
        assert!(!domain_first.needs_domain_resolution(&target, None));
        assert_eq!(domain_first.route(&target), RouteAction::Reject);

        let no_resolve = rule_set(&["IP-CIDR,127.0.0.0/8,REJECT,no-resolve", "MATCH,DIRECT"]);
        assert!(!no_resolve.needs_domain_resolution(&target, None));
        assert_eq!(
            no_resolve.route_with_resolved_ips(&target, None, &["127.0.0.1".parse().unwrap()],),
            RouteAction::Direct
        );

        let ordinary_cidr = rule_set(&["IP-CIDR,127.0.0.0/8,REJECT", "MATCH,DIRECT"]);
        assert!(ordinary_cidr.needs_domain_resolution(&target, None));
    }

    #[test]
    fn domain_cidr_matches_any_resolved_ip_and_preserves_ordered_fallback() {
        let target = domain_target("example.com", 443);
        let rules = rule_set(&[
            "IP-CIDR,10.0.0.0/8,REJECT",
            "DOMAIN-SUFFIX,example.com,DIRECT",
            "MATCH,REJECT",
        ]);
        assert_eq!(
            rules.route_with_resolved_ips(
                &target,
                None,
                &["2001:db8::1".parse().unwrap(), "10.2.3.4".parse().unwrap(),],
            ),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route_with_resolved_ips(&target, None, &["192.0.2.1".parse().unwrap()],),
            RouteAction::Direct
        );
        assert_eq!(
            rules.route_with_resolved_ips(
                &domain_target("elsewhere.invalid", 443),
                None,
                &["192.0.2.1".parse().unwrap()],
            ),
            RouteAction::Reject
        );
    }

    #[test]
    fn ip_cidr_no_resolve_does_not_change_literal_ip_matching() {
        let rules = rule_set(&["IP-CIDR6,2001:db8::/32,REJECT,no-resolve", "MATCH,DIRECT"]);
        assert_eq!(
            rules.route(&ip_target("2001:db8::44", 443)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&ip_target("192.0.2.1", 443)),
            RouteAction::Direct
        );
    }

    #[test]
    fn destination_port_matches_single_values_and_inclusive_ranges() {
        let rules = rule_set(&["DST-PORT,8000-8100,REJECT", "MATCH,DIRECT"]);
        assert_eq!(
            rules.route(&domain_target("example.com", 8000)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&domain_target("example.com", 8100)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&domain_target("example.com", 8101)),
            RouteAction::Direct
        );

        let single = rule_set(&["DST-PORT,443,REJECT", "MATCH,DIRECT"]);
        assert_eq!(
            single.route(&domain_target("example.com", 443)),
            RouteAction::Reject
        );
    }

    #[test]
    fn first_matching_rule_wins_and_implicit_match_is_direct() {
        let rules = rule_set(&["DOMAIN,example.com,REJECT"]);
        assert_eq!(rules.rule_count(), 2);
        assert_eq!(
            rules.route(&domain_target("example.com", 443)),
            RouteAction::Reject
        );
        assert_eq!(
            rules.route(&domain_target("other.com", 443)),
            RouteAction::Direct
        );
    }

    #[test]
    fn rejects_match_not_at_the_end_and_unknown_rule_sets() {
        let lines = vec![
            "MATCH,DIRECT".to_owned(),
            "DOMAIN,example.com,REJECT".to_owned(),
        ];
        assert!(matches!(
            RuleSet::parse(&lines),
            Err(RuleError::MatchMustBeLast)
        ));
        let lines = vec!["RULE-SET,ads,REJECT".to_owned()];
        assert!(matches!(
            RuleSet::parse(&lines),
            Err(RuleError::UnknownRuleProvider { .. })
        ));
    }

    #[test]
    fn rejects_invalid_cidr_domain_and_port_range() {
        assert!(matches!(
            RuleSet::parse(&["IP-CIDR,192.0.2.1/33,REJECT".to_owned()]),
            Err(RuleError::InvalidCidr { .. })
        ));
        assert!(matches!(
            RuleSet::parse(&["SRC-IP-CIDR,192.0.2.1/33,REJECT".to_owned()]),
            Err(RuleError::InvalidCidr { .. })
        ));
        assert!(matches!(
            RuleSet::parse(&["DOMAIN,not a domain,REJECT".to_owned()]),
            Err(RuleError::InvalidDomain { .. })
        ));
        assert!(matches!(
            RuleSet::parse(&["DOMAIN-KEYWORD,bad keyword,REJECT".to_owned()]),
            Err(RuleError::InvalidDomainKeyword { .. })
        ));
        assert!(matches!(
            RuleSet::parse(&["DOMAIN-WILDCARD,*.éxample.com,REJECT".to_owned()]),
            Err(RuleError::InvalidDomainWildcard { .. })
        ));
        assert!(matches!(
            RuleSet::parse(&["DOMAIN-REGEX,[,REJECT".to_owned()]),
            Err(RuleError::InvalidDomainRegex { .. })
        ));
        assert!(matches!(
            RuleSet::parse(&["DST-PORT,90-80,REJECT".to_owned()]),
            Err(RuleError::InvalidPort { .. })
        ));
    }

    #[test]
    fn concurrent_persistent_selections_leave_a_complete_matching_snapshot() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("groups.json");
        let definitions = HashMap::from([(
            "selected".to_owned(),
            ProxyGroupDefinition {
                members: vec!["DIRECT".to_owned(), "REJECT".to_owned()],
                default_selected: "DIRECT".to_owned(),
            },
        )]);
        let rules = RuleSet::parse_with_rule_providers_and_groups(
            &["MATCH,selected".to_owned()],
            &[],
            &definitions,
            &HashMap::new(),
        )
        .unwrap();
        rules.load_persistent_proxy_group_selections(path.clone());

        let workers = (0..4)
            .map(|index| {
                let rules = rules.clone();
                std::thread::spawn(move || {
                    let member = if index % 2 == 0 { "DIRECT" } else { "REJECT" };
                    for _ in 0..4 {
                        rules.select_proxy_group_member("selected", member).unwrap();
                    }
                })
            })
            .collect::<Vec<_>>();
        for worker in workers {
            worker.join().unwrap();
        }

        let disk = read_proxy_group_selection_state(&path)
            .unwrap()
            .expect("selection state should be persisted");
        assert_eq!(
            disk.selected.get("selected"),
            rules.selected_proxy_group_member("selected").as_ref()
        );
        assert_eq!(std::fs::read_dir(directory.path()).unwrap().count(), 1);
    }
}
