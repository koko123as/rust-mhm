use std::net::{IpAddr, SocketAddr};

use regex::Regex;
use thiserror::Error;

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
pub struct RuleSet {
    rules: Vec<RoutingRule>,
}

#[derive(Debug, Clone)]
struct RoutingRule {
    matcher: Matcher,
    action: RouteAction,
}

#[derive(Debug, Clone)]
enum Matcher {
    DomainExact(String),
    DomainSuffix(String),
    DomainKeyword(String),
    DomainWildcard(String),
    DomainRegex(Regex),
    IpCidr(Cidr),
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
}

impl Default for RuleSet {
    fn default() -> Self {
        Self {
            rules: vec![RoutingRule {
                matcher: Matcher::Any,
                action: RouteAction::Direct,
            }],
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
        if lines.is_empty() {
            return Ok(Self::default());
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
                    (Matcher::IpCidr(cidr), fields[2])
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
                action: parse_action(action_field, index, proxy_names)?,
            });
        }

        if !has_match {
            rules.push(RoutingRule {
                matcher: Matcher::Any,
                action: RouteAction::Direct,
            });
        }

        Ok(Self { rules })
    }

    /// Evaluate rules in source order; the first matching rule wins.
    pub fn route(&self, target: &RequestTarget) -> RouteAction {
        self.route_with_source(target, None)
    }

    /// Evaluate rules with the source address of the inbound connection when available.
    pub(crate) fn route_with_source(
        &self,
        target: &RequestTarget,
        source: Option<SocketAddr>,
    ) -> RouteAction {
        self.rules
            .iter()
            .find(|rule| rule.matches(target, source))
            .map(|rule| rule.action.clone())
            .unwrap_or(RouteAction::Direct)
    }

    pub fn rule_count(&self) -> usize {
        self.rules.len()
    }
}

impl RoutingRule {
    fn matches(&self, target: &RequestTarget, source: Option<SocketAddr>) -> bool {
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
            Matcher::IpCidr(cidr) => match target.host {
                TargetHost::Ip(ip) => cidr.contains(ip),
                TargetHost::Domain(_) => false,
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
) -> Result<RouteAction, RuleError> {
    match value {
        "DIRECT" => Ok(RouteAction::Direct),
        "REJECT" => Ok(RouteAction::Reject),
        name if proxy_names.iter().any(|proxy_name| proxy_name == name) => {
            Ok(RouteAction::Proxy(name.to_owned()))
        }
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
            Err(RuleError::UnsupportedRuleType { .. })
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
}
