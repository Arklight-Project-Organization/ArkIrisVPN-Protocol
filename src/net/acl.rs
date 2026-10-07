//! 访问控制列表（ACL）。

use ipnetwork::IpNetwork;
use std::{net::IpAddr, str::FromStr};

#[derive(Clone)]
pub enum AclRule {
    Allow(IpNetwork),
    Deny(IpNetwork),
}

pub fn parse_acl(rules_str: &str) -> Vec<AclRule> {
    let mut rules = Vec::new();
    for part in rules_str.split(',') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        if let Some(cidr) = part.strip_prefix("allow:") {
            if let Ok(net) = IpNetwork::from_str(cidr) {
                rules.push(AclRule::Allow(net));
            }
        } else if let Some(cidr) = part.strip_prefix("deny:") {
            if let Ok(net) = IpNetwork::from_str(cidr) {
                rules.push(AclRule::Deny(net));
            }
        }
    }
    rules
}

pub fn acl_check(rules: &[AclRule], ip: IpAddr) -> bool {
    let mut allow = false;
    for rule in rules {
        match rule {
            AclRule::Allow(net) => {
                if net.contains(ip) {
                    allow = true;
                }
            }
            AclRule::Deny(net) => {
                if net.contains(ip) {
                    return false;
                }
            }
        }
    }
    allow
}
