/*!
Network / DNS utilities for abusedetector.

This module centralizes:
- IPv4 parsing and range helpers
- Private & reserved range detection
- Reverse DNS lookup (async) via trust-dns-resolver
- in-addr.arpa construction
- Simple domain extraction heuristic

If you later want a more accurate domain extraction (public suffix awareness),
add a dependency such as `publicsuffix` and replace `domain_of()` accordingly.
*/

use std::net::{IpAddr, Ipv4Addr};
use std::str::FromStr;
use std::time::Duration;

use anyhow::{anyhow, Result};
use tokio::time::timeout;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    TokioAsyncResolver,
};

/// Parse a numeric IPv4 address string into Ipv4Addr.
/// Provides a user-friendly error aligned with legacy messaging.
pub fn parse_ipv4(s: &str) -> Result<Ipv4Addr> {
    Ipv4Addr::from_str(s)
        .map_err(|_| anyhow!("Error: This doesn't look like a numeric IPv4 address"))
}

/// Return true if the IPv4 address is in RFC1918 private ranges.
pub fn is_private(ip: Ipv4Addr) -> bool {
    let o = ip.octets();
    (o[0] == 10) || (o[0] == 172 && (16..=31).contains(&o[1])) || (o[0] == 192 && o[1] == 168)
}

/// Return true if the IPv4 address is in one of the "reserved" / special ranges
/// Based on IANA reserved ranges (RFC 5735, RFC 6890) and actual special-use allocations.
/// Only includes truly reserved ranges, not allocated public IP space.
pub fn is_reserved(ip: Ipv4Addr) -> bool {
    const RANGES: [(&str, &str); 11] = [
        ("0.0.0.0", "0.255.255.255"),       // "This" Network (RFC 1122)
        ("127.0.0.0", "127.255.255.255"),   // Loopback (RFC 1122)
        ("169.254.0.0", "169.254.255.255"), // Link Local (RFC 3927)
        ("192.0.0.0", "192.0.0.255"),       // IETF Protocol Assignments (RFC 6890)
        ("192.0.2.0", "192.0.2.255"),       // Documentation (TEST-NET-1) (RFC 5737)
        ("192.88.99.0", "192.88.99.255"),   // 6to4 Relay Anycast (RFC 3068)
        ("198.18.0.0", "198.19.255.255"),   // Benchmarking (RFC 2544)
        ("198.51.100.0", "198.51.100.255"), // Documentation (TEST-NET-2) (RFC 5737)
        ("203.0.113.0", "203.0.113.255"),   // Documentation (TEST-NET-3) (RFC 5737)
        ("224.0.0.0", "239.255.255.255"),   // Multicast (RFC 3171)
        ("240.0.0.0", "255.255.255.255"),   // Reserved for Future Use (RFC 1112)
    ];
    RANGES.iter().any(|(s, e)| in_range(ip, s, e))
}

/// Convert an IPv4 address to its reverse in-addr.arpa domain.
pub fn ipv4_to_inaddr(ip: Ipv4Addr) -> String {
    let o = ip.octets();
    format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
}

/// Perform a reverse DNS (PTR) lookup; returns first hostname if any.
/// Returns Ok(None) on timeout or NXDOMAIN-like conditions.
pub async fn reverse_dns(ip: Ipv4Addr, show_cmd: bool) -> Result<Option<String>> {
    if show_cmd {
        eprintln!("(cmd) host {ip}");
    }

    // Build a resolver each call (acceptable here; can be optimized with once_cell).
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

    let fut = resolver.reverse_lookup(IpAddr::V4(ip));
    match timeout(Duration::from_secs(5), fut).await {
        Ok(Ok(resp)) => {
            let name = resp.iter().next().map(|n| n.to_utf8());
            Ok(name)
        }
        Ok(Err(_e)) => Ok(None),
        Err(_) => Ok(None), // timeout
    }
}

/// Heuristic extraction of a registrable-ish domain from a hostname.
///
/// Strategy:
/// - Trim trailing dot
/// - If < 2 labels, return None
/// - If matches a known 2-label public suffix like "co.uk", use last 3 labels
/// - Else use last 2 labels
///
/// This is intentionally simple; for accuracy integrate the public suffix list.
pub fn domain_of(host: &str) -> Option<String> {
    let trimmed = host.trim_end_matches('.');
    let parts: Vec<&str> = trimmed.split('.').collect();
    if parts.len() < 2 {
        return None;
    }

    // Built‑in list of common 2‑part public suffixes where we want to keep
    // additional labels to better approximate the organizational domain.
    const SPECIAL_SUFFIXES: [&str; 4] = ["co.uk", "org.uk", "com.au", "co.jp"];

    let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);

    if SPECIAL_SUFFIXES
        .iter()
        .any(|suf| suf.eq_ignore_ascii_case(&last_two))
    {
        // Prefer TWO labels before the public suffix when available (e.g.
        // a.b.c.d.e.co.uk -> d.e.co.uk) matching the test expectation.
        if parts.len() >= 4 {
            return Some(format!(
                "{}.{}.{}",
                parts[parts.len() - 4],
                parts[parts.len() - 3],
                last_two
            ));
        } else if parts.len() >= 3 {
            // Fallback: only one label available before suffix.
            return Some(format!("{}.{}", parts[parts.len() - 3], last_two));
        }
        // If only the suffix itself exists, fall through to last_two
    }

    Some(last_two)
}

/// Internal: check if ip is between start and end inclusive.
fn in_range(ip: Ipv4Addr, start: &str, end: &str) -> bool {
    let s: Ipv4Addr = start.parse().unwrap();
    let e: Ipv4Addr = end.parse().unwrap();
    ipv4_to_u32(ip) >= ipv4_to_u32(s) && ipv4_to_u32(ip) <= ipv4_to_u32(e)
}

/// Convert IPv4 to u32 big-endian.
fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    let o = ip.octets();
    ((o[0] as u32) << 24) | ((o[1] as u32) << 16) | ((o[2] as u32) << 8) | (o[3] as u32)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ipv4_to_inaddr() {
        let ip: Ipv4Addr = "203.0.113.7".parse().unwrap();
        assert_eq!(ipv4_to_inaddr(ip), "7.113.0.203.in-addr.arpa");
    }

    #[test]
    fn test_private() {
        assert!(is_private("10.0.0.1".parse().unwrap()));
        assert!(is_private("172.16.0.1".parse().unwrap()));
        assert!(is_private("192.168.1.5".parse().unwrap()));
        assert!(!is_private("8.8.8.8".parse().unwrap()));
    }

    #[test]
    fn test_domain_of_basic() {
        assert_eq!(domain_of("sub.example.org").as_deref(), Some("example.org"));
        assert_eq!(domain_of("a.b.c.d.e.co.uk").as_deref(), Some("d.e.co.uk"));
    }
}
