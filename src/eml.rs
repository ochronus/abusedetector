//! EML (RFC 5322 / RFC 822 style) message parsing utilities.
//!
//! This module provides a lightweight parser to extract the *originating IPv4
//! address* from an email message file (.eml). We intentionally avoid adding
//! heavyweight MIME / message parsing dependencies and rely on a pragmatic
//! heuristic approach suitable for abuse reporting workflows.
//!
//! Strategy (ordered):
//! 1. Look for an `X-Originating-IP:` style header (Outlook / some MTAs).
//! 2. Collect all `Received:` headers, unfold continuations, and parse IPv4
//!    addresses in each. We ignore private / reserved ranges.
//! 3. Return the *earliest* public IPv4 (i.e., the one from the **bottom-most**
//!    Received header containing a public IP), falling back to the first public
//!    one encountered if ordering is ambiguous.
//!
//! Limitations:
//! - Does not validate SPF, DKIM, or ARC chains.
//! - Does not attempt IPv6 extraction (could be added later).
//! - Assumes the file uses UTF-8 or ASCII superset encoding.
//!
//! If no suitable public IPv4 is found, an error is returned.

use std::fs;
use std::net::Ipv4Addr;
use std::path::Path;
use std::str::FromStr;

use anyhow::{anyhow, bail, Result};
use regex::Regex;

use crate::netutil::{is_private, is_reserved};

/// Extract the sender domain from an EML file's From header.
///
/// Returns the domain part of the From header (e.g., "carebrain.co" from "melissanash@carebrain.co")
pub fn extract_sender_domain_from_path<P: AsRef<Path>>(path: P) -> Result<Option<String>> {
    let content = fs::read_to_string(&path)
        .map_err(|e| anyhow!("Failed to read {:?}: {e}", path.as_ref()))?;
    Ok(extract_sender_domain(&content))
}

/// Extract the sender domain from raw EML content.
pub fn extract_sender_domain(content: &str) -> Option<String> {
    // Get header block (stop at first blank line)
    let header_end = content.find("\n\n").unwrap_or(content.len());
    let headers_raw = &content[..header_end];

    // Unfold headers
    let unfolded = unfold_headers(headers_raw);

    // Look for From: header - try various patterns
    let from_patterns = [
        r"(?im)^\s*From:\s*.*?<([^@]+@([^>]+))>", // "Name <email@domain.com>"
        r"(?im)^\s*From:\s*([^@\s]+@([^\s]+))",   // "email@domain.com"
    ];

    for pattern in &from_patterns {
        if let Ok(re) = Regex::new(pattern) {
            if let Some(caps) = re.captures(&unfolded) {
                if let Some(domain_match) = caps.get(2) {
                    let domain = domain_match
                        .as_str()
                        .trim()
                        .trim_end_matches('>')
                        .to_lowercase();
                    // Basic validation - should contain at least one dot
                    if domain.contains('.') && !domain.is_empty() {
                        return Some(domain);
                    }
                }
            }
        }
    }

    None
}

/// Extract the originating public IPv4 address from an on-disk `.eml` file.
///
/// Returns an error if:
/// - The file cannot be read
/// - No public IPv4 address can be confidently determined
pub fn parse_eml_origin_ip_from_path<P: AsRef<Path>>(path: P) -> Result<Ipv4Addr> {
    let content = fs::read_to_string(&path)
        .map_err(|e| anyhow!("Failed to read {:?}: {e}", path.as_ref()))?;
    parse_eml_origin_ip(&content)
}

/// Extract the originating public IPv4 address from raw `.eml` content.
///
/// This function does not mutate input and performs a best-effort derivation.
/// It may return an error if no public IPv4 is found.
pub fn parse_eml_origin_ip(content: &str) -> Result<Ipv4Addr> {
    // 1. Raw header block (stop at first blank line).
    let header_end = content.find("\n\n").unwrap_or(content.len());
    let headers_raw = &content[..header_end];

    // 2. Unfold (RFC 5322: continuation lines start with WSP).
    let unfolded = unfold_headers(headers_raw);

    // Helper to validate public IP
    let is_public = |ip: Ipv4Addr| !is_private(ip) && !is_reserved(ip);

    // Priority 0: X-Mailgun-Sending-Ip
    if let Some(ip) = extract_first_ipv4(
        &unfolded,
        r"(?im)^\s*X-Mailgun-Sending-Ip:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})\s*$",
        &is_public,
    ) {
        eprintln!("Detected originating IP: {ip} (source: X-Mailgun-Sending-Ip)");
        return Ok(ip);
    }

    // Priority 1: X-Spam-source IP='x.x.x.x'
    if let Some(ip) = extract_first_ipv4(
        &unfolded,
        r"(?im)^\s*X-Spam-source:.*?IP='([0-9]{1,3}(?:\.[0-9]{1,3}){3})'",
        &is_public,
    ) {
        eprintln!("Detected originating IP: {ip} (source: X-Spam-source)");
        return Ok(ip);
    }

    // Priority 2: Authentication-Results / ARC-Authentication-Results smtp.remote-ip=
    if let Some(ip) = extract_first_ipv4(
        &unfolded,
        r"(?im)smtp\.remote-ip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        &is_public,
    ) {
        eprintln!("Detected originating IP: {ip} (source: Authentication-Results smtp.remote-ip)");
        return Ok(ip);
    }

    // Priority 3: Received-SPF client-ip=
    if let Some(ip) = extract_first_ipv4(
        &unfolded,
        r"(?im)^\s*Received-SPF:.*?client-ip=([0-9]{1,3}(?:\.[0-9]{1,3}){3})",
        &is_public,
    ) {
        eprintln!("Detected originating IP: {ip} (source: Received-SPF client-ip)");
        return Ok(ip);
    }

    // Priority 4: X-Originating-IP (sometimes in form: [x.x.x.x] or x.x.x.x)
    if let Some(ip) = find_x_originating_ip(&unfolded) {
        eprintln!("Detected originating IP: {ip} (source: X-Originating-IP)");
        return Ok(ip);
    }

    // Priority 5: Received headers parsing (fallback heuristic)
    let received_blocks = collect_received_headers(&unfolded);
    if received_blocks.is_empty() {
        bail!("No Received headers found and no higher-priority headers present.");
    }

    // Collect all public IPs in chronological order (top = most recent, bottom = earliest)
    let mut public_ips: Vec<Ipv4Addr> = Vec::new();
    for block in &received_blocks {
        for ip in extract_ipv4s(block) {
            if is_public(ip) {
                public_ips.push(ip);
            }
        }
    }

    if public_ips.is_empty() {
        bail!("No public IPv4 addresses discovered in Received chain.");
    }

    // Heuristic refinement:
    // Prefer an IP whose associated hostname (in same Received line) contains known outbound provider keywords.
    // This is intentionally lightweight; extend as needed.
    let provider_keywords = ["mailgun", "sendgrid", "amazonses", "sparkpost"];
    if let Some(provider_ip) = received_blocks
        .iter()
        .rev()
        .flat_map(|block| {
            let block_lc = block.to_ascii_lowercase();
            provider_keywords.iter().find_map(|kw| {
                if block_lc.contains(kw) {
                    extract_ipv4s(block).into_iter().find(|ip| is_public(*ip))
                } else {
                    None
                }
            })
        })
        .next()
    {
        eprintln!("Detected originating IP: {provider_ip} (source: Received provider heuristic)");
        return Ok(provider_ip);
    }

    // Otherwise choose earliest hop (last collected public IP).
    let chosen = *public_ips.last().unwrap();
    eprintln!("Detected originating IP: {chosen} (source: Received fallback earliest hop)");
    Ok(chosen)
}

/// Generic regex-based first public IPv4 extractor with validation predicate.
fn extract_first_ipv4(
    unfolded: &str,
    pattern: &str,
    public_pred: &impl Fn(Ipv4Addr) -> bool,
) -> Option<Ipv4Addr> {
    let re = Regex::new(pattern).ok()?;
    for caps in re.captures_iter(unfolded) {
        if let Some(mat) = caps.get(1) {
            if let Ok(ip) = mat.as_str().parse::<Ipv4Addr>() {
                if public_pred(ip) {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// Unfold headers: join continuation lines (those starting with space or tab)
/// into the previous line, separated by a single space.
fn unfold_headers(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for line in raw.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            out.push(' ');
            out.push_str(line.trim_start());
        } else {
            if !out.is_empty() {
                out.push('\n');
            }
            out.push_str(line.trim_end());
        }
    }
    out
}

/// Locate and parse an X-Originating-IP style header.
/// Common formats:
///   X-Originating-IP: [203.0.113.5]
///   X-Originating-IP: 203.0.113.5
fn find_x_originating_ip(headers_unfolded: &str) -> Option<Ipv4Addr> {
    let re = Regex::new(r"(?im)^\s*x-originating-ip:\s*\[?([0-9]{1,3}(?:\.[0-9]{1,3}){3})]?\s*$")
        .expect("valid regex");
    if let Some(caps) = re.captures(headers_unfolded) {
        let candidate = &caps[1];
        if let Ok(ip) = candidate.parse::<Ipv4Addr>() {
            if !is_private(ip) && !is_reserved(ip) {
                return Some(ip);
            }
        }
    }
    None
}

/// Collect all unfolded `Received:` headers as standalone strings.
/// We assume unfolded form (each header on one line).
fn collect_received_headers(unfolded: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in unfolded.lines() {
        if line.to_ascii_lowercase().starts_with("received:") {
            out.push(line.to_string());
        }
    }
    out
}

/// Extract all syntactically valid IPv4 addresses from a header line.
/// Performs basic octet range validation (0..=255).
fn extract_ipv4s(line: &str) -> Vec<Ipv4Addr> {
    // Match candidate IPv4 tokens
    let re = Regex::new(r"(?i)\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b")
        .expect("valid IPv4 extraction regex");
    let mut ips = Vec::new();
    for cap in re.captures_iter(line) {
        let s = &cap[1];
        if let Ok(ip) = parse_ipv4_strict(s) {
            ips.push(ip);
        }
    }
    ips
}

/// Strict IPv4 parser ensuring each octet <= 255 (std::net::Ipv4Addr allows this
/// inherently, but we double-check for clarity with manual parsing).
fn parse_ipv4_strict(s: &str) -> Result<Ipv4Addr> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 {
        bail!("invalid ipv4");
    }
    let mut octets = [0u8; 4];
    for (i, part) in parts.iter().enumerate() {
        let n = u16::from_str(part).map_err(|_| anyhow!("invalid octet"))?;
        if n > 255 {
            bail!("octet out of range");
        }
        octets[i] = n as u8;
    }
    Ok(Ipv4Addr::from(octets))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::netutil::{is_private, is_reserved};
    const SAMPLE: &str = "\
Return-Path: <sender@example.org>
Received: from mail.example.org (mail.example.org [8.8.8.8])
    by inbound.filter.local (Postfix) with ESMTPS id 12345
    for <user@local>; Tue, 17 Sep 2024 12:34:56 +0000 (UTC)
Received: from laptop (cpe-94-156-175-86.example.net [94.156.175.86])
    by mail.example.org (Postfix) with ESMTPSA id 77777
    for <user@local>; Tue, 17 Sep 2024 12:34:10 +0000 (UTC)
Subject: Test
X-Originating-IP: [94.156.175.86]

Body here
";
    #[test]
    fn test_unfold() {
        let raw = "Header: value\n  continuation\nAnother: x\n";
        let unfolded = unfold_headers(raw);
        assert!(unfolded.contains("Header: value continuation"));
        assert!(unfolded.contains("Another: x"));
    }

    #[test]
    fn test_parse_originating_ip_prefers_x_originating() {
        let ip = parse_eml_origin_ip(SAMPLE).unwrap();
        assert_eq!(ip, Ipv4Addr::new(94, 156, 175, 86));
    }

    #[test]
    fn test_received_only() {
        let alt = SAMPLE.replace("X-Originating-IP: [94.156.175.86]\n", "");
        let ip = parse_eml_origin_ip(&alt).unwrap();
        // earliest (bottom-most public) is 94.156.175.86
        assert_eq!(ip, Ipv4Addr::new(94, 156, 175, 86));
    }

    #[test]
    fn test_no_public_ip() {
        let sample = "\
Received: from internal (localhost [127.0.0.1]) by mx.local with ESMTP id 1;
Received: from internal2 (gateway [10.0.0.10]) by internal with ESMTP id 2;
";
        let res = parse_eml_origin_ip(sample);
        assert!(res.is_err(), "expected error, got {:?}", res);
    }

    #[test]
    fn test_private_and_reserved_checks() {
        assert!(is_private(Ipv4Addr::new(10, 0, 0, 1)));
        assert!(is_reserved(Ipv4Addr::new(127, 0, 0, 1)));
    }
}
