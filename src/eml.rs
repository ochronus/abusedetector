//! EML (RFC 5322 / RFC 822 style) message parsing utilities.
//!
//! This module provides a lightweight parser to extract the *originating IP
//! address* (v4 or v6) from an email message file (.eml). We intentionally avoid
//! adding heavyweight MIME / message parsing dependencies and rely on a pragmatic
//! heuristic approach suitable for abuse reporting workflows.
//!
//! Strategy (ordered):
//! 1. Look for an `X-Originating-IP:` style header (Outlook / some MTAs).
//! 2. Collect all `Received:` headers, unfold continuations, and parse IP
//!    addresses in each. We ignore private / reserved ranges.
//! 3. Return the *earliest* public IP (i.e., the one from the **bottom-most**
//!    `Received` header containing a public IP), falling back to the first public
//!    one encountered if ordering is ambiguous.
//!
//! Limitations:
//! - Does not validate SPF, DKIM, or ARC chains.
//! - Assumes the file uses UTF-8 or ASCII superset encoding.
//!
//! If no suitable public IP is found, an error is returned.

use std::fs;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{anyhow, bail, Result};
use regex::Regex;

use crate::netutil::{is_private, is_reserved};

/// A regex to find IPv4 or IPv6 addresses. This is a pragmatic choice and may
/// not cover all edge cases of IPv6 representation, but is good enough for this
/// tool's purpose.
const IP_REGEX: &str = r"\b((?:[0-9]{1,3}(?:\.[0-9]{1,3}){3})|(?:[a-f0-9:]+:+[a-f0-9:.]+))\b";

/// Result of IP extraction with source information
#[derive(Debug, Clone)]
pub struct IpExtractionResult {
    pub ip: IpAddr,
    #[allow(dead_code)]
    pub source: String,
}

/// Extract the sender domain from an EML file's From header.
pub fn extract_sender_domain_from_path<P: AsRef<Path>>(path: P) -> Result<Option<String>> {
    let content = fs::read_to_string(&path)
        .map_err(|e| anyhow!("Failed to read {:?}: {e}", path.as_ref()))?;
    Ok(extract_sender_domain(&content))
}

/// Extract the sender domain from raw EML content.
pub fn extract_sender_domain(content: &str) -> Option<String> {
    let header_end = content.find("\n\n").unwrap_or(content.len());
    let headers_raw = &content[..header_end];
    let unfolded = unfold_headers(headers_raw);

    let from_patterns = [
        r"(?im)^\s*From:\s*.*?<([^@]+@([^>]+))>",
        r"(?im)^\s*From:\s*([^@\s]+@([^\s]+))",
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
                    if domain.contains('.') && !domain.is_empty() {
                        return Some(domain);
                    }
                }
            }
        }
    }
    None
}

/// Extract the originating public IP address from an on-disk `.eml` file.
pub fn parse_eml_origin_ip_from_path<P: AsRef<Path>>(path: P) -> Result<IpExtractionResult> {
    let content = fs::read_to_string(&path)
        .map_err(|e| anyhow!("Failed to read {:?}: {e}", path.as_ref()))?;
    parse_eml_origin_ip(&content)
}

/// Extract the originating public IP address from raw `.eml` content.
pub fn parse_eml_origin_ip(content: &str) -> Result<IpExtractionResult> {
    let header_end = content.find("\n\n").unwrap_or(content.len());
    let headers_raw = &content[..header_end];
    let unfolded = unfold_headers(headers_raw);

    let is_public = |ip: IpAddr| !is_private(ip) && !is_reserved(ip);

    let ip_patterns = [
        (
            "X-Mailgun-Sending-Ip",
            r"(?im)^\s*X-Mailgun-Sending-Ip:\s*([a-f0-9:.]+|[0-9.]{7,15})\s*$",
        ),
        (
            "X-Spam-source",
            r"(?im)^\s*X-Spam-source:.*?IP='([a-f0-9:.]+|[0-9.]{7,15})'",
        ),
        (
            "Authentication-Results smtp.remote-ip",
            r"(?im)smtp\.remote-ip=([a-f0-9:.]+|[0-9.]{7,15})",
        ),
        (
            "Received-SPF client-ip",
            r"(?im)^\s*Received-SPF:.*?client-ip=([a-f0-9:.]+|[0-9.]{7,15})",
        ),
    ];

    for (source, pattern) in &ip_patterns {
        if let Some(ip) = extract_first_ip(&unfolded, pattern, &is_public) {
            eprintln!("Detected originating IP: {ip} (source: {source})");
            return Ok(IpExtractionResult {
                ip,
                source: source.to_string(),
            });
        }
    }

    if let Some(ip) = find_x_originating_ip(&unfolded, &is_public) {
        let source = "X-Originating-IP".to_string();
        eprintln!("Detected originating IP: {ip} (source: {source})");
        return Ok(IpExtractionResult { ip, source });
    }

    let received_blocks = collect_received_headers(&unfolded);
    if received_blocks.is_empty() {
        bail!("No Received headers found and no higher-priority headers present.");
    }

    let mut public_ips: Vec<IpAddr> = Vec::new();
    for block in &received_blocks {
        for ip in extract_ips(block) {
            if is_public(ip) {
                public_ips.push(ip);
            }
        }
    }

    if public_ips.is_empty() {
        bail!("No public IP addresses discovered in Received chain.");
    }

    let provider_keywords = ["mailgun", "sendgrid", "amazonses", "sparkpost"];
    if let Some(provider_ip) = received_blocks
        .iter()
        .rev()
        .flat_map(|block| {
            let block_lc = block.to_ascii_lowercase();
            provider_keywords.iter().find_map(|kw| {
                if block_lc.contains(kw) {
                    extract_ips(block).into_iter().find(|ip| is_public(*ip))
                } else {
                    None
                }
            })
        })
        .next()
    {
        let source = "Received provider heuristic".to_string();
        eprintln!("Detected originating IP: {provider_ip} (source: {source})");
        return Ok(IpExtractionResult {
            ip: provider_ip,
            source,
        });
    }

    let chosen = *public_ips.last().unwrap();
    let source = "Received fallback earliest hop".to_string();
    eprintln!("Detected originating IP: {chosen} (source: {source})");
    Ok(IpExtractionResult { ip: chosen, source })
}

/// Generic regex-based first public IP extractor.
fn extract_first_ip(
    unfolded: &str,
    pattern: &str,
    public_pred: &impl Fn(IpAddr) -> bool,
) -> Option<IpAddr> {
    let re = Regex::new(pattern).ok()?;
    for caps in re.captures_iter(unfolded) {
        if let Some(mat) = caps.get(1) {
            if let Ok(ip) = mat.as_str().parse::<IpAddr>() {
                if public_pred(ip) {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// Unfold headers: join continuation lines.
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

/// Locate and parse an X-Originating-IP style header for IPv4 or IPv6.
fn find_x_originating_ip(
    headers_unfolded: &str,
    public_pred: &impl Fn(IpAddr) -> bool,
) -> Option<IpAddr> {
    let re = Regex::new(&format!(
        r"(?im)^\s*x-originating-ip:\s*\[?({})\]?$",
        IP_REGEX
    ))
    .expect("valid regex");
    if let Some(caps) = re.captures(headers_unfolded) {
        if let Some(candidate) = caps.get(1) {
            if let Ok(ip) = candidate.as_str().parse::<IpAddr>() {
                if public_pred(ip) {
                    return Some(ip);
                }
            }
        }
    }
    None
}

/// Collect all unfolded `Received:` headers.
fn collect_received_headers(unfolded: &str) -> Vec<String> {
    unfolded
        .lines()
        .filter(|line| line.to_ascii_lowercase().starts_with("received:"))
        .map(|s| s.to_string())
        .collect()
}

/// Extract all syntactically valid IP addresses from a header line.
fn extract_ips(line: &str) -> Vec<IpAddr> {
    let re = Regex::new(IP_REGEX).expect("valid IP extraction regex");
    let mut ips = Vec::new();
    for cap in re.captures_iter(line) {
        if let Some(s_match) = cap.get(1) {
            let s = s_match.as_str();
            if let Ok(ip) = s.parse::<IpAddr>() {
                ips.push(ip);
            }
        }
    }
    ips
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    const SAMPLE_IPV4: &str = "
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

    const SAMPLE_IPV6: &str = "
Received: from mail-eopbgr6500.outbound.protection.outlook.com (mail-eopbgr6500.outbound.protection.outlook.com [2a01:111:e400:6500::4a])
    by inbound.filter.local (Postfix) with ESMTPS id 12345
    for <user@local>; Tue, 17 Sep 2024 12:34:56 +0000 (UTC)
Received: from User-PC ([2001:db8::1])
    by mail.example.org (Postfix) with ESMTPSA id 77777
    for <user@local>; Tue, 17 Sep 2024 12:34:10 +0000 (UTC)
Subject: Test IPv6
";

    #[test]
    fn test_unfold() {
        let raw = "Header: value
  continuation
Another: x
";
        let unfolded = unfold_headers(raw);
        assert!(unfolded.contains("Header: value continuation"));
        assert!(unfolded.contains("Another: x"));
    }

    #[test]
    fn test_parse_originating_ip_prefers_x_originating_ipv4() {
        let ip = parse_eml_origin_ip(SAMPLE_IPV4).unwrap();
        assert_eq!(ip.ip, IpAddr::V4(Ipv4Addr::new(94, 156, 175, 86)));
    }

    #[test]
    fn test_received_only_ipv4() {
        let alt = SAMPLE_IPV4.replace("X-Originating-IP: [94.156.175.86]\n", "");
        let ip = parse_eml_origin_ip(&alt).unwrap();
        assert_eq!(ip.ip, IpAddr::V4(Ipv4Addr::new(94, 156, 175, 86)));
    }

    #[test]
    fn test_received_only_ipv6() {
        let ip = parse_eml_origin_ip(SAMPLE_IPV6).unwrap();
        // We select the earliest (bottom-most) public IPv6 hop in the Received chain.
        assert_eq!(ip.ip, "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn test_no_public_ip() {
        let sample = "
Received: from internal (localhost [127.0.0.1]) by mx.local with ESMTP id 1;
Received: from internal2 (gateway [10.0.0.10]) by internal with ESMTP id 2;
Received: from host.local ([fe80::1]) by internal with ESMTP id 3;
";
        let res = parse_eml_origin_ip(sample);
        assert!(res.is_err(), "expected error, got {:?}", res);
    }
}
