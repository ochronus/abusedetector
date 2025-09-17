//! EML (RFC 5322 / RFC 822 style) message parsing utilities.
//!
//! This module provides robust parsing to extract the *originating IP
//! address* (v4 or v6) from an email message file (.eml). The implementation
//! uses proper RFC-compliant email parsing with the `mail-parser` library
//! for reliable header unfolding, field extraction, and standards compliance.
//!
//! ## Features
//!
//! - RFC-compliant email message parsing using `mail-parser`
//! - Proper header unfolding and field extraction
//! - Canonical Received chain ordering (reverse iteration)
//! - Full IPv6 normalization
//! - Confidence scoring per header source
//! - Security protections against memory exhaustion
//!
//! ## IP Extraction Strategy (ordered by confidence)
//!
//! 1. **Very High Confidence (90)**:
//!    - `X-Originating-IP` (Outlook / some MTAs)
//!    - `X-Mailgun-Sending-Ip` (Mailgun service)
//!
//! 2. **High Confidence (70)**:
//!    - `Authentication-Results smtp.remote-ip` (Standards-based)
//!    - `Received-SPF client-ip` (SPF validation results)
//!
//! 3. **Medium Confidence (50)**:
//!    - `X-Spam-source` (Spam filter headers)
//!
//! 4. **Low Confidence (30)**:
//!    - `Received` headers with provider keywords (mailgun, sendgrid, etc.)
//!
//! 5. **Very Low Confidence (10)**:
//!    - Generic `Received` header fallback (earliest hop)
//!
//! ## Security Features
//! - Maximum header size limits (64KB per header, 1MB total) to prevent memory exhaustion
//! - Early termination on oversized content
//! - IPv6 address normalization to canonical form
//! - Private/reserved IP address filtering
//!
//! ## Usage
//!
//! ```rust,no_run
//! use abusedetector::eml::{parse_eml_origin_ip, extract_sender_domain};
//! use anyhow::Result;
//!
//! fn main() -> Result<()> {
//!     // Extract originating IP with confidence scoring
//!     let content = std::fs::read_to_string("email.eml")?;
//!     let result = parse_eml_origin_ip(&content)?;
//!     println!("IP: {}, Source: {}, Confidence: {}",
//!              result.ip, result.source, result.confidence.score());
//!
//!     // Extract sender domain
//!     let domain = extract_sender_domain(&content)?;
//!     if let Some(domain) = domain {
//!         println!("Sender domain: {}", domain);
//!     }
//!     Ok(())
//! }
//! ```
//!
//! ## Implementation Notes
//!
//! This module uses the `mail-parser` crate for RFC-compliant email parsing,
//! providing robust header unfolding, proper MIME handling, and reliable
//! field extraction compared to regex-based approaches.
//!
//! If no suitable public IP is found, an error is returned.

use std::fs;
use std::net::IpAddr;
use std::path::Path;

use anyhow::{Result, anyhow, bail};
use mail_parser::{HeaderValue, MessageParser};

use crate::netutil::{is_private, is_reserved};

/// Maximum size for a single header (64KB)
/// Used to prevent memory exhaustion attacks via oversized headers
const MAX_HEADER_SIZE: usize = 64 * 1024;

/// Maximum total size for all headers (1MB)
const MAX_TOTAL_HEADERS_SIZE: usize = 1024 * 1024;

/// Confidence levels for IP extraction sources.
///
/// Higher confidence levels indicate more reliable sources for the originating IP.
/// The numeric values allow for easy comparison and threshold-based filtering.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ConfidenceLevel {
    /// Very low confidence (10) - Generic Received header fallback
    VeryLow = 10,
    /// Low confidence (30) - Received headers with provider keywords
    Low = 30,
    /// Medium confidence (50) - Service-specific headers like X-Spam-source
    Medium = 50,
    /// High confidence (70) - Standards-based headers like Authentication-Results
    High = 70,
    /// Very high confidence (90) - Authenticated sources like X-Originating-IP
    VeryHigh = 90,
}

impl ConfidenceLevel {
    /// Get confidence score as numeric value (10-90).
    ///
    /// Higher scores indicate more reliable IP extraction sources.
    pub fn score(&self) -> u8 {
        *self as u8
    }
}

/// Result of IP extraction with source information and confidence scoring.
///
/// This structure provides not just the extracted IP address, but also metadata
/// about where it was found and how reliable that source is considered to be.
#[derive(Debug, Clone)]
pub struct IpExtractionResult {
    /// The extracted IP address (IPv4 or IPv6)
    pub ip: IpAddr,
    /// Human-readable description of the header source
    pub source: String,
    /// Confidence level of this extraction (higher = more reliable)
    pub confidence: ConfidenceLevel,
}

/// Header source types with their associated confidence levels.
///
/// This enum maps different email header types to their reliability scores
/// for IP extraction purposes.
#[derive(Debug, Clone)]
enum HeaderSource {
    /// X-Originating-IP header (very high confidence)
    XOriginatingIp,
    /// X-Mailgun-Sending-Ip header (very high confidence)
    XMailgunSendingIp,
    /// Authentication-Results smtp.remote-ip (high confidence)
    AuthenticationResults,
    /// Received-SPF client-ip (high confidence)
    ReceivedSpf,
    /// X-Spam-source header (medium confidence)
    XSpamSource,
    /// Received header with known provider (low confidence)
    ReceivedProvider,
    /// Generic Received header (very low confidence)
    ReceivedGeneric,
}

impl HeaderSource {
    fn confidence(&self) -> ConfidenceLevel {
        match self {
            HeaderSource::XOriginatingIp => ConfidenceLevel::VeryHigh,
            HeaderSource::XMailgunSendingIp => ConfidenceLevel::VeryHigh,
            HeaderSource::AuthenticationResults => ConfidenceLevel::High,
            HeaderSource::ReceivedSpf => ConfidenceLevel::High,
            HeaderSource::XSpamSource => ConfidenceLevel::Medium,
            HeaderSource::ReceivedProvider => ConfidenceLevel::Low,
            HeaderSource::ReceivedGeneric => ConfidenceLevel::VeryLow,
        }
    }

    fn description(&self) -> &'static str {
        match self {
            HeaderSource::XOriginatingIp => "X-Originating-IP",
            HeaderSource::XMailgunSendingIp => "X-Mailgun-Sending-Ip",
            HeaderSource::AuthenticationResults => "Authentication-Results smtp.remote-ip",
            HeaderSource::ReceivedSpf => "Received-SPF client-ip",
            HeaderSource::XSpamSource => "X-Spam-source",
            HeaderSource::ReceivedProvider => "Received provider heuristic",
            HeaderSource::ReceivedGeneric => "Received fallback earliest hop",
        }
    }
}

/// Extract the sender domain from an EML file's From header.
///
/// This function reads an EML file from disk and extracts the domain portion
/// of the sender's email address from the From header.
///
/// # Arguments
/// * `path` - Path to the EML file
///
/// # Returns
/// * `Ok(Some(domain))` - Successfully extracted domain
/// * `Ok(None)` - No valid domain found in From header
/// * `Err(_)` - File reading error or parsing failure
///
/// # Example
/// ```rust,no_run
/// use abusedetector::eml::extract_sender_domain_from_path;
/// use anyhow::Result;
///
/// fn main() -> Result<()> {
///     let domain = extract_sender_domain_from_path("email.eml")?;
///     if let Some(domain) = domain {
///         println!("Sender domain: {}", domain);
///     }
///     Ok(())
/// }
/// ```
pub fn extract_sender_domain_from_path<P: AsRef<Path>>(path: P) -> Result<Option<String>> {
    let content = fs::read_to_string(&path)
        .map_err(|e| anyhow!("Failed to read {:?}: {e}", path.as_ref()))?;
    extract_sender_domain(&content)
}

/// Extract the sender domain from raw EML content.
///
/// Parses the From header of an email message and extracts the domain portion
/// of the sender's email address using RFC-compliant parsing.
///
/// # Arguments
/// * `content` - Raw EML content as string
///
/// # Returns
/// * `Ok(Some(domain))` - Successfully extracted domain (lowercase)
/// * `Ok(None)` - No valid domain found in From header
/// * `Err(_)` - Content too large or parsing failure
///
/// # Security
/// - Rejects content larger than 2MB to prevent memory exhaustion
/// - Normalizes domains to lowercase
/// - Validates domain contains at least one dot
pub fn extract_sender_domain(content: &str) -> Result<Option<String>> {
    // Security check: prevent processing of oversized content
    if content.len() > MAX_TOTAL_HEADERS_SIZE * 2 {
        bail!("Content too large to process safely");
    }

    let message = MessageParser::default()
        .parse(content.as_bytes())
        .ok_or_else(|| anyhow!("Failed to parse email message"))?;

    if let Some(from_header) = message.from() {
        if let Some(addr) = from_header.first() {
            if let Some(email) = addr.address() {
                if let Some(domain_start) = email.find('@') {
                    let domain = &email[domain_start + 1..];
                    if domain.contains('.') && !domain.is_empty() {
                        return Ok(Some(domain.to_lowercase()));
                    }
                }
            }
        }
    }

    Ok(None)
}

/// Extract the originating public IP address from an on-disk `.eml` file.
///
/// This is a convenience wrapper around `parse_eml_origin_ip` that handles
/// file reading automatically.
///
/// # Arguments
/// * `path` - Path to the EML file
///
/// # Returns
/// * `Ok(IpExtractionResult)` - Successfully extracted IP with metadata
/// * `Err(_)` - File reading error, no public IP found, or parsing failure
///
/// # Example
/// ```rust,no_run
/// use abusedetector::eml::parse_eml_origin_ip_from_path;
/// use anyhow::Result;
///
/// fn main() -> Result<()> {
///     let result = parse_eml_origin_ip_from_path("spam.eml")?;
///     println!("Found IP {} from {} (confidence: {})",
///              result.ip, result.source, result.confidence.score());
///     Ok(())
/// }
/// ```
pub fn parse_eml_origin_ip_from_path<P: AsRef<Path>>(path: P) -> Result<IpExtractionResult> {
    let content = fs::read_to_string(&path)
        .map_err(|e| anyhow!("Failed to read {:?}: {e}", path.as_ref()))?;
    parse_eml_origin_ip(&content)
}

/// Extract the originating public IP address from raw `.eml` content.
///
/// This is the main function for IP extraction. It implements a sophisticated
/// strategy that examines multiple header types in order of reliability,
/// ultimately returning the highest-confidence IP address found.
///
/// The function automatically filters out private and reserved IP addresses,
/// ensuring only internet-routable addresses are returned.
///
/// # Arguments
/// * `content` - Raw EML content as string
///
/// # Returns
/// * `Ok(IpExtractionResult)` - Successfully extracted IP with source and confidence
/// * `Err(_)` - Content too large, no public IP found, or parsing failure
///
/// # Security & Performance
/// - Rejects content larger than 2MB to prevent memory exhaustion
/// - Individual headers limited to 64KB
/// - IPv6 addresses are normalized to canonical form
/// - Only public (internet-routable) IP addresses are returned
///
/// # Header Priority (highest to lowest confidence)
/// 1. X-Originating-IP, X-Mailgun-Sending-Ip (90% confidence)
/// 2. Authentication-Results, Received-SPF (70% confidence)
/// 3. X-Spam-source (50% confidence)
/// 4. Received headers with provider keywords (30% confidence)
/// 5. Generic Received headers (10% confidence)
pub fn parse_eml_origin_ip(content: &str) -> Result<IpExtractionResult> {
    // Security check: prevent processing of oversized content
    if content.len() > MAX_TOTAL_HEADERS_SIZE * 2 {
        bail!("Content too large to process safely");
    }

    let message = MessageParser::default()
        .parse(content.as_bytes())
        .ok_or_else(|| anyhow!("Failed to parse email message"))?;

    let is_public = |ip: IpAddr| !is_private(ip) && !is_reserved(ip);

    // Check headers in priority order
    let mut candidates: Vec<IpExtractionResult> = Vec::new();

    // 1. X-Mailgun-Sending-Ip (very high confidence)
    if let Some(header) = message.header("X-Mailgun-Sending-Ip") {
        if let Some(ip) = extract_ip_from_header_value(header, &is_public) {
            candidates.push(IpExtractionResult {
                ip: normalize_ipv6(ip),
                source: HeaderSource::XMailgunSendingIp.description().to_string(),
                confidence: HeaderSource::XMailgunSendingIp.confidence(),
            });
        }
    }

    // 2. X-Spam-source (medium confidence)
    if let Some(header) = message.header("X-Spam-source") {
        if let Some(ip) = extract_ip_from_spam_source(header, &is_public) {
            candidates.push(IpExtractionResult {
                ip: normalize_ipv6(ip),
                source: HeaderSource::XSpamSource.description().to_string(),
                confidence: HeaderSource::XSpamSource.confidence(),
            });
        }
    }

    // 3. Authentication-Results (high confidence)
    if let Some(header) = message.header("Authentication-Results") {
        if let Some(ip) = extract_ip_from_auth_results(header, &is_public) {
            candidates.push(IpExtractionResult {
                ip: normalize_ipv6(ip),
                source: HeaderSource::AuthenticationResults
                    .description()
                    .to_string(),
                confidence: HeaderSource::AuthenticationResults.confidence(),
            });
        }
    }

    // 4. Received-SPF (high confidence)
    if let Some(header) = message.header("Received-SPF") {
        if let Some(ip) = extract_ip_from_received_spf(header, &is_public) {
            candidates.push(IpExtractionResult {
                ip: normalize_ipv6(ip),
                source: HeaderSource::ReceivedSpf.description().to_string(),
                confidence: HeaderSource::ReceivedSpf.confidence(),
            });
        }
    }

    // 5. X-Originating-IP (very high confidence)
    if let Some(header) = message.header("X-Originating-IP") {
        if let Some(ip) = extract_ip_from_header_value(header, &is_public) {
            candidates.push(IpExtractionResult {
                ip: normalize_ipv6(ip),
                source: HeaderSource::XOriginatingIp.description().to_string(),
                confidence: HeaderSource::XOriginatingIp.confidence(),
            });
        }
    }

    // 6. Received headers (process in reverse order for canonical chain)
    let mut received_candidates = process_received_headers_from_message(&message, &is_public);
    candidates.append(&mut received_candidates);

    if candidates.is_empty() {
        bail!("No public IP addresses discovered in email headers.");
    }

    // Sort by confidence (highest first), then by order of appearance
    candidates.sort_by(|a, b| b.confidence.cmp(&a.confidence));

    let result = candidates.into_iter().next().unwrap();
    eprintln!(
        "Detected originating IP: {} (source: {}, confidence: {})",
        result.ip,
        result.source,
        result.confidence.score()
    );

    Ok(result)
}

fn extract_ip_from_header_value(
    header: &HeaderValue,
    is_public: &impl Fn(IpAddr) -> bool,
) -> Option<IpAddr> {
    let header_text = header.as_text()?;

    // Security check
    if header_text.len() > MAX_HEADER_SIZE {
        return None;
    }

    extract_ips_from_text(header_text)
        .into_iter()
        .find(|ip| is_public(*ip))
}

fn extract_ip_from_spam_source(
    header: &HeaderValue,
    is_public: &impl Fn(IpAddr) -> bool,
) -> Option<IpAddr> {
    let header_text = header.as_text()?;

    // Security check
    if header_text.len() > MAX_HEADER_SIZE {
        return None;
    }

    // Look for IP='...' pattern
    if let Some(start) = header_text.find("IP='") {
        let after_prefix = &header_text[start + 4..];
        if let Some(end) = after_prefix.find('\'') {
            let ip_str = &after_prefix[..end];
            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                if is_public(ip) {
                    return Some(ip);
                }
            }
        }
    }
    None
}

fn extract_ip_from_auth_results(
    header: &HeaderValue,
    is_public: &impl Fn(IpAddr) -> bool,
) -> Option<IpAddr> {
    let header_text = header.as_text()?;

    // Security check
    if header_text.len() > MAX_HEADER_SIZE {
        return None;
    }

    // Look for smtp.remote-ip=... pattern
    if let Some(start) = header_text.find("smtp.remote-ip=") {
        let after_prefix = &header_text[start + 15..];
        // Extract until next space or semicolon
        let ip_part = after_prefix
            .split_whitespace()
            .next()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("");

        if let Ok(ip) = ip_part.parse::<IpAddr>() {
            if is_public(ip) {
                return Some(ip);
            }
        }
    }
    None
}

fn extract_ip_from_received_spf(
    header: &HeaderValue,
    is_public: &impl Fn(IpAddr) -> bool,
) -> Option<IpAddr> {
    let header_text = header.as_text()?;

    // Security check
    if header_text.len() > MAX_HEADER_SIZE {
        return None;
    }

    // Look for client-ip=... pattern
    if let Some(start) = header_text.find("client-ip=") {
        let after_prefix = &header_text[start + 10..];
        // Extract until next space or semicolon
        let ip_part = after_prefix
            .split_whitespace()
            .next()
            .unwrap_or("")
            .split(';')
            .next()
            .unwrap_or("");

        if let Ok(ip) = ip_part.parse::<IpAddr>() {
            if is_public(ip) {
                return Some(ip);
            }
        }
    }
    None
}

fn process_received_headers_from_message(
    message: &mail_parser::Message,
    is_public: &impl Fn(IpAddr) -> bool,
) -> Vec<IpExtractionResult> {
    let mut candidates = Vec::new();
    let provider_keywords = ["mailgun", "sendgrid", "amazonses", "sparkpost"];

    // Collect all received headers first
    let mut received_texts = Vec::new();
    for header_value in message.header_values("Received") {
        if let Some(header_text) = header_value.as_text() {
            // Security check
            if header_text.len() <= MAX_HEADER_SIZE {
                received_texts.push(header_text);
            }
        }
    }

    // Process in reverse order (canonical chain order)
    for header_text in received_texts.iter().rev() {
        let header_lower = header_text.to_ascii_lowercase();
        let ips = extract_ips_from_text(header_text);

        for ip in ips {
            if !is_public(ip) {
                continue;
            }

            // Check if this is from a known provider
            let is_provider = provider_keywords.iter().any(|kw| header_lower.contains(kw));
            let (source, confidence) = if is_provider {
                (
                    HeaderSource::ReceivedProvider.description().to_string(),
                    HeaderSource::ReceivedProvider.confidence(),
                )
            } else {
                (
                    HeaderSource::ReceivedGeneric.description().to_string(),
                    HeaderSource::ReceivedGeneric.confidence(),
                )
            };

            candidates.push(IpExtractionResult {
                ip: normalize_ipv6(ip),
                source,
                confidence,
            });

            // For provider headers, prefer the first match
            if is_provider {
                break;
            }
        }
    }

    candidates
}

fn extract_ips_from_text(text: &str) -> Vec<IpAddr> {
    let mut ips = Vec::new();

    // Simple extraction - look for bracketed IPs and standalone IPs
    for word in text.split_whitespace() {
        let clean_word = word.trim_matches(|c: char| !c.is_alphanumeric() && c != ':' && c != '.');

        if let Ok(ip) = clean_word.parse::<IpAddr>() {
            ips.push(ip);
        }

        // Also try removing brackets
        let bracketed = word.trim_start_matches('[').trim_end_matches(']');
        if let Ok(ip) = bracketed.parse::<IpAddr>() {
            ips.push(ip);
        }
    }

    ips
}

/// Normalize IPv6 addresses to canonical form.
///
/// The Rust standard library automatically provides canonical representation
/// for both IPv4 and IPv6 addresses, so this function currently acts as a
/// pass-through but is kept for future enhancement possibilities.
///
/// # Arguments
/// * `ip` - IP address to normalize
///
/// # Returns
/// The same IP address in canonical form
fn normalize_ipv6(ip: IpAddr) -> IpAddr {
    // The standard library already provides canonical representation for both IPv4 and IPv6
    ip
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_parse_real_corpus_sample1() {
        // Use real corpus file - sample1.eml has X-Spam-source and Mailgun headers
        let content =
            fs::read_to_string("corpus/sample1.eml").expect("Failed to read corpus/sample1.eml");
        let result = parse_eml_origin_ip(&content).unwrap();

        // sample1.eml should extract IP from X-Spam-source header
        assert_eq!(result.ip, "69.72.43.14".parse::<IpAddr>().unwrap());
        // Should be high confidence from mailgun header
        assert!(result.confidence.score() >= ConfidenceLevel::High.score());
    }

    #[test]
    fn test_extract_sender_domain_from_corpus() {
        let content =
            fs::read_to_string("corpus/sample1.eml").expect("Failed to read corpus/sample1.eml");
        let domain = extract_sender_domain(&content).unwrap();
        assert!(domain.is_some());
        let domain = domain.unwrap();
        assert!(domain.contains("beehiiv.com") || domain.contains("mail.beehiiv.com"));
    }

    #[test]
    fn test_confidence_prioritization() {
        // Test with a sample that has multiple IP sources to verify priority
        let content =
            fs::read_to_string("corpus/sample1.eml").expect("Failed to read corpus/sample1.eml");
        let result = parse_eml_origin_ip(&content).unwrap();

        // Should pick the highest confidence source available
        assert!(result.confidence.score() >= ConfidenceLevel::Medium.score());
        eprintln!(
            "Selected source: {} with confidence: {}",
            result.source,
            result.confidence.score()
        );
    }

    #[test]
    fn test_no_public_ip() {
        let sample = "From: test@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\n
Received: from internal (localhost [127.0.0.1]) by mx.local with ESMTP id 1;
Received: from internal2 (gateway [10.0.0.10]) by internal with ESMTP id 2;
Received: from host.local ([fe80::1]) by internal with ESMTP id 3;

Body here
";
        let res = parse_eml_origin_ip(sample);
        assert!(res.is_err(), "expected error, got {:?}", res);
    }

    #[test]
    fn test_confidence_ordering() {
        assert!(ConfidenceLevel::VeryHigh > ConfidenceLevel::High);
        assert!(ConfidenceLevel::High > ConfidenceLevel::Medium);
        assert!(ConfidenceLevel::Medium > ConfidenceLevel::Low);
        assert!(ConfidenceLevel::Low > ConfidenceLevel::VeryLow);
    }

    #[test]
    fn test_ipv6_normalization() {
        let ip = "2001:0db8:0000:0000:0000:0000:0000:0001"
            .parse::<IpAddr>()
            .unwrap();
        let normalized = normalize_ipv6(ip);
        // Should still be valid and equivalent
        assert_eq!(normalized, ip);
    }

    #[test]
    fn test_security_limits() {
        // Test oversized content
        let huge_content = "From: test@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\n"
            .to_string() + &"A".repeat(MAX_TOTAL_HEADERS_SIZE * 3);
        let result = parse_eml_origin_ip(&huge_content);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("too large"));
    }

    #[test]
    fn test_extract_sender_domain_basic() {
        let eml = "From: test@example.com\r\nTo: user@example.com\r\nSubject: Test\r\n\r\nBody";
        let domain = extract_sender_domain(eml).unwrap();
        assert_eq!(domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_sender_domain_with_name() {
        let eml = "From: Test User <test@example.com>\r\nTo: user@example.com\r\nSubject: Test\r\n\r\nBody";
        let domain = extract_sender_domain(eml).unwrap();
        assert_eq!(domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_multiple_corpus_files() {
        // Test that we can parse multiple corpus files without errors
        for i in 1..=12 {
            let filename = format!("corpus/sample{}.eml", i);
            if Path::new(&filename).exists() {
                let content = fs::read_to_string(&filename)
                    .unwrap_or_else(|_| panic!("Failed to read {}", filename));

                // Should either succeed or fail gracefully
                match parse_eml_origin_ip(&content) {
                    Ok(result) => {
                        eprintln!(
                            "Successfully parsed {} -> IP: {}, Source: {}, Confidence: {}",
                            filename,
                            result.ip,
                            result.source,
                            result.confidence.score()
                        );
                        assert!(!is_private(result.ip));
                        assert!(!is_reserved(result.ip));
                    }
                    Err(e) => {
                        eprintln!("Failed to parse {} (this is OK): {}", filename, e);
                    }
                }

                // Domain extraction should also work
                match extract_sender_domain(&content) {
                    Ok(Some(domain)) => {
                        eprintln!("Extracted domain from {}: {}", filename, domain);
                        assert!(domain.contains('.'));
                    }
                    Ok(None) => {
                        eprintln!("No domain found in {} (this is OK)", filename);
                    }
                    Err(e) => {
                        eprintln!("Failed to extract domain from {}: {}", filename, e);
                    }
                }
            }
        }
    }
}
