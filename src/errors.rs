//! Unified error handling (Improvement Plan – Section 2)
//!
//! This module refactors the previous ad‑hoc / manual error enum into a
//! `thiserror`-based model with:
//!   * Typed variants for common failure domains
//!   * A categorization layer (`ErrorCategory`) for analytics & reporting
//!   * Helper constructors
//!   * `From` conversions for common lower-level errors
//!   * Timeout + WHOIS unavailability distinctions
//!
//! Design goals:
//!   * Keep end-user messages clear & actionable
//!   * Avoid leaking internal implementation details
//!   * Enable structured output to classify errors deterministically
//!
//! Usage:
//!   use abusedetector::errors::{Result, AbuseDetectorError, ErrorCategory};
//!
//!   fn do_something() -> Result<()> {
//!       Err(AbuseDetectorError::Configuration { message: "invalid mode".into() })
//!   }
//!
//! Categories are intentionally coarse to support metrics dashboards:
//!   - Input: User / data validation issues
//!   - Network: Transient or remote-service problems
//!   - Parse: Syntax / data-format decoding issues
//!   - Internal: Logic bugs or unexpected states
//!
//! NOTE: Variants that wrap external errors retain sources to preserve backtraces
//!       (when RUST_BACKTRACE=1).
//!
//! Future extensions:
//!   * Attach retry hints
//!   * Map categories to exit codes
//!   * Serialize into structured output (JSON schema)
//!

use std::io;
use std::net::AddrParseError;

use thiserror::Error;

/// High-level classification for metrics / structured reporting.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCategory {
    Input,
    Network,
    Parse,
    Internal,
}

impl std::fmt::Display for ErrorCategory {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            ErrorCategory::Input => "input",
            ErrorCategory::Network => "network",
            ErrorCategory::Parse => "parse",
            ErrorCategory::Internal => "internal",
        };
        f.write_str(s)
    }
}

/// Primary application error type.
#[derive(Error, Debug)]
pub enum AbuseDetectorError {
    // ------------------------ Input / Validation ----------------------------
    #[error("Invalid IP address format: {ip}")]
    InvalidIpAddress { ip: String },

    #[error("{ip} is a private (RFC1918) IP address")]
    PrivateIpAddress { ip: String },

    #[error("{ip} is a reserved IP address")]
    ReservedIpAddress { ip: String },

    #[error("No public IPv4 addresses found in EML file: {file_path}")]
    NoPublicIpInEml { file_path: String },

    #[error("Failed to extract sender domain from EML file {file_path}: {reason}")]
    DomainExtractionFailed { file_path: String, reason: String },

    #[error("Unsupported or unknown content encoding: {details}")]
    UnsupportedContentEncoding { details: String },

    #[error("No abuse contacts discovered for target: {target}")]
    NoAbuseContacts { target: String },

    #[error("Configuration error: {message}")]
    Configuration { message: String },

    // ---------------------------- Parsing -----------------------------------
    #[error("Failed to parse EML file {file_path}: {reason}")]
    EmlParsing { file_path: String, reason: String },

    #[error("WHOIS response parse failed for query '{query}': {reason}")]
    WhoisParse { query: String, reason: String },

    // ----------------------------- Network ----------------------------------
    #[error("Network error during {operation} for '{target}': {source}")]
    Network {
        operation: String,
        target: String,
        #[source]
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    #[error("DNS query timed out after {seconds}s: {query}")]
    DnsTimeout { query: String, seconds: u64 },

    #[error("DNS {record_type} lookup failed for {domain}: {reason}")]
    DnsResolution {
        domain: String,
        record_type: String,
        reason: String,
    },

    #[error("WHOIS query '{query}' to server '{server}' failed: {reason}")]
    WhoisQuery {
        server: String,
        query: String,
        reason: String,
    },

    #[error("WHOIS service unavailable for '{query}': {reason}")]
    WhoisUnavailable { query: String, reason: String },

    // ----------------------------- I/O / FS ---------------------------------
    #[error("I/O error during {operation} on {path}: {source}")]
    Io {
        path: String,
        operation: String,
        #[source]
        source: io::Error,
    },

    // ---------------------------- Internal ----------------------------------
    #[error("Internal error: {message}")]
    Internal {
        message: String,
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
}

impl AbuseDetectorError {
    /// Categorize the error for structured output / metrics.
    pub fn category(&self) -> ErrorCategory {
        use AbuseDetectorError::*;
        match self {
            InvalidIpAddress { .. }
            | PrivateIpAddress { .. }
            | ReservedIpAddress { .. }
            | NoPublicIpInEml { .. }
            | DomainExtractionFailed { .. }
            | UnsupportedContentEncoding { .. }
            | NoAbuseContacts { .. }
            | Configuration { .. } => ErrorCategory::Input,

            EmlParsing { .. } | WhoisParse { .. } => ErrorCategory::Parse,

            Network { .. }
            | DnsTimeout { .. }
            | DnsResolution { .. }
            | WhoisQuery { .. }
            | WhoisUnavailable { .. } => ErrorCategory::Network,

            Io { .. } | Internal { .. } => ErrorCategory::Internal,
        }
    }

    // ---------------------------- Constructors -----------------------------

    pub fn invalid_ip(ip: impl Into<String>) -> Self {
        Self::InvalidIpAddress { ip: ip.into() }
    }

    pub fn private_ip(ip: impl Into<String>) -> Self {
        Self::PrivateIpAddress { ip: ip.into() }
    }

    pub fn reserved_ip(ip: impl Into<String>) -> Self {
        Self::ReservedIpAddress { ip: ip.into() }
    }

    pub fn eml_parsing(file_path: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::EmlParsing {
            file_path: file_path.into(),
            reason: reason.into(),
        }
    }

    pub fn domain_extraction_failed(
        file_path: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::DomainExtractionFailed {
            file_path: file_path.into(),
            reason: reason.into(),
        }
    }

    pub fn network(
        operation: impl Into<String>,
        target: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Network {
            operation: operation.into(),
            target: target.into(),
            source: source.into(),
        }
    }

    pub fn dns_timeout(query: impl Into<String>, seconds: u64) -> Self {
        Self::DnsTimeout {
            query: query.into(),
            seconds,
        }
    }

    pub fn dns_resolution(
        domain: impl Into<String>,
        record_type: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::DnsResolution {
            domain: domain.into(),
            record_type: record_type.into(),
            reason: reason.into(),
        }
    }

    pub fn whois_query(
        server: impl Into<String>,
        query: impl Into<String>,
        reason: impl Into<String>,
    ) -> Self {
        Self::WhoisQuery {
            server: server.into(),
            query: query.into(),
            reason: reason.into(),
        }
    }

    pub fn whois_unavailable(query: impl Into<String>, reason: impl Into<String>) -> Self {
        Self::WhoisUnavailable {
            query: query.into(),
            reason: reason.into(),
        }
    }

    pub fn io(path: impl Into<String>, operation: impl Into<String>, source: io::Error) -> Self {
        Self::Io {
            path: path.into(),
            operation: operation.into(),
            source,
        }
    }

    pub fn internal(message: impl Into<String>) -> Self {
        Self::Internal {
            message: message.into(),
            source: None,
        }
    }

    pub fn internal_with(
        message: impl Into<String>,
        source: impl Into<Box<dyn std::error::Error + Send + Sync>>,
    ) -> Self {
        Self::Internal {
            message: message.into(),
            source: Some(source.into()),
        }
    }
}

/// Public result alias.
pub type Result<T> = std::result::Result<T, AbuseDetectorError>;

/// Map standard IO errors into `Io` variant (generic context).
impl From<io::Error> for AbuseDetectorError {
    fn from(e: io::Error) -> Self {
        AbuseDetectorError::Io {
            path: "<unknown>".into(),
            operation: "unspecified".into(),
            source: e,
        }
    }
}

impl From<AddrParseError> for AbuseDetectorError {
    fn from(e: AddrParseError) -> Self {
        AbuseDetectorError::InvalidIpAddress { ip: e.to_string() }
    }
}

impl From<tokio::time::error::Elapsed> for AbuseDetectorError {
    fn from(_: tokio::time::error::Elapsed) -> Self {
        // Query string not available at this conversion point; caller should
        // wrap via `dns_timeout` where context is known. Provide placeholder.
        AbuseDetectorError::DnsTimeout {
            query: "<unknown>".into(),
            seconds: 0,
        }
    }
}

/// Extension trait for enriching IO results with path + operation context.
pub trait IoResultExt<T> {
    fn with_path(self, path: impl Into<String>, operation: impl Into<String>) -> Result<T>;
}

impl<T> IoResultExt<T> for std::result::Result<T, io::Error> {
    fn with_path(self, path: impl Into<String>, operation: impl Into<String>) -> Result<T> {
        self.map_err(|e| AbuseDetectorError::io(path.into(), operation.into(), e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn category_mapping() {
        assert_eq!(
            AbuseDetectorError::invalid_ip("x").category(),
            ErrorCategory::Input
        );
        assert_eq!(
            AbuseDetectorError::dns_timeout("a", 5).category(),
            ErrorCategory::Network
        );
        assert_eq!(
            AbuseDetectorError::eml_parsing("f", "bad").category(),
            ErrorCategory::Parse
        );
    }

    #[test]
    fn display_snippets() {
        let e = AbuseDetectorError::dns_resolution("example.com", "SOA", "NXDOMAIN");
        let s = e.to_string();
        assert!(s.contains("example.com"));
        assert!(s.contains("SOA"));
        let i = AbuseDetectorError::internal("boom");
        assert!(i.to_string().contains("Internal error"));
    }

    #[test]
    fn io_context() {
        let res: std::result::Result<(), io::Error> =
            Err(io::Error::new(io::ErrorKind::NotFound, "missing"));
        let mapped = res.with_path("/tmp/file", "read");
        match mapped.err().unwrap() {
            AbuseDetectorError::Io {
                path, operation, ..
            } => {
                assert_eq!(path, "/tmp/file");
                assert_eq!(operation, "read");
            }
            other => panic!("unexpected variant: {other:?}"),
        }
    }
}
