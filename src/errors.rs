//! Custom error types for abusedetector.
//!
//! This module provides structured error handling to improve user experience
//! and debugging capabilities. Instead of using generic anyhow errors everywhere,
//! we define specific error types for different failure modes.

#![allow(dead_code)]

use std::fmt;
use std::io;
use std::net::AddrParseError;

/// Main error type for abusedetector operations.
#[derive(Debug)]
pub enum AbuseDetectorError {
    /// Invalid IP address format
    InvalidIpAddress(String),

    /// IP address is in a private range (RFC 1918)
    PrivateIpAddress(String),

    /// IP address is in a reserved range
    ReservedIpAddress(String),

    /// Failed to read or parse EML file
    EmlParsing { file_path: String, reason: String },

    /// No public IP addresses found in EML file
    NoPublicIpInEml(String),

    /// Network operation failed (DNS, WHOIS, etc.)
    NetworkError {
        operation: String,
        target: String,
        source: Box<dyn std::error::Error + Send + Sync>,
    },

    /// Network operation timed out
    NetworkTimeout {
        operation: String,
        target: String,
        timeout_secs: u64,
    },

    /// DNS resolution failed
    DnsResolution {
        domain: String,
        record_type: String,
        reason: String,
    },

    /// WHOIS query failed
    WhoisQuery {
        server: String,
        query: String,
        reason: String,
    },

    /// File I/O error
    IoError {
        file_path: String,
        operation: String,
        source: io::Error,
    },

    /// Configuration error
    Configuration(String),

    /// No abuse contacts could be discovered
    NoAbuseContacts(String),
}

impl fmt::Display for AbuseDetectorError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AbuseDetectorError::InvalidIpAddress(ip) => {
                write!(f, "Invalid IP address format: '{}'", ip)
            }
            AbuseDetectorError::PrivateIpAddress(ip) => {
                write!(
                    f,
                    "{} is a private IP address (RFC 1918). Cannot proceed with abuse lookup",
                    ip
                )
            }
            AbuseDetectorError::ReservedIpAddress(ip) => {
                write!(
                    f,
                    "{} is a reserved IP address. Cannot proceed with abuse lookup",
                    ip
                )
            }
            AbuseDetectorError::EmlParsing { file_path, reason } => {
                write!(f, "Failed to parse EML file '{}': {}", file_path, reason)
            }
            AbuseDetectorError::NoPublicIpInEml(file_path) => {
                write!(
                    f,
                    "No public IPv4 addresses found in EML file '{}'",
                    file_path
                )
            }
            AbuseDetectorError::NetworkError {
                operation,
                target,
                source,
            } => {
                write!(
                    f,
                    "Network error during {} for '{}': {}",
                    operation, target, source
                )
            }
            AbuseDetectorError::NetworkTimeout {
                operation,
                target,
                timeout_secs,
            } => {
                write!(
                    f,
                    "{} timed out after {} seconds for '{}'",
                    operation, timeout_secs, target
                )
            }
            AbuseDetectorError::DnsResolution {
                domain,
                record_type,
                reason,
            } => {
                write!(
                    f,
                    "DNS {} lookup failed for '{}': {}",
                    record_type, domain, reason
                )
            }
            AbuseDetectorError::WhoisQuery {
                server,
                query,
                reason,
            } => {
                write!(
                    f,
                    "WHOIS query to '{}' for '{}' failed: {}",
                    server, query, reason
                )
            }
            AbuseDetectorError::IoError {
                file_path,
                operation,
                source,
            } => {
                write!(
                    f,
                    "I/O error during {} on '{}': {}",
                    operation, file_path, source
                )
            }
            AbuseDetectorError::Configuration(msg) => {
                write!(f, "Configuration error: {}", msg)
            }
            AbuseDetectorError::NoAbuseContacts(ip) => {
                write!(f, "No abuse contacts discovered for {}", ip)
            }
        }
    }
}

impl std::error::Error for AbuseDetectorError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            AbuseDetectorError::NetworkError { source, .. } => Some(source.as_ref()),
            AbuseDetectorError::IoError { source, .. } => Some(source),
            _ => None,
        }
    }
}

impl From<io::Error> for AbuseDetectorError {
    fn from(err: io::Error) -> Self {
        AbuseDetectorError::IoError {
            file_path: "<unknown>".to_string(),
            operation: "unknown operation".to_string(),
            source: err,
        }
    }
}

impl From<AddrParseError> for AbuseDetectorError {
    fn from(err: AddrParseError) -> Self {
        AbuseDetectorError::InvalidIpAddress(err.to_string())
    }
}

/// Result type alias for convenience
pub type Result<T> = std::result::Result<T, AbuseDetectorError>;

/// Helper functions for creating specific error types
impl AbuseDetectorError {
    pub fn eml_parsing<P: AsRef<str>, R: AsRef<str>>(file_path: P, reason: R) -> Self {
        Self::EmlParsing {
            file_path: file_path.as_ref().to_string(),
            reason: reason.as_ref().to_string(),
        }
    }

    pub fn network_error<O: AsRef<str>, T: AsRef<str>>(
        operation: O,
        target: T,
        source: Box<dyn std::error::Error + Send + Sync>,
    ) -> Self {
        Self::NetworkError {
            operation: operation.as_ref().to_string(),
            target: target.as_ref().to_string(),
            source,
        }
    }

    pub fn network_timeout<O: AsRef<str>, T: AsRef<str>>(
        operation: O,
        target: T,
        timeout_secs: u64,
    ) -> Self {
        Self::NetworkTimeout {
            operation: operation.as_ref().to_string(),
            target: target.as_ref().to_string(),
            timeout_secs,
        }
    }

    pub fn dns_resolution<D: AsRef<str>, R: AsRef<str>, E: AsRef<str>>(
        domain: D,
        record_type: R,
        reason: E,
    ) -> Self {
        Self::DnsResolution {
            domain: domain.as_ref().to_string(),
            record_type: record_type.as_ref().to_string(),
            reason: reason.as_ref().to_string(),
        }
    }

    pub fn whois_query<S: AsRef<str>, Q: AsRef<str>, R: AsRef<str>>(
        server: S,
        query: Q,
        reason: R,
    ) -> Self {
        Self::WhoisQuery {
            server: server.as_ref().to_string(),
            query: query.as_ref().to_string(),
            reason: reason.as_ref().to_string(),
        }
    }

    pub fn io_error<P: AsRef<str>, O: AsRef<str>>(
        file_path: P,
        operation: O,
        source: io::Error,
    ) -> Self {
        Self::IoError {
            file_path: file_path.as_ref().to_string(),
            operation: operation.as_ref().to_string(),
            source,
        }
    }
}

/// Extension trait for Result to add context for file operations
pub trait IoResultExt<T> {
    fn with_file_context<P: AsRef<str>, O: AsRef<str>>(
        self,
        file_path: P,
        operation: O,
    ) -> Result<T>;
}

impl<T> IoResultExt<T> for std::result::Result<T, io::Error> {
    fn with_file_context<P: AsRef<str>, O: AsRef<str>>(
        self,
        file_path: P,
        operation: O,
    ) -> Result<T> {
        self.map_err(|err| {
            AbuseDetectorError::io_error(file_path.as_ref(), operation.as_ref(), err)
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Error, ErrorKind};

    #[test]
    fn test_error_display() {
        let err = AbuseDetectorError::InvalidIpAddress("not.an.ip".to_string());
        assert!(err.to_string().contains("Invalid IP address format"));

        let err = AbuseDetectorError::PrivateIpAddress("192.168.1.1".to_string());
        assert!(err.to_string().contains("private IP address"));

        let err = AbuseDetectorError::eml_parsing("test.eml", "invalid format");
        assert!(err.to_string().contains("Failed to parse EML"));
    }

    #[test]
    fn test_io_result_ext() {
        let io_err = Error::new(ErrorKind::NotFound, "file not found");
        let result: std::result::Result<(), _> = Err(io_err);

        let abuse_err = result.with_file_context("test.eml", "reading file");
        assert!(abuse_err.is_err());

        match abuse_err.unwrap_err() {
            AbuseDetectorError::IoError {
                file_path,
                operation,
                ..
            } => {
                assert_eq!(file_path, "test.eml");
                assert_eq!(operation, "reading file");
            }
            _ => panic!("Expected IoError"),
        }
    }

    #[test]
    fn test_helper_constructors() {
        let err = AbuseDetectorError::network_timeout("DNS lookup", "example.com", 5);
        assert!(err.to_string().contains("timed out after 5 seconds"));

        let err = AbuseDetectorError::dns_resolution("example.com", "SOA", "NXDOMAIN");
        assert!(err.to_string().contains("DNS SOA lookup failed"));
    }
}
