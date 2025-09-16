//! AbuseDetector Library
//!
//! A Rust library for extracting abuse contact information from IPv4 addresses
//! and email (.eml) files. This library provides functionality to:
//!
//! - Parse EML files to extract originating IP addresses
//! - Classify IP addresses (private, reserved, public)
//! - Collect and rank abuse contact email addresses
//! - Query various sources (WHOIS, DNS SOA, abuse.net) for contact information
//!
//! # Example
//!
//! ```rust,no_run
//! use abusedetector::eml::parse_eml_origin_ip_from_path;
//! use abusedetector::netutil::{is_private, is_reserved};
//!
//! // Extract IP from EML file
//! let ip = parse_eml_origin_ip_from_path("message.eml")?;
//!
//! // Check if IP is usable for abuse reporting
//! if !is_private(ip) && !is_reserved(ip) {
//!     println!("Public IP suitable for abuse reporting: {}", ip);
//! }
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```

// Re-export all modules for library use
pub mod cli;
pub mod config;
pub mod emails;
pub mod eml;
pub mod errors;
pub mod escalation;
pub mod netutil;
pub mod output;
pub mod retry;
pub mod styled_output;
pub mod whois;

// Re-export commonly used types and functions for convenience
pub use emails::{EmailSet, FinalizeOptions};
pub use errors::{AbuseDetectorError, Result};
pub use escalation::{EscalationContactType, EscalationPath};
pub use netutil::{is_private, is_reserved, parse_ipv4};
pub use output::{AbuseContact, AbuseResults, ContactSource, OutputFormat};
pub use styled_output::StyledFormatter;

// Version information
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const NAME: &str = env!("CARGO_PKG_NAME");
