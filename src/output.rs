//! Output formatting for abusedetector results.
//!
//! This module provides different output formats including human-readable text,
//! machine-parsable JSON, and batch formats. It handles result serialization
//! and formatting according to user preferences.

#![allow(dead_code)]

use std::io;
use std::net::Ipv4Addr;

/// Represents the final results of an abuse detection query
#[derive(Debug, Clone)]
pub struct AbuseResults {
    /// The IP address that was queried
    pub ip: Ipv4Addr,

    /// List of discovered abuse contacts with confidence scores
    pub contacts: Vec<AbuseContact>,

    /// Metadata about the query process
    pub metadata: QueryMetadata,
}

/// Individual abuse contact with confidence and source information
#[derive(Debug, Clone)]
pub struct AbuseContact {
    /// Email address
    pub email: String,

    /// Confidence score (higher is better)
    pub confidence: u32,

    /// Source that provided this contact
    pub source: ContactSource,

    /// Additional metadata
    pub metadata: ContactMetadata,
}

/// Source of an abuse contact
#[derive(Debug, Clone)]
pub enum ContactSource {
    /// From WHOIS registry data
    Whois { server: String },

    /// From DNS SOA records
    DnsSoa { domain: String },

    /// From abuse.net directory
    AbuseNet,

    /// From reverse DNS hostname analysis
    ReverseDns { hostname: String },

    /// From EML headers (for email-derived queries)
    EmlHeaders { header_name: String },

    /// From provider-specific analysis
    Provider { provider: String },

    /// Unknown or mixed sources
    Unknown,
}

/// Additional metadata for contacts
#[derive(Debug, Clone, Default)]
pub struct ContactMetadata {
    /// Domain the contact is associated with
    pub domain: Option<String>,

    /// Whether this is an abuse-specific address (vs generic)
    pub is_abuse_specific: bool,

    /// Whether this contact was filtered/deprioritized
    pub filtered: bool,

    /// Additional notes
    pub notes: Vec<String>,
}

/// Metadata about the query process
#[derive(Debug, Clone, Default)]
pub struct QueryMetadata {
    /// How long the query took
    pub duration_ms: Option<u64>,

    /// Whether the IP was extracted from an EML file
    pub from_eml: bool,

    /// EML file path if applicable
    pub eml_file: Option<String>,

    /// Reverse DNS hostname if found
    pub hostname: Option<String>,

    /// Number of WHOIS servers queried
    pub whois_servers_queried: u32,

    /// Whether abuse.net was queried
    pub abuse_net_queried: bool,

    /// Number of DNS queries performed
    pub dns_queries: u32,

    /// Errors encountered (non-fatal)
    pub warnings: Vec<String>,

    /// Source priorities that were applied
    pub source_priorities: Vec<String>,
}

/// Output format options
#[derive(Debug, Clone)]
pub enum OutputFormat {
    /// Human-readable text format
    Text {
        /// Show confidence scores
        show_confidence: bool,
        /// Show source information
        show_sources: bool,
        /// Show metadata
        show_metadata: bool,
    },

    /// JSON format
    Json {
        /// Pretty-print the JSON
        pretty: bool,
    },

    /// Batch format: ip:email1,email2,...
    Batch,

    /// CSV format
    Csv {
        /// Include header row
        include_header: bool,
    },
}

impl Default for OutputFormat {
    fn default() -> Self {
        OutputFormat::Text {
            show_confidence: false,
            show_sources: false,
            show_metadata: false,
        }
    }
}

/// Output formatter trait - made dyn-compatible by removing generic methods
pub trait OutputFormatter {
    /// Format the results to stdout
    fn format_results(&self, results: &AbuseResults) -> io::Result<String>;

    /// Get the MIME type for this format
    fn mime_type(&self) -> &'static str;

    /// Get the file extension for this format
    fn file_extension(&self) -> &'static str;
}

/// Text output formatter
pub struct TextFormatter {
    show_confidence: bool,
    show_sources: bool,
    show_metadata: bool,
}

impl TextFormatter {
    pub fn new(show_confidence: bool, show_sources: bool, show_metadata: bool) -> Self {
        Self {
            show_confidence,
            show_sources,
            show_metadata,
        }
    }
}

impl OutputFormatter for TextFormatter {
    fn format_results(&self, results: &AbuseResults) -> io::Result<String> {
        let mut output = String::new();

        if results.contacts.is_empty() {
            output.push_str(&format!(
                "No abuse contacts discovered for {}\n",
                results.ip
            ));
            return Ok(output);
        }

        if self.show_metadata {
            if let Some(hostname) = &results.metadata.hostname {
                output.push_str(&format!("Hostname: {}\n", hostname));
            }
            if results.metadata.from_eml {
                if let Some(ref eml_file) = results.metadata.eml_file {
                    output.push_str(&format!(
                        "Detected sender IP (from EML): {} ({})\n",
                        results.ip, eml_file
                    ));
                } else {
                    output.push_str(&format!("Detected sender IP (from EML): {}\n", results.ip));
                }
            }
            output.push('\n');
        }

        if self.show_confidence || self.show_sources {
            output.push_str("Found abuse addresses:\n");
            for contact in &results.contacts {
                output.push_str(&contact.email);

                if self.show_confidence {
                    output.push_str(&format!("\t{}", contact.confidence));
                }

                if self.show_sources {
                    output.push_str(&format!("\t{}", format_source(&contact.source)));
                }

                output.push('\n');
            }
        } else {
            // Simple format - just email addresses
            for contact in &results.contacts {
                output.push_str(&format!("{}\n", contact.email));
            }
        }

        if self.show_metadata && !results.metadata.warnings.is_empty() {
            output.push('\n');
            output.push_str("Warnings:\n");
            for warning in &results.metadata.warnings {
                output.push_str(&format!("  {}\n", warning));
            }
        }

        Ok(output)
    }

    fn mime_type(&self) -> &'static str {
        "text/plain"
    }

    fn file_extension(&self) -> &'static str {
        "txt"
    }
}

/// JSON output formatter
pub struct JsonFormatter {
    pretty: bool,
}

impl JsonFormatter {
    pub fn new(pretty: bool) -> Self {
        Self { pretty }
    }
}

impl OutputFormatter for JsonFormatter {
    fn format_results(&self, results: &AbuseResults) -> io::Result<String> {
        let json_results = JsonResults::from(results);

        let json_string = if self.pretty {
            serde_json::to_string_pretty(&json_results).map_err(io::Error::other)?
        } else {
            serde_json::to_string(&json_results).map_err(io::Error::other)?
        };

        Ok(format!("{}\n", json_string))
    }

    fn mime_type(&self) -> &'static str {
        "application/json"
    }

    fn file_extension(&self) -> &'static str {
        "json"
    }
}

/// Batch output formatter
pub struct BatchFormatter;

impl OutputFormatter for BatchFormatter {
    fn format_results(&self, results: &AbuseResults) -> io::Result<String> {
        let emails: Vec<&str> = results.contacts.iter().map(|c| c.email.as_str()).collect();
        Ok(format!("{}:{}\n", results.ip, emails.join(",")))
    }

    fn mime_type(&self) -> &'static str {
        "text/plain"
    }

    fn file_extension(&self) -> &'static str {
        "txt"
    }
}

/// CSV output formatter
pub struct CsvFormatter {
    include_header: bool,
}

impl CsvFormatter {
    pub fn new(include_header: bool) -> Self {
        Self { include_header }
    }
}

impl OutputFormatter for CsvFormatter {
    fn format_results(&self, results: &AbuseResults) -> io::Result<String> {
        let mut output = String::new();

        if self.include_header {
            output.push_str("ip,email,confidence,source,domain,is_abuse_specific\n");
        }

        for contact in &results.contacts {
            output.push_str(&format!(
                "{},{},{},{},{},{}\n",
                results.ip,
                contact.email,
                contact.confidence,
                format_source(&contact.source),
                contact.metadata.domain.as_deref().unwrap_or(""),
                contact.metadata.is_abuse_specific
            ));
        }

        Ok(output)
    }

    fn mime_type(&self) -> &'static str {
        "text/csv"
    }

    fn file_extension(&self) -> &'static str {
        "csv"
    }
}

/// JSON serializable version of results
#[derive(serde::Serialize)]
struct JsonResults {
    ip: String,
    contacts: Vec<JsonContact>,
    metadata: JsonMetadata,
    #[serde(skip_serializing_if = "Option::is_none")]
    query_time: Option<String>,
}

#[derive(serde::Serialize)]
struct JsonContact {
    email: String,
    confidence: u32,
    source: JsonSource,
    metadata: JsonContactMetadata,
}

#[derive(serde::Serialize)]
struct JsonSource {
    #[serde(rename = "type")]
    source_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    server: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    header_name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    provider: Option<String>,
}

#[derive(serde::Serialize)]
struct JsonContactMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    domain: Option<String>,
    is_abuse_specific: bool,
    filtered: bool,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    notes: Vec<String>,
}

#[derive(serde::Serialize)]
struct JsonMetadata {
    #[serde(skip_serializing_if = "Option::is_none")]
    duration_ms: Option<u64>,
    from_eml: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    eml_file: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    hostname: Option<String>,
    whois_servers_queried: u32,
    abuse_net_queried: bool,
    dns_queries: u32,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    warnings: Vec<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    source_priorities: Vec<String>,
}

impl From<&AbuseResults> for JsonResults {
    fn from(results: &AbuseResults) -> Self {
        Self {
            ip: results.ip.to_string(),
            contacts: results.contacts.iter().map(JsonContact::from).collect(),
            metadata: JsonMetadata::from(&results.metadata),
            query_time: chrono::Utc::now()
                .to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
                .into(),
        }
    }
}

impl From<&AbuseContact> for JsonContact {
    fn from(contact: &AbuseContact) -> Self {
        Self {
            email: contact.email.clone(),
            confidence: contact.confidence,
            source: JsonSource::from(&contact.source),
            metadata: JsonContactMetadata::from(&contact.metadata),
        }
    }
}

impl From<&ContactSource> for JsonSource {
    fn from(source: &ContactSource) -> Self {
        match source {
            ContactSource::Whois { server } => Self {
                source_type: "whois".to_string(),
                server: Some(server.clone()),
                domain: None,
                hostname: None,
                header_name: None,
                provider: None,
            },
            ContactSource::DnsSoa { domain } => Self {
                source_type: "dns_soa".to_string(),
                server: None,
                domain: Some(domain.clone()),
                hostname: None,
                header_name: None,
                provider: None,
            },
            ContactSource::AbuseNet => Self {
                source_type: "abuse_net".to_string(),
                server: None,
                domain: None,
                hostname: None,
                header_name: None,
                provider: None,
            },
            ContactSource::ReverseDns { hostname } => Self {
                source_type: "reverse_dns".to_string(),
                server: None,
                domain: None,
                hostname: Some(hostname.clone()),
                header_name: None,
                provider: None,
            },
            ContactSource::EmlHeaders { header_name } => Self {
                source_type: "eml_headers".to_string(),
                server: None,
                domain: None,
                hostname: None,
                header_name: Some(header_name.clone()),
                provider: None,
            },
            ContactSource::Provider { provider } => Self {
                source_type: "provider".to_string(),
                server: None,
                domain: None,
                hostname: None,
                header_name: None,
                provider: Some(provider.clone()),
            },
            ContactSource::Unknown => Self {
                source_type: "unknown".to_string(),
                server: None,
                domain: None,
                hostname: None,
                header_name: None,
                provider: None,
            },
        }
    }
}

impl From<&ContactMetadata> for JsonContactMetadata {
    fn from(metadata: &ContactMetadata) -> Self {
        Self {
            domain: metadata.domain.clone(),
            is_abuse_specific: metadata.is_abuse_specific,
            filtered: metadata.filtered,
            notes: metadata.notes.clone(),
        }
    }
}

impl From<&QueryMetadata> for JsonMetadata {
    fn from(metadata: &QueryMetadata) -> Self {
        Self {
            duration_ms: metadata.duration_ms,
            from_eml: metadata.from_eml,
            eml_file: metadata.eml_file.clone(),
            hostname: metadata.hostname.clone(),
            whois_servers_queried: metadata.whois_servers_queried,
            abuse_net_queried: metadata.abuse_net_queried,
            dns_queries: metadata.dns_queries,
            warnings: metadata.warnings.clone(),
            source_priorities: metadata.source_priorities.clone(),
        }
    }
}

/// Format a contact source for human reading
fn format_source(source: &ContactSource) -> String {
    match source {
        ContactSource::Whois { server } => format!("whois:{}", server),
        ContactSource::DnsSoa { domain } => format!("dns_soa:{}", domain),
        ContactSource::AbuseNet => "abuse.net".to_string(),
        ContactSource::ReverseDns { hostname } => format!("reverse_dns:{}", hostname),
        ContactSource::EmlHeaders { header_name } => format!("eml:{}", header_name),
        ContactSource::Provider { provider } => format!("provider:{}", provider),
        ContactSource::Unknown => "unknown".to_string(),
    }
}

/// Create a formatter based on the output format
pub fn create_formatter(format: &OutputFormat) -> Box<dyn OutputFormatter> {
    match format {
        OutputFormat::Text {
            show_confidence,
            show_sources,
            show_metadata,
        } => Box::new(TextFormatter::new(
            *show_confidence,
            *show_sources,
            *show_metadata,
        )),
        OutputFormat::Json { pretty } => Box::new(JsonFormatter::new(*pretty)),
        OutputFormat::Batch => Box::new(BatchFormatter),
        OutputFormat::Csv { include_header } => Box::new(CsvFormatter::new(*include_header)),
    }
}

/// Utility function to format results to a string
pub fn format_results_to_string(
    results: &AbuseResults,
    format: &OutputFormat,
) -> io::Result<String> {
    let formatter = create_formatter(format);
    formatter.format_results(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn create_test_results() -> AbuseResults {
        AbuseResults {
            ip: "1.2.3.4".parse().unwrap(),
            contacts: vec![
                AbuseContact {
                    email: "abuse@example.com".to_string(),
                    confidence: 5,
                    source: ContactSource::Whois {
                        server: "whois.example.com".to_string(),
                    },
                    metadata: ContactMetadata {
                        domain: Some("example.com".to_string()),
                        is_abuse_specific: true,
                        filtered: false,
                        notes: vec!["Primary contact".to_string()],
                    },
                },
                AbuseContact {
                    email: "security@example.org".to_string(),
                    confidence: 3,
                    source: ContactSource::AbuseNet,
                    metadata: ContactMetadata {
                        domain: Some("example.org".to_string()),
                        is_abuse_specific: false,
                        filtered: false,
                        notes: vec![],
                    },
                },
            ],
            metadata: QueryMetadata {
                duration_ms: Some(1500),
                from_eml: false,
                hostname: Some("mail.example.com".to_string()),
                whois_servers_queried: 2,
                abuse_net_queried: true,
                dns_queries: 3,
                warnings: vec!["Timeout on secondary WHOIS server".to_string()],
                source_priorities: vec!["whois".to_string(), "abuse.net".to_string()],
                ..Default::default()
            },
        }
    }

    #[test]
    fn test_text_formatter_simple() {
        let results = create_test_results();
        let formatter = TextFormatter::new(false, false, false);

        let text = formatter.format_results(&results).unwrap();

        assert!(text.contains("abuse@example.com"));
        assert!(text.contains("security@example.org"));
        assert!(!text.contains("confidence"));
    }
    #[test]
    fn test_text_formatter_with_confidence() {
        let results = create_test_results();
        let formatter = TextFormatter::new(true, false, false);

        let text = formatter.format_results(&results).unwrap();

        assert!(text.contains("abuse@example.com\t5"));
        assert!(text.contains("security@example.org\t3"));
    }

    #[test]
    fn test_batch_formatter() {
        let results = create_test_results();
        let formatter = BatchFormatter;

        let text = formatter.format_results(&results).unwrap();

        assert_eq!(
            text.trim(),
            "1.2.3.4:abuse@example.com,security@example.org"
        );
    }

    #[test]
    fn test_json_formatter() {
        let results = create_test_results();
        let formatter = JsonFormatter::new(false);

        let text = formatter.format_results(&results).unwrap();

        // Basic JSON structure checks
        assert!(text.contains("\"ip\":\"1.2.3.4\""));
        assert!(text.contains("\"email\":\"abuse@example.com\""));
        assert!(text.contains("\"confidence\":5"));
        assert!(text.contains("\"source\""));
        assert!(text.contains("\"whois\""));
    }

    #[test]
    fn test_csv_formatter() {
        let results = create_test_results();
        let formatter = CsvFormatter::new(true);

        let text = formatter.format_results(&results).unwrap();

        let lines: Vec<&str> = text.trim().split('\n').collect();
        assert_eq!(lines.len(), 3); // header + 2 contacts
        assert!(lines[0].contains("ip,email,confidence"));
        assert!(lines[1].contains("1.2.3.4,abuse@example.com,5"));
    }

    #[test]
    fn test_empty_results() {
        let results = AbuseResults {
            ip: "1.2.3.4".parse().unwrap(),
            contacts: vec![],
            metadata: QueryMetadata::default(),
        };

        let formatter = TextFormatter::new(false, false, false);

        let text = formatter.format_results(&results).unwrap();

        assert!(text.contains("No abuse contacts discovered"));
    }

    #[test]
    fn test_format_source() {
        assert_eq!(format_source(&ContactSource::AbuseNet), "abuse.net");
        assert_eq!(
            format_source(&ContactSource::Whois {
                server: "whois.ripe.net".to_string()
            }),
            "whois:whois.ripe.net"
        );
        assert_eq!(
            format_source(&ContactSource::DnsSoa {
                domain: "example.com".to_string()
            }),
            "dns_soa:example.com"
        );
    }
}
