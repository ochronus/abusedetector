//! Structured output module for JSON and YAML serialization.
//!
//! This module defines comprehensive data structures that represent all the information
//! the abusedetector tool can discover, including primary contacts, escalation paths,
//! metadata, and statistics. These structures are designed to be both human-readable
//! and machine-parsable.

use anyhow::Result;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

use crate::escalation::{DualEscalationPath, EscalationContact, EscalationContactType};

/// Root structure for all abusedetector output in structured formats
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct AbuseDetectorOutput {
    /// Tool version and metadata
    pub metadata: OutputMetadata,

    /// Input information that was analyzed
    pub input: InputInfo,

    /// Primary abuse contacts discovered
    pub primary_contacts: Vec<Contact>,

    /// Escalation paths (if requested and available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub escalation_paths: Option<EscalationPaths>,

    /// Query statistics and performance metrics
    pub statistics: QueryStatistics,

    /// Warnings and errors encountered during processing
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub warnings: Vec<String>,

    /// Success status and result summary
    pub result: ResultSummary,
}

/// Tool metadata and versioning information
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct OutputMetadata {
    /// Tool name
    pub tool_name: String,

    /// Tool version
    pub version: String,

    /// Timestamp when analysis was performed
    pub generated_at: chrono::DateTime<chrono::Utc>,

    /// JSON schema version for this output format
    pub schema_version: String,

    /// URL to the JSON schema definition
    pub schema_url: String,
}

/// Information about what was analyzed
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct InputInfo {
    /// The IP address that was analyzed (may be 0.0.0.0 in domain-fallback mode when no public IPv4 was found in EML headers)
    pub ip_address: Ipv4Addr,

    /// How the IP was obtained
    pub ip_source: IpSource,

    /// Original input method
    pub input_method: InputMethod,

    /// Reverse DNS hostname (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// Sender domain extracted from email (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_domain: Option<String>,

    /// EML file path (if applicable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eml_file: Option<String>,
}

/// How the IP address was obtained
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum IpSource {
    /// Directly provided by user
    DirectInput,
    /// Extracted from email header
    EmailHeader {
        /// Specific header field used
        header_field: String,
        /// Priority/confidence of this source
        priority: u8,
    },
}

/// Input method used
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum InputMethod {
    /// Direct IP address input
    DirectIp,
    /// EML file analysis
    EmlFile,
}

/// A contact entry with rich metadata
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct Contact {
    /// The email address
    pub email: String,

    /// Domain the contact is associated with
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,

    /// Type of contact
    pub contact_type: ContactType,

    /// How this contact was discovered
    pub sources: Vec<ContactSource>,

    /// Confidence score (0-100)
    pub confidence: u8,

    /// Whether this is an abuse-specific address
    pub is_abuse_specific: bool,

    /// Additional metadata about this contact
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ContactMetadata>,
}

/// Type of abuse contact
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContactType {
    /// Direct abuse contact
    Abuse,
    /// Security contact
    Security,
    /// Hostmaster contact
    Hostmaster,
    /// Administrative contact
    Admin,
    /// Technical contact
    Tech,
    /// Generic contact
    Generic,
}

/// Source where a contact was discovered
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ContactSource {
    /// WHOIS database lookup
    Whois {
        /// WHOIS server queried
        server: String,
    },
    /// DNS SOA record RNAME
    DnsSoa {
        /// Domain queried
        domain: String,
    },
    /// abuse.net database
    AbuseNet,
    /// Hostname-based heuristics
    HostnameHeuristic,
    /// Multiple sources confirm this contact
    MultipleConfirmed,
}

/// Additional contact metadata
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ContactMetadata {
    /// Organization name
    #[serde(skip_serializing_if = "Option::is_none")]
    pub organization: Option<String>,

    /// Country code
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,

    /// Additional notes
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,
}

/// Escalation paths for when primary contacts don't respond
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct EscalationPaths {
    /// Email infrastructure escalation (for stopping email sending)
    pub email_infrastructure: EscalationPath,

    /// Sender hosting escalation (for stopping website/business)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_hosting: Option<EscalationPath>,

    /// When these paths were generated
    pub generated_at: chrono::DateTime<chrono::Utc>,

    /// Recommended escalation strategy
    pub strategy: EscalationStrategy,
}

/// A single escalation path with prioritized contacts
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct EscalationPath {
    /// Purpose of this escalation path
    pub purpose: String,

    /// Description of what this path targets
    pub description: String,

    /// Ordered list of escalation contacts (Level 0, 1, 2, etc.)
    pub contacts: Vec<EscalationContactInfo>,

    /// Network information relevant to this path
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_info: Option<NetworkInfo>,
}

/// Escalation contact with level and metadata
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct EscalationContactInfo {
    /// Escalation level (0 = first contact, 1 = second, etc.)
    pub level: u8,

    /// Type of escalation contact
    pub contact_type: EscalationContactType,

    /// Organization name
    pub organization: String,

    /// Email contact (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,

    /// Web form URL (if available)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub web_form: Option<String>,

    /// Expected response time
    #[serde(skip_serializing_if = "Option::is_none")]
    pub response_expectation: Option<String>,

    /// Notes about this contact
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub notes: Vec<String>,

    /// Effectiveness rating (if known)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub effectiveness: Option<EffectivenessRating>,
}

/// Network information for escalation context
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct NetworkInfo {
    /// Autonomous System Number
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn: Option<u32>,

    /// ASN name/description
    #[serde(skip_serializing_if = "Option::is_none")]
    pub asn_name: Option<String>,

    /// Cloud provider information
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_provider: Option<CloudProviderInfo>,

    /// Regional Internet Registry
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,

    /// Country of registration
    #[serde(skip_serializing_if = "Option::is_none")]
    pub country: Option<String>,
}

/// Cloud provider information
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct CloudProviderInfo {
    /// Provider name (e.g., "Amazon Web Services")
    pub provider: String,

    /// Specific service (if identifiable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service: Option<String>,

    /// Cloud region (if identifiable)
    #[serde(skip_serializing_if = "Option::is_none")]
    pub region: Option<String>,
}

/// Escalation strategy recommendation
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct EscalationStrategy {
    /// Recommended primary path
    pub primary_path: EscalationPathType,

    /// When to escalate to secondary path
    pub secondary_escalation_trigger: String,

    /// Recommended waiting time between escalation levels
    pub escalation_interval: String,

    /// Special considerations
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub considerations: Vec<String>,
}

/// Type of escalation path
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EscalationPathType {
    /// Focus on email infrastructure
    EmailInfrastructure,
    /// Focus on sender hosting
    SenderHosting,
    /// Use both paths simultaneously
    Dual,
}

/// Effectiveness rating for contacts
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum EffectivenessRating {
    /// Highly effective, fast response
    High,
    /// Moderately effective
    Medium,
    /// Lower effectiveness or slow response
    Low,
    /// Effectiveness unknown
    Unknown,
}

/// Query statistics and performance metrics
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct QueryStatistics {
    /// Number of DNS queries performed
    pub dns_queries: u32,

    /// Number of WHOIS servers queried
    pub whois_servers_queried: u32,

    /// Total processing time in milliseconds
    pub total_time_ms: u64,

    /// Breakdown of time spent in different phases
    pub time_breakdown: TimeBreakdown,

    /// Success/failure rates for different query types
    pub query_success_rates: QuerySuccessRates,

    /// Network-related statistics
    pub network_stats: NetworkStats,
}

/// Time breakdown for different processing phases
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct TimeBreakdown {
    /// Time spent on input parsing/validation
    pub input_processing_ms: u64,

    /// Time spent on DNS lookups
    pub dns_time_ms: u64,

    /// Time spent on WHOIS queries
    pub whois_time_ms: u64,

    /// Time spent on escalation path generation
    pub escalation_time_ms: u64,

    /// Time spent on output formatting
    pub output_formatting_ms: u64,
}

/// Success rates for different query types
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct QuerySuccessRates {
    /// DNS query success rate (0.0 - 1.0)
    pub dns_success_rate: f64,

    /// WHOIS query success rate (0.0 - 1.0)
    pub whois_success_rate: f64,

    /// Overall success rate (0.0 - 1.0)
    pub overall_success_rate: f64,
}

/// Network-related statistics
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct NetworkStats {
    /// Number of unique servers contacted
    pub unique_servers_contacted: u32,

    /// Average response time per query
    pub average_response_time_ms: u64,

    /// Number of timeouts encountered
    pub timeouts: u32,

    /// Number of failed connections
    pub failed_connections: u32,
}

/// Result summary and status
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub struct ResultSummary {
    /// Overall success status
    pub success: bool,

    /// Number of primary contacts found
    pub primary_contacts_found: u32,

    /// Whether escalation paths were generated
    pub escalation_paths_generated: bool,

    /// Quality assessment of results
    pub result_quality: ResultQuality,

    /// Recommendations for the user
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub recommendations: Vec<String>,

    /// Confidence in the overall result (0-100)
    pub overall_confidence: u8,
}

/// Quality assessment of the results
#[derive(Debug, Clone, Serialize, Deserialize, JsonSchema)]
#[serde(rename_all = "snake_case")]
pub enum ResultQuality {
    /// Excellent results with high confidence
    Excellent,
    /// Good results with reasonable confidence
    Good,
    /// Fair results with some limitations
    Fair,
    /// Poor results with low confidence
    Poor,
}

impl AbuseDetectorOutput {
    /// Create a new output structure with basic metadata
    pub fn new() -> Self {
        Self {
            metadata: OutputMetadata {
                tool_name: "abusedetector".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
                generated_at: chrono::Utc::now(),
                schema_version: "1.0.0".to_string(),
                schema_url: "https://raw.githubusercontent.com/ochronus/abusedetector/main/schema/output.json".to_string(),
            },
            input: InputInfo {
                ip_address: std::net::Ipv4Addr::new(0, 0, 0, 0),
                ip_source: IpSource::DirectInput,
                input_method: InputMethod::DirectIp,
                hostname: None,
                sender_domain: None,
                eml_file: None,
            },
            primary_contacts: Vec::new(),
            escalation_paths: None,
            statistics: QueryStatistics {
                dns_queries: 0,
                whois_servers_queried: 0,
                total_time_ms: 0,
                time_breakdown: TimeBreakdown {
                    input_processing_ms: 0,
                    dns_time_ms: 0,
                    whois_time_ms: 0,
                    escalation_time_ms: 0,
                    output_formatting_ms: 0,
                },
                query_success_rates: QuerySuccessRates {
                    dns_success_rate: 0.0,
                    whois_success_rate: 0.0,
                    overall_success_rate: 0.0,
                },
                network_stats: NetworkStats {
                    unique_servers_contacted: 0,
                    average_response_time_ms: 0,
                    timeouts: 0,
                    failed_connections: 0,
                },
            },
            warnings: Vec::new(),
            result: ResultSummary {
                success: false,
                primary_contacts_found: 0,
                escalation_paths_generated: false,
                result_quality: ResultQuality::Poor,
                recommendations: Vec::new(),
                overall_confidence: 0,
            },
        }
    }

    /// Convert dual escalation paths to structured format
    pub fn from_dual_escalation_path(&mut self, dual_path: &DualEscalationPath) {
        let email_infrastructure = EscalationPath {
            purpose: "Email Infrastructure".to_string(),
            description: "For stopping email sending abuse".to_string(),
            contacts: dual_path
                .get_email_infrastructure_contacts()
                .iter()
                .enumerate()
                .map(|(i, contact)| self.convert_escalation_contact(contact, i as u8))
                .collect(),
            network_info: None, // TODO: Add network info extraction
        };

        let sender_hosting = dual_path.get_sender_hosting_contacts().map(|contacts| {
            EscalationPath {
                purpose: "Sender Hosting".to_string(),
                description: "For stopping website/business abuse".to_string(),
                contacts: contacts
                    .iter()
                    .enumerate()
                    .map(|(i, contact)| self.convert_escalation_contact(contact, i as u8))
                    .collect(),
                network_info: None, // TODO: Add network info extraction
            }
        });

        self.escalation_paths = Some(EscalationPaths {
            email_infrastructure,
            sender_hosting: sender_hosting.clone(),
            generated_at: dual_path.generated_at,
            strategy: EscalationStrategy {
                primary_path: if sender_hosting.is_some() {
                    EscalationPathType::Dual
                } else {
                    EscalationPathType::EmailInfrastructure
                },
                secondary_escalation_trigger: "No response within 2-3 business days".to_string(),
                escalation_interval: "2-3 business days between levels".to_string(),
                considerations: vec![
                    "Email infrastructure path stops sending, hosting path stops business"
                        .to_string(),
                ],
            },
        });

        self.result.escalation_paths_generated = true;
    }

    /// Convert an escalation contact to structured format
    fn convert_escalation_contact(
        &self,
        contact: &EscalationContact,
        level: u8,
    ) -> EscalationContactInfo {
        EscalationContactInfo {
            level,
            contact_type: contact.contact_type.clone(),
            organization: contact.organization.clone(),
            email: contact.email.clone(),
            web_form: contact.web_form.clone(),
            response_expectation: contact.response_expectation.clone(),
            notes: contact.notes.clone(),
            effectiveness: Some(EffectivenessRating::Unknown), // TODO: Add effectiveness tracking
        }
    }

    /// Generate JSON schema for this output format
    pub fn generate_json_schema() -> Result<String> {
        let schema = schemars::schema_for!(AbuseDetectorOutput);
        Ok(serde_json::to_string_pretty(&schema)?)
    }

    /// Serialize to JSON
    pub fn to_json(&self) -> Result<String> {
        Ok(serde_json::to_string_pretty(self)?)
    }

    /// Serialize to YAML
    pub fn to_yaml(&self) -> Result<String> {
        Ok(serde_yaml::to_string(self)?)
    }
}

impl Default for AbuseDetectorOutput {
    fn default() -> Self {
        Self::new()
    }
}
