//! Shared analysis data structures consumed by façade and output formatters.

use std::net::Ipv4Addr;

use crate::escalation::DualEscalationPath;

/// Aggregated runtime toggles (CLI-independent).
#[derive(Clone, Debug)]
pub struct AnalysisOptions {
    pub use_hostname: bool,
    pub use_abusenet: bool,
    pub use_dns_soa: bool,
    pub use_whois_ip: bool,
    pub generate_escalation: bool,
    pub show_commands: bool,
    pub dns_timeout_secs: u64,
    /// Maximum number of concurrent network tasks (reverse DNS, reverse SOA, WHOIS)
    pub concurrency_limit: usize,
}

impl Default for AnalysisOptions {
    fn default() -> Self {
        Self {
            use_hostname: true,
            use_abusenet: true,
            use_dns_soa: true,
            use_whois_ip: true,
            generate_escalation: true,
            show_commands: false,
            dns_timeout_secs: 5,
            concurrency_limit: 3,
        }
    }
}

impl AnalysisOptions {
    /// Create an instance with all external network lookups disabled.
    pub fn minimal() -> Self {
        Self {
            use_hostname: false,
            use_abusenet: false,
            use_dns_soa: false,
            use_whois_ip: false,
            generate_escalation: false,
            show_commands: false,
            dns_timeout_secs: 5,
            concurrency_limit: 1,
        }
    }
}

/// Simplified domain representation (placeholder until dedicated newtype lands).
pub type Domain = String;

/// Alias to keep the façade API aligned with the planned naming.
pub type DualEscalation = DualEscalationPath;

/// Normalized result produced by the façade and consumed by formatters.
#[derive(Debug)]
pub struct AbuseAnalysis {
    pub ip: Option<Ipv4Addr>,
    pub sender_domain: Option<Domain>,
    pub hostname: Option<String>,
    pub primary_contacts: Vec<ContactEntry>,
    pub escalation: Option<DualEscalation>,
    pub stats: AnalysisStats,
    pub warnings: Vec<String>,
}

/// Simple contact representation for downstream formatters.
#[derive(Debug, Clone)]
pub struct ContactEntry {
    pub email: String,
    pub confidence: u8,
    pub is_abuse_specific: bool,
}

/// Statistical + diagnostic data about the analysis run.
#[derive(Debug)]
pub struct AnalysisStats {
    pub dns_queries: u32,
    pub whois_servers_queried: u32,
    pub duration_ms: u64,
}
