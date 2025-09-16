//! Escalation framework for abuse contact resolution.
//!
//! When primary abuse contacts don't respond, this module provides structured
//! escalation paths including hosting providers, domain registrars, ASN owners,
//! regional internet registries, and cloud providers.

use anyhow::Result;
use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::process::Command;
use std::str;

/// Represents different types of escalation contacts
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum EscalationContactType {
    /// Direct abuse contact from original source
    DirectAbuse,
    /// Hosting provider for the domain/service
    HostingProvider,
    /// Domain name registrar
    DomainRegistrar,
    /// Autonomous System Number owner (ISP/hosting company)
    AsnOwner,
    /// Regional Internet Registry (ARIN, RIPE, etc.)
    RegionalRegistry,
    /// Cloud provider (AWS, Azure, GCP, etc.)
    CloudProvider,
    /// Parent organization (university, corporation)
    ParentOrganization,
    /// Legal/regulatory authority
    LegalAuthority,
}

/// Represents a single escalation contact with metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationContact {
    pub contact_type: EscalationContactType,
    pub email: Option<String>,
    pub web_form: Option<String>,
    pub organization: String,
    pub notes: Vec<String>,
    pub response_expectation: Option<String>,
}

/// Complete escalation path for an IP/domain
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EscalationPath {
    pub ip: Ipv4Addr,
    pub domain: Option<String>,
    pub contacts: Vec<EscalationContact>,
    pub asn_info: Option<AsnInfo>,
    pub cloud_provider: Option<CloudProviderInfo>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// Dual escalation paths - one for email infrastructure, one for sender hosting
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DualEscalationPath {
    pub email_infrastructure: EscalationPath,
    pub sender_hosting: Option<EscalationPath>,
    pub sender_domain: Option<String>,
    pub generated_at: chrono::DateTime<chrono::Utc>,
}

/// ASN (Autonomous System Number) information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AsnInfo {
    pub asn: u32,
    pub name: String,
    pub country: Option<String>,
    pub registry: String, // ARIN, RIPE, APNIC, etc.
    pub abuse_contacts: Vec<String>,
}

/// Cloud provider information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CloudProviderInfo {
    pub provider: String,
    pub service: Option<String>,
    pub abuse_form: Option<String>,
    pub abuse_email: Option<String>,
    pub region: Option<String>,
}

/// Cloud provider IP ranges and metadata
static CLOUD_PROVIDERS: Lazy<HashMap<&'static str, CloudProviderInfo>> = Lazy::new(|| {
    let mut map = HashMap::new();

    // AWS
    map.insert(
        "aws",
        CloudProviderInfo {
            provider: "Amazon Web Services".to_string(),
            service: None,
            abuse_form: Some("https://aws.amazon.com/forms/report-abuse".to_string()),
            abuse_email: Some("abuse@amazonaws.com".to_string()),
            region: None,
        },
    );

    // Google Cloud
    map.insert(
        "gcp",
        CloudProviderInfo {
            provider: "Google Cloud Platform".to_string(),
            service: None,
            abuse_form: Some("https://cloud.google.com/support/docs/report-abuse".to_string()),
            abuse_email: Some("abuse@google.com".to_string()),
            region: None,
        },
    );

    // Microsoft Azure
    map.insert(
        "azure",
        CloudProviderInfo {
            provider: "Microsoft Azure".to_string(),
            service: None,
            abuse_form: Some("https://msrc.microsoft.com/report".to_string()),
            abuse_email: Some("abuse@microsoft.com".to_string()),
            region: None,
        },
    );

    // DigitalOcean
    map.insert(
        "digitalocean",
        CloudProviderInfo {
            provider: "DigitalOcean".to_string(),
            service: None,
            abuse_form: Some("https://www.digitalocean.com/company/contact/abuse".to_string()),
            abuse_email: Some("abuse@digitalocean.com".to_string()),
            region: None,
        },
    );

    // Cloudflare
    map.insert(
        "cloudflare",
        CloudProviderInfo {
            provider: "Cloudflare".to_string(),
            service: None,
            abuse_form: Some("https://abuse.cloudflare.com".to_string()),
            abuse_email: Some("abuse@cloudflare.com".to_string()),
            region: None,
        },
    );

    map
});

/// Regional Internet Registry information
static RIR_INFO: Lazy<HashMap<&'static str, (&'static str, &'static str)>> = Lazy::new(|| {
    let mut map = HashMap::new();
    map.insert(
        "ARIN",
        ("American Registry for Internet Numbers", "abuse@arin.net"),
    );
    map.insert("RIPE", ("Réseaux IP Européens", "abuse@ripe.net"));
    map.insert(
        "APNIC",
        ("Asia-Pacific Network Information Centre", "abuse@apnic.net"),
    );
    map.insert(
        "LACNIC",
        (
            "Latin America and Caribbean Network Information Centre",
            "abuse@lacnic.net",
        ),
    );
    map.insert(
        "AFRINIC",
        ("African Network Information Centre", "abuse@afrinic.net"),
    );
    map
});

/// Educational domain patterns
static EDU_PATTERNS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\.edu(\.[a-z]{2})?$|university|college|school").unwrap());

/// Government domain patterns
static GOV_PATTERNS: Lazy<Regex> =
    Lazy::new(|| Regex::new(r"(?i)\.gov(\.[a-z]{2})?$|\.mil(\.[a-z]{2})?$").unwrap());

impl EscalationPath {
    /// Create a new escalation path for the given IP and optional domain
    pub async fn new(
        ip: Ipv4Addr,
        domain: Option<String>,
        hostname: Option<String>,
    ) -> Result<Self> {
        let mut path = EscalationPath {
            ip,
            domain: domain.clone(),
            contacts: Vec::new(),
            asn_info: None,
            cloud_provider: None,
            generated_at: chrono::Utc::now(),
        };

        path.build_escalation_contacts(hostname).await?;
        Ok(path)
    }

    /// Build the complete escalation contact list
    async fn build_escalation_contacts(&mut self, hostname: Option<String>) -> Result<()> {
        // 1. Cloud provider detection (often most effective)
        if let Some(cloud_info) = self.detect_cloud_provider().await {
            self.cloud_provider = Some(cloud_info.clone());
            self.contacts.push(EscalationContact {
                contact_type: EscalationContactType::CloudProvider,
                email: cloud_info.abuse_email,
                web_form: cloud_info.abuse_form,
                organization: cloud_info.provider,
                notes: vec![
                    "Cloud providers typically respond quickly to abuse reports".to_string()
                ],
                response_expectation: Some("Usually responds quickly".to_string()),
            });
        }

        // 2. ASN owner lookup
        if let Some(asn_info) = self.lookup_asn_info().await {
            self.asn_info = Some(asn_info.clone());
            for abuse_email in &asn_info.abuse_contacts {
                self.contacts.push(EscalationContact {
                    contact_type: EscalationContactType::AsnOwner,
                    email: Some(abuse_email.clone()),
                    web_form: None,
                    organization: format!("AS{} - {}", asn_info.asn, asn_info.name),
                    notes: vec!["ASN owner controls the IP address space".to_string()],
                    response_expectation: Some("Standard business response time".to_string()),
                });
            }
        }

        // 3. Domain-based escalation (if domain provided or can be extracted from hostname)
        let escalation_domain = self.domain.clone().or_else(|| {
            // Try to extract domain from provided hostname
            if let Some(ref hostname) = hostname {
                // Remove trailing dot and extract domain
                let clean_hostname = hostname.trim_end_matches('.');
                Some(
                    self.extract_registrable_domain(clean_hostname)
                        .unwrap_or(clean_hostname.to_string()),
                )
            } else {
                None
            }
        });

        if let Some(domain) = escalation_domain {
            self.add_domain_escalation_contacts(&domain).await?;
        }

        // 4. Regional Internet Registry
        if let Some(ref asn_info) = self.asn_info {
            if let Some((name, email)) = RIR_INFO.get(asn_info.registry.as_str()) {
                self.contacts.push(EscalationContact {
                    contact_type: EscalationContactType::RegionalRegistry,
                    email: Some(email.to_string()),
                    web_form: None,
                    organization: name.to_string(),
                    notes: vec!["RIRs can pressure their members to respond".to_string()],
                    response_expectation: Some(
                        "May take longer due to bureaucratic process".to_string(),
                    ),
                });
            }
        }

        // 5. Legal/regulatory (for specific domains)
        self.add_legal_escalation_contacts();

        Ok(())
    }

    /// Detect cloud provider based on IP address
    async fn detect_cloud_provider(&self) -> Option<CloudProviderInfo> {
        // This is a simplified implementation. In practice, you'd want to:
        // 1. Maintain updated IP range databases for major cloud providers
        // 2. Use APIs where available (AWS has a JSON endpoint for their ranges)
        // 3. Check reverse DNS patterns

        // For now, we'll do basic reverse DNS pattern matching
        if let Ok(Some(hostname)) = crate::netutil::reverse_dns(self.ip, false).await {
            let hostname_lower = hostname.to_lowercase();

            if hostname_lower.contains("amazonaws.com") || hostname_lower.contains("aws") {
                return CLOUD_PROVIDERS.get("aws").cloned();
            } else if hostname_lower.contains("googleusercontent.com")
                || hostname_lower.contains("google")
            {
                return CLOUD_PROVIDERS.get("gcp").cloned();
            } else if hostname_lower.contains("azure") || hostname_lower.contains("microsoft") {
                return CLOUD_PROVIDERS.get("azure").cloned();
            } else if hostname_lower.contains("digitalocean") {
                return CLOUD_PROVIDERS.get("digitalocean").cloned();
            } else if hostname_lower.contains("cloudflare") {
                return CLOUD_PROVIDERS.get("cloudflare").cloned();
            }
        }

        None
    }

    /// Lookup ASN information for the IP address
    async fn lookup_asn_info(&self) -> Option<AsnInfo> {
        // First try regular WHOIS parsing
        if let Ok(whois_output) = self.query_whois_for_ip().await {
            if let Some(asn_info) = self.parse_whois_for_asn(&whois_output) {
                return Some(asn_info);
            }
        }

        // Fallback to Team Cymru ASN lookup
        if let Ok(cymru_info) =
            crate::whois::query_cymru_asn(self.ip, &crate::cli::Cli::from_args()).await
        {
            return Some(AsnInfo {
                asn: cymru_info.asn,
                name: cymru_info.as_name,
                country: Some(cymru_info.country),
                registry: cymru_info.registry,
                abuse_contacts: vec![], // Will be filled by WHOIS if available
            });
        }

        None
    }

    /// Query WHOIS for IP information
    async fn query_whois_for_ip(&self) -> Result<String> {
        let output = Command::new("whois")
            .arg(self.ip.to_string())
            .output()
            .map_err(|e| {
                anyhow::anyhow!(
                    "Failed to execute whois command: {}. Please ensure whois is installed.",
                    e
                )
            })?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("WHOIS query failed: {}", stderr))
        }
    }

    /// Parse WHOIS output to extract ASN information
    fn parse_whois_for_asn(&self, whois_text: &str) -> Option<AsnInfo> {
        let mut asn = None;
        let mut name = None;
        let mut country = None;
        let mut registry = None;
        let mut abuse_contacts = Vec::new();

        // Regex patterns for common WHOIS fields
        let asn_regex = Regex::new(r"(?i)(?:origin(?:as)?|asn?):\s*(?:as)?(\d+)").unwrap();
        let netname_regex = Regex::new(r"(?i)netname:\s*(.+)").unwrap();
        let name_regex = Regex::new(r"(?i)(?:org-?name|organization|org|descr):\s*(.+)").unwrap();
        let country_regex = Regex::new(r"(?i)country:\s*([A-Z]{2})").unwrap();
        let registry_regex = Regex::new(r"(?i)(?:source|registry):\s*(\w+)").unwrap();
        let abuse_regex = Regex::new(r"(?i)abuse[_-]?(?:c|contact|email)?:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})").unwrap();

        for line in whois_text.lines() {
            let line = line.trim();

            if let Some(cap) = asn_regex.captures(line) {
                if let Ok(asn_num) = cap[1].parse::<u32>() {
                    asn = Some(asn_num);
                }
            }

            // Prefer netname over generic name/org fields for hosting providers
            if let Some(cap) = netname_regex.captures(line) {
                name = Some(cap[1].trim().to_string());
            } else if let Some(cap) = name_regex.captures(line) {
                if name.is_none() {
                    // Take first occurrence only if netname wasn't found
                    name = Some(cap[1].trim().to_string());
                }
            }

            if let Some(cap) = country_regex.captures(line) {
                country = Some(cap[1].to_string());
            }

            if let Some(cap) = registry_regex.captures(line) {
                registry = Some(cap[1].to_uppercase());
            }

            if let Some(cap) = abuse_regex.captures(line) {
                abuse_contacts.push(cap[1].to_lowercase());
            }
        }

        // Determine registry from WHOIS server or default based on IP ranges
        if registry.is_none() {
            registry = Some(self.determine_registry_from_ip());
        }

        // If no abuse contacts found, try to construct generic ones
        if abuse_contacts.is_empty() {
            if let Some(ref org_name) = name {
                // Try common abuse email patterns
                if let Some(domain) = self.extract_domain_from_org_name(org_name) {
                    abuse_contacts.push(format!("abuse@{}", domain));
                }
            }
        }

        if let (Some(asn), Some(name)) = (asn, name) {
            Some(AsnInfo {
                asn,
                name,
                country,
                registry: registry.unwrap_or_else(|| "UNKNOWN".to_string()),
                abuse_contacts,
            })
        } else {
            None
        }
    }

    /// Determine RIR based on IP address ranges
    fn determine_registry_from_ip(&self) -> String {
        let octets = self.ip.octets();
        let first_octet = octets[0];

        // Simplified RIR allocation ranges (non-overlapping)
        match first_octet {
            1 => "APNIC".to_string(),
            2 => "RIPE".to_string(),
            3..=6 => "ARIN".to_string(),
            7..=13 => "ARIN".to_string(),
            14 => "APNIC".to_string(),
            15 => "ARIN".to_string(),
            16..=61 => "ARIN".to_string(),
            62..=63 => "RIPE".to_string(),
            64..=76 => "ARIN".to_string(),
            77..=95 => "RIPE".to_string(),
            96..=100 => "ARIN".to_string(),
            101..=103 => "APNIC".to_string(),
            104..=105 => "ARIN".to_string(),
            106..=126 => "APNIC".to_string(),
            127 => "ARIN".to_string(), // Loopback
            128..=162 => "ARIN".to_string(),
            163 => "APNIC".to_string(),
            164..=170 => "ARIN".to_string(),
            171 => "APNIC".to_string(),
            172..=174 => "ARIN".to_string(),
            175 => "APNIC".to_string(),
            176..=179 => "ARIN".to_string(),
            180 => "APNIC".to_string(),
            181 => "LACNIC".to_string(),
            182..=183 => "APNIC".to_string(),
            184..=191 => "ARIN".to_string(),
            192..=201 => "ARIN".to_string(),
            202..=203 => "APNIC".to_string(),
            204..=209 => "ARIN".to_string(),
            210..=211 => "APNIC".to_string(),
            212..=213 => "RIPE".to_string(),
            214..=216 => "ARIN".to_string(),
            217 => "RIPE".to_string(),
            218..=223 => "APNIC".to_string(),
            _ => "UNKNOWN".to_string(),
        }
    }

    /// Add domain-based escalation contacts
    async fn add_domain_escalation_contacts(&mut self, domain: &str) -> Result<()> {
        // Extract the registrable domain (handle subdomains)
        let registrable_domain = self.extract_registrable_domain(domain)?;

        // Check for special domain types
        if EDU_PATTERNS.is_match(domain) {
            self.contacts.push(EscalationContact {
                contact_type: EscalationContactType::ParentOrganization,
                email: Some(format!("security@{}", registrable_domain)),
                web_form: None,
                organization: format!("IT Security - {}", registrable_domain),

                notes: vec![
                    "Educational institutions often have dedicated security teams".to_string(),
                ],
                response_expectation: Some("Usually has dedicated security teams".to_string()),
            });
        } else if GOV_PATTERNS.is_match(domain) {
            self.contacts.push(EscalationContact {
                contact_type: EscalationContactType::LegalAuthority,
                email: Some("info@cisa.gov".to_string()),
                web_form: Some("https://www.cisa.gov/report".to_string()),
                organization: "CISA - Cybersecurity and Infrastructure Security Agency".to_string(),

                notes: vec!["Government domain - report to CISA".to_string()],
                response_expectation: Some("Government response time varies".to_string()),
            });
        }

        // Look up real registrar information - skip hosting provider lookup from nameservers
        // as it's often inaccurate for domain whois
        if let Ok(whois_output) = self.query_whois_for_domain(&registrable_domain).await {
            if let Some((registrar_org, registrar_email)) = self.parse_registrar_info(&whois_output)
            {
                self.contacts.push(EscalationContact {
                    contact_type: EscalationContactType::DomainRegistrar,
                    email: registrar_email,
                    web_form: None,
                    organization: registrar_org,

                    notes: vec!["Registrar can suspend domain if ToS violated".to_string()],
                    response_expectation: Some(
                        "Response time depends on registrar SLA".to_string(),
                    ),
                });
            }
        }

        Ok(())
    }

    /// Query WHOIS for domain information
    async fn query_whois_for_domain(&self, domain: &str) -> Result<String> {
        let output = Command::new("whois").arg(domain).output().map_err(|e| {
            anyhow::anyhow!(
                "Failed to execute whois command: {}. Please ensure whois is installed.",
                e
            )
        })?;

        if output.status.success() {
            Ok(String::from_utf8_lossy(&output.stdout).to_string())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            Err(anyhow::anyhow!("Domain WHOIS query failed: {}", stderr))
        }
    }

    /// Parse registrar information from domain WHOIS
    fn parse_registrar_info(&self, whois_text: &str) -> Option<(String, Option<String>)> {
        let mut registrar_name = None;
        let mut registrar_abuse_email = None;

        // More specific patterns for registrar information
        let registrar_regex = Regex::new(r"(?i)^\s*registrar:\s*(.+)").unwrap();
        let registrar_name_regex =
            Regex::new(r"(?i)^\s*registrar[_\s-]*(?:organization|name):\s*(.+)").unwrap();
        let abuse_email_regex = Regex::new(r"(?i)registrar[_\s-]*abuse[_\s-]*(?:contact[_\s-]*)?email:\s*([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})").unwrap();

        for line in whois_text.lines() {
            let line = line.trim();

            // Skip lines that are just referrals or descriptions
            if line.starts_with('%') || line.starts_with('#') || line.is_empty() {
                continue;
            }

            if let Some(cap) = registrar_name_regex.captures(line) {
                registrar_name = Some(cap[1].trim().to_string());
            } else if let Some(cap) = registrar_regex.captures(line) {
                if registrar_name.is_none() {
                    registrar_name = Some(cap[1].trim().to_string());
                }
            }

            if let Some(cap) = abuse_email_regex.captures(line) {
                registrar_abuse_email = Some(cap[1].to_lowercase());
            }
        }

        registrar_name.map(|name| (name, registrar_abuse_email))
    }

    /// Add legal/regulatory escalation contacts
    fn add_legal_escalation_contacts(&mut self) {
        // Skip FBI/legal contacts as they are not useful for typical abuse reporting
        // Users can escalate to legal authorities manually if needed
    }

    /// Extract registrable domain using public suffix list
    fn extract_registrable_domain(&self, domain: &str) -> Result<String> {
        // Simple domain extraction - in a real implementation you'd use public suffix list
        // For now, just extract the last two parts of the domain
        let clean_domain = domain.trim_end_matches('.');
        let parts: Vec<&str> = clean_domain.split('.').collect();
        if parts.len() >= 2 {
            Ok(format!(
                "{}.{}",
                parts[parts.len() - 2],
                parts[parts.len() - 1]
            ))
        } else {
            Ok(clean_domain.to_string())
        }
    }

    /// Extract domain from organization name
    fn extract_domain_from_org_name(&self, org_name: &str) -> Option<String> {
        // Look for domain-like patterns in organization names
        let domain_regex = Regex::new(r"([a-zA-Z0-9-]+\.(?:com|net|org|info|biz))").unwrap();
        if let Some(cap) = domain_regex.captures(org_name) {
            Some(cap[1].to_lowercase())
        } else {
            // Try to construct from company name
            let clean_name = org_name
                .to_lowercase()
                .replace(" ", "")
                .replace(",", "")
                .replace("inc", "")
                .replace("llc", "")
                .replace("ltd", "")
                .replace("corp", "")
                .replace("corporation", "");

            if clean_name.len() > 3 && clean_name.len() < 20 {
                Some(format!("{}.com", clean_name))
            } else {
                None
            }
        }
    }

    /// Get contacts by type
    #[allow(dead_code)]
    pub fn get_contacts_by_type(
        &self,
        contact_type: EscalationContactType,
    ) -> Vec<&EscalationContact> {
        self.contacts
            .iter()
            .filter(|c| c.contact_type == contact_type)
            .collect()
    }

    /// Get highest confidence contact for each type
    #[allow(dead_code)]
    pub fn get_best_contacts(&self) -> HashMap<EscalationContactType, &EscalationContact> {
        let mut best_contacts = HashMap::new();

        for contact in &self.contacts {
            match best_contacts.get(&contact.contact_type) {
                None => {
                    best_contacts.insert(contact.contact_type.clone(), contact);
                }
                Some(_existing) => {
                    // Keep the first contact of each type found
                    // Could be enhanced with more sophisticated selection logic
                }
            }
        }

        best_contacts
    }

    /// Sort contacts by recommended escalation order
    pub fn get_recommended_order(&self) -> Vec<&EscalationContact> {
        let mut contacts = self.contacts.iter().collect::<Vec<_>>();

        // Sort by type priority only
        contacts.sort_by(|a, b| {
            let a_priority = self.get_type_priority(&a.contact_type);
            let b_priority = self.get_type_priority(&b.contact_type);

            a_priority.cmp(&b_priority)
        });

        contacts
    }

    /// Get priority order for contact types (lower number = higher priority)
    fn get_type_priority(&self, contact_type: &EscalationContactType) -> u8 {
        match contact_type {
            EscalationContactType::DirectAbuse => 1,
            EscalationContactType::CloudProvider => 2,
            EscalationContactType::AsnOwner => 3,
            EscalationContactType::HostingProvider => 4,
            EscalationContactType::ParentOrganization => 5,
            EscalationContactType::DomainRegistrar => 6,
            EscalationContactType::RegionalRegistry => 7,
            EscalationContactType::LegalAuthority => 8,
        }
    }
}

impl DualEscalationPath {
    /// Create dual escalation paths from EML file analysis
    pub async fn from_eml_analysis(
        sending_ip: Ipv4Addr,
        sending_hostname: Option<String>,
        sender_domain: Option<String>,
    ) -> Result<Self> {
        // Create email infrastructure escalation path
        let email_infrastructure = EscalationPath::new(
            sending_ip,
            sending_hostname.clone().map(|h| {
                // Extract domain from hostname if possible
                h.split('.').skip(1).collect::<Vec<_>>().join(".")
            }),
            sending_hostname,
        )
        .await?;

        // Create sender hosting escalation path if we have a sender domain
        let sender_hosting = if let Some(ref domain) = sender_domain {
            match Self::create_sender_hosting_path(domain).await {
                Ok(path) => Some(path),
                Err(_) => None, // Don't fail if sender hosting lookup fails
            }
        } else {
            None
        };

        Ok(DualEscalationPath {
            email_infrastructure,
            sender_hosting,
            sender_domain,
            generated_at: chrono::Utc::now(),
        })
    }

    /// Create escalation path for sender's domain hosting
    async fn create_sender_hosting_path(domain: &str) -> Result<EscalationPath> {
        use trust_dns_resolver::{
            config::{ResolverConfig, ResolverOpts},
            TokioAsyncResolver,
        };

        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());

        // Try the original domain first
        let mut lookup_domain = domain.to_string();
        let mut lookup_result = Self::try_domain_lookup(&resolver, &lookup_domain).await;

        // If the original domain fails and it looks like a subdomain, try the parent domain
        if lookup_result.is_err() {
            let parts: Vec<&str> = domain.split('.').collect();
            if parts.len() >= 3 {
                // Check for common email/marketing subdomains
                let first_part = parts[0];
                if matches!(
                    first_part,
                    "em" | "email"
                        | "mail"
                        | "newsletter"
                        | "marketing"
                        | "promo"
                        | "campaign"
                        | "try"
                ) {
                    let parent_domain = parts[1..].join(".");
                    lookup_domain = parent_domain;
                    lookup_result = Self::try_domain_lookup(&resolver, &lookup_domain).await;
                }
            }
        }

        // If still failing, try the registrable domain
        if lookup_result.is_err() {
            let parts: Vec<&str> = lookup_domain.split('.').collect();
            if parts.len() >= 2 {
                let registrable = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
                if registrable != lookup_domain {
                    lookup_domain = registrable;
                    lookup_result = Self::try_domain_lookup(&resolver, &lookup_domain).await;
                }
            }
        }

        // Create escalation path based on results
        match lookup_result {
            Ok(ipv4) => {
                // Found hosting IP - create full escalation path with hosting and domain info
                EscalationPath::new(
                    ipv4,
                    Some(lookup_domain),
                    None, // No hostname for hosting lookup
                )
                .await
            }
            Err(_) => {
                // No hosting IP found - create domain-only escalation path
                Self::create_domain_only_escalation_path(&lookup_domain).await
            }
        }
    }

    /// Create escalation path based only on domain registration info (when no hosting IP available)
    async fn create_domain_only_escalation_path(domain: &str) -> Result<EscalationPath> {
        let mut path = EscalationPath {
            ip: std::net::Ipv4Addr::new(0, 0, 0, 0), // Placeholder IP for domain-only paths
            domain: Some(domain.to_string()),
            contacts: Vec::new(),
            asn_info: None,
            cloud_provider: None,
            generated_at: chrono::Utc::now(),
        };

        // Add domain-based escalation contacts directly
        path.add_domain_escalation_contacts(domain).await?;

        Ok(path)
    }

    /// Try to lookup A records for a specific domain
    async fn try_domain_lookup(
        resolver: &trust_dns_resolver::TokioAsyncResolver,
        domain: &str,
    ) -> Result<std::net::Ipv4Addr> {
        use trust_dns_resolver::proto::rr::{Name, RecordType};

        let domain_name = Name::from_ascii(domain)?;
        let response = resolver.lookup(domain_name, RecordType::A).await?;

        // Get the first A record IP
        if let Some(record) = response.iter().next() {
            if let Some(ip_addr) = record.as_a() {
                return Ok(ip_addr.0);
            }
        }

        Err(anyhow::anyhow!("No A records found"))
    }

    /// Get recommended escalation order prioritizing email vs hosting paths
    pub fn get_email_infrastructure_contacts(&self) -> &[EscalationContact] {
        &self.email_infrastructure.contacts
    }

    pub fn get_sender_hosting_contacts(&self) -> Option<&[EscalationContact]> {
        self.sender_hosting.as_ref().map(|p| p.contacts.as_slice())
    }
}

impl EscalationContactType {
    /// Get display name for the contact type
    pub fn display_name(&self) -> &'static str {
        match self {
            EscalationContactType::DirectAbuse => "Direct Abuse Contact",
            EscalationContactType::HostingProvider => "Hosting Provider",
            EscalationContactType::DomainRegistrar => "Domain Registrar",
            EscalationContactType::AsnOwner => "ASN Owner",
            EscalationContactType::RegionalRegistry => "Regional Registry",
            EscalationContactType::CloudProvider => "Cloud Provider",
            EscalationContactType::ParentOrganization => "Parent Organization",
            EscalationContactType::LegalAuthority => "Legal Authority",
        }
    }

    /// Get icon for the contact type
    pub fn icon(&self) -> &'static str {
        match self {
            EscalationContactType::DirectAbuse => "📮",
            EscalationContactType::HostingProvider => "🏢",
            EscalationContactType::DomainRegistrar => "📝",
            EscalationContactType::AsnOwner => "🌐",
            EscalationContactType::RegionalRegistry => "🏛️",
            EscalationContactType::CloudProvider => "☁️",
            EscalationContactType::ParentOrganization => "🏢",
            EscalationContactType::LegalAuthority => "⚖️",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_escalation_path_creation() {
        let ip = "8.8.8.8".parse().unwrap();
        let domain = Some("example.com".to_string());
        let hostname = Some("dns.google.".to_string());

        let path = EscalationPath::new(ip, domain, hostname).await.unwrap();

        assert_eq!(path.ip, ip);
        assert!(!path.contacts.is_empty());
    }

    #[test]
    fn test_contact_type_display() {
        assert_eq!(
            EscalationContactType::CloudProvider.display_name(),
            "Cloud Provider"
        );
        assert_eq!(EscalationContactType::CloudProvider.icon(), "☁️");
    }

    #[test]
    fn test_edu_domain_detection() {
        assert!(EDU_PATTERNS.is_match("university.edu"));
        assert!(EDU_PATTERNS.is_match("college.edu.au"));
        assert!(EDU_PATTERNS.is_match("mit.university"));
        assert!(!EDU_PATTERNS.is_match("example.com"));
    }

    #[test]
    fn test_gov_domain_detection() {
        assert!(GOV_PATTERNS.is_match("agency.gov"));
        assert!(GOV_PATTERNS.is_match("ministry.gov.uk"));
        assert!(GOV_PATTERNS.is_match("base.mil"));
        assert!(!GOV_PATTERNS.is_match("example.com"));
    }
}
