use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::time::Instant;

use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::{Name, RecordType},
    TokioAsyncResolver,
};

use crate::domain_utils;
use crate::emails::{soa_rname_to_email, EmailSet, FinalizeOptions};
use crate::eml::{self, IpExtractionResult};
use crate::errors::{AbuseDetectorError, Result};
use crate::escalation::DualEscalationPath;
use crate::netutil::{is_private, is_reserved};
use crate::output::{AbuseContact, AbuseResults, ContactMetadata, ContactSource, QueryMetadata};
// Sources pipeline (replaces removed net_orchestrator)
use crate::sources::{
    AbuseNetSource, ContactSource as _, DnsSoaSource, QueryContext, ReverseDnsSource,
    SourceOptions, WhoisIpSource,
};

/// Placeholder IP used during domain-only fallback (no usable IPv4 extracted).
const FALLBACK_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

/// High-level façade providing library-consumable entry points.
///
/// This abstracts the internal orchestration previously confined to the binary's
/// `main.rs` / `app` layer and offers a stable API for embedding inside other
/// Rust applications or services.
///
/// Design goals:
/// - Internal side-effects (printing, styling) are excluded.
/// - Focus on returning a normalized `AbuseAnalysis`.
/// - Provide both IP-centric and EML-centric entry points.
/// - Preserve (for now) the same discovery methodology as the CLI.
pub struct AbuseDetector;

impl AbuseDetector {
    /// Analyze a direct IPv4 input.
    pub async fn analyze_ip(ip: Ipv4Addr, opts: AnalysisOptions) -> Result<AbuseAnalysis> {
        if is_private(IpAddr::V4(ip)) {
            return Err(AbuseDetectorError::Configuration {
                message: format!("{ip} is a private (RFC1918) address"),
            });
        }
        if is_reserved(IpAddr::V4(ip)) {
            return Err(AbuseDetectorError::Configuration {
                message: format!("{ip} is a reserved address"),
            });
        }

        let start = Instant::now();
        let mut emails = EmailSet::new();
        let mut metadata = QueryMetadata {
            from_eml: false,
            eml_file: None,
            ..Default::default()
        };

        // Sources pipeline orchestration (reverse DNS, SOA, WHOIS, abuse.net)
        let source_opts = SourceOptions {
            enable_reverse_dns: opts.use_hostname,
            enable_dns_soa: opts.use_dns_soa,
            enable_whois: opts.use_whois_ip,
            enable_abusenet: opts.use_abusenet,
            enable_pattern_domains: false,
            dns_timeout_secs: opts.dns_timeout_secs,
            show_commands: opts.show_commands,
        };
        let mut ctx = QueryContext::new(Some(ip), None, None, source_opts).await?;
        // Assemble pipeline (order matters: hostname -> SOA -> WHOIS -> abuse.net)
        if opts.use_hostname {
            // PatternDomainSource not used here (no sender domain for direct IP path)
            let _ = ReverseDnsSource
                .collect(&mut ctx)
                .await
                .map(|raws| ctx.ingest(raws));
        }
        if opts.use_dns_soa {
            let _ = DnsSoaSource
                .collect(&mut ctx)
                .await
                .map(|raws| ctx.ingest(raws));
        }
        if opts.use_whois_ip {
            let _ = WhoisIpSource
                .collect(&mut ctx)
                .await
                .map(|raws| ctx.ingest(raws));
        }
        if opts.use_abusenet {
            let _ = AbuseNetSource
                .collect(&mut ctx)
                .await
                .map(|raws| ctx.ingest(raws));
        }

        // Merge context results
        metadata.hostname = ctx.reverse_hostname.clone();
        metadata.dns_queries = metadata.dns_queries.saturating_add(ctx.dns_queries);
        metadata.whois_servers_queried = metadata
            .whois_servers_queried
            .saturating_add(ctx.whois_servers);
        metadata.warnings.extend(ctx.warnings.clone());
        for (email, conf) in ctx.into_email_set().into_sorted() {
            emails.add_with_conf(email, conf);
        }

        // Finalization
        metadata.duration_ms = Some(start.elapsed().as_millis() as u64);
        let finalize_opts = FinalizeOptions {
            single_if_not_verbose: true,
            ..Default::default()
        };
        let finalized = emails.finalize(finalize_opts);

        let contacts: Vec<AbuseEmailContact> = finalized
            .iter()
            .map(|(email, confidence)| AbuseEmailContact {
                email: email.clone(),
                confidence: *confidence,
                is_abuse_specific: email.starts_with("abuse@"),
            })
            .collect();

        // Optional escalation
        let escalation = if opts.generate_escalation || contacts.is_empty() {
            match DualEscalationPath::from_eml_analysis(ip, metadata.hostname.clone(), None).await {
                Ok(p) => Some(p),
                Err(e) => {
                    metadata
                        .warnings
                        .push(format!("Escalation generation failed: {e}"));
                    None
                }
            }
        } else {
            None
        };

        Ok(AbuseAnalysis {
            input: InputMetadata {
                ip: Some(ip),
                ip_source: IpSource::Direct,
                eml_file: None,
                sender_domain: None,
                hostname: metadata.hostname.clone(),
                from_eml: false,
            },
            contacts,
            escalation,
            stats: AnalysisStats {
                dns_queries: metadata.dns_queries,
                whois_servers_queried: metadata.whois_servers_queried,
                duration_ms: metadata.duration_ms.unwrap_or(0),
                warnings: metadata.warnings,
            },
        })
    }

    /// Analyze an EML file, extracting the sender IPv4 if possible, otherwise
    /// falling back to a domain-based inference path.
    pub async fn analyze_eml(path: &Path, opts: AnalysisOptions) -> Result<AbuseAnalysis> {
        let start = Instant::now();
        // (removed unused variable path_str)
        let sender_domain = eml::extract_sender_domain_from_path(path).unwrap_or(None);

        // Attempt IP extraction
        let ip_result = eml::parse_eml_origin_ip_from_path(path);
        match ip_result {
            Ok(IpExtractionResult {
                ip: IpAddr::V4(v4),
                source: _,
            }) if !is_private(IpAddr::V4(v4)) && !is_reserved(IpAddr::V4(v4)) => {
                // Delegate to IP path but embed EML context
                let mut analysis = Self::analyze_ip(v4, opts.clone()).await?;
                analysis.input.from_eml = true;
                analysis.input.eml_file = Some(path.to_path_buf());
                analysis.input.sender_domain = sender_domain;
                analysis.input.ip_source = IpSource::EmlHeader;
                Ok(analysis)
            }
            Ok(IpExtractionResult { ip, .. }) => {
                // Non-IPv4 or unusable IPv4 => fallback
                domain_fallback(
                    sender_domain,
                    path,
                    &opts,
                    start,
                    format!("Unusable IP: {ip}"),
                )
                .await
            }
            Err(e) => {
                // Parse failure => fallback (if we have a domain)
                domain_fallback(sender_domain, path, &opts, start, format!("{e}")).await
            }
        }
    }
}

/// Domain fallback flow used when no valid public IPv4 could be extracted
/// from an EML file.
async fn domain_fallback(
    sender_domain: Option<String>,
    path: &Path,
    opts: &AnalysisOptions,
    start: Instant,
    reason: String,
) -> Result<AbuseAnalysis> {
    let mut emails = EmailSet::new();
    let mut metadata = QueryMetadata {
        from_eml: true,
        eml_file: Some(path.display().to_string()),
        ..Default::default()
    };

    let mut warnings = vec![format!(
        "Falling back to domain-based analysis (reason: {reason})"
    )];

    if let Some(ref domain) = sender_domain {
        if let Ok(patterns) = domain_utils::generate_abuse_emails(domain) {
            for p in patterns {
                emails.add_with_conf(p, 2);
            }
        }

        // abuse.net
        if opts.use_abusenet {
            metadata.abuse_net_queried = true;
            // abuse.net lookup skipped in façade (requires full CLI context)
            warnings.push("abuse.net lookup skipped in façade API".to_string());
        }

        // SOA traversal
        if opts.use_dns_soa {
            if let Err(e) = traverse_soa(domain, &mut emails, opts, &mut metadata).await {
                warnings.push(format!("DNS SOA traversal failed: {e}"));
            } else {
                metadata.dns_queries += 1;
            }
        }
    } else {
        warnings.push("No sender domain available; no contacts collected".to_string());
    }

    metadata.duration_ms = Some(start.elapsed().as_millis() as u64);
    let finalize_opts = FinalizeOptions {
        single_if_not_verbose: true,
        ..Default::default()
    };
    let finalized = emails.finalize(finalize_opts);

    let contacts: Vec<AbuseEmailContact> = finalized
        .iter()
        .map(|(email, confidence)| AbuseEmailContact {
            email: email.clone(),
            confidence: *confidence,
            is_abuse_specific: email.starts_with("abuse@"),
        })
        .collect();

    // Optional escalation (still permitted with fallback)
    let escalation = if opts.generate_escalation || contacts.is_empty() {
        match DualEscalationPath::from_eml_analysis(FALLBACK_IP, None, sender_domain.clone()).await
        {
            Ok(p) => Some(p),
            Err(e) => {
                warnings.push(format!("Escalation generation failed: {e}"));
                None
            }
        }
    } else {
        None
    };

    Ok(AbuseAnalysis {
        input: InputMetadata {
            ip: Some(FALLBACK_IP),
            ip_source: IpSource::DomainFallback,
            eml_file: Some(path.to_path_buf()),
            sender_domain,
            hostname: None,
            from_eml: true,
        },
        contacts,
        escalation,
        stats: AnalysisStats {
            dns_queries: metadata.dns_queries,
            whois_servers_queried: metadata.whois_servers_queried,
            duration_ms: metadata.duration_ms.unwrap_or(0),
            warnings,
        },
    })
}

/// Perform SOA traversal adding RNAME-derived emails.
async fn traverse_soa(
    base: &str,
    emails: &mut EmailSet,
    opts: &AnalysisOptions,
    metadata: &mut QueryMetadata,
) -> Result<()> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let mut labels: Vec<&str> = base.trim_end_matches('.').split('.').collect();

    while labels.len() > 1 {
        let candidate = labels.join(".");
        metadata.dns_queries += 1;

        match tokio::time::timeout(
            std::time::Duration::from_secs(opts.dns_timeout_secs),
            resolver.lookup(
                Name::from_ascii(&candidate).map_err(|e| AbuseDetectorError::Configuration {
                    message: format!("Invalid domain name: {e}"),
                })?,
                RecordType::SOA,
            ),
        )
        .await
        {
            Ok(Ok(answer)) => {
                if let Some(trust_dns_resolver::proto::rr::RData::SOA(soa)) = answer.iter().next() {
                    let rname = soa.rname().to_utf8();
                    if let Some(email) = soa_rname_to_email(rname.trim_end_matches('.')) {
                        emails.add_with_conf(&email, 1);
                    }
                }
            }
            Ok(Err(_)) => { /* ignored, soft fail */ }
            Err(_) => { /* timeout */ }
        }

        labels.remove(0);
    }

    Ok(())
}

/* ----------------------------- Public Data Model --------------------------- */

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

/// Stand-in structure to satisfy APIs expecting a subset of CLI behavior.
/// Only implements what the underlying functions read.
/// Normalized result produced by the façade.
#[derive(Debug)]
pub struct AbuseAnalysis {
    pub input: InputMetadata,
    pub contacts: Vec<AbuseEmailContact>,
    pub escalation: Option<DualEscalationPath>,
    pub stats: AnalysisStats,
}

impl AbuseAnalysis {
    /// Convert façade analysis into the legacy `AbuseResults` structure
    /// used by existing output formatting paths.
    pub fn to_abuse_results(&self) -> AbuseResults {
        let contacts = self
            .contacts
            .iter()
            .map(|c| AbuseContact {
                email: c.email.clone(),
                confidence: c.confidence,
                source: ContactSource::Unknown,
                metadata: ContactMetadata {
                    domain: c.email.split('@').nth(1).map(|s| s.to_string()),
                    is_abuse_specific: c.is_abuse_specific,
                    filtered: false,
                    notes: vec![],
                },
            })
            .collect::<Vec<_>>();

        AbuseResults {
            ip: self.input.ip.unwrap_or(FALLBACK_IP),
            contacts,
            metadata: QueryMetadata {
                from_eml: self.input.from_eml,
                eml_file: self
                    .input
                    .eml_file
                    .as_ref()
                    .map(|p| p.display().to_string()),
                hostname: self.input.hostname.clone(),
                dns_queries: self.stats.dns_queries,
                whois_servers_queried: self.stats.whois_servers_queried,
                warnings: self.stats.warnings.clone(),
                duration_ms: Some(self.stats.duration_ms),
                ..Default::default()
            },
        }
    }
}

/// Input context metadata.
#[derive(Debug)]
pub struct InputMetadata {
    pub ip: Option<Ipv4Addr>,
    pub ip_source: IpSource,
    pub eml_file: Option<PathBuf>,
    pub sender_domain: Option<String>,
    pub hostname: Option<String>,
    pub from_eml: bool,
}

/// Classification of how the IP (or lack thereof) was determined.
#[derive(Debug)]
pub enum IpSource {
    Direct,
    EmlHeader,
    DomainFallback,
}

/// Simple contact representation for the façade consumer.
#[derive(Debug, Clone)]
pub struct AbuseEmailContact {
    pub email: String,
    pub confidence: u32,
    pub is_abuse_specific: bool,
}

/// Statistical + diagnostic data about the analysis run.
#[derive(Debug)]
pub struct AnalysisStats {
    pub dns_queries: u32,
    pub whois_servers_queried: u32,
    pub duration_ms: u64,
    pub warnings: Vec<String>,
}
