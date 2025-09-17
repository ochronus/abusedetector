#![allow(clippy::too_many_lines)]
//! High-level application orchestration layer (canonical rewrite).
//!
//! This module provides the CLI-facing `App` façade. It parses input,
//! executes the unified sources pipeline (reverse DNS, SOA, WHOIS,
//! abuse.net) and then renders either structured (JSON/YAML) or
//! human-oriented output (styled / plain / batch).
//!
//! The legacy `net_orchestrator` has been removed; all contact and
//! metadata discovery flows through `sources` abstractions to enable
//! provenance, timing and extensibility.
//!
//! Major steps in `App::run`:
//!   1. Schema generation early-exit
//!   2. Config load / validation
//!   3. Input interpretation (direct IP or EML parsing)
//!   4. Unified sources pipeline execution
//!   5. Contact finalization & confidence summary
//!   6. Optional escalation path generation
//!   7. Structured output (JSON/YAML) or styled/plain fallback
//!
//! Domain‑fallback path (no public IPv4 derived from EML) handled in
//! `handle_domain_fallback`.
//!
//! NOTE: The code intentionally keeps user messaging stable (errors
//! vs warnings) to avoid surprising existing workflows.

use std::collections::HashMap;
use std::net::Ipv4Addr;
use std::time::Instant;

use trust_dns_resolver::{
    TokioAsyncResolver,
    config::{ResolverConfig, ResolverOpts},
    proto::rr::{Name, RecordType},
};

use crate::cli::{Cli, OutputFormat};
use crate::config::Config;
use crate::domain_utils;
use crate::emails::{EmailSet, FinalizeOptions, soa_rname_to_email};
use crate::eml::{self, IpExtractionResult};
use crate::errors::{AbuseDetectorError, Result};
use crate::escalation::DualEscalationPath;
use crate::netutil::{is_private, is_reserved};
use crate::output::{
    AbuseContact, AbuseResults, ContactMetadata, ContactSource, OutputFormat as LegacyOutputFormat,
    QueryMetadata,
};
use crate::sources::{
    AbuseNetSource, DnsSoaSource, PatternDomainSource, QueryContext, RawContact, ReverseDnsSource,
    SourceOptions, SourceProvenance, WhoisIpSource, map_provenance_to_contact_sources,
};
use crate::structured_output::{self, AbuseDetectorOutput};
use crate::styled_output::StyledFormatter;
use crate::whois::query_abuse_net;

/// Input resolution result (direct IP or EML-derived).
struct InputResolution {
    ip: Ipv4Addr,
    from_eml: bool,
    eml_file: Option<String>,
    sender_domain: Option<String>,
}

/// Result of attempting to interpret CLI input.
enum ResolvedInput {
    /// Direct IPv4 execution path.
    Ip(InputResolution),
    /// Domain fallback path when no public IPv4 can be derived from an EML file.
    DomainFallback {
        domain: String,
        eml_path: String,
        sender_domain: Option<String>,
    },
}

/// Outcome of the unified sources orchestration before final formatting.
struct OrchestrationOutcome {
    emails: EmailSet,
    metadata: QueryMetadata,
    provenance_lookup: HashMap<String, Vec<structured_output::ContactSource>>,
    source_timings: Option<Vec<crate::sources::SourceTiming>>,
    fallback_added: bool,
}

/// Placeholder IP used when no public IPv4 could be extracted (domain fallback mode)
const FALLBACK_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

/// Application façade.
pub struct App;

impl App {
    /// Execute the end-to-end abuse contact discovery workflow.
    ///
    /// Returns: intended process exit code (0 = success, 1 = user/input error).
    pub async fn run(cli: &Cli) -> Result<i32> {
        if Self::maybe_print_schema(cli)? {
            return Ok(0);
        }
        if !Self::validate_config(cli)? {
            return Ok(0);
        }

        let start_time = Instant::now();

        let resolved = Self::resolve_input(cli).await?;

        let InputResolution {
            ip,
            from_eml,
            eml_file,
            sender_domain,
        } = match resolved {
            ResolvedInput::Ip(res) => res,
            ResolvedInput::DomainFallback {
                domain,
                eml_path,
                sender_domain,
            } => {
                return Self::handle_domain_fallback(cli, &domain, &eml_path, sender_domain).await;
            }
        };

        if let Some(code) = Self::enforce_public_ip(cli, ip)? {
            return Ok(code);
        }

        let OrchestrationOutcome {
            emails,
            mut metadata,
            provenance_lookup,
            source_timings,
            fallback_added,
        } = Self::run_sources_pipeline(cli, ip, &sender_domain, &eml_file, from_eml).await?;

        let hostname = metadata.hostname.clone();

        let finalize_opts = FinalizeOptions {
            single_if_not_verbose: !cli.show_internal() && !cli.batch,
            ..Default::default()
        };
        let email_results = emails.finalize(finalize_opts);

        if cli.is_trace() {
            eprintln!(
                "[trace] Finalized {} contact(s){}",
                email_results.len(),
                if fallback_added {
                    " (includes fallback contact)"
                } else {
                    ""
                }
            );
        }

        let dual_escalation = if cli.should_show_escalation() || email_results.is_empty() {
            match DualEscalationPath::from_eml_analysis(ip, hostname.clone(), sender_domain.clone())
                .await
            {
                Ok(p) => Some(p),
                Err(e) => {
                    if cli.warn_enabled() {
                        eprintln!("Warning: Could not generate escalation paths: {e}");
                    }
                    None
                }
            }
        } else {
            None
        };

        metadata.duration_ms = Some(start_time.elapsed().as_millis() as u64);

        if Self::maybe_render_structured(
            cli,
            ip,
            &hostname,
            &sender_domain,
            &eml_file,
            from_eml,
            &email_results,
            &provenance_lookup,
            &metadata,
            &source_timings,
            dual_escalation.as_ref(),
        )? {
            return Ok(0);
        }

        Self::render_human(
            cli,
            ip,
            &hostname,
            &email_results,
            &metadata,
            dual_escalation.as_ref(),
        )?;

        Ok(0)
    }
}

/// Render human-oriented (styled/plain/batch) output after structured path short‑circuits.
impl App {
    fn render_human(
        cli: &Cli,
        ip: Ipv4Addr,
        _hostname: &Option<String>,
        email_results: &[(String, u32)],
        metadata: &QueryMetadata,
        dual: Option<&DualEscalationPath>,
    ) -> Result<()> {
        // Build AbuseResults adapter
        let contacts: Vec<AbuseContact> = email_results
            .iter()
            .map(|(email, confidence)| AbuseContact {
                email: email.clone(),
                confidence: *confidence,
                source: ContactSource::Unknown,
                metadata: ContactMetadata {
                    domain: email.split('@').nth(1).map(|s| s.to_string()),
                    is_abuse_specific: email.starts_with("abuse@"),
                    filtered: false,
                    notes: vec![],
                },
            })
            .collect();
        let results = AbuseResults {
            ip,
            contacts,
            metadata: metadata.clone(),
        };

        // Styled
        if cli.should_use_styling()
            && !cli.batch
            && !matches!(cli.output_format(), OutputFormat::Json | OutputFormat::Yaml)
        {
            let formatter = if cli.no_color {
                StyledFormatter::without_colors()
            } else {
                StyledFormatter::new()
            };
            if formatter
                .print_results_with_dual_escalation(&results, dual)
                .is_ok()
            {
                return Ok(());
            }
        }

        // Plain / batch
        let legacy_format = if cli.batch {
            LegacyOutputFormat::Batch
        } else if cli.show_internal() {
            LegacyOutputFormat::Text {
                show_confidence: true,
                show_sources: true,
                show_metadata: cli.is_trace(),
            }
        } else {
            LegacyOutputFormat::Text {
                show_confidence: false,
                show_sources: false,
                show_metadata: false,
            }
        };
        let formatter = crate::output::create_formatter(&legacy_format);
        if let Ok(s) = formatter.format_results(&results) {
            print!("{s}");
        }

        // Escalation listing (plain mode)
        if let Some(paths) = dual {
            if cli.should_show_escalation() {
                println!("\n--- EMAIL INFRASTRUCTURE ESCALATION PATH ---");
                for (i, c) in paths.get_email_infrastructure_contacts().iter().enumerate() {
                    println!(
                        "{}. {} - {}",
                        i + 1,
                        c.contact_type.display_name(),
                        c.organization
                    );
                    if let Some(ref email) = c.email {
                        println!("   Email: {email}");
                    }
                    if let Some(ref form) = c.web_form {
                        println!("   Web Form: {form}");
                    }
                    println!();
                }
                if let Some(hosting) = paths.get_sender_hosting_contacts() {
                    if !hosting.is_empty() {
                        println!("\n--- SENDER HOSTING ESCALATION PATH ---");
                        for (i, c) in hosting.iter().enumerate() {
                            println!(
                                "{}. {} - {}",
                                i + 1,
                                c.contact_type.display_name(),
                                c.organization
                            );
                            if let Some(ref email) = c.email {
                                println!("   Email: {email}");
                            }
                            if let Some(ref form) = c.web_form {
                                println!("   Web Form: {form}");
                            }
                            println!();
                        }
                    }
                }
            }
        }

        if results.contacts.is_empty() && cli.error_enabled() && dual.is_none() {
            eprintln!(
                "No abuse contacts discovered and no escalation paths available (try --show-escalation)."
            );
        }
        Ok(())
    }
}

/// Helper: schema generation early-exit
impl App {
    fn maybe_print_schema(cli: &Cli) -> Result<bool> {
        if cli.generate_schema {
            match AbuseDetectorOutput::generate_json_schema() {
                Ok(schema) => {
                    println!("{schema}");
                }
                Err(e) => {
                    eprintln!("Error generating JSON schema: {e}");
                }
            }
            return Ok(true);
        }
        Ok(false)
    }

    fn validate_config(cli: &Cli) -> Result<bool> {
        let mut config = Config::from_env();
        config.merge_with_cli(cli);
        if let Err(e) = config.validate() {
            if cli.error_enabled() {
                eprintln!("Configuration error: {e}");
            }
            return Ok(false);
        }
        Ok(true)
    }

    fn enforce_public_ip(cli: &Cli, ip: Ipv4Addr) -> Result<Option<i32>> {
        if is_private(std::net::IpAddr::V4(ip)) {
            if cli.error_enabled() {
                eprintln!("Error: {ip} is a private IP address (RFC1918). Cannot proceed.");
            }
            return Ok(Some(0));
        }
        if is_reserved(std::net::IpAddr::V4(ip)) {
            if cli.error_enabled() {
                eprintln!("Error: {ip} is a reserved IP address. Cannot proceed.");
            }
            return Ok(Some(0));
        }
        Ok(None)
    }

    async fn resolve_input(cli: &Cli) -> Result<ResolvedInput> {
        if let Some(ref eml_path) = cli.eml {
            if cli.is_trace() {
                eprintln!("Deriving originating IP from EML file: {eml_path}");
            }
            let sender_domain = eml::extract_sender_domain_from_path(eml_path)
                .ok()
                .flatten();
            if let Some(ref d) = sender_domain {
                if !cli.is_structured_output() {
                    println!("Detected sender domain (from EML): {d}");
                }
            }
            match eml::parse_eml_origin_ip_from_path(eml_path) {
                Ok(IpExtractionResult {
                    ip: std::net::IpAddr::V4(v4),
                    source,
                    confidence: _,
                }) => {
                    if cli.is_trace() {
                        eprintln!("Originating IP extracted from EML: {v4} (source: {source})");
                    }
                    if !cli.is_structured_output() {
                        println!("Detected sender IP (from EML): {v4}");
                    }
                    return Ok(ResolvedInput::Ip(InputResolution {
                        ip: v4,
                        from_eml: true,
                        eml_file: Some(eml_path.clone()),
                        sender_domain,
                    }));
                }
                Ok(IpExtractionResult {
                    ip: non_v4,
                    source,
                    confidence: _,
                }) => {
                    if cli.error_enabled() {
                        eprintln!(
                            "Error extracting IP: No public IPv4 found (extracted {non_v4}; source: {source})"
                        );
                    } else if cli.warn_enabled() {
                        eprintln!(
                            "Info: extracted non-IPv4 ({non_v4}; source: {source}); domain fallback"
                        );
                    }
                    if let Some(domain) = sender_domain.clone() {
                        if !cli.is_structured_output() {
                            println!(
                                "Falling back to domain-based abuse contact lookup for: {domain}"
                            );
                        }
                        return Ok(ResolvedInput::DomainFallback {
                            domain,
                            eml_path: eml_path.clone(),
                            sender_domain,
                        });
                    }
                    return Err(AbuseDetectorError::Configuration {
                        message: "No public IPv4 found and no sender domain available (EML path)"
                            .into(),
                    });
                }
                Err(e) => {
                    let msg = e.to_string();
                    if cli.error_enabled() {
                        if msg.to_ascii_lowercase().contains("no public ip") {
                            eprintln!("Error extracting IP: No public IPv4 found in EML headers");
                        } else {
                            eprintln!("Error extracting IP: {msg}");
                        }
                    } else if cli.warn_enabled() {
                        eprintln!("Warning: Could not extract IP from EML ({eml_path}): {msg}");
                    }
                    if let Some(domain) = sender_domain.clone() {
                        if !cli.is_structured_output() {
                            println!(
                                "Falling back to domain-based abuse contact lookup for: {domain}"
                            );
                        }
                        return Ok(ResolvedInput::DomainFallback {
                            domain,
                            eml_path: eml_path.clone(),
                            sender_domain,
                        });
                    }
                    return Err(AbuseDetectorError::Configuration {
                        message: "No public IPv4 found and no sender domain available (EML path)"
                            .into(),
                    });
                }
            }
        } else if let Some(ref ip_str) = cli.ip {
            let ip = ip_str
                .parse::<Ipv4Addr>()
                .map_err(|_| AbuseDetectorError::Configuration {
                    message: format!("Invalid IPv4 address format: {ip_str}"),
                })?;
            return Ok(ResolvedInput::Ip(InputResolution {
                ip,
                from_eml: false,
                eml_file: None,
                sender_domain: None,
            }));
        }
        Err(AbuseDetectorError::Configuration {
            message: "Either an IP address or --eml file must be provided.".into(),
        })
    }

    async fn run_sources_pipeline(
        cli: &Cli,
        ip: Ipv4Addr,
        sender_domain: &Option<String>,
        eml_file: &Option<String>,
        from_eml: bool,
    ) -> Result<OrchestrationOutcome> {
        let source_opts = SourceOptions {
            enable_reverse_dns: !cli.no_use_hostname,
            enable_dns_soa: !cli.no_use_dns_soa,
            enable_whois: !cli.no_use_whois_ip,
            enable_abusenet: !cli.no_use_abusenet,
            enable_pattern_domains: sender_domain.is_some(),
            dns_timeout_secs: 5,
            show_commands: cli.show_commands,
        };
        let mut ctx = QueryContext::new(
            Some(ip),
            sender_domain.clone(),
            eml_file.as_ref().map(std::path::PathBuf::from),
            source_opts,
        )
        .await?;
        // Phase 1 ordered
        let mut phase1: Vec<Box<dyn crate::sources::ContactSource>> = Vec::new();
        if sender_domain.is_some() {
            phase1.push(Box::new(PatternDomainSource));
        }
        if !cli.no_use_hostname {
            phase1.push(Box::new(ReverseDnsSource));
        }
        for s in phase1 {
            let _ = s.collect(&mut ctx).await.map(|r| ctx.ingest(r));
        }
        if sender_domain.is_none() {
            if let Some(effective) = ctx.effective_domain() {
                if let Ok(patterns) = domain_utils::generate_abuse_emails(&effective) {
                    let raws = patterns
                        .into_iter()
                        .map(|email| {
                            RawContact::new(email, 2, SourceProvenance::Pattern)
                                .with_pattern()
                                .with_note("pattern heuristic (reverse hostname)")
                        })
                        .collect();
                    ctx.ingest(raws);
                }
            }
        }
        // Phase 2 parallel (DNS SOA, WHOIS, abuse.net)
        let mut builders: Vec<
            Box<dyn Fn() -> Box<dyn crate::sources::ContactSource + Send + Sync> + Send + Sync>,
        > = Vec::new();
        if !cli.no_use_dns_soa {
            builders.push(Box::new(|| {
                Box::new(DnsSoaSource) as Box<dyn crate::sources::ContactSource + Send + Sync>
            }));
        }
        if !cli.no_use_whois_ip {
            builders.push(Box::new(|| {
                Box::new(WhoisIpSource) as Box<dyn crate::sources::ContactSource + Send + Sync>
            }));
        }
        if !cli.no_use_abusenet {
            builders.push(Box::new(|| {
                Box::new(AbuseNetSource) as Box<dyn crate::sources::ContactSource + Send + Sync>
            }));
        }
        if !builders.is_empty() {
            crate::sources::run_parallel_phase2(&mut ctx, builders, 3).await?;
        }
        let provenance_lookup = map_provenance_to_contact_sources(ctx.provenance());
        let hostname = ctx.reverse_hostname.clone();
        let dns_queries = ctx.dns_queries;
        let whois_servers = ctx.whois_servers;
        let warnings = ctx.warnings.clone();
        let timings = ctx.source_timings.clone();

        let collected = ctx.into_email_set().into_sorted();
        let mut emails = EmailSet::new();
        let mut fallback_added = false;

        if collected.is_empty() {
            fallback_added = true;
            if let Some(ref domain) = sender_domain
                .clone()
                .or_else(|| hostname.clone())
                .and_then(|h| domain_utils::extract_registrable_domain(&h))
            {
                emails.add_with_conf(format!("abuse@{}", domain), 1);
            } else {
                emails.add_with_conf(format!("abuse@{}", ip), 1);
            }
        } else {
            for (email, conf) in collected {
                emails.add_with_conf(email, conf);
            }
        }
        let metadata = QueryMetadata {
            from_eml,
            eml_file: eml_file.clone(),
            hostname,
            dns_queries,
            whois_servers_queried: whois_servers,
            warnings,
            ..Default::default()
        };
        Ok(OrchestrationOutcome {
            emails,
            metadata,
            provenance_lookup,
            source_timings: if timings.is_empty() {
                None
            } else {
                Some(timings)
            },
            fallback_added,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn maybe_render_structured(
        cli: &Cli,
        ip: Ipv4Addr,
        hostname: &Option<String>,
        sender_domain: &Option<String>,
        eml_file: &Option<String>,
        from_eml: bool,
        email_results: &[(String, u32)],
        provenance_lookup: &HashMap<String, Vec<structured_output::ContactSource>>,
        metadata: &QueryMetadata,
        source_timings: &Option<Vec<crate::sources::SourceTiming>>,
        dual: Option<&DualEscalationPath>,
    ) -> Result<bool> {
        if !matches!(cli.output_format(), OutputFormat::Json | OutputFormat::Yaml) {
            return Ok(false);
        }

        let input_ctx = structured_output::StructuredInputContext {
            ip_address: ip,
            ip_source: if from_eml {
                structured_output::IpSource::EmailHeader {
                    header_field: "Email-derived IPv4".to_string(),
                    priority: 1,
                }
            } else {
                structured_output::IpSource::DirectInput
            },
            input_method: if from_eml {
                structured_output::InputMethod::EmlFile
            } else {
                structured_output::InputMethod::DirectIp
            },
            hostname: hostname.clone(),
            sender_domain: sender_domain.clone(),
            eml_file: eml_file.clone(),
        };

        let contacts: Vec<structured_output::Contact> = email_results
            .iter()
            .map(|(email, confidence)| {
                let domain = email.split('@').nth(1).map(|s| s.to_string());
                let sources = provenance_lookup
                    .get(&email.to_ascii_lowercase())
                    .cloned()
                    .unwrap_or_else(|| vec![structured_output::ContactSource::MultipleConfirmed]);
                structured_output::Contact {
                    email: email.clone(),
                    domain,
                    contact_type: if email.starts_with("abuse@") {
                        structured_output::ContactType::Abuse
                    } else if email.starts_with("security@") {
                        structured_output::ContactType::Security
                    } else if email.starts_with("hostmaster@") {
                        structured_output::ContactType::Hostmaster
                    } else if email.starts_with("admin@") {
                        structured_output::ContactType::Admin
                    } else if email.starts_with("tech@") {
                        structured_output::ContactType::Tech
                    } else {
                        structured_output::ContactType::Generic
                    },
                    sources,
                    confidence: *confidence as u8,
                    is_abuse_specific: email.starts_with("abuse@"),
                    metadata: None,
                }
            })
            .collect();

        let mut stats_ctx = structured_output::StructuredStatsContext {
            dns_queries: metadata.dns_queries,
            whois_servers_queried: metadata.whois_servers_queried,
            total_time_ms: metadata.duration_ms.unwrap_or(0),
            confidence_summary: email_results
                .iter()
                .map(|(e, c)| structured_output::ConfidenceEntry {
                    email: e.clone(),
                    confidence: *c,
                })
                .collect(),
            ..Default::default()
        };

        if let Some(timings) = source_timings {
            let (mut dns_ms, mut whois_ms) = (0u64, 0u64);
            let (mut dns_total, mut dns_ok, mut whois_total, mut whois_ok) =
                (0u32, 0u32, 0u32, 0u32);
            for t in timings {
                match t.name {
                    "reverse-dns" | "dns-soa" => {
                        dns_total += 1;
                        if t.success {
                            dns_ok += 1;
                        }
                        dns_ms = dns_ms.saturating_add(t.duration_ms as u64);
                    }
                    "whois-ip" | "abuse-net" => {
                        whois_total += 1;
                        if t.success {
                            whois_ok += 1;
                        }
                        whois_ms = whois_ms.saturating_add(t.duration_ms as u64);
                    }
                    _ => {}
                }
            }
            if dns_total > 0 {
                stats_ctx.dns_success_rate = Some(dns_ok as f64 / dns_total as f64);
            }
            if whois_total > 0 {
                stats_ctx.whois_success_rate = Some(whois_ok as f64 / whois_total as f64);
            }
            let total_tasks = dns_total + whois_total;
            if total_tasks > 0 {
                stats_ctx.overall_success_rate =
                    Some((dns_ok + whois_ok) as f64 / total_tasks as f64);
            }
            stats_ctx.dns_time_ms = Some(dns_ms);
            stats_ctx.whois_time_ms = Some(whois_ms);
        }

        let output = structured_output::StructuredOutputBuilder::new()
            .with_input(&input_ctx)
            .with_contacts(&contacts)
            .with_stats(&stats_ctx)
            .with_warnings(&metadata.warnings)
            .with_escalation(dual)
            .finish();

        let rendered = match cli.output_format() {
            OutputFormat::Json => output.to_json(),
            OutputFormat::Yaml => output.to_yaml(),
            _ => unreachable!(),
        };
        match rendered {
            Ok(s) => println!("{s}"),
            Err(e) => eprintln!("Error formatting structured output: {e}"),
        }
        Ok(true)
    }

    /// Handle the domain fallback path when no public IPv4 is available.
    async fn handle_domain_fallback(
        cli: &Cli,
        domain: &str,
        eml_path: &str,
        sender_domain: Option<String>,
    ) -> Result<i32> {
        let start = Instant::now();
        let mut emails = EmailSet::new();
        let mut metadata = QueryMetadata {
            from_eml: true,
            eml_file: Some(eml_path.to_string()),
            ..Default::default()
        };

        if let Ok(patterns) = domain_utils::generate_abuse_emails(domain) {
            for addr in patterns {
                emails.add_with_conf(addr, 2);
            }
        }

        if !cli.no_use_abusenet {
            metadata.abuse_net_queried = true;
            if let Err(e) = query_abuse_net(domain, &mut emails, cli).await {
                if cli.warn_enabled() {
                    eprintln!("Warning: abuse.net query failed for {domain}: {e}");
                }
            }
        }

        if !cli.no_use_dns_soa {
            if cli.is_trace() {
                eprintln!("DNS SOA traversal (domain fallback): {domain}");
            }
            if let Err(e) = traverse_soa(domain, &mut emails, cli, &mut metadata).await {
                if cli.warn_enabled() {
                    eprintln!("Warning: DNS SOA traversal failed for {domain}: {e}");
                }
            } else {
                metadata.dns_queries += 1;
            }
        }

        metadata.duration_ms = Some(start.elapsed().as_millis() as u64);

        let finalize_opts = FinalizeOptions {
            single_if_not_verbose: !cli.show_internal() && !cli.batch,
            ..Default::default()
        };
        let finalized = emails.finalize(finalize_opts);

        let contacts: Vec<AbuseContact> = finalized
            .iter()
            .map(|(email, confidence)| AbuseContact {
                email: email.clone(),
                confidence: *confidence,
                source: ContactSource::Unknown,
                metadata: ContactMetadata {
                    domain: email.split('@').nth(1).map(|s| s.to_string()),
                    is_abuse_specific: email.starts_with("abuse@"),
                    filtered: false,
                    notes: vec!["Domain fallback (no originating IPv4)".to_string()],
                },
            })
            .collect();

        let results = AbuseResults {
            ip: FALLBACK_IP,
            contacts,
            metadata: metadata.clone(),
        };

        let dual_escalation = if cli.should_show_escalation() || results.contacts.is_empty() {
            match DualEscalationPath::from_eml_analysis(FALLBACK_IP, None, sender_domain.clone())
                .await
            {
                Ok(p) => Some(p),
                Err(e) => {
                    if cli.warn_enabled() {
                        eprintln!("Warning: Could not generate escalation paths: {e}");
                    }
                    None
                }
            }
        } else {
            None
        };

        match cli.output_format() {
            OutputFormat::Json | OutputFormat::Yaml => {
                let input_ctx = structured_output::StructuredInputContext {
                    ip_address: FALLBACK_IP,
                    ip_source: structured_output::IpSource::EmailHeader {
                        header_field: "Domain fallback (no IPv4 found)".to_string(),
                        priority: 0,
                    },
                    input_method: structured_output::InputMethod::EmlFile,
                    hostname: None,
                    sender_domain: sender_domain.clone(),
                    eml_file: Some(eml_path.to_string()),
                };

                let contacts: Vec<structured_output::Contact> = finalized
                    .iter()
                    .map(|(email, confidence)| structured_output::Contact {
                        email: email.clone(),
                        domain: email.split('@').nth(1).map(|s| s.to_string()),
                        contact_type: if email.starts_with("abuse@") {
                            structured_output::ContactType::Abuse
                        } else if email.starts_with("security@") {
                            structured_output::ContactType::Security
                        } else {
                            structured_output::ContactType::Generic
                        },
                        sources: vec![structured_output::ContactSource::MultipleConfirmed],
                        confidence: *confidence as u8,
                        is_abuse_specific: email.starts_with("abuse@"),
                        metadata: None,
                    })
                    .collect();

                let stats_ctx = structured_output::StructuredStatsContext {
                    dns_queries: metadata.dns_queries,
                    whois_servers_queried: metadata.whois_servers_queried,
                    total_time_ms: metadata.duration_ms.unwrap_or(0),
                    confidence_summary: finalized
                        .iter()
                        .map(|(e, c)| structured_output::ConfidenceEntry {
                            email: e.clone(),
                            confidence: *c,
                        })
                        .collect(),
                    ..Default::default()
                };

                let output = structured_output::StructuredOutputBuilder::new()
                    .with_input(&input_ctx)
                    .with_contacts(&contacts)
                    .with_stats(&stats_ctx)
                    .with_warnings(&metadata.warnings)
                    .with_escalation(dual_escalation.as_ref())
                    .finish();

                let rendered = match cli.output_format() {
                    OutputFormat::Json => output.to_json(),
                    OutputFormat::Yaml => output.to_yaml(),
                    _ => unreachable!(),
                };

                match rendered {
                    Ok(s) => println!("{s}"),
                    Err(e) => eprintln!("Error formatting structured output: {e}"),
                }
                return Ok(0);
            }
            _ => {}
        }

        if cli.should_use_styling() && !cli.batch {
            println!(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            );
            println!("  🚨 Abuse Contacts for Domain {domain} (from EML)");
            println!("  📧 EML File: {eml_path}");
            println!(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            );
            if !results.contacts.is_empty() {
                println!("\n  📮 Primary Abuse Contacts\n");
                for (i, c) in results.contacts.iter().enumerate() {
                    println!("    {}. {}", i + 1, c.email);
                    if let Some(ref dom) = c.metadata.domain {
                        println!("       ├─ Domain: {dom}");
                    }
                    if c.metadata.is_abuse_specific {
                        println!("       ├─ ✓ Abuse-specific address");
                    }
                    println!("       └─ Source: Domain-based fallback");
                    println!();
                }
            } else {
                println!("  ⚠️  No domain-based abuse contacts discovered");
            }
            if let Some(dual) = &dual_escalation {
                println!(
                    "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
                );
                println!("  🚀 Escalation Paths\n");
                let infra_contacts = dual.get_email_infrastructure_contacts();
                if !infra_contacts.is_empty() {
                    println!("  📬 Email Infrastructure:");
                    for (i, c) in infra_contacts.iter().enumerate() {
                        let email = c.email.as_deref().unwrap_or("<unknown>");
                        println!(
                            "    {}. {} - {}",
                            i + 1,
                            email,
                            c.contact_type.display_name()
                        );
                        if !c.organization.is_empty() {
                            println!("       └─ Org: {}", c.organization);
                        }
                    }
                    println!();
                } else {
                    println!(
                        "  🛈 No email infrastructure escalation contacts (domain fallback - no sending IPv4)"
                    );
                    println!();
                }
                if let Some(hosting) = dual.get_sender_hosting_contacts() {
                    if !hosting.is_empty() {
                        println!("\n  🏢 Sender Hosting:");
                        for (i, c) in hosting.iter().enumerate() {
                            let email = c.email.as_deref().unwrap_or("<unknown>");
                            println!(
                                "    {}. {} - {}",
                                i + 1,
                                email,
                                c.contact_type.display_name()
                            );
                            if !c.organization.is_empty() {
                                println!("       └─ Org: {}", c.organization);
                            }
                        }
                    }
                }
            }
            println!(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            );
            println!("  📊 Query Statistics:");
            println!("    ├─ DNS queries performed: {}", metadata.dns_queries);
            println!(
                "    ├─ WHOIS servers queried: {}",
                metadata.whois_servers_queried
            );
            println!("    └─ Total time: {}ms", metadata.duration_ms.unwrap_or(0));
            println!();
            println!("  💡 Tips for Effective Abuse Reporting:");
            println!("    • Include concrete evidence (headers, timestamps, body excerpts)");
            println!("    • Allow 2-3 business days before escalating");
            println!("    • Escalate to registrar or hosting provider if unresponsive");
            println!(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            );
            return Ok(0);
        }

        if cli.batch {
            let list: Vec<&str> = finalized.iter().map(|(e, _)| e.as_str()).collect();
            println!("{domain}:{}", list.join(","));
        } else {
            println!("Abuse contacts for domain {domain}:");
            for (email, conf) in &finalized {
                println!("  {email} (confidence: {conf})");
            }
            if finalized.is_empty() {
                println!("  (none)");
            }
        }

        Ok(0)
    }
}

/// Traverse SOA hierarchy collecting RNAME-derived emails.
async fn traverse_soa(
    base: &str,
    emails: &mut EmailSet,
    cli: &Cli,
    metadata: &mut QueryMetadata,
) -> Result<()> {
    let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
    let mut labels: Vec<&str> = base.trim_end_matches('.').split('.').collect();
    if cli.is_trace() {
        eprintln!("SOA traversal seed: {base}");
    }
    while labels.len() > 1 {
        let candidate = labels.join(".");
        if cli.show_commands {
            eprintln!("(cmd) dig {candidate} SOA");
        }
        if cli.is_trace() {
            eprintln!(" SOA query: {candidate}");
        }
        metadata.dns_queries += 1;
        match tokio::time::timeout(
            std::time::Duration::from_secs(5),
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
                        if cli.is_trace() {
                            eprintln!("  SOA rname => {email}");
                        }
                    }
                }
            }
            Ok(Err(e)) => {
                if cli.is_trace() {
                    eprintln!("  SOA query failed for {candidate}: {e}");
                }
            }
            Err(_) => {
                if cli.is_trace() {
                    eprintln!("  SOA query timeout for {candidate}");
                }
            }
        }
        labels.remove(0);
    }
    Ok(())
}
