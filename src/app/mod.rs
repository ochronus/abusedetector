//! High-level application orchestration layer.
//!
//! This module encapsulates the large `main.rs` procedural flow into a reusable
//! `App` façade so the binary's `main` function can stay minimal. Over time,
//! additional architectural refactors (feature flags, retry policy injection,
//! tracing spans, etc.) can hook in here without bloating `main.rs`.
//!
//! Responsibilities moved here (previously in `main.rs`):
//! - Input interpretation (direct IP vs. --eml path)
//! - Schema generation early-exit
//! - Configuration merge & validation
//! - Data collection (reverse DNS, abuse.net, SOA traversal, WHOIS)
//! - Result assembly (plain / styled / structured output)
//! - Escalation path generation
//! - Domain fallback flow (no public IPv4 found)
//!
//! Public surface:
//!   `App::run(&Cli) -> Result<i32>` returning an intended process exit code.
//!
//! NOTE: `main.rs` should now only:
//!   1. Parse CLI
//!   2. Call `App::run(&cli).await`
//!   3. Map returned `i32` to `std::process::exit`
//!
//! Future refactors (from improvement plan):
//! - Split sub-stages into dedicated structs/services
//! - Introduce traits for source abstraction
//! - Centralize error/report routing
//!
//! For now this is a near 1:1 migration of logic for safety.

use std::net::Ipv4Addr;
use std::time::{Duration, Instant};

use crate::cli::{Cli, OutputFormat};
use crate::config::Config;
use crate::domain_utils;
use crate::emails::{soa_rname_to_email, EmailSet, FinalizeOptions};
use crate::eml::{self, IpExtractionResult};
use crate::errors::{AbuseDetectorError, Result};
use crate::escalation::DualEscalationPath;
use crate::netutil::{domain_of, is_private, is_reserved, reverse_dns};
use crate::output::{
    AbuseContact, AbuseResults, ContactMetadata, ContactSource, OutputFormat as OutputFormatOrig,
    QueryMetadata,
};
use crate::structured_output::{self, AbuseDetectorOutput};
use crate::styled_output::StyledFormatter;
use crate::whois::{query_abuse_net, whois_ip_chain};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::{Name, RecordType},
    TokioAsyncResolver,
};

/// Placeholder IP used when no public IPv4 could be extracted (domain fallback mode)
const FALLBACK_IP: Ipv4Addr = Ipv4Addr::new(0, 0, 0, 0);

/// Application façade.
pub struct App;

impl App {
    /// Execute the end-to-end abuse contact discovery workflow.
    ///
    /// Returns: intended process exit code (0 = success, 1 = user/input error).
    pub async fn run(cli: &Cli) -> Result<i32> {
        // Early exit: schema generation
        if cli.generate_schema {
            match AbuseDetectorOutput::generate_json_schema() {
                Ok(schema) => {
                    println!("{schema}");
                    return Ok(0);
                }
                Err(e) => {
                    eprintln!("Error generating JSON schema: {e}");
                    return Ok(0);
                }
            }
        }

        // Load / validate config
        let mut config = Config::from_env();
        config.merge_with_cli(cli);
        if let Err(e) = config.validate() {
            if cli.error_enabled() {
                eprintln!("Configuration error: {e}");
            }
            // Historically this was a non-fatal zero exit; preserve behavior.
            return Ok(0);
        }

        let start_time = Instant::now();

        // Decide input: --eml or direct IP
        let (ip, from_eml, eml_file, sender_domain): (
            Ipv4Addr,
            bool,
            Option<String>,
            Option<String>,
        ) = if let Some(ref eml_path) = cli.eml {
            if cli.is_trace() {
                eprintln!("Deriving originating IP from EML file: {eml_path}");
            }

            let sender_domain = eml::extract_sender_domain_from_path(eml_path).unwrap_or(None);
            if let Some(ref d) = sender_domain {
                if !cli.is_structured_output() {
                    println!("Detected sender domain (from EML): {d}");
                }
            }

            // Try extracting IPv4
            match eml::parse_eml_origin_ip_from_path(eml_path) {
                Ok(IpExtractionResult {
                    ip: std::net::IpAddr::V4(v4),
                    source,
                }) => {
                    if cli.is_trace() {
                        eprintln!("Originating IP extracted from EML: {v4} (source: {source})");
                    }
                    if !cli.is_structured_output() {
                        println!("Detected sender IP (from EML): {v4}");
                    }
                    (v4, true, Some(eml_path.clone()), sender_domain)
                }
                Ok(IpExtractionResult {
                    ip: _non_v4,
                    source,
                }) => {
                    // Always surface an error-level message so verbosity=1 integration tests see it
                    if cli.error_enabled() {
                        eprintln!("Error extracting IP: No public IPv4 found (extracted non-IPv4; source: {source})");
                    } else if cli.warn_enabled() {
                        eprintln!("Info: Extracted non-IPv4 address (source: {source}); falling back to domain-based lookup");
                    }
                    if let Some(ref domain) = sender_domain {
                        if !cli.is_structured_output() {
                            println!(
                                "Falling back to domain-based abuse contact lookup for: {domain}"
                            );
                        }
                        return handle_domain_fallback(
                            domain,
                            eml_path,
                            sender_domain.clone(),
                            cli,
                        )
                        .await;
                    } else {
                        if cli.error_enabled() {
                            eprintln!("Error extracting IP: No public IPv4 found and no sender domain available.");
                        }
                        return Ok(1);
                    }
                }
                Err(e) => {
                    // No public IPv4 found → domain fallback (only if we have a sender domain)
                    let err_msg = format!("{e}");
                    if cli.error_enabled() {
                        if err_msg.to_ascii_lowercase().contains("no public ip") {
                            eprintln!("Error extracting IP: No public IPv4 found in EML headers");
                        } else {
                            eprintln!("Error extracting IP: {err_msg}");
                        }
                    } else if cli.warn_enabled() {
                        eprintln!("Warning: Could not extract IP from EML ({eml_path}): {err_msg}");
                    }
                    if let Some(ref domain) = sender_domain {
                        if !cli.is_structured_output() {
                            println!(
                                "Falling back to domain-based abuse contact lookup for: {domain}"
                            );
                        }
                        return handle_domain_fallback(
                            domain,
                            eml_path,
                            sender_domain.clone(),
                            cli,
                        )
                        .await;
                    } else {
                        if cli.error_enabled() {
                            eprintln!("Error extracting IP: No public IPv4 found and no sender domain available.");
                        }
                        return Ok(1);
                    }
                }
            }
        } else if let Some(ref ip_str) = cli.ip {
            let ip = match ip_str.parse::<Ipv4Addr>() {
                Ok(v) => v,
                Err(_) => {
                    if cli.error_enabled() {
                        eprintln!("Error: Invalid IPv4 address format: {ip_str}");
                    }
                    return Ok(1);
                }
            };
            (ip, false, None, None)
        } else {
            if cli.error_enabled() {
                eprintln!("Error: either an IP address or --eml file must be provided.");
            }
            return Ok(1);
        };

        // Basic IPv4 validation
        if is_private(std::net::IpAddr::V4(ip)) {
            if cli.error_enabled() {
                eprintln!("Error: {ip} is a private IP address (RFC1918). Cannot proceed.");
            }
            return Ok(0);
        }
        if is_reserved(std::net::IpAddr::V4(ip)) {
            if cli.error_enabled() {
                eprintln!("Error: {ip} is a reserved IP address. Cannot proceed.");
            }
            return Ok(0);
        }

        // Collection + metadata
        let mut emails = EmailSet::new();
        let mut metadata = QueryMetadata {
            from_eml,
            eml_file: eml_file.clone(),
            ..Default::default()
        };

        // --- Parallel Network Phase (Reverse DNS + Reverse SOA + WHOIS) ---
        // Improvement Plan 4.1 (full):
        // Run independent network lookups concurrently with bounded concurrency.
        // Tasks:
        //   * Reverse DNS (hostname)
        //   * Reverse SOA traversal (in-addr.arpa chain)
        //   * WHOIS IP chain
        //
        // Each task returns a typed enum; results are merged after completion.
        // Forward SOA traversal & abuse.net remain after this phase (need hostname).
        use futures::{future::BoxFuture, FutureExt};
        use futures::{stream::FuturesUnordered, StreamExt};
        use std::sync::Arc;
        use tokio::sync::Semaphore;

        // Local enum describing heterogeneous network task outputs
        #[derive(Debug)]
        enum ParallelResult {
            ReverseDns(Option<String>, u32), // (hostname, dns_query_count)
            ReverseSoa {
                emails: EmailSet,
                dns_queries: u32,
            },
            Whois {
                emails: EmailSet,
                whois_servers: u32,
            },
        }

        let mut parallel: FuturesUnordered<BoxFuture<'static, ParallelResult>> =
            FuturesUnordered::new();

        let semaphore = Arc::new(Semaphore::new(3)); // allow up to 3 concurrent network tasks
        let cli_arc = Arc::new(cli.clone());

        // Reverse DNS
        if !cli.no_use_hostname {
            let sem = semaphore.clone();
            let cli_ref = cli_arc.clone();
            let show_cmds = cli_ref.show_commands;
            let trace = cli_ref.is_trace();
            parallel.push(
                async move {
                    let _permit = sem.acquire().await;
                    if trace {
                        eprintln!("Reverse DNS lookup for {ip}...");
                    }
                    // Reverse DNS counts as one DNS query
                    let host = reverse_dns(std::net::IpAddr::V4(ip), show_cmds)
                        .await
                        .unwrap_or(None);
                    ParallelResult::ReverseDns(host, 1)
                }
                .boxed(),
            );
        }

        // Reverse SOA traversal (in-addr.arpa) independent of hostname
        if !cli.no_use_dns_soa {
            let sem = semaphore.clone();
            let cli_ref = cli_arc.clone();
            let rev_name = crate::netutil::ip_to_inaddr(std::net::IpAddr::V4(ip));
            parallel.push(
                async move {
                    let _permit = sem.acquire().await;
                    let mut local_set = EmailSet::new();
                    let mut local_meta = QueryMetadata::default();
                    if let Err(e) =
                        traverse_soa(&rev_name, &mut local_set, &cli_ref, &mut local_meta).await
                    {
                        if cli_ref.warn_enabled() {
                            eprintln!("Warning: Reverse SOA traversal failed: {e}");
                        }
                    }
                    ParallelResult::ReverseSoa {
                        emails: local_set,
                        dns_queries: local_meta.dns_queries,
                    }
                }
                .boxed(),
            );
        }

        // WHOIS IP chain
        if !cli.no_use_whois_ip {
            let sem = semaphore.clone();
            let cli_ref = cli_arc.clone();
            parallel.push(
                async move {
                    let _permit = sem.acquire().await;
                    let mut local_set = EmailSet::new();
                    let mut servers = 0u32;
                    if let Err(e) = whois_ip_chain(ip, &mut local_set, &cli_ref).await {
                        if cli_ref.warn_enabled() {
                            eprintln!("Warning: WHOIS chain query failed: {e}");
                        }
                    } else {
                        servers = 1; // count root chain invocation; deeper referrals not separately tallied here
                    }
                    ParallelResult::Whois {
                        emails: local_set,
                        whois_servers: servers,
                    }
                }
                .boxed(),
            );
        }

        // Collect and merge results
        while let Some(res) = parallel.next().await {
            match res {
                ParallelResult::ReverseDns(host_opt, dns_q) => {
                    metadata.hostname = host_opt;
                    metadata.dns_queries = metadata.dns_queries.saturating_add(dns_q);
                }
                ParallelResult::ReverseSoa {
                    emails: set,
                    dns_queries,
                } => {
                    for (email, conf) in set.finalize(FinalizeOptions::default()) {
                        emails.add_with_conf(email, conf);
                    }
                    metadata.dns_queries = metadata.dns_queries.saturating_add(dns_queries);
                }
                ParallelResult::Whois {
                    emails: set,
                    whois_servers,
                } => {
                    for (email, conf) in set.finalize(FinalizeOptions::default()) {
                        emails.add_with_conf(email, conf);
                    }
                    metadata.whois_servers_queried =
                        metadata.whois_servers_queried.saturating_add(whois_servers);
                }
            }
        }

        let hostname = metadata.hostname.clone();
        if cli.is_trace() {
            eprintln!("Hostname: {}", hostname.as_deref().unwrap_or("<none>"));
        }

        // abuse.net (depends on hostname's registrable domain)
        if !cli.no_use_abusenet {
            metadata.abuse_net_queried = true;
            if let Some(ref h) = hostname {
                if let Some(dom) = domain_of(h) {
                    if let Err(e) = query_abuse_net(&dom, &mut emails, cli).await {
                        if cli.warn_enabled() {
                            metadata
                                .warnings
                                .push(format!("abuse.net query failed: {e}"));
                        }
                    }
                }
            }
        }

        // Forward SOA traversal (now that hostname—if any—is known)
        if !cli.no_use_dns_soa {
            if let Some(ref h) = hostname {
                if let Err(e) = traverse_soa(h, &mut emails, cli, &mut metadata).await {
                    if cli.warn_enabled() {
                        metadata
                            .warnings
                            .push(format!("DNS SOA traversal failed for hostname: {e}"));
                    }
                }
            }
        }

        // Record duration
        metadata.duration_ms = Some(start_time.elapsed().as_millis() as u64);

        // Finalize & filter
        let finalize_opts = FinalizeOptions {
            single_if_not_verbose: !cli.show_internal() && !cli.batch,
            ..Default::default()
        };
        let email_results = emails.finalize(finalize_opts);

        // Prepare results (IP-based)
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

        // Escalation paths generation conditionally
        let dual_escalation = if cli.should_show_escalation() || results.contacts.is_empty() {
            match DualEscalationPath::from_eml_analysis(ip, hostname.clone(), sender_domain.clone())
                .await
            {
                Ok(paths) => Some(paths),
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

        // Structured output (JSON / YAML)
        match cli.output_format() {
            OutputFormat::Json | OutputFormat::Yaml => {
                let mut structured_output = AbuseDetectorOutput::new();

                structured_output.input.ip_address = ip;
                structured_output.input.hostname = hostname.clone();
                structured_output.input.sender_domain = sender_domain.clone();
                structured_output.input.eml_file = eml_file;
                structured_output.input.input_method = if from_eml {
                    structured_output::InputMethod::EmlFile
                } else {
                    structured_output::InputMethod::DirectIp
                };
                structured_output.input.ip_source = if from_eml {
                    structured_output::IpSource::EmailHeader {
                        header_field: "Email-derived IPv4".to_string(),
                        priority: 1,
                    }
                } else {
                    structured_output::IpSource::DirectInput
                };

                for (email, confidence) in &email_results {
                    let domain = email.split('@').nth(1).map(|s| s.to_string());
                    structured_output
                        .primary_contacts
                        .push(structured_output::Contact {
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
                            sources: vec![structured_output::ContactSource::MultipleConfirmed],
                            confidence: *confidence as u8,
                            is_abuse_specific: email.starts_with("abuse@"),
                            metadata: None,
                        });
                }

                structured_output.result.primary_contacts_found =
                    structured_output.primary_contacts.len() as u32;
                structured_output.result.success = !structured_output.primary_contacts.is_empty();

                if let Some(ref dual) = dual_escalation {
                    structured_output.from_dual_escalation_path(dual);
                    structured_output.result.escalation_paths_generated = true;
                }

                structured_output.statistics.dns_queries = metadata.dns_queries;
                structured_output.statistics.whois_servers_queried = metadata.whois_servers_queried;
                structured_output.statistics.total_time_ms = metadata.duration_ms.unwrap_or(0);
                structured_output.warnings = metadata.warnings.clone();

                structured_output.result.result_quality =
                    if structured_output.result.primary_contacts_found > 0 {
                        if structured_output.result.escalation_paths_generated {
                            structured_output::ResultQuality::Excellent
                        } else {
                            structured_output::ResultQuality::Good
                        }
                    } else if structured_output.result.escalation_paths_generated {
                        structured_output::ResultQuality::Fair
                    } else {
                        structured_output::ResultQuality::Poor
                    };

                structured_output.result.overall_confidence =
                    if structured_output.result.primary_contacts_found > 0 {
                        (structured_output
                            .primary_contacts
                            .iter()
                            .map(|c| c.confidence as u32)
                            .sum::<u32>()
                            / structured_output.primary_contacts.len() as u32)
                            as u8
                    } else {
                        0
                    };

                let rendered = match cli.output_format() {
                    OutputFormat::Json => structured_output.to_json(),
                    OutputFormat::Yaml => structured_output.to_yaml(),
                    _ => unreachable!(),
                };

                match rendered {
                    Ok(s) => {
                        println!("{s}");
                    }
                    Err(e) => {
                        eprintln!("Error formatting structured output: {e}");
                    }
                }
                return Ok(0);
            }
            _ => {}
        }

        // Styled output (rich)
        if cli.should_use_styling() && !cli.batch {
            let formatter = if cli.no_color {
                StyledFormatter::without_colors()
            } else {
                StyledFormatter::new()
            };
            if let Err(e) =
                formatter.print_results_with_dual_escalation(&results, dual_escalation.as_ref())
            {
                eprintln!("Error formatting styled output: {e}");
                // Fallback to plain below
            } else {
                return Ok(0);
            }
        }

        // Plain / batch fallback
        let output_format = if cli.batch {
            OutputFormatOrig::Batch
        } else if cli.show_internal() {
            OutputFormatOrig::Text {
                show_confidence: true,
                show_sources: true,
                show_metadata: cli.is_trace(),
            }
        } else {
            OutputFormatOrig::Text {
                show_confidence: false,
                show_sources: false,
                show_metadata: false,
            }
        };

        let formatter = crate::output::create_formatter(&output_format);
        let plain =
            formatter
                .format_results(&results)
                .map_err(|e| AbuseDetectorError::Configuration {
                    message: format!("Output formatting failed: {e}"),
                })?;
        print!("{plain}");

        // Provide separate escalation path listing if requested but plain output mode
        if let Some(ref paths) = dual_escalation {
            if cli.should_show_escalation() {
                println!("\n--- EMAIL INFRASTRUCTURE ESCALATION PATH ---");
                for (i, contact) in paths.get_email_infrastructure_contacts().iter().enumerate() {
                    println!(
                        "{}. {} - {}",
                        i + 1,
                        contact.contact_type.display_name(),
                        contact.organization
                    );
                    if let Some(ref email) = contact.email {
                        println!("   Email: {email}");
                    }
                    if let Some(ref form) = contact.web_form {
                        println!("   Web Form: {form}");
                    }
                    println!();
                }
                if let Some(hosting_contacts) = paths.get_sender_hosting_contacts() {
                    if !hosting_contacts.is_empty() {
                        println!("\n--- SENDER HOSTING ESCALATION PATH ---");
                        for (i, contact) in hosting_contacts.iter().enumerate() {
                            println!(
                                "{}. {} - {}",
                                i + 1,
                                contact.contact_type.display_name(),
                                contact.organization
                            );
                            if let Some(ref email) = contact.email {
                                println!("   Email: {email}");
                            }
                            if let Some(ref form) = contact.web_form {
                                println!("   Web Form: {form}");
                            }
                            println!();
                        }
                    }
                }
            }
        }

        if results.contacts.is_empty() && cli.error_enabled() && dual_escalation.is_none() {
            eprintln!("No abuse contacts discovered and no escalation paths available (try --show-escalation).");
        }

        Ok(0)
    }
}

/// Domain fallback handler (no public IPv4 found in EML).
async fn handle_domain_fallback(
    domain: &str,
    eml_path: &str,
    sender_domain: Option<String>,
    cli: &Cli,
) -> Result<i32> {
    let start = Instant::now();
    let mut emails = EmailSet::new();
    let mut metadata = QueryMetadata {
        from_eml: true,
        eml_file: Some(eml_path.to_string()),
        ..Default::default()
    };

    // Generate abuse/security pattern addresses
    if let Ok(patterns) = domain_utils::generate_abuse_emails(domain) {
        for addr in patterns {
            emails.add_with_conf(addr, 2);
        }
    }

    // abuse.net for domain
    if !cli.no_use_abusenet {
        metadata.abuse_net_queried = true;
        if let Err(e) = query_abuse_net(domain, &mut emails, cli).await {
            if cli.warn_enabled() {
                eprintln!("Warning: abuse.net query failed for {domain}: {e}");
            }
        }
    }

    // SOA traversal over the sender domain
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

    // Build AbuseResults with placeholder IP
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

    // Escalation paths (optional)
    let dual_escalation = if cli.should_show_escalation() || results.contacts.is_empty() {
        match DualEscalationPath::from_eml_analysis(FALLBACK_IP, None, sender_domain.clone()).await
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

    // Structured output
    match cli.output_format() {
        OutputFormat::Json | OutputFormat::Yaml => {
            let mut so = AbuseDetectorOutput::new();
            so.input.ip_address = FALLBACK_IP;
            so.input.hostname = None;
            so.input.sender_domain = sender_domain.clone();
            so.input.eml_file = Some(eml_path.to_string());
            so.input.input_method = structured_output::InputMethod::EmlFile;
            so.input.ip_source = structured_output::IpSource::EmailHeader {
                header_field: "Domain fallback (no IPv4 found)".to_string(),
                priority: 0,
            };

            for (email, confidence) in &finalized {
                let domain_part = email.split('@').nth(1).map(|s| s.to_string());
                so.primary_contacts.push(structured_output::Contact {
                    email: email.clone(),
                    domain: domain_part,
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
                });
            }

            so.result.primary_contacts_found = so.primary_contacts.len() as u32;
            so.result.success = !so.primary_contacts.is_empty();

            if let Some(ref d) = dual_escalation {
                so.from_dual_escalation_path(d);
                so.result.escalation_paths_generated = true;
            }

            so.statistics.dns_queries = metadata.dns_queries;
            so.statistics.whois_servers_queried = metadata.whois_servers_queried;
            so.statistics.total_time_ms = metadata.duration_ms.unwrap_or(0);
            so.warnings = metadata.warnings.clone();

            so.result.result_quality = if so.result.primary_contacts_found > 0 {
                if so.result.escalation_paths_generated {
                    structured_output::ResultQuality::Excellent
                } else {
                    structured_output::ResultQuality::Good
                }
            } else if so.result.escalation_paths_generated {
                structured_output::ResultQuality::Fair
            } else {
                structured_output::ResultQuality::Poor
            };

            so.result.overall_confidence = if so.result.primary_contacts_found > 0 {
                (so.primary_contacts
                    .iter()
                    .map(|c| c.confidence as u32)
                    .sum::<u32>()
                    / so.primary_contacts.len() as u32) as u8
            } else {
                0
            };

            let rendered = match cli.output_format() {
                OutputFormat::Json => so.to_json(),
                OutputFormat::Yaml => so.to_yaml(),
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

    // Styled domain fallback output
    if cli.should_use_styling() && !cli.batch {
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        println!("  🚨 Abuse Contacts for Domain {domain} (from EML)");
        println!("  📧 EML File: {eml_path}");
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
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
        // Escalation paths (if requested/generated)
        if let Some(dual) = &dual_escalation {
            println!(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
            );
            println!("  🚀 Escalation Paths\n");

            // Email infrastructure path (only show if there are contacts)
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
                println!("  🛈 No email infrastructure escalation contacts (domain fallback - no distinct sending IPv4 path)");
                println!();
            }

            // Sender hosting path (if available)
            if let Some(hosting) = dual.get_sender_hosting_contacts() {
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

        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
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
        println!("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━");
        return Ok(0);
    }

    // Plain / batch fallback for domain mode
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
            Duration::from_secs(5),
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
