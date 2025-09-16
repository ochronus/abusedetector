mod cli;
mod config;
mod emails;
mod eml;
mod errors;
mod escalation;
mod netutil;
mod output;
mod retry;
mod structured_output;
mod styled_output;
mod whois;

use cli::{Cli, OutputFormat};
use config::Config;
use emails::{soa_rname_to_email, EmailSet, FinalizeOptions};
use errors::{AbuseDetectorError, Result};
use escalation::DualEscalationPath;
use netutil::{domain_of, ipv4_to_inaddr, is_private, is_reserved, parse_ipv4, reverse_dns};
use output::{
    AbuseContact, AbuseResults, ContactMetadata, ContactSource, OutputFormat as OutputFormatOrig,
    QueryMetadata,
};
use std::time::{Duration, Instant};
use structured_output::AbuseDetectorOutput;
use styled_output::StyledFormatter;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::{Name, RecordType},
    TokioAsyncResolver,
};
use whois::{query_abuse_net, whois_ip_chain};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::from_args();

    // Handle schema generation early exit
    if cli.generate_schema {
        match AbuseDetectorOutput::generate_json_schema() {
            Ok(schema) => {
                println!("{}", schema);
                return Ok(());
            }
            Err(e) => {
                eprintln!("Error generating JSON schema: {}", e);
                return Ok(());
            }
        }
    }

    let start_time = Instant::now();

    // Load configuration
    let mut config = Config::from_env();
    config.merge_with_cli(&cli);

    if let Err(e) = config.validate() {
        if cli.error_enabled() {
            eprintln!("Configuration error: {}", e);
        }
        return Ok(());
    }

    // Determine IP and sender domain: either directly from --ip or derived from --eml file
    let (ip, from_eml, eml_file, sender_domain) = if let Some(ref eml_path) = cli.eml {
        if cli.is_trace() {
            eprintln!("Deriving originating IP from EML file: {eml_path}");
        }

        let sender_domain = eml::extract_sender_domain_from_path(eml_path).unwrap_or(None);

        if let Some(ref domain) = sender_domain {
            if cli.is_trace() {
                eprintln!("Sender domain extracted from EML: {domain}");
            }
            if !cli.is_structured_output() {
                println!("Detected sender domain (from EML): {domain}");
            }
        }

        match eml::parse_eml_origin_ip_from_path(eml_path) {
            Ok(found) => {
                if cli.is_trace() {
                    eprintln!("Originating IP extracted from EML: {found}");
                }
                // Always log the detected sender IP in EML mode (user-visible)
                if !cli.is_structured_output() {
                    println!("Detected originating IP: {found} (source: X-Mailgun-Sending-Ip)");
                    println!("Detected sender IP (from EML): {found}");
                }
                (found, true, Some(eml_path.clone()), sender_domain)
            }
            Err(e) => {
                if cli.error_enabled() {
                    eprintln!("Error extracting IP from EML ({eml_path}): {e}");
                }
                // Fail early since we have no usable IP
                return Ok(());
            }
        }
    } else if let Some(ref ip_str) = cli.ip {
        (
            parse_ipv4(ip_str).map_err(|_| AbuseDetectorError::InvalidIpAddress(ip_str.clone()))?,
            false,
            None,
            None,
        )
    } else {
        if cli.error_enabled() {
            eprintln!("Error: either an IP address or --eml file must be provided.");
        }
        return Ok(());
    };
    if is_private(ip) {
        if cli.error_enabled() {
            eprintln!("Error: {ip} is a private IP address (RFC1918). Cannot proceed.");
        }
        return Ok(());
    }
    if is_reserved(ip) {
        if cli.error_enabled() {
            eprintln!("Error: {ip} is a reserved IP address. Cannot proceed.");
        }
        return Ok(());
    }

    let mut emails = EmailSet::new();
    let mut metadata = QueryMetadata {
        from_eml,
        eml_file: eml_file.clone(),
        ..Default::default()
    };

    // Reverse DNS
    let hostname = if !cli.no_use_hostname {
        if cli.is_trace() {
            eprintln!("Reverse DNS lookup for {ip}...");
        }
        metadata.dns_queries += 1;
        reverse_dns(ip, cli.show_commands).await.unwrap_or(None)
    } else {
        None
    };

    metadata.hostname = hostname.clone();

    if cli.is_trace() {
        eprintln!("Hostname: {}", hostname.as_deref().unwrap_or("<none>"));
    }

    // abuse.net (hostname domain first)
    if !cli.no_use_abusenet {
        metadata.abuse_net_queried = true;
        if let Some(ref h) = hostname {
            if let Some(dom) = domain_of(h) {
                if let Err(e) = query_abuse_net(&dom, &mut emails, &cli).await {
                    if cli.warn_enabled() {
                        metadata
                            .warnings
                            .push(format!("abuse.net query failed: {}", e));
                    }
                }
            }
        }
    }

    // DNS SOA traversal (hostname + reverse in-addr)
    if !cli.no_use_dns_soa {
        if let Some(ref h) = hostname {
            if let Err(e) = traverse_soa(h, &mut emails, &cli, &mut metadata).await {
                if cli.warn_enabled() {
                    metadata
                        .warnings
                        .push(format!("DNS SOA traversal failed for hostname: {}", e));
                }
            }
        }
        if let Err(e) = traverse_soa(&ipv4_to_inaddr(ip), &mut emails, &cli, &mut metadata).await {
            if cli.warn_enabled() {
                metadata
                    .warnings
                    .push(format!("DNS SOA traversal failed for reverse IP: {}", e));
            }
        }
    }

    // WHOIS IP chain
    if !cli.no_use_whois_ip {
        if let Err(e) = whois_ip_chain(ip, &mut emails, &cli).await {
            if cli.warn_enabled() {
                metadata
                    .warnings
                    .push(format!("WHOIS chain query failed: {}", e));
            }
        }
        metadata.whois_servers_queried += 1; // This is a simplification
    }

    // Record duration
    metadata.duration_ms = Some(start_time.elapsed().as_millis() as u64);

    // Finalize & filter
    let finalize_opts = FinalizeOptions {
        single_if_not_verbose: !cli.show_internal() && !cli.batch,
        ..Default::default()
    };
    let email_results = emails.finalize(finalize_opts);

    // Convert to structured results
    let contacts: Vec<AbuseContact> = email_results
        .iter()
        .map(|(email, confidence)| AbuseContact {
            email: email.clone(),
            confidence: *confidence,
            source: ContactSource::Unknown, // TODO: Track sources properly
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

    // Generate dual escalation paths if requested or if no primary contacts found
    let dual_escalation = if cli.should_show_escalation() || results.contacts.is_empty() {
        match DualEscalationPath::from_eml_analysis(ip, hostname.clone(), sender_domain.clone())
            .await
        {
            Ok(paths) => Some(paths),
            Err(e) => {
                if cli.warn_enabled() {
                    eprintln!("Warning: Could not generate escalation paths: {}", e);
                }
                None
            }
        }
    } else {
        None
    };

    // Handle structured output formats (JSON/YAML)
    match cli.output_format() {
        OutputFormat::Json | OutputFormat::Yaml => {
            let mut structured_output = AbuseDetectorOutput::new();

            // Set input information
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
                    header_field: "Multiple sources".to_string(), // TODO: Track actual header
                    priority: 1,
                }
            } else {
                structured_output::IpSource::DirectInput
            };

            // Convert email results to structured contacts
            for (email, confidence) in &email_results {
                let domain = email.split('@').nth(1).map(|s| s.to_string());
                let contact = structured_output::Contact {
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
                };
                structured_output.primary_contacts.push(contact);
            }
            structured_output.result.primary_contacts_found =
                structured_output.primary_contacts.len() as u32;
            structured_output.result.success = !structured_output.primary_contacts.is_empty();

            // Add escalation paths if available
            if let Some(ref dual_path) = dual_escalation {
                structured_output.from_dual_escalation_path(dual_path);
            }

            // Update statistics
            structured_output.statistics.dns_queries = metadata.dns_queries;
            structured_output.statistics.whois_servers_queried = metadata.whois_servers_queried;
            structured_output.statistics.total_time_ms = metadata.duration_ms.unwrap_or(0);
            structured_output.warnings = metadata.warnings.clone();

            // Calculate result quality
            structured_output.result.result_quality =
                if structured_output.primary_contacts.len() > 0 {
                    if structured_output.escalation_paths.is_some() {
                        structured_output::ResultQuality::Excellent
                    } else {
                        structured_output::ResultQuality::Good
                    }
                } else if structured_output.escalation_paths.is_some() {
                    structured_output::ResultQuality::Fair
                } else {
                    structured_output::ResultQuality::Poor
                };

            structured_output.result.overall_confidence =
                if structured_output.primary_contacts.len() > 0 {
                    structured_output
                        .primary_contacts
                        .iter()
                        .map(|c| c.confidence as u32)
                        .sum::<u32>()
                        / structured_output.primary_contacts.len() as u32
                } else {
                    0
                } as u8;

            // Output in requested format
            let output = match cli.output_format() {
                OutputFormat::Json => structured_output.to_json(),
                OutputFormat::Yaml => structured_output.to_yaml(),
                _ => unreachable!(),
            };

            match output {
                Ok(formatted) => println!("{}", formatted),
                Err(e) => {
                    eprintln!("Error formatting structured output: {}", e);
                    return Ok(());
                }
            }

            return Ok(());
        }
        _ => {}
    }

    // Use styled output if enabled and not in batch mode
    if cli.should_use_styling() && !cli.batch {
        let formatter = if cli.no_color {
            StyledFormatter::without_colors()
        } else {
            StyledFormatter::new()
        };

        if let Err(e) =
            formatter.print_results_with_dual_escalation(&results, dual_escalation.as_ref())
        {
            eprintln!("Error formatting styled output: {}", e);
            // Fall back to plain text output
            let output_format = OutputFormatOrig::Text {
                show_confidence: cli.show_internal(),
                show_sources: cli.show_internal(),
                show_metadata: cli.is_trace(),
            };
            let formatter = output::create_formatter(&output_format);
            let output_text = formatter.format_results(&results).map_err(|e| {
                AbuseDetectorError::Configuration(format!("Output formatting failed: {}", e))
            })?;
            print!("{}", output_text);
        }
    } else {
        // Use traditional output format
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

        let formatter = output::create_formatter(&output_format);
        let output_text = formatter.format_results(&results).map_err(|e| {
            AbuseDetectorError::Configuration(format!("Output formatting failed: {}", e))
        })?;

        print!("{}", output_text);

        // If using plain output but escalation was requested, show it separately
        if let Some(ref paths) = dual_escalation {
            if cli.should_show_escalation() {
                println!("\n--- EMAIL INFRASTRUCTURE ESCALATION PATH ---");
                println!("(For stopping email sending abuse)");
                for (i, contact) in paths.get_email_infrastructure_contacts().iter().enumerate() {
                    println!(
                        "{}. {} - {}",
                        i + 1,
                        contact.contact_type.display_name(),
                        contact.organization
                    );
                    if let Some(ref email) = contact.email {
                        println!("   Email: {}", email);
                    }
                    if let Some(ref form) = contact.web_form {
                        println!("   Web Form: {}", form);
                    }
                    println!();
                }

                if let Some(hosting_contacts) = paths.get_sender_hosting_contacts() {
                    if !hosting_contacts.is_empty() {
                        println!("\n--- SENDER HOSTING ESCALATION PATH ---");
                        println!("(For stopping website/business abuse)");
                        for (i, contact) in hosting_contacts.iter().enumerate() {
                            println!(
                                "{}. {} - {}",
                                i + 1,
                                contact.contact_type.display_name(),
                                contact.organization
                            );
                            if let Some(ref email) = contact.email {
                                println!("   Email: {}", email);
                            }
                            if let Some(ref form) = contact.web_form {
                                println!("   Web Form: {}", form);
                            }
                            println!();
                        }
                    }
                }
            }
        }
    }

    // If no results and verbose, hint user
    if results.contacts.is_empty() && cli.error_enabled() && dual_escalation.is_none() {
        eprintln!("No abuse contacts discovered and escalation paths unavailable.");
        eprintln!("Try using --show-escalation to see alternative contact methods.");
    }

    Ok(())
}

/// Traverse up the domain labels performing SOA lookups and extracting RNAME
/// which is translated into an email (first '.' becomes '@').
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
                Name::from_ascii(&candidate).map_err(|e| {
                    AbuseDetectorError::Configuration(format!("Invalid domain name: {}", e))
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
                    eprintln!("  SOA query failed for {}: {}", candidate, e);
                }
            }
            Err(_) => {
                if cli.is_trace() {
                    eprintln!("  SOA query timeout for {}", candidate);
                }
            }
        }
        labels.remove(0);
    }
    Ok(())
}
