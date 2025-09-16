mod cli;
mod config;
mod emails;
mod eml;
mod errors;
mod netutil;
mod output;
mod retry;
mod whois;

use cli::Cli;
use config::Config;
use emails::{soa_rname_to_email, EmailSet, FinalizeOptions};
use errors::{AbuseDetectorError, Result};
use netutil::{domain_of, ipv4_to_inaddr, is_private, is_reserved, parse_ipv4, reverse_dns};
use output::{
    AbuseContact, AbuseResults, ContactMetadata, ContactSource, OutputFormat, QueryMetadata,
};
use std::time::{Duration, Instant};
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::{Name, RecordType},
    TokioAsyncResolver,
};
use whois::{query_abuse_net, whois_ip_chain};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::from_args();
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

    // Determine IP: either directly from --ip or derived from --eml file
    let (ip, from_eml, eml_file) = if let Some(ref eml_path) = cli.eml {
        if cli.is_trace() {
            eprintln!("Deriving originating IP from EML file: {eml_path}");
        }
        match eml::parse_eml_origin_ip_from_path(eml_path) {
            Ok(found) => {
                if cli.is_trace() {
                    eprintln!("Originating IP extracted from EML: {found}");
                }
                // Always log the detected sender IP in EML mode (user-visible)
                println!("Detected sender IP (from EML): {found}");
                (found, true, Some(eml_path.clone()))
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
        eml_file,
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
        .into_iter()
        .map(|(email, confidence)| AbuseContact {
            email: email.clone(),
            confidence,
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
        metadata,
    };

    // Determine output format
    let output_format = if cli.batch {
        OutputFormat::Batch
    } else if cli.show_internal() {
        OutputFormat::Text {
            show_confidence: true,
            show_sources: true,
            show_metadata: cli.is_trace(),
        }
    } else {
        OutputFormat::Text {
            show_confidence: false,
            show_sources: false,
            show_metadata: false,
        }
    };

    // Format and output results
    let formatter = output::create_formatter(&output_format);
    let output_text = formatter.format_results(&results).map_err(|e| {
        AbuseDetectorError::Configuration(format!("Output formatting failed: {}", e))
    })?;

    print!("{}", output_text);

    // If no results and verbose, hint user
    if results.contacts.is_empty() && cli.error_enabled() {
        eprintln!("No abuse contacts discovered.");
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
