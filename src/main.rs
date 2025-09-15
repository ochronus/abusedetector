mod cli;
mod emails;
mod eml;
mod netutil;
mod whois;

use anyhow::Result;
use cli::Cli;
use emails::{soa_rname_to_email, EmailSet, FinalizeOptions};
use netutil::{domain_of, ipv4_to_inaddr, is_private, is_reserved, parse_ipv4, reverse_dns};
use std::time::Duration;
use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::{Name, RecordType},
    TokioAsyncResolver,
};
use whois::{query_abuse_net, whois_ip_chain};

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::from_args();

    // Determine IP: either directly from --ip or derived from --eml file
    let ip = if let Some(ref eml_path) = cli.eml {
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
                found
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
        parse_ipv4(ip_str)?
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

    // Reverse DNS
    let hostname = if !cli.no_use_hostname {
        if cli.is_trace() {
            eprintln!("Reverse DNS lookup for {ip}...");
        }
        reverse_dns(ip, cli.show_commands).await?
    } else {
        None
    };
    if cli.is_trace() {
        eprintln!("Hostname: {}", hostname.as_deref().unwrap_or("<none>"));
    }

    // abuse.net (hostname domain first)
    if !cli.no_use_abusenet {
        if let Some(ref h) = hostname {
            if let Some(dom) = domain_of(h) {
                query_abuse_net(&dom, &mut emails, &cli).await?;
            }
        }
    }

    // DNS SOA traversal (hostname + reverse in-addr)
    if !cli.no_use_dns_soa {
        if let Some(ref h) = hostname {
            traverse_soa(h, &mut emails, &cli).await?;
        }
        traverse_soa(&ipv4_to_inaddr(ip), &mut emails, &cli).await?;
    }

    // WHOIS IP chain
    if !cli.no_use_whois_ip {
        whois_ip_chain(ip, &mut emails, &cli).await?;
    }

    // Finalize & filter
    let finalize_opts = FinalizeOptions {
        single_if_not_verbose: !cli.show_internal() && !cli.batch,
        ..Default::default()
    };
    let results = emails.finalize(finalize_opts);

    // Batch output
    if cli.batch {
        let joined = results
            .iter()
            .map(|(e, _)| e.as_str())
            .collect::<Vec<_>>()
            .join(",");
        println!("{}:{joined}", ip);
        return Ok(());
    }

    // Human output
    if cli.show_internal() {
        println!("Found abuse addresses (email\tconfidence):");
        for (e, c) in &results {
            println!("{e}\t{c}");
        }
    } else {
        // Only print addresses
        for (e, _) in &results {
            println!("{e}");
        }
    }

    // If no results and verbose, hint user
    if results.is_empty() && cli.error_enabled() {
        eprintln!("No abuse contacts discovered.");
    }

    Ok(())
}

/// Traverse up the domain labels performing SOA lookups and extracting RNAME
/// which is translated into an email (first '.' becomes '@').
async fn traverse_soa(base: &str, emails: &mut EmailSet, cli: &Cli) -> Result<()> {
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

        if let Ok(Ok(answer)) = tokio::time::timeout(
            Duration::from_secs(5),
            resolver.lookup(Name::from_ascii(&candidate)?, RecordType::SOA),
        )
        .await
        {
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
        labels.remove(0);
    }
    Ok(())
}
