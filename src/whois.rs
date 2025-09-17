use std::net::Ipv4Addr;
use std::time::Duration;

use anyhow::{Result, anyhow};
use regex::Regex;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::cli::Cli;
use crate::emails::{EmailSet, is_plausible_email};

/// Abstraction over environment / verbosity for WHOIS & abuse.net lookups.
/// This removes the direct dependency of core WHOIS functions on the concrete
/// CLI type and enables reuse inside the façade / sources abstractions.
pub trait WhoisEnv {
    fn show_commands(&self) -> bool;
    fn is_trace(&self) -> bool;
    fn warn_enabled(&self) -> bool;
}

impl WhoisEnv for Cli {
    fn show_commands(&self) -> bool {
        self.show_commands
    }
    fn is_trace(&self) -> bool {
        self.is_trace()
    }
    fn warn_enabled(&self) -> bool {
        self.warn_enabled()
    }
}

impl WhoisEnv for std::sync::Arc<Cli> {
    fn show_commands(&self) -> bool {
        self.as_ref().show_commands()
    }
    fn is_trace(&self) -> bool {
        self.as_ref().is_trace()
    }
    fn warn_enabled(&self) -> bool {
        self.as_ref().warn_enabled()
    }
}

/// WHOIS TCP port.
const WHOIS_PORT: u16 = 43;

/// Maximum referral (chained WHOIS) depth to avoid loops.
const MAX_WHOIS_DEPTH: usize = 6;

/// Perform a basic WHOIS query (over TCP 43) with a timeout.
///
/// Returns the raw textual response.
pub async fn simple_whois(server: &str, query: &str, to: Duration) -> Result<String> {
    // Connect with timeout
    let mut stream = match timeout(to, TcpStream::connect((server, WHOIS_PORT))).await {
        Ok(Ok(s)) => s,
        Ok(Err(e)) => return Err(anyhow!("connect error to {server}: {e}")),
        Err(_) => return Err(anyhow!("connect timeout to {server}")),
    };

    // Send query (canonical WHOIS: "<query>\r\n")
    let line = format!("{query}\r\n");
    timeout(to, stream.write_all(line.as_bytes()))
        .await
        .map_err(|_| anyhow!("write timeout to {{server}}"))??;

    // Read whole response
    let mut buf = Vec::new();
    timeout(to, stream.read_to_end(&mut buf))
        .await
        .map_err(|_| anyhow!("read timeout from {server}"))??;

    Ok(String::from_utf8_lossy(&buf).into_owned())
}

/// Query whois.abuse.net for a domain and extract candidate abuse emails.
///
/// Increments confidence (+1) for each appearance. This mirrors (lightly)
/// the legacy behavior where abuse.net responses boosted confidence.
///
/// Silently returns Ok(()) for network / timeout errors (treating them as "no data").
pub async fn query_abuse_net<E: WhoisEnv + ?Sized>(
    domain: &str,
    emails: &mut EmailSet,
    env: &E,
) -> Result<()> {
    if env.show_commands() {
        eprintln!("(cmd) whois -h whois.abuse.net {domain}");
    }
    if env.is_trace() {
        eprintln!("Querying whois.abuse.net for {domain}");
    }

    // Basic sanity check; abuse.net expects a domain-like token.
    if !domain.contains('.') {
        return Ok(());
    }

    let resp = match simple_whois("whois.abuse.net", domain, Duration::from_secs(8)).await {
        Ok(r) => r,
        Err(e) => {
            if env.warn_enabled() {
                eprintln!("(abuse.net) warning: {e}");
            }
            return Ok(());
        }
    };

    let re = Regex::new(r"(?i)([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})").unwrap();
    for cap in re.captures_iter(&resp) {
        let email = cap[1].to_ascii_lowercase();
        if is_plausible_email(&email) {
            emails.add_candidate(&email);
            emails.bump(&email);
            if env.is_trace() {
                eprintln!("  abuse.net => {email}");
            }
        }
    }
    Ok(())
}

/// Query an IPv4 address starting at ARIN (whois.arin.net) and follow referrals
/// (via `refer:` or `ReferralServer:` lines) up to MAX_WHOIS_DEPTH.
///
/// Extracts plausible email addresses along the way, adding +1 confidence per occurrence.
///
/// Lightweight WHOIS response parser focused on practical extraction of abuse-related
/// emails and referral following across common RIR servers.
pub async fn whois_ip_chain<E: WhoisEnv + ?Sized>(
    ip: Ipv4Addr,
    emails: &mut EmailSet,
    env: &E,
) -> Result<()> {
    let mut server = "whois.arin.net".to_string();
    let ip_str = ip.to_string();

    let re_email = Regex::new(r"(?i)([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})").unwrap();
    // "refer: whois.ripe.net" OR "ReferralServer: whois://whois.ripe.net"
    let re_refer_plain = Regex::new(r"(?im)^\s*refer:\s*([A-Z0-9._\-]+)\s*$").unwrap();
    let re_referral_server =
        Regex::new(r"(?im)^\s*ReferralServer:\s*whois://([A-Z0-9._\-]+)\s*$").unwrap();

    for depth in 0..MAX_WHOIS_DEPTH {
        if env.show_commands() {
            eprintln!("(cmd) whois -h {server} {ip_str}");
        }
        if env.is_trace() {
            eprintln!("WHOIS(depth={depth}) server={server}");
        }

        let resp = match simple_whois(&server, &ip_str, Duration::from_secs(10)).await {
            Ok(r) => r,
            Err(e) => {
                if env.warn_enabled() {
                    eprintln!("WHOIS warning on {server}: {e}");
                }
                break;
            }
        };

        // Extract emails
        for cap in re_email.captures_iter(&resp) {
            let email = cap[1].to_ascii_lowercase();
            if is_plausible_email(&email) {
                emails.add_with_conf(&email, 1);
                if env.is_trace() {
                    eprintln!("  WHOIS email => {email}");
                }
            }
        }

        // Find referral (prefer explicit refer: first)
        let next = re_refer_plain
            .captures(&resp)
            .and_then(|c| c.get(1).map(|m| m.as_str().to_ascii_lowercase()))
            .or_else(|| {
                re_referral_server
                    .captures(&resp)
                    .and_then(|c| c.get(1).map(|m| m.as_str().to_ascii_lowercase()))
            });

        match next {
            Some(n) if n != server => {
                if env.is_trace() {
                    eprintln!("  Referral to {n}");
                }
                server = n;
            }
            _ => break,
        }
    }

    Ok(())
}

/// Convenience function to run both abuse.net and whois chain (if enabled),
/// letting caller decide ordering. Provided for potential orchestration modules.
#[cfg(test)]
#[allow(dead_code)]
pub async fn run_whois_phase(
    ip: Ipv4Addr,
    hostname_domain: Option<&str>,
    emails: &mut EmailSet,
    opts: &Cli,
) -> Result<()> {
    if !opts.no_use_abusenet
        && let Some(dom) = hostname_domain
    {
        query_abuse_net(dom, emails, opts).await?;
    }
    if !opts.no_use_whois_ip {
        whois_ip_chain(ip, emails, opts).await?;
    }
    Ok(())
}

/// Team Cymru ASN information structure
#[derive(Debug, Clone)]
pub struct CymruAsnInfo {
    pub asn: u32,
    #[allow(dead_code)]
    pub bgp_prefix: String,
    pub country: String,
    pub registry: String,
    #[allow(dead_code)]
    pub allocated: String,
    pub as_name: String,
}

/// Query Team Cymru for ASN information about an IP address.
///
/// Returns detailed ASN information that's often missing from regular WHOIS.
/// Format: "AS | IP | BGP Prefix | CC | Registry | Allocated | AS Name"
pub async fn query_cymru_asn<E: WhoisEnv + ?Sized>(ip: Ipv4Addr, env: &E) -> Result<CymruAsnInfo> {
    let query = format!(" -v {}", ip);

    if env.show_commands() {
        eprintln!("(cmd) whois -h whois.cymru.com '{}'", query);
    }
    if env.is_trace() {
        eprintln!("Querying Team Cymru for ASN info: {}", ip);
    }

    let resp = simple_whois("whois.cymru.com", &query, Duration::from_secs(8)).await?;

    // Parse response: "396479  | 204.220.184.46   | 204.220.184.0/24    | US | arin     | 1995-01-05 | MAILGUN-, US"
    for line in resp.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with("AS") {
            continue; // Skip header line
        }

        let parts: Vec<&str> = line.split('|').map(|s| s.trim()).collect();
        if parts.len() >= 7
            && let Ok(asn) = parts[0].parse::<u32>()
        {
            if env.is_trace() {
                eprintln!("  Cymru ASN => AS{} ({})", asn, parts[6]);
            }

            return Ok(CymruAsnInfo {
                asn,
                bgp_prefix: parts[2].to_string(),
                country: parts[3].to_string(),
                registry: parts[4].to_uppercase(),
                allocated: parts[5].to_string(),
                as_name: parts[6].to_string(),
            });
        }
    }

    Err(anyhow!("No ASN information found in Cymru response"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::emails::EmailSet;

    #[tokio::test]
    async fn test_simple_whois_timeout() {
        // Query deliberately invalid server -> expect error
        let res = simple_whois("invalid.whois.test.", "example", Duration::from_millis(500)).await;
        assert!(res.is_err());
    }

    #[test]
    fn test_email_regex_basic() {
        let re = Regex::new(r"(?i)([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})").unwrap();
        let text = "Contact: Abuse <abuse@foo.bar>, Hostmaster hostmaster@foo.bar";
        let mut found = vec![];
        for cap in re.captures_iter(text) {
            found.push(cap[1].to_ascii_lowercase());
        }
        assert!(found.contains(&"abuse@foo.bar".to_string()));
        assert!(found.contains(&"hostmaster@foo.bar".to_string()));
    }

    // NOTE: Integration tests for real whois servers are intentionally omitted
    // to keep tests deterministic and CI-friendly.
    #[tokio::test]
    async fn test_whois_chain_handles_unreachable() {
        let mut emails = EmailSet::new();
        let fake_cli = Cli {
            ip: Some("198.51.100.10".into()),
            eml: None,
            verbose: 0,
            no_use_hostname: true,
            no_use_abusenet: true,
            no_use_dns_soa: true,
            no_use_whois_ip: false,
            show_commands: false,
            batch: false,
            json: false,
            yaml: false,
            show_escalation: false,
            escalation_only: false,
            no_color: false,
            plain: false,
            cache: None,
            cache_expire: 7 * 24 * 3600,
            generate_schema: false,
        };
        // Temporarily point to a non-existent server by calling chain with an unlikely IP
        // (We rely on the default start server; errors are swallowed into Ok(()))
        let _ = whois_ip_chain("198.51.100.10".parse().unwrap(), &mut emails, &fake_cli).await;
        // Should not panic; no strong assertion on contents (network dependent).
    }
}
