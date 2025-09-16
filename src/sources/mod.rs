//! Pluggable contact data sources (Improvement Plan 1.3)
//!
//! This module introduces a first-pass abstraction over the various
//! "contact discovery" mechanisms. Each source implements a uniform
//! async trait so an orchestrator can:
//!   * Run cheap synchronous heuristics first
//!   * Run DNS-related lookups concurrently
//!   * Defer slower / rate-limited sources (WHOIS, abuse.net)
//!   * Provide controlled / testable fallbacks
//!
//! NOTE: This is an initial skeleton. Some sources (WHOIS / abuse.net)
//! are currently stubbed and should be fleshed out in follow-up
//! iterations (they emit warnings in the context).
//!
//! Future extensions (planned):
//!   * Bounded concurrency manager
//!   * Retry / backoff integration (see improvement plan section 11)
//!   * Feature flag gating per source
//!   * Metrics hooks for timings & success rates
//!   * Structured provenance enrichment (multi-source tagging)
//!
//! The façade (`facade.rs`) can later be refactored to build on top of
//! this abstraction instead of hand‑coded logic.
//!
//! High-level flow envisioned:
//!   1. PatternDomainSource (instant heuristics)
//!   2. ReverseDnsSource (extract hostname)
//!   3. DnsSoaSource (RNAME derived contacts)
//!   4. WhoisIpSource + AbuseNetSource (slower / optional)
//!   5. EmlHeaderSource (context enrichment)
//!
//! Orchestrator concept (pseudo):
//!   let mut ctx = QueryContext::new(ip, domain, eml_file, SourceOptions::default()).await?;
//!   run_all(&[PatternDomainSource, ReverseDnsSource, ...], &mut ctx).await;
//!   aggregate RawContact -> EmailSet -> finalize
//!
//! For now this file only provides the abstractions and minimal,
//! compilable implementations.
//!
//! Public items:
//!   - `ContactSource` trait
//!   - `QueryContext` (mutable shared state)
//!   - `RawContact`, `SourceProvenance`
//!   - Concrete source structs (skeletons)
//!
//! Usage (example skeleton):
//! ```ignore
//! let mut ctx = QueryContext::new(Some(ip), sender_domain, eml_path, SourceOptions::default()).await?;
//! let sources: Vec<Box<dyn ContactSource>> = vec![
//!     Box::new(PatternDomainSource),
//!     Box::new(ReverseDnsSource),
//!     Box::new(DnsSoaSource),
//! ];
//! for src in sources {
//!     let raws = src.collect(&mut ctx).await?;
//!     ctx.ingest(raws);
//! }
//! let finalized = ctx.into_email_set().finalize(FinalizeOptions::default());
//! ```
//!
use async_trait::async_trait;
use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;
use std::time::{Duration, Instant};

use trust_dns_resolver::{
    config::{ResolverConfig, ResolverOpts},
    proto::rr::{Name, RecordType},
    TokioAsyncResolver,
};

use crate::domain_utils;
use crate::emails::{soa_rname_to_email, EmailSet};
use crate::errors::{AbuseDetectorError, Result};
use crate::netutil::{domain_of, reverse_dns};

/// Representation of an extracted / inferred contact prior to ranking & normalization.
#[derive(Debug, Clone)]
pub struct RawContact {
    pub email: String,
    /// Confidence delta (will be accumulated inside `EmailSet`).
    pub confidence: u32,
    /// Simple provenance classification.
    pub provenance: SourceProvenance,
    /// Optional notes (diagnostics / rationale).
    pub notes: Vec<String>,
    /// Whether the contact originated from a pattern heuristic (vs discovered).
    pub is_pattern: bool,
}

impl RawContact {
    pub fn new(email: impl Into<String>, confidence: u32, provenance: SourceProvenance) -> Self {
        Self {
            email: email.into(),
            confidence,
            provenance,
            notes: vec![],
            is_pattern: false,
        }
    }

    pub fn with_pattern(mut self) -> Self {
        self.is_pattern = true;
        self
    }

    pub fn with_note(mut self, note: impl Into<String>) -> Self {
        self.notes.push(note.into());
        self
    }
}

/// Origin of a `RawContact`.
#[derive(Debug, Clone)]
pub enum SourceProvenance {
    Pattern,
    ReverseDns,
    DnsSoa,
    Whois,
    AbuseNet,
    EmlHeader,
    Other(&'static str),
}

/// Runtime toggles / configuration for source orchestration.
#[derive(Debug, Clone)]
pub struct SourceOptions {
    pub enable_reverse_dns: bool,
    pub enable_dns_soa: bool,
    pub enable_whois: bool,
    pub enable_abusenet: bool,
    pub enable_pattern_domains: bool,
    pub dns_timeout_secs: u64,
}

impl Default for SourceOptions {
    fn default() -> Self {
        Self {
            enable_reverse_dns: true,
            enable_dns_soa: true,
            enable_whois: true,
            enable_abusenet: true,
            enable_pattern_domains: true,
            dns_timeout_secs: 5,
        }
    }
}

/// Shared mutable state passed across sources.
pub struct QueryContext {
    pub ip: Option<Ipv4Addr>,
    pub reverse_hostname: Option<String>,
    pub sender_domain: Option<String>,
    pub eml_file: Option<PathBuf>,
    pub opts: SourceOptions,
    pub started_at: Instant,

    // Aggregation
    email_set: EmailSet,

    // Stats / diagnostics
    pub dns_queries: u32,
    pub whois_servers: u32,
    pub warnings: Vec<String>,

    // Resolver reused across DNS-based sources
    resolver: Option<TokioAsyncResolver>,
}

impl QueryContext {
    pub async fn new(
        ip: Option<Ipv4Addr>,
        sender_domain: Option<String>,
        eml_file: Option<PathBuf>,
        opts: SourceOptions,
    ) -> Result<Self> {
        Ok(Self {
            ip,
            reverse_hostname: None,
            sender_domain,
            eml_file,
            opts,
            started_at: Instant::now(),
            email_set: EmailSet::new(),
            dns_queries: 0,
            whois_servers: 0,
            warnings: vec![],
            resolver: None,
        })
    }

    fn ensure_resolver(&mut self) -> Result<&TokioAsyncResolver> {
        if self.resolver.is_none() {
            let r = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
            self.resolver = Some(r);
        }
        Ok(self.resolver.as_ref().unwrap())
    }

    /// Add raw contacts into the internal EmailSet.
    pub fn ingest(&mut self, raws: Vec<RawContact>) {
        for rc in raws {
            self.email_set.add_with_conf(&rc.email, rc.confidence);
        }
    }

    /// Expose aggregated email set (by value for downstream finalize()).
    pub fn into_email_set(self) -> EmailSet {
        self.email_set
    }

    /// Derived effective domain for IP-based flows (using reverse hostname if available).
    pub fn effective_domain(&self) -> Option<String> {
        if let Some(ref d) = self.sender_domain {
            return Some(d.clone());
        }
        if let Some(ref h) = self.reverse_hostname {
            return domain_of(h).map(|s| s.to_string());
        }
        None
    }
}

/// Trait every contact discovery component must implement.
#[async_trait]
pub trait ContactSource: Send + Sync {
    fn name(&self) -> &'static str;
    async fn collect(&self, ctx: &mut QueryContext) -> Result<Vec<RawContact>>;
}

/* -------------------------------------------------------------------------- */
/*                            Source Implementations                          */
/* -------------------------------------------------------------------------- */

/// 1. Fast pattern-based generation given a sender domain.
pub struct PatternDomainSource;
#[async_trait]
impl ContactSource for PatternDomainSource {
    fn name(&self) -> &'static str {
        "pattern-domain"
    }

    async fn collect(&self, ctx: &mut QueryContext) -> Result<Vec<RawContact>> {
        if !ctx.opts.enable_pattern_domains {
            return Ok(vec![]);
        }
        let mut out = Vec::new();
        if let Some(ref dom) = ctx.sender_domain {
            if let Ok(pats) = domain_utils::generate_abuse_emails(dom) {
                for p in pats {
                    out.push(
                        RawContact::new(p, 2, SourceProvenance::Pattern)
                            .with_pattern()
                            .with_note("pattern heuristic"),
                    );
                }
            }
        }
        Ok(out)
    }
}

/// 2. Reverse DNS hostname resolution.
pub struct ReverseDnsSource;
#[async_trait]
impl ContactSource for ReverseDnsSource {
    fn name(&self) -> &'static str {
        "reverse-dns"
    }

    async fn collect(&self, ctx: &mut QueryContext) -> Result<Vec<RawContact>> {
        if !ctx.opts.enable_reverse_dns {
            return Ok(vec![]);
        }
        let Some(ipv4) = ctx.ip else {
            return Ok(vec![]);
        };
        if ctx.reverse_hostname.is_some() {
            return Ok(vec![]); // Already resolved
        }
        match reverse_dns(IpAddr::V4(ipv4), false).await {
            Ok(host_opt) => {
                ctx.reverse_hostname = host_opt;
            }
            Err(e) => {
                ctx.warnings.push(format!("reverse DNS lookup failed: {e}"));
            }
        }
        Ok(vec![]) // Reverse DNS does not directly yield email contacts
    }
}

/// 3. DNS SOA traversal (collect RNAME based emails along the label chain).
pub struct DnsSoaSource;
#[async_trait]
impl ContactSource for DnsSoaSource {
    fn name(&self) -> &'static str {
        "dns-soa"
    }

    async fn collect(&self, ctx: &mut QueryContext) -> Result<Vec<RawContact>> {
        if !ctx.opts.enable_dns_soa {
            return Ok(vec![]);
        }

        let resolver = ctx.ensure_resolver()?.clone();
        let dns_timeout = ctx.opts.dns_timeout_secs;
        let mut candidates: Vec<String> = Vec::new();

        // Clone context fields early to avoid overlapping borrows during mutation.
        let reverse_host_opt = ctx.reverse_hostname.clone();
        let sender_domain_opt = ctx.sender_domain.clone();

        if let Some(h) = reverse_host_opt {
            candidates.push(h);
        }
        if let Some(d) = sender_domain_opt {
            if !candidates.iter().any(|c| c == &d) {
                candidates.push(d);
            }
        }

        let mut out = Vec::new();
        for seed in candidates {
            // Traverse by progressively removing leftmost label (like existing logic)
            let mut labels: Vec<&str> = seed.trim_end_matches('.').split('.').collect();
            while labels.len() > 1 {
                let query_name = labels.join(".");
                ctx.dns_queries += 1;

                let res = tokio::time::timeout(
                    Duration::from_secs(dns_timeout),
                    resolver.lookup(
                        Name::from_ascii(&query_name).map_err(|e| {
                            AbuseDetectorError::Configuration(format!(
                                "Invalid domain name {query_name}: {e}"
                            ))
                        })?,
                        RecordType::SOA,
                    ),
                )
                .await;

                if let Ok(Ok(answer)) = res {
                    if let Some(trust_dns_resolver::proto::rr::RData::SOA(soa)) =
                        answer.iter().next()
                    {
                        let rname = soa.rname().to_utf8();
                        if let Some(email) = soa_rname_to_email(rname.trim_end_matches('.')) {
                            out.push(
                                RawContact::new(email, 1, SourceProvenance::DnsSoa)
                                    .with_note(format!("SOA rname from {query_name}")),
                            );
                        }
                    }
                }
                labels.remove(0);
            }
        }

        Ok(out)
    }
}

/// 4. WHOIS IP chain collection (stub – to be implemented fully later).
pub struct WhoisIpSource;
#[async_trait]
impl ContactSource for WhoisIpSource {
    fn name(&self) -> &'static str {
        "whois-ip"
    }

    async fn collect(&self, ctx: &mut QueryContext) -> Result<Vec<RawContact>> {
        if !ctx.opts.enable_whois {
            return Ok(vec![]);
        }
        // TODO: integrate existing `whois_ip_chain` logic with parsing -> RawContact.
        ctx.warnings
            .push("WHOIS IP source not yet integrated into abstraction".to_string());
        Ok(vec![])
    }
}

/// 5. abuse.net directory lookup (stub – to be implemented fully later).
pub struct AbuseNetSource;
#[async_trait]
impl ContactSource for AbuseNetSource {
    fn name(&self) -> &'static str {
        "abuse-net"
    }

    async fn collect(&self, ctx: &mut QueryContext) -> Result<Vec<RawContact>> {
        if !ctx.opts.enable_abusenet {
            return Ok(vec![]);
        }
        // TODO: integrate existing `query_abuse_net` and transform results.
        ctx.warnings
            .push("abuse.net source not yet integrated into abstraction".to_string());
        Ok(vec![])
    }
}

/// 6. EML header parsing / enrichment (currently does not emit contacts
///    directly; would set context details or derive domain-level signals).
pub struct EmlHeaderSource;
#[async_trait]
impl ContactSource for EmlHeaderSource {
    fn name(&self) -> &'static str {
        "eml-header"
    }

    async fn collect(&self, ctx: &mut QueryContext) -> Result<Vec<RawContact>> {
        if ctx.eml_file.is_none() {
            return Ok(vec![]);
        }
        // Future: parse additional header-based abuse contacts (e.g. X-Abuse / custom fields).
        Ok(vec![])
    }
}

/* -------------------------------------------------------------------------- */
/*                           Convenience Orchestration                        */
/* -------------------------------------------------------------------------- */

/// Helper to run a slice of sources sequentially (simple baseline;
/// future work: parallelization + bounded concurrency).
pub async fn run_sources(sources: &[&(dyn ContactSource)], ctx: &mut QueryContext) -> Result<()> {
    for src in sources {
        let raws = src.collect(ctx).await?;
        ctx.ingest(raws);
    }
    Ok(())
}
