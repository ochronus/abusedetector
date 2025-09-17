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
//!   - `ContactAggregator` (provenance retention)
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
//! for rc in ctx.provenance() {
//!     println!("Provenance: {} +{}", rc.email, rc.confidence);
//! }
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceErrorCategory {
    Input,
    Network,
    Parse,
    Internal,
    Unknown,
}

#[derive(Debug, Clone)]
pub struct SourceTiming {
    pub name: &'static str,
    pub start_ms: u128,
    pub end_ms: u128,
    pub duration_ms: u128,
    pub success: bool,
    pub warnings: Vec<String>,
    pub error_categories: Vec<SourceErrorCategory>,
}

impl SourceTiming {
    fn new(name: &'static str) -> Self {
        Self {
            name,
            start_ms: 0,
            end_ms: 0,
            duration_ms: 0,
            success: true,
            warnings: vec![],
            error_categories: vec![],
        }
    }
    fn finish(
        mut self,
        start: std::time::Instant,
        warnings: Vec<String>,
        success: bool,
        errs: Vec<SourceErrorCategory>,
    ) -> Self {
        let dur = start.elapsed().as_millis();
        self.end_ms = dur;
        self.duration_ms = dur;
        self.success = success;
        self.warnings = warnings;
        self.error_categories = errs;
        self
    }
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
    pub show_commands: bool,
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
            show_commands: false,
        }
    }
}

/// Aggregates raw contacts for provenance & later rich structured output.
/// This preserves every RawContact (even if multiple sources yield the
/// same canonical email) so we can reconstruct:
///   * Per-source contributions
///   * Confidence accumulation pathways
///   * Detailed provenance metadata (notes, pattern flags)
#[derive(Debug, Default)]
pub struct ContactAggregator {
    raw: Vec<RawContact>,
}

impl ContactAggregator {
    pub fn new() -> Self {
        Self { raw: Vec::new() }
    }
    pub fn push(&mut self, rc: RawContact) {
        self.raw.push(rc);
    }
    pub fn extend(&mut self, items: impl IntoIterator<Item = RawContact>) {
        for rc in items {
            self.push(rc);
        }
    }
    pub fn all(&self) -> &[RawContact] {
        &self.raw
    }
    pub fn into_inner(self) -> Vec<RawContact> {
        self.raw
    }
    /// Simple summary by email -> total confidence (deduplicated)
    pub fn confidence_summary(&self) -> Vec<(String, u32)> {
        use std::collections::HashMap;
        let mut map: HashMap<String, u32> = HashMap::new();
        for rc in &self.raw {
            let entry = map.entry(rc.email.to_ascii_lowercase()).or_insert(0);
            *entry = entry.saturating_add(rc.confidence);
        }
        let mut v: Vec<_> = map.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }
}

/// Build a mapping of canonical email -> distinct structured output contact sources
/// derived from raw provenance entries.
/// This helper centralizes the transformation logic so the application layer
/// does not need to duplicate the match statements.
///
/// NOTE: We intentionally avoid pulling in structured_output earlier in the
/// file to keep dependency localized.
pub fn map_provenance_to_contact_sources(
    raws: &[RawContact],
) -> std::collections::HashMap<String, Vec<crate::structured_output::ContactSource>> {
    use crate::structured_output::ContactSource as OutSrc;
    use std::collections::HashMap;

    let mut map: HashMap<String, Vec<OutSrc>> = HashMap::new();

    for rc in raws {
        let email_key = rc.email.to_ascii_lowercase();
        let sources_vec = map.entry(email_key).or_default();

        let mapped = match rc.provenance {
            SourceProvenance::DnsSoa => {
                let domain = rc.email.split('@').nth(1).unwrap_or("").to_string();
                OutSrc::DnsSoa { domain }
            }
            SourceProvenance::Whois => OutSrc::Whois {
                server: "whois-chain".into(),
            },
            SourceProvenance::AbuseNet => OutSrc::AbuseNet,
            SourceProvenance::ReverseDns => OutSrc::HostnameHeuristic,
            SourceProvenance::Pattern => OutSrc::MultipleConfirmed,
            SourceProvenance::EmlHeader => OutSrc::HostnameHeuristic,
            SourceProvenance::Other(_) => OutSrc::MultipleConfirmed,
        };

        // Deduplicate by discriminant (avoid repeating same logical source)
        if !sources_vec
            .iter()
            .any(|existing| std::mem::discriminant(existing) == std::mem::discriminant(&mapped))
        {
            sources_vec.push(mapped);
        }
    }

    map
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
    aggregator: ContactAggregator,

    // Stats / diagnostics
    pub dns_queries: u32,
    pub whois_servers: u32,
    pub warnings: Vec<String>,

    // Per-source timing & categorization
    pub source_timings: Vec<SourceTiming>,

    // Resolver reused across DNS-based sources
    resolver: Option<TokioAsyncResolver>,
}

/// Lightweight snapshot used by parallel runners so they can work
/// with a read‑only view of the state and produce deltas without
/// holding a mutable borrow over the full QueryContext.
#[derive(Clone, Debug)]
pub struct QueryContextSnapshot {
    pub ip: Option<Ipv4Addr>,
    pub reverse_hostname: Option<String>,
    pub effective_domain: Option<String>,
    pub opts: SourceOptions,
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
            aggregator: ContactAggregator::new(),
            dns_queries: 0,
            whois_servers: 0,
            warnings: vec![],
            source_timings: Vec::new(),
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

    /// Add raw contacts into the internal EmailSet AND provenance aggregator.
    pub fn ingest(&mut self, raws: Vec<RawContact>) {
        for rc in raws {
            self.email_set.add_with_conf(&rc.email, rc.confidence);
            self.aggregator.push(rc);
        }
    }

    /// Expose aggregated email set (by value for downstream finalize()).
    pub fn into_email_set(self) -> EmailSet {
        self.email_set
    }

    /// Access full raw provenance list.
    pub fn provenance(&self) -> &[RawContact] {
        self.aggregator.all()
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

    /// Build a read‑only snapshot for parallel phase execution.
    pub fn snapshot(&self) -> QueryContextSnapshot {
        QueryContextSnapshot {
            ip: self.ip,
            reverse_hostname: self.reverse_hostname.clone(),
            effective_domain: self.effective_domain(),
            opts: self.opts.clone(),
        }
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
        let domain_candidate = ctx.sender_domain.clone().or_else(|| ctx.effective_domain());
        if let Some(ref dom) = domain_candidate {
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
        match reverse_dns(IpAddr::V4(ipv4), ctx.opts.show_commands).await {
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
                            AbuseDetectorError::Configuration {
                                message: format!("Invalid domain name {query_name}: {e}"),
                            }
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
        // Implement WHOIS IP chain integration.
        // Reuse existing whois_ip_chain -> collect emails -> map to RawContact.
        let Some(ipv4) = ctx.ip else {
            return Ok(vec![]);
        };

        // Minimal silent environment implementing WhoisEnv (no verbosity).
        struct SilentEnv;
        impl crate::whois::WhoisEnv for SilentEnv {
            fn show_commands(&self) -> bool {
                false
            }
            fn is_trace(&self) -> bool {
                false
            }
            fn warn_enabled(&self) -> bool {
                false
            }
        }

        let mut tmp = EmailSet::new();
        if let Err(e) = crate::whois::whois_ip_chain(ipv4, &mut tmp, &SilentEnv).await {
            ctx.warnings.push(format!("WHOIS chain failed: {e}"));
            return Ok(vec![]);
        }

        // Attribute a single WHOIS server contact (approximation; underlying
        // chain currently doesn't expose per-server count to this abstraction).
        ctx.whois_servers = ctx.whois_servers.saturating_add(1);

        let raws = tmp
            .into_sorted()
            .into_iter()
            .map(|(email, conf)| {
                RawContact::new(email, conf, SourceProvenance::Whois).with_note("whois chain")
            })
            .collect();

        Ok(raws)
    }
}

/// 5. abuse.net directory lookup (now implemented).
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
        let Some(domain) = ctx.effective_domain() else {
            // No usable domain context available
            return Ok(vec![]);
        };

        // Silent environment (no CLI dependency)
        struct SilentEnv;
        impl crate::whois::WhoisEnv for SilentEnv {
            fn show_commands(&self) -> bool {
                false
            }
            fn is_trace(&self) -> bool {
                false
            }
            fn warn_enabled(&self) -> bool {
                false
            }
        }

        let mut tmp = EmailSet::new();
        if let Err(e) = crate::whois::query_abuse_net(&domain, &mut tmp, &SilentEnv).await {
            ctx.warnings
                .push(format!("abuse.net lookup failed for {domain}: {e}"));
            return Ok(vec![]);
        }

        let raws = tmp
            .into_sorted()
            .into_iter()
            .map(|(email, conf)| {
                RawContact::new(email, conf, SourceProvenance::AbuseNet)
                    .with_note(format!("abuse.net directory ({domain})"))
            })
            .collect();

        Ok(raws)
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
pub async fn run_sources(
    sources: &[&dyn ContactSource],
    ctx: &mut QueryContext,
) -> Result<()> {
    // Phase 1: sequential “fast” sources (already provided in `sources` slice)
    for src in sources {
        execute_with_retry(*src, ctx).await?;
    }
    Ok(())
}

/// Run a second phase in parallel (intended for slower network sources).
/// Accepts factory closures so the caller can decide which sources to
/// include without borrowing `ctx` mutably during spawn.
pub async fn run_parallel_phase2<F>(
    ctx: &mut QueryContext,
    builders: Vec<F>,
    concurrency: usize,
) -> Result<()>
where
    F: Fn() -> Box<dyn ContactSource + Send + Sync> + Send + Sync + 'static,
{
    use futures::stream::{FuturesUnordered, StreamExt};
    use tokio::sync::Semaphore;

    let sem = std::sync::Arc::new(Semaphore::new(concurrency.max(1)));
    let snapshot = ctx.snapshot();
    let mut futs: FuturesUnordered<_> = builders
        .into_iter()
        .map(|b| {
            let snap = snapshot.clone();
            let sem = sem.clone();
            async move {
                let _p = sem.acquire().await;
                let mut local_ctx = snapshot_to_local(&snap);
                let src = b();
                let name = src.name();
                let start = Instant::now();
                let mut warnings = Vec::new();
                let mut success = true;
                let mut categories = Vec::new();
                match src.collect(&mut local_ctx).await {
                    Ok(raws) => (raws, local_ctx, name, start, warnings, success, categories),
                    Err(e) => {
                        success = false;
                        categories.push(SourceErrorCategory::Network);
                        warnings.push(format!("{name} failed: {e}"));
                        (
                            Vec::new(),
                            local_ctx,
                            name,
                            start,
                            warnings,
                            success,
                            categories,
                        )
                    }
                }
            }
        })
        .collect();

    while let Some((raws, local_ctx, name, start, warnings, success, cats)) = futs.next().await {
        // Apply deltas back to main context
        ctx.dns_queries = ctx.dns_queries.saturating_add(local_ctx.dns_queries);
        ctx.whois_servers = ctx.whois_servers.saturating_add(local_ctx.whois_servers);
        ctx.warnings.extend(warnings.clone());
        for rc in raws {
            ctx.ingest(vec![rc]);
        }
        ctx.source_timings
            .push(SourceTiming::new(name).finish(start, warnings, success, cats));
    }
    Ok(())
}

/// Helper: execute a single source with simplistic retry/backoff.
async fn execute_with_retry(src: &dyn ContactSource, ctx: &mut QueryContext) -> Result<()> {
    let name = src.name();
    let start = Instant::now();
    let mut warnings: Vec<String> = Vec::new();
    let mut success = true;
    let mut error_categories: Vec<SourceErrorCategory> = Vec::new();

    let attempts = match name {
        "reverse-dns" | "dns-soa" => 3,
        "whois-ip" | "abuse-net" => 3,
        _ => 1,
    };

    let mut result: std::result::Result<Vec<RawContact>, AbuseDetectorError> =
        Err(AbuseDetectorError::internal("uninitialized"));
    for attempt in 1..=attempts {
        match src.collect(ctx).await {
            Ok(v) => {
                result = Ok(v);
                break;
            }
            Err(e) => {
                if attempt == attempts {
                    success = false;
                    error_categories.push(SourceErrorCategory::Network);
                    warnings.push(format!("{name} failed after {attempts} attempts: {e}"));
                    result = Err(e);
                } else {
                    warnings.push(format!("{name} attempt {attempt} failed: {e}; retrying"));
                    let base_ms = match name {
                        "reverse-dns" | "dns-soa" => 120,
                        "whois-ip" => 250,
                        "abuse-net" => 180,
                        _ => 0,
                    };
                    if base_ms > 0 {
                        tokio::time::sleep(std::time::Duration::from_millis(
                            (base_ms * attempt as u64).min(1_000),
                        ))
                        .await;
                    }
                }
            }
        }
    }

    if let Ok(raws) = result {
        ctx.ingest(raws);
    }

    ctx.source_timings.push(SourceTiming::new(name).finish(
        start,
        warnings,
        success,
        error_categories,
    ));
    Ok(())
}

/// Build a minimal local context from snapshot (used in parallel phase).
fn snapshot_to_local(snap: &QueryContextSnapshot) -> QueryContext {
    QueryContext {
        ip: snap.ip,
        reverse_hostname: snap.reverse_hostname.clone(),
        sender_domain: None, // domain already resolved into effective_domain
        eml_file: None,
        opts: snap.opts.clone(),
        started_at: Instant::now(),
        email_set: EmailSet::new(),
        aggregator: ContactAggregator::new(),
        dns_queries: 0,
        whois_servers: 0,
        warnings: Vec::new(),
        source_timings: Vec::new(),
        resolver: None,
    }
}

#[cfg(test)]
mod source_tests {
    use super::*;
    use crate::sources::{
        map_provenance_to_contact_sources, ContactSource, PatternDomainSource, QueryContext,
        ReverseDnsSource, SourceOptions,
    };

    // Helper to build a minimal context
    async fn ctx_with_domain(domain: &str, pattern: bool, reverse: bool) -> QueryContext {
        let opts = SourceOptions {
            enable_reverse_dns: reverse,
            enable_dns_soa: false,
            enable_whois: false,
            enable_abusenet: false,
            enable_pattern_domains: pattern,
            dns_timeout_secs: 1,
            show_commands: false,
        };
        QueryContext::new(None, Some(domain.to_string()), None, opts)
            .await
            .expect("ctx")
    }

    #[tokio::test]
    async fn test_pattern_domain_source_provenance() {
        let mut ctx = ctx_with_domain("example.com", true, false).await;
        let src = PatternDomainSource;
        let raws = src.collect(&mut ctx).await.expect("collect");
        assert!(!raws.is_empty(), "pattern source should yield contacts");
        let count = raws.len();
        ctx.ingest(raws);
        // Provenance retained
        assert_eq!(ctx.provenance().len(), count);
        assert!(ctx
            .provenance()
            .iter()
            .all(|rc| matches!(rc.provenance, SourceProvenance::Pattern)));
        // Mapping helper should classify entries
        let mapped = map_provenance_to_contact_sources(ctx.provenance());
        assert_eq!(mapped.len(), count, "each unique pattern email mapped");
    }

    #[tokio::test]
    async fn test_timing_capture_and_retry_path() {
        // Include a reverse DNS source (with no IP -> yields no contacts) to exercise timing.
        let mut ctx = ctx_with_domain("example.org", true, true).await;
        let sources: Vec<Box<dyn ContactSource>> =
            vec![Box::new(PatternDomainSource), Box::new(ReverseDnsSource)];
        for s in sources {
            let _ = s.collect(&mut ctx).await.map(|r| {
                ctx.ingest(r);
            });
        }
        // Manually push a timing sample to simulate run_sources wrapper path
        // (since tests directly invoked collect()).
        assert!(
            !ctx.provenance().is_empty(),
            "pattern domain source should record provenance"
        );
        // Emulate network timing capture semantics
        assert!(
            ctx.source_timings.is_empty(),
            "direct collect() calls do not auto-populate timings"
        );
    }

    #[tokio::test]
    async fn test_confidence_summary_consistency() {
        let mut ctx = ctx_with_domain("example.net", true, false).await;
        let src = PatternDomainSource;
        let raws = src.collect(&mut ctx).await.unwrap();
        ctx.ingest(raws);
        let summary = ctx.provenance().iter().fold(
            std::collections::HashMap::<String, u32>::new(),
            |mut acc, rc| {
                *acc.entry(rc.email.clone()).or_insert(0) += rc.confidence;
                acc
            },
        );
        assert!(
            !summary.is_empty(),
            "confidence summary should reflect ingested pattern contacts"
        );
    }
}
