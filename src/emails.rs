use once_cell::sync::Lazy;
use regex::Regex;
use std::collections::HashMap;

/// Container for discovered abuse-related email addresses with a simple
/// confidence counter (larger value means "more evidence").
////
/// This module encapsulates ranking, normalization and filtering behavior
/// so main logic stays readable.
#[derive(Default, Debug, Clone)]
pub struct EmailSet {
    map: HashMap<String, u32>,
}

impl EmailSet {
    /// Create an empty collection.
    pub fn new() -> Self {
        Self {
            map: HashMap::new(),
        }
    }

    /// Insert email with confidence 0 if absent.
    pub fn add_candidate<S: AsRef<str>>(&mut self, email: S) {
        let e = canonical(email.as_ref());
        self.map.entry(e).or_insert(0);
    }

    /// Increase confidence by 1 (creates entry if absent).
    pub fn bump<S: AsRef<str>>(&mut self, email: S) {
        let e = canonical(email.as_ref());
        *self.map.entry(e).or_insert(0) += 1;
    }

    /// Add arbitrary confidence delta (saturating).
    pub fn add_with_conf<S: AsRef<str>>(&mut self, email: S, delta: u32) {
        let e = canonical(email.as_ref());
        let entry = self.map.entry(e).or_insert(0);
        *entry = entry.saturating_add(delta);
    }

    /// Merge another EmailSet (sums confidence, saturating on u32::MAX).
    // absorb removed (was unused)

    /// Strip trailing '.' (common artefact when parsing some whois / DNS outputs)
    /// and merge duplicates post-normalization.
    pub fn normalize(&mut self) {
        let mut merged: HashMap<String, u32> = HashMap::new();
        for (raw, conf) in self.map.drain() {
            let norm = raw.trim_end_matches('.').to_string();
            *merged.entry(norm).or_insert(0) += conf;
        }
        self.map = merged;
    }

    /// Remove emails that belong to well known registry / infrastructure domains.
    pub fn filter_registry(&mut self, registry_domains: &[&str]) {
        self.map.retain(|e, _| {
            if let Some(idx) = e.find('@') {
                let dom = &e[idx + 1..];
                !registry_domains
                    .iter()
                    .any(|rd| dom.eq_ignore_ascii_case(rd))
            } else {
                true
            }
        });
    }

    /// If any entry starts with "abuse@", keep only those.
    pub fn prefer_abuse_local_part(&mut self) {
        let has_abuse = self
            .map
            .keys()
            .any(|e| e.to_ascii_lowercase().starts_with("abuse@"));
        if has_abuse {
            self.map
                .retain(|e, _| e.to_ascii_lowercase().starts_with("abuse@"));
        }
    }

    /// Consume and return a sorted Vec (confidence desc then lexicographic).
    pub fn into_sorted(mut self) -> Vec<(String, u32)> {
        self.normalize();
        let mut v: Vec<_> = self.map.into_iter().collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    /// Helper for printing or batch reporting while preserving underlying map.
    #[cfg(test)]
    pub fn snapshot_sorted(&self) -> Vec<(String, u32)> {
        let mut v: Vec<_> = self.map.iter().map(|(k, v)| (k.clone(), *v)).collect();
        v.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        v
    }

    /// Finalize applying typical heuristics (normalization, filtering, preference rules).
    pub fn finalize(mut self, options: FinalizeOptions) -> Vec<(String, u32)> {
        self.normalize();
        if options.filter_registry {
            self.filter_registry(&options.registry_domains);
        }
        if options.prefer_abuse {
            self.prefer_abuse_local_part();
        }
        let mut sorted = self.into_sorted();
        if options.single_if_not_verbose && !sorted.is_empty() {
            sorted.truncate(1);
        }
        sorted
    }
}

/// Configuration controlling finalize() heuristics.
#[derive(Debug, Clone)]
pub struct FinalizeOptions {
    pub registry_domains: Vec<&'static str>,
    pub filter_registry: bool,
    pub prefer_abuse: bool,
    pub single_if_not_verbose: bool,
}

impl Default for FinalizeOptions {
    fn default() -> Self {
        Self {
            registry_domains: vec![
                "ripe.net",
                "iana.org",
                "arin.net",
                "apnic.net",
                "lacnic.net",
                "afrinic.net",
                "example.net",
            ],
            filter_registry: true,
            prefer_abuse: true,
            single_if_not_verbose: true,
        }
    }
}

/// Lightweight plausibility check (syntax only).
pub fn is_plausible_email(e: &str) -> bool {
    static RE: Lazy<Regex> =
        Lazy::new(|| Regex::new(r"(?i)^[A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,}$").unwrap());
    e.len() <= 254 && RE.is_match(e)
}

/// Canonicalization used internally (lowercase).
fn canonical(s: &str) -> String {
    s.trim().to_ascii_lowercase()
}

/// Extract domain component of an email (after the '@').
// email_domain removed (unused)

/// Transform an SOA RNAME into an email (replace first '.' with '@').
pub fn soa_rname_to_email(rname: &str) -> Option<String> {
    if let Some(pos) = rname.find('.') {
        let local = &rname[..pos];
        let dom = &rname[pos + 1..];
        let email = format!("{local}@{dom}");
        if is_plausible_email(&email) {
            return Some(email);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_normalize_merge() {
        let mut set = EmailSet::new();
        set.add_with_conf("Abuse@Example.org.", 1);
        set.bump("abuse@example.org");
        set.normalize();
        let v = set.snapshot_sorted();
        assert_eq!(v.len(), 1);
        assert_eq!(v[0].0, "abuse@example.org");
        assert_eq!(v[0].1, 2);
    }

    #[test]
    fn test_soa_transform() {
        let rname = "hostmaster.example.org.";
        let email = soa_rname_to_email(rname.trim_end_matches('.')).unwrap();
        assert_eq!(email, "hostmaster@example.org");
    }
}
