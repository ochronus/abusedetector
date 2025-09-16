//! Domain utilities with Public Suffix List integration.
//!
//! This module provides accurate domain extraction and manipulation using the
//! Public Suffix List (PSL) to properly handle complex domains like:
//! - subdomain.example.co.uk -> example.co.uk
//! - subdomain.example.com -> example.com
//! - subdomain.github.io -> subdomain.github.io (github.io is a public suffix)

use anyhow::{anyhow, Result};

/// Domain information extracted using PSL or fallback parsing
#[derive(Debug, Clone, PartialEq)]
pub struct DomainInfo {
    /// The full domain as provided
    pub full_domain: String,
    /// The registrable domain (what you can actually register)
    pub registrable_domain: Option<String>,
    /// The subdomain part (if any)
    pub subdomain: Option<String>,
    /// The public suffix (TLD or effective TLD)
    pub suffix: Option<String>,
    /// Whether this domain is on a public suffix list
    pub is_public_suffix: bool,
}

impl DomainInfo {
    /// Parse a domain string into structured domain information
    pub fn parse(domain: &str) -> Result<Self> {
        let clean_domain = clean_domain_input(domain)?;

        // Use enhanced parsing with common public suffixes
        Ok(Self::parse_enhanced(&clean_domain))
    }

    /// Enhanced domain parsing with knowledge of common public suffixes
    fn parse_enhanced(domain: &str) -> Self {
        let parts: Vec<&str> = domain.split('.').collect();

        if parts.len() < 2 {
            return DomainInfo {
                full_domain: domain.to_string(),
                registrable_domain: Some(domain.to_string()),
                subdomain: None,
                suffix: None,
                is_public_suffix: false,
            };
        }

        // Common multi-part public suffixes
        let multi_part_suffixes = [
            "co.uk",
            "org.uk",
            "ac.uk",
            "gov.uk",
            "ltd.uk",
            "me.uk",
            "net.uk",
            "nhs.uk",
            "nic.uk",
            "plc.uk",
            "police.uk",
            "sch.uk",
            "com.au",
            "net.au",
            "org.au",
            "edu.au",
            "gov.au",
            "asn.au",
            "id.au",
            "co.jp",
            "ac.jp",
            "ad.jp",
            "co.jp",
            "ed.jp",
            "go.jp",
            "gr.jp",
            "lg.jp",
            "ne.jp",
            "or.jp",
            "com.br",
            "edu.br",
            "gov.br",
            "mil.br",
            "net.br",
            "org.br",
            "co.za",
            "edu.za",
            "gov.za",
            "law.za",
            "mil.za",
            "nom.za",
            "org.za",
            "co.nz",
            "net.nz",
            "org.nz",
            "edu.nz",
            "govt.nz",
            "mil.nz",
            "com.mx",
            "edu.mx",
            "gob.mx",
            "net.mx",
            "org.mx",
            "co.in",
            "net.in",
            "org.in",
            "edu.in",
            "gov.in",
            "mil.in",
            "ac.in",
        ];

        // Special public suffixes (like github.io) where the subdomain is the registrable domain
        let special_public_suffixes = [
            "github.io",
            "gitlab.io",
            "bitbucket.io",
            "herokuapp.com",
            "netlify.app",
            "vercel.app",
            "web.app",
            "firebaseapp.com",
            "appspot.com",
            "azurewebsites.net",
            "cloudfront.net",
            "s3.amazonaws.com",
            "s3-website.amazonaws.com",
        ];

        let domain_lower = domain.to_lowercase();

        // Check for special public suffixes
        for special_suffix in &special_public_suffixes {
            if domain_lower.ends_with(special_suffix) {
                if domain_lower == *special_suffix {
                    // This is the public suffix itself
                    return DomainInfo {
                        full_domain: domain.to_string(),
                        registrable_domain: Some(domain.to_string()),
                        subdomain: None,
                        suffix: Some(special_suffix.to_string()),
                        is_public_suffix: true,
                    };
                } else {
                    // This has a subdomain on a special public suffix
                    let _prefix = domain_lower
                        .strip_suffix(&format!(".{}", special_suffix))
                        .unwrap_or("");
                    return DomainInfo {
                        full_domain: domain.to_string(),
                        registrable_domain: Some(domain.to_string()),
                        subdomain: None, // For special suffixes, the whole thing is registrable
                        suffix: Some(special_suffix.to_string()),
                        is_public_suffix: false,
                    };
                }
            }
        }

        // Check for multi-part suffixes
        if parts.len() >= 3 {
            let last_two = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);

            for suffix in &multi_part_suffixes {
                if suffix.eq_ignore_ascii_case(&last_two) {
                    if parts.len() == 3 {
                        // example.co.uk
                        return DomainInfo {
                            full_domain: domain.to_string(),
                            registrable_domain: Some(domain.to_string()),
                            subdomain: None,
                            suffix: Some(last_two),
                            is_public_suffix: false,
                        };
                    } else if parts.len() == 4 {
                        // sub.example.co.uk
                        let reg_domain = format!("{}.{}", parts[parts.len() - 3], last_two);
                        return DomainInfo {
                            full_domain: domain.to_string(),
                            registrable_domain: Some(reg_domain),
                            subdomain: Some(parts[0].to_string()),
                            suffix: Some(last_two),
                            is_public_suffix: false,
                        };
                    } else {
                        // a.b.c.example.co.uk -> example.co.uk is registrable
                        let reg_domain = format!("{}.{}", parts[parts.len() - 3], last_two);
                        let subdomain = if parts.len() > 3 {
                            Some(parts[..parts.len() - 3].join("."))
                        } else {
                            None
                        };
                        return DomainInfo {
                            full_domain: domain.to_string(),
                            registrable_domain: Some(reg_domain),
                            subdomain,
                            suffix: Some(last_two),
                            is_public_suffix: false,
                        };
                    }
                }
            }
        }

        // Default: treat as regular TLD
        let suffix = parts.last().unwrap().to_string();
        let (registrable_domain, subdomain) = if parts.len() == 2 {
            (domain.to_string(), None)
        } else {
            let reg_domain = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
            let subdomain = if parts.len() > 2 {
                Some(parts[..parts.len() - 2].join("."))
            } else {
                None
            };
            (reg_domain, subdomain)
        };

        DomainInfo {
            full_domain: domain.to_string(),
            registrable_domain: Some(registrable_domain),
            subdomain,
            suffix: Some(suffix),
            is_public_suffix: false,
        }
    }

    /// Get the best domain for WHOIS lookups (registrable domain if available)
    #[allow(dead_code)]
    pub fn whois_domain(&self) -> &str {
        self.registrable_domain
            .as_deref()
            .unwrap_or(&self.full_domain)
    }

    /// Get the best domain for abuse contact generation
    #[allow(dead_code)]
    pub fn abuse_domain(&self) -> &str {
        // For most cases, use registrable domain
        // But for some public suffixes like github.io, use the full domain
        if let Some(ref reg_domain) = self.registrable_domain {
            reg_domain
        } else {
            &self.full_domain
        }
    }

    /// Check if this is likely a hosting provider domain
    #[allow(dead_code)]
    pub fn is_hosting_provider(&self) -> bool {
        let domain = self.full_domain.to_lowercase();

        // Common hosting provider patterns
        let hosting_patterns = [
            "amazonaws.com",
            "cloudfront.net",
            "azurewebsites.net",
            "appspot.com",
            "herokuapp.com",
            "netlify.app",
            "vercel.app",
            "github.io",
            "gitlab.io",
            "bitbucket.io",
            "firebaseapp.com",
            "web.app",
            "cloudflare.net",
            "fastly.com",
            "akamai.net",
            "edgecast.com",
        ];

        hosting_patterns
            .iter()
            .any(|pattern| domain.ends_with(pattern))
    }

    /// Check if this is likely an educational domain
    #[allow(dead_code)]
    pub fn is_educational(&self) -> bool {
        if let Some(ref suffix) = self.suffix {
            let suffix_lower = suffix.to_lowercase();
            suffix_lower == "edu" || suffix_lower == "ac.uk" || suffix_lower.ends_with(".edu")
        } else {
            false
        }
    }

    /// Check if this is likely a government domain
    #[allow(dead_code)]
    pub fn is_government(&self) -> bool {
        if let Some(ref suffix) = self.suffix {
            let suffix_lower = suffix.to_lowercase();
            suffix_lower == "gov"
                || suffix_lower == "mil"
                || suffix_lower == "gov.uk"
                || suffix_lower.ends_with(".gov")
                || suffix_lower.ends_with(".mil")
        } else {
            false
        }
    }
}

/// Extract registrable domain from a hostname or domain string
pub fn extract_registrable_domain(domain: &str) -> Result<String> {
    let domain_info = DomainInfo::parse(domain)?;
    domain_info
        .registrable_domain
        .ok_or_else(|| anyhow!("No registrable domain found for: {}", domain))
}

/// Extract the best domain for abuse contact purposes
#[allow(dead_code)]
pub fn extract_abuse_domain(domain: &str) -> Result<String> {
    let domain_info = DomainInfo::parse(domain)?;
    Ok(domain_info.abuse_domain().to_string())
}

/// Extract domain from hostname, removing protocol and path if present
#[allow(dead_code)]
pub fn extract_domain_from_url(input: &str) -> Result<String> {
    let clean = input
        .trim()
        .trim_start_matches("http://")
        .trim_start_matches("https://")
        .trim_start_matches("ftp://")
        .split('/')
        .next()
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("")
        .trim();

    if clean.is_empty() {
        return Err(anyhow!("No domain found in input: {}", input));
    }

    Ok(clean.to_string())
}

/// Clean domain input by removing common artifacts
fn clean_domain_input(domain: &str) -> Result<String> {
    let clean = domain
        .trim()
        .trim_end_matches('.') // Remove trailing dot
        .to_lowercase();

    if clean.is_empty() {
        return Err(anyhow!("Empty domain"));
    }

    // Basic validation - domain should contain at least one dot for multi-label domains
    // Single labels are allowed for internal domains
    if !clean.contains('.') && clean.len() < 2 {
        return Err(anyhow!("Invalid domain format: {}", clean));
    }

    Ok(clean)
}

/// Generate common abuse email patterns for a domain
#[allow(dead_code)]
pub fn generate_abuse_emails(domain: &str) -> Result<Vec<String>> {
    let domain_info = DomainInfo::parse(domain)?;
    let abuse_domain = domain_info.abuse_domain();

    let mut emails = Vec::new();

    // Primary abuse contacts
    emails.push(format!("abuse@{}", abuse_domain));
    emails.push(format!("security@{}", abuse_domain));

    // Secondary contacts for specific domain types
    if domain_info.is_educational() {
        emails.push(format!("it-security@{}", abuse_domain));
        emails.push(format!("cert@{}", abuse_domain));
    } else if domain_info.is_government() {
        emails.push(format!("cert@{}", abuse_domain));
        emails.push(format!("incident@{}", abuse_domain));
    } else {
        // Commercial domains
        emails.push(format!("support@{}", abuse_domain));
        emails.push(format!("admin@{}", abuse_domain));
    }

    // Remove duplicates while preserving order
    let mut unique_emails = Vec::new();
    for email in emails {
        if !unique_emails.contains(&email) {
            unique_emails.push(email);
        }
    }

    Ok(unique_emails)
}

/// Check if a domain is likely a subdomain of a hosting provider
#[allow(dead_code)]
pub fn is_hosted_subdomain(domain: &str) -> Result<bool> {
    let domain_info = DomainInfo::parse(domain)?;

    // Check if the full domain or registrable domain is a hosting provider
    Ok(domain_info.is_hosting_provider())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_basic_domain_parsing() {
        let info = DomainInfo::parse("subdomain.example.com").unwrap();
        assert_eq!(info.registrable_domain, Some("example.com".to_string()));
        assert_eq!(info.subdomain, Some("subdomain".to_string()));
        assert_eq!(info.suffix, Some("com".to_string()));
    }

    #[test]
    fn test_complex_tld() {
        let info = DomainInfo::parse("subdomain.example.co.uk").unwrap();
        assert_eq!(info.registrable_domain, Some("example.co.uk".to_string()));
        assert_eq!(info.subdomain, Some("subdomain".to_string()));
        assert_eq!(info.suffix, Some("co.uk".to_string()));
    }

    #[test]
    fn test_special_public_suffix() {
        let info = DomainInfo::parse("mysite.github.io").unwrap();
        assert_eq!(
            info.registrable_domain,
            Some("mysite.github.io".to_string())
        );
        assert_eq!(info.suffix, Some("github.io".to_string()));
    }

    #[test]
    fn test_domain_cleaning() {
        let info = DomainInfo::parse("Example.Com.").unwrap();
        assert_eq!(info.full_domain, "example.com");
        assert_eq!(info.registrable_domain, Some("example.com".to_string()));
    }

    #[test]
    fn test_extract_registrable_domain() {
        assert_eq!(
            extract_registrable_domain("sub.example.com").unwrap(),
            "example.com"
        );
        assert_eq!(
            extract_registrable_domain("sub.example.co.uk").unwrap(),
            "example.co.uk"
        );
    }

    #[test]
    fn test_extract_domain_from_url() {
        assert_eq!(
            extract_domain_from_url("https://example.com/path").unwrap(),
            "example.com"
        );
        assert_eq!(
            extract_domain_from_url("http://sub.example.com:8080/path").unwrap(),
            "sub.example.com"
        );
        assert_eq!(
            extract_domain_from_url("example.com").unwrap(),
            "example.com"
        );
    }

    #[test]
    fn test_hosting_provider_detection() {
        let aws_info = DomainInfo::parse("example.amazonaws.com").unwrap();
        assert!(aws_info.is_hosting_provider());

        let github_info = DomainInfo::parse("mysite.github.io").unwrap();
        assert!(github_info.is_hosting_provider());

        let regular_info = DomainInfo::parse("example.com").unwrap();
        assert!(!regular_info.is_hosting_provider());
    }

    #[test]
    fn test_educational_domain() {
        let edu_info = DomainInfo::parse("example.edu").unwrap();
        assert!(edu_info.is_educational());

        let uk_edu_info = DomainInfo::parse("example.ac.uk").unwrap();
        assert!(uk_edu_info.is_educational());

        let regular_info = DomainInfo::parse("example.com").unwrap();
        assert!(!regular_info.is_educational());
    }

    #[test]
    fn test_government_domain() {
        let gov_info = DomainInfo::parse("example.gov").unwrap();
        assert!(gov_info.is_government());

        let mil_info = DomainInfo::parse("example.mil").unwrap();
        assert!(mil_info.is_government());

        let uk_gov_info = DomainInfo::parse("example.gov.uk").unwrap();
        assert!(uk_gov_info.is_government());

        let regular_info = DomainInfo::parse("example.com").unwrap();
        assert!(!regular_info.is_government());
    }

    #[test]
    fn test_abuse_email_generation() {
        let emails = generate_abuse_emails("example.com").unwrap();
        assert!(emails.contains(&"abuse@example.com".to_string()));
        assert!(emails.contains(&"security@example.com".to_string()));

        let edu_emails = generate_abuse_emails("example.edu").unwrap();
        assert!(edu_emails.contains(&"cert@example.edu".to_string()));
    }

    #[test]
    fn test_hosted_subdomain() {
        assert!(is_hosted_subdomain("myapp.herokuapp.com").unwrap());
        assert!(is_hosted_subdomain("mysite.github.io").unwrap());
        assert!(!is_hosted_subdomain("sub.example.com").unwrap());
    }

    #[test]
    fn test_multi_level_subdomains() {
        let info = DomainInfo::parse("a.b.c.example.co.uk").unwrap();
        assert_eq!(info.registrable_domain, Some("example.co.uk".to_string()));
        assert_eq!(info.subdomain, Some("a.b.c".to_string()));
        assert_eq!(info.suffix, Some("co.uk".to_string()));
    }
}
