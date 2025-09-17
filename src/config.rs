//! Configuration management for abusedetector.
//!
//! This module provides structured configuration options that can be loaded
//! from files, environment variables, or command-line arguments. It centralizes
//! timeout settings, retry policies, and user preferences.

#![allow(dead_code)]

use std::fs;
use std::path::Path;
use std::time::Duration;

/// Main configuration structure for abusedetector.
#[derive(Debug, Clone, Default)]
pub struct Config {
    /// Network operation settings
    pub network: NetworkConfig,

    /// EML parsing settings
    pub eml: EmlConfig,

    /// Output and filtering preferences
    pub output: OutputConfig,

    /// Cache settings (for future implementation)
    pub cache: CacheConfig,
}

/// Network-related configuration options
#[derive(Debug, Clone)]
pub struct NetworkConfig {
    /// Timeout for DNS queries
    pub dns_timeout: Duration,

    /// Timeout for WHOIS queries
    pub whois_timeout: Duration,

    /// Timeout for abuse.net queries
    pub abuse_net_timeout: Duration,

    /// Maximum number of WHOIS referral hops
    pub max_whois_depth: usize,

    /// Maximum concurrent network operations
    pub max_concurrent_ops: usize,

    /// Retry attempts for failed network operations
    pub retry_attempts: u32,

    /// Delay between retry attempts
    pub retry_delay: Duration,
}

/// EML parsing configuration
#[derive(Debug, Clone)]
pub struct EmlConfig {
    /// Maximum file size to process (in bytes)
    pub max_file_size: usize,

    /// Priority order for IP extraction headers
    pub header_priorities: Vec<String>,

    /// Whether to trust provider-specific headers over Received headers
    pub trust_provider_headers: bool,

    /// Minimum confidence score for extracted IPs
    pub min_ip_confidence: u32,
}

/// Output and filtering configuration
#[derive(Debug, Clone)]
pub struct OutputConfig {
    /// Registry domains to filter out
    pub registry_domains: Vec<String>,

    /// Whether to prefer abuse@ addresses
    pub prefer_abuse_addresses: bool,

    /// Whether to filter out registry addresses
    pub filter_registry_addresses: bool,

    /// Custom email patterns to exclude (regex)
    pub exclude_patterns: Vec<String>,

    /// Custom email patterns to include (regex)
    pub include_patterns: Vec<String>,

    /// Maximum number of results to return (0 = unlimited)
    pub max_results: usize,

    /// Minimum confidence score for final results
    pub min_confidence: u32,
}

/// Cache configuration (for future implementation)
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// Whether caching is enabled
    pub enabled: bool,

    /// Cache directory path
    pub directory: Option<String>,

    /// Default TTL for cached entries
    pub default_ttl: Duration,

    /// Maximum cache size (in MB)
    pub max_size_mb: usize,

    /// Whether to cache WHOIS results
    pub cache_whois: bool,

    /// Whether to cache DNS results
    pub cache_dns: bool,

    /// Whether to cache abuse.net results
    pub cache_abuse_net: bool,
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            dns_timeout: Duration::from_secs(5),
            whois_timeout: Duration::from_secs(10),
            abuse_net_timeout: Duration::from_secs(8),
            max_whois_depth: 6,
            max_concurrent_ops: 10,
            retry_attempts: 2,
            retry_delay: Duration::from_millis(500),
        }
    }
}

impl Default for EmlConfig {
    fn default() -> Self {
        Self {
            max_file_size: 50 * 1024 * 1024, // 50MB
            header_priorities: vec![
                "X-Mailgun-Sending-Ip".to_string(),
                "X-Spam-source".to_string(),
                "Authentication-Results".to_string(),
                "Received-SPF".to_string(),
                "X-Originating-IP".to_string(),
                "Received".to_string(),
            ],
            trust_provider_headers: true,
            min_ip_confidence: 1,
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            registry_domains: vec![
                "ripe.net".to_string(),
                "iana.org".to_string(),
                "arin.net".to_string(),
                "apnic.net".to_string(),
                "lacnic.net".to_string(),
                "afrinic.net".to_string(),
                "example.net".to_string(),
                "example.com".to_string(),
                "example.org".to_string(),
            ],
            prefer_abuse_addresses: true,
            filter_registry_addresses: true,
            exclude_patterns: vec![
                r"noreply@.*".to_string(),
                r"no-reply@.*".to_string(),
                r"donotreply@.*".to_string(),
                r"postmaster@localhost".to_string(),
            ],
            include_patterns: vec![],
            max_results: 0, // unlimited
            min_confidence: 1,
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            directory: None,
            default_ttl: Duration::from_secs(7 * 24 * 3600), // 7 days
            max_size_mb: 100,
            cache_whois: true,
            cache_dns: true,
            cache_abuse_net: true,
        }
    }
}

impl Config {
    /// Create a new configuration with default values
    pub fn new() -> Self {
        Self::default()
    }

    /// Load configuration from a TOML file
    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<Self, ConfigError> {
        let content = fs::read_to_string(&path).map_err(|e| ConfigError::FileRead {
            path: path.as_ref().to_string_lossy().to_string(),
            source: e,
        })?;

        Self::from_toml(&content)
    }

    /// Parse configuration from TOML string
    pub fn from_toml(content: &str) -> Result<Self, ConfigError> {
        // For now, return default config since we don't have toml dependency
        // In a real implementation, you'd parse the TOML here
        let _ = content; // Silence unused parameter warning
        Ok(Self::default())
    }

    /// Load configuration from environment variables
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Network timeouts
        if let Ok(timeout) = std::env::var("ABUSEDETECTOR_DNS_TIMEOUT_SECS")
            && let Ok(secs) = timeout.parse::<u64>()
        {
            config.network.dns_timeout = Duration::from_secs(secs);
        }

        if let Ok(timeout) = std::env::var("ABUSEDETECTOR_WHOIS_TIMEOUT_SECS")
            && let Ok(secs) = timeout.parse::<u64>()
        {
            config.network.whois_timeout = Duration::from_secs(secs);
        }

        if let Ok(depth) = std::env::var("ABUSEDETECTOR_MAX_WHOIS_DEPTH")
            && let Ok(d) = depth.parse::<usize>()
        {
            config.network.max_whois_depth = d;
        }

        // Cache settings
        if let Ok(enabled) = std::env::var("ABUSEDETECTOR_CACHE_ENABLED") {
            config.cache.enabled = enabled.eq_ignore_ascii_case("true")
                || enabled.eq_ignore_ascii_case("1")
                || enabled.eq_ignore_ascii_case("yes");
        }

        if let Ok(cache_dir) = std::env::var("ABUSEDETECTOR_CACHE_DIR") {
            config.cache.directory = Some(cache_dir);
        }

        // Output preferences
        if let Ok(max_results) = std::env::var("ABUSEDETECTOR_MAX_RESULTS")
            && let Ok(max) = max_results.parse::<usize>()
        {
            config.output.max_results = max;
        }

        config
    }

    /// Merge with CLI arguments, giving CLI precedence
    pub fn merge_with_cli(&mut self, cli: &crate::cli::Cli) {
        // Update cache settings from CLI
        if let Some(ref cache_dir) = cli.cache {
            self.cache.directory = Some(cache_dir.clone());
            self.cache.enabled = true;
        }

        if cli.cache_expire > 0 {
            self.cache.default_ttl = Duration::from_secs(cli.cache_expire);
        }

        // Update network settings based on CLI flags
        if cli.no_use_hostname {
            // Could disable certain DNS operations
        }

        if cli.no_use_abusenet {
            // Could set abuse.net timeout to 0
            self.network.abuse_net_timeout = Duration::from_secs(0);
        }
    }

    /// Validate configuration values
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.network.dns_timeout.as_secs() == 0 {
            return Err(ConfigError::InvalidValue {
                field: "network.dns_timeout".to_string(),
                value: "0".to_string(),
                reason: "Timeout must be greater than 0".to_string(),
            });
        }

        if self.network.max_whois_depth == 0 {
            return Err(ConfigError::InvalidValue {
                field: "network.max_whois_depth".to_string(),
                value: "0".to_string(),
                reason: "Max WHOIS depth must be at least 1".to_string(),
            });
        }

        if self.eml.max_file_size == 0 {
            return Err(ConfigError::InvalidValue {
                field: "eml.max_file_size".to_string(),
                value: "0".to_string(),
                reason: "Max file size must be greater than 0".to_string(),
            });
        }

        if self.cache.enabled && self.cache.directory.is_none() {
            return Err(ConfigError::InvalidValue {
                field: "cache.directory".to_string(),
                value: "none".to_string(),
                reason: "Cache directory must be specified when caching is enabled".to_string(),
            });
        }

        Ok(())
    }

    /// Get effective timeout for a specific operation
    pub fn timeout_for_operation(&self, operation: &str) -> Duration {
        match operation {
            "dns" => self.network.dns_timeout,
            "whois" => self.network.whois_timeout,
            "abuse_net" => self.network.abuse_net_timeout,
            _ => Duration::from_secs(10), // default
        }
    }

    /// Check if a domain should be filtered out
    pub fn should_filter_domain(&self, domain: &str) -> bool {
        if !self.output.filter_registry_addresses {
            return false;
        }

        self.output
            .registry_domains
            .iter()
            .any(|reg_domain| domain.eq_ignore_ascii_case(reg_domain))
    }

    /// Check if an email matches exclude patterns
    pub fn should_exclude_email(&self, email: &str) -> bool {
        // In a real implementation, you'd compile these regexes once and reuse them
        for pattern in &self.output.exclude_patterns {
            if let Ok(regex) = regex::Regex::new(pattern)
                && regex.is_match(email)
            {
                return true;
            }
        }
        false
    }
}

/// Configuration-related errors
#[derive(Debug)]
pub enum ConfigError {
    /// Failed to read configuration file
    FileRead {
        path: String,
        source: std::io::Error,
    },

    /// Failed to parse configuration format
    Parse { format: String, reason: String },

    /// Invalid configuration value
    InvalidValue {
        field: String,
        value: String,
        reason: String,
    },

    /// Missing required configuration
    MissingRequired { field: String },
}

impl std::fmt::Display for ConfigError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConfigError::FileRead { path, source } => {
                write!(f, "Failed to read config file '{}': {}", path, source)
            }
            ConfigError::Parse { format, reason } => {
                write!(f, "Failed to parse {} config: {}", format, reason)
            }
            ConfigError::InvalidValue {
                field,
                value,
                reason,
            } => {
                write!(f, "Invalid value '{}' for '{}': {}", value, field, reason)
            }
            ConfigError::MissingRequired { field } => {
                write!(f, "Missing required configuration field: {}", field)
            }
        }
    }
}

impl std::error::Error for ConfigError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            ConfigError::FileRead { source, .. } => Some(source),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    #[test]
    fn test_default_config() {
        let config = Config::default();
        assert_eq!(config.network.dns_timeout, Duration::from_secs(5));
        assert_eq!(config.network.max_whois_depth, 6);
        assert!(!config.cache.enabled);
        assert!(config.output.prefer_abuse_addresses);
    }

    #[test]
    fn test_config_validation() {
        let mut config = Config::default();
        assert!(config.validate().is_ok());

        config.network.dns_timeout = Duration::from_secs(0);
        assert!(config.validate().is_err());

        config.network.dns_timeout = Duration::from_secs(5);
        config.cache.enabled = true;
        config.cache.directory = None;
        assert!(config.validate().is_err());
    }

    #[test]
    fn test_env_loading() {
        unsafe {
            env::set_var("ABUSEDETECTOR_DNS_TIMEOUT_SECS", "15");
            env::set_var("ABUSEDETECTOR_MAX_WHOIS_DEPTH", "10");
            env::set_var("ABUSEDETECTOR_CACHE_ENABLED", "true");
        }

        let config = Config::from_env();
        assert_eq!(config.network.dns_timeout, Duration::from_secs(15));
        assert_eq!(config.network.max_whois_depth, 10);
        assert!(config.cache.enabled);

        // Clean up
        unsafe {
            env::remove_var("ABUSEDETECTOR_DNS_TIMEOUT_SECS");
            env::remove_var("ABUSEDETECTOR_MAX_WHOIS_DEPTH");
            env::remove_var("ABUSEDETECTOR_CACHE_ENABLED");
        }
    }

    #[test]
    fn test_operation_timeout() {
        let config = Config::default();
        assert_eq!(config.timeout_for_operation("dns"), Duration::from_secs(5));
        assert_eq!(
            config.timeout_for_operation("whois"),
            Duration::from_secs(10)
        );
        assert_eq!(
            config.timeout_for_operation("unknown"),
            Duration::from_secs(10)
        );
    }

    #[test]
    fn test_domain_filtering() {
        let config = Config::default();
        assert!(config.should_filter_domain("ripe.net"));
        assert!(config.should_filter_domain("IANA.ORG"));
        assert!(!config.should_filter_domain("somecompany.com"));

        let mut config = config;
        config.output.filter_registry_addresses = false;
        assert!(!config.should_filter_domain("ripe.net"));
    }
}
