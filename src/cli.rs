use clap::Parser;

/// Command-line interface definition.
/// Provides command-line options for abuse address discovery.
///
/// Verbosity levels:
/// 0 - silent (only final output)
/// 1 - errors (default)
/// 2 - warnings + errors
/// 5 - trace/debug
#[derive(Parser, Debug, Clone)]
#[command(
    author,
    version,
    about = "Discover likely abuse reporting email addresses for an IPv4 address or an .eml message"
)]
pub struct Cli {
    /// Target IPv4 address (numeric, e.g. 203.0.113.10). Required unless --eml is provided.
    #[arg(required_unless_present = "eml", conflicts_with = "eml")]
    pub ip: Option<String>,

    /// Path to a .eml message file; if supplied the originating sender IP will be extracted and used.
    #[arg(long, value_name = "FILE", conflicts_with = "ip")]
    pub eml: Option<String>,

    /// Verbosity level (0,1,2,5)
    #[arg(long, default_value_t = 1)]
    pub verbose: u8,

    /// Disable using the reverse hostname heuristics
    #[arg(long = "no-use-hostname", default_value_t = false)]
    pub no_use_hostname: bool,

    /// Disable querying whois.abuse.net
    #[arg(long = "no-use-abusenet", default_value_t = false)]
    pub no_use_abusenet: bool,

    /// Disable DNS SOA traversal
    #[arg(long = "no-use-dns-soa", default_value_t = false)]
    pub no_use_dns_soa: bool,

    /// Disable IP whois chain queries
    #[arg(long = "no-use-whois-ip", default_value_t = false)]
    pub no_use_whois_ip: bool,

    /// Show approximate shell-equivalent commands
    #[arg(long)]
    pub show_commands: bool,

    /// Batch output: single line "ip:addr1,addr2"
    #[arg(long)]
    pub batch: bool,

    /// Cache directory (future feature, currently not used)
    #[arg(long)]
    pub cache: Option<String>,

    /// Cache expiration seconds (future feature)
    #[arg(long = "cache-expire", default_value_t = 7 * 24 * 3600)]
    pub cache_expire: u64,
}

impl Cli {
    /// Parse CLI arguments from process args.
    pub fn from_args() -> Self {
        Self::parse()
    }

    /// Convenience: are we in very verbose/debug mode?
    pub fn is_trace(&self) -> bool {
        self.verbose >= 5
    }

    /// Should we show confidence values and internal steps?
    pub fn show_internal(&self) -> bool {
        self.is_trace()
    }

    /// Are warning-level messages enabled?
    pub fn warn_enabled(&self) -> bool {
        self.verbose >= 2
    }

    /// Are error-level messages enabled?
    pub fn error_enabled(&self) -> bool {
        self.verbose >= 1
    }
}
