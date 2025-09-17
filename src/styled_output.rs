//! Styled output formatting for abusedetector using anstyle.
//!
//! This module provides beautiful, colored terminal output for abuse detection
//! results and escalation paths. It uses the anstyle crate for cross-platform
//! color support and follows modern CLI design principles.

use anstyle::{AnsiColor, Color, Style};
use std::fmt::Write;
use std::io::{self, Write as IoWrite};

use crate::escalation::{DualEscalationPath, EscalationPath};
use crate::output::{AbuseResults, ContactSource};

/// Style definitions for different UI elements
pub struct Styles {
    pub header: Style,
    pub subheader: Style,
    pub success: Style,
    pub warning: Style,
    #[allow(dead_code)]
    pub error: Style,
    pub info: Style,
    pub muted: Style,
    pub bold: Style,
    pub email: Style,
    pub url: Style,
    #[allow(dead_code)]
    pub ip: Style,
    #[allow(dead_code)]
    pub confidence_high: Style,
    #[allow(dead_code)]
    pub confidence_medium: Style,
    #[allow(dead_code)]
    pub confidence_low: Style,
    pub escalation_level: Style,
    pub organization: Style,
}

impl Default for Styles {
    fn default() -> Self {
        Self {
            header: Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Blue))),
            subheader: Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Cyan))),
            success: Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Green))),
            warning: Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
            error: Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Red))),
            info: Style::new().fg_color(Some(Color::Ansi(AnsiColor::Blue))),
            muted: Style::new().fg_color(Some(Color::Ansi(AnsiColor::BrightBlack))),
            bold: Style::new().bold(),
            email: Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::Green)))
                .underline(),
            url: Style::new()
                .fg_color(Some(Color::Ansi(AnsiColor::Blue)))
                .underline(),
            ip: Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Magenta))),
            confidence_high: Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Green))),
            confidence_medium: Style::new().fg_color(Some(Color::Ansi(AnsiColor::Yellow))),
            confidence_low: Style::new().fg_color(Some(Color::Ansi(AnsiColor::Red))),
            escalation_level: Style::new()
                .bold()
                .fg_color(Some(Color::Ansi(AnsiColor::Cyan))),
            organization: Style::new()
                .italic()
                .fg_color(Some(Color::Ansi(AnsiColor::BrightBlue))),
        }
    }
}

/// Styled output formatter for abuse detection results
pub struct StyledFormatter {
    styles: Styles,
    use_colors: bool,
}

impl StyledFormatter {
    /// Create a new styled formatter
    pub fn new() -> Self {
        Self {
            styles: Styles::default(),
            use_colors: Self::should_use_colors(),
        }
    }

    /// Create a formatter with custom styles
    #[allow(dead_code)]
    pub fn with_styles(styles: Styles) -> Self {
        Self {
            styles,
            use_colors: Self::should_use_colors(),
        }
    }

    /// Create a formatter without colors (for non-interactive use)
    pub fn without_colors() -> Self {
        Self {
            styles: Styles::default(),
            use_colors: false,
        }
    }

    /// Determine if colors should be used based on environment
    fn should_use_colors() -> bool {
        // Check if we're in a terminal and colors are supported
        atty::is(atty::Stream::Stdout) && std::env::var("NO_COLOR").is_err()
    }

    /// Apply style to text if colors are enabled
    fn styled(&self, text: &str, style: &Style) -> String {
        if self.use_colors {
            format!("{}{}{}", style.render(), text, style.render_reset())
        } else {
            text.to_string()
        }
    }

    /// Format abuse detection results with escalation paths
    #[allow(dead_code)]
    pub fn format_results_with_escalation(
        &self,
        results: &AbuseResults,
        escalation_path: Option<&EscalationPath>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut output = String::new();

        // Header with IP information
        self.write_header(&mut output, results)?;

        // Primary abuse contacts
        self.write_primary_contacts(&mut output, results)?;

        // Escalation path (if available)
        if let Some(path) = escalation_path {
            self.write_escalation_path(&mut output, path)?;
        }

        // Footer with additional information
        self.write_footer(&mut output, results)?;

        Ok(output)
    }

    /// Format abuse detection results with dual escalation paths
    pub fn format_results_with_dual_escalation(
        &self,
        results: &AbuseResults,
        dual_escalation: Option<&DualEscalationPath>,
    ) -> Result<String, Box<dyn std::error::Error>> {
        let mut output = String::new();

        // Header with IP information
        self.write_header(&mut output, results)?;

        // Primary abuse contacts
        self.write_primary_contacts(&mut output, results)?;

        // Dual escalation paths (if available)
        if let Some(paths) = dual_escalation {
            self.write_dual_escalation_paths_string(&mut output, paths)?;
        }

        // Footer with additional information
        self.write_footer(&mut output, results)?;

        Ok(output)
    }

    /// Write the main header with IP and basic info
    fn write_header(
        &self,
        output: &mut String,
        results: &AbuseResults,
    ) -> Result<(), std::fmt::Error> {
        writeln!(output)?;
        writeln!(
            output,
            "{}",
            self.styled(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                &self.styles.muted
            )
        )?;

        let title = if results.metadata.from_eml {
            format!("🚨 Abuse Contacts for IP {} (from EML)", results.ip)
        } else {
            format!("🚨 Abuse Contacts for IP {}", results.ip)
        };

        writeln!(output, "  {}", self.styled(&title, &self.styles.header))?;

        if let Some(ref hostname) = results.metadata.hostname {
            writeln!(
                output,
                "  {} Hostname: {}",
                self.styled("🌐", &self.styles.info),
                self.styled(hostname, &self.styles.bold)
            )?;
        }

        if let Some(ref eml_file) = results.metadata.eml_file {
            writeln!(
                output,
                "  {} EML File: {}",
                self.styled("📧", &self.styles.info),
                self.styled(eml_file, &self.styles.muted)
            )?;
        }

        writeln!(
            output,
            "{}",
            self.styled(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                &self.styles.muted
            )
        )?;

        Ok(())
    }

    /// Write primary abuse contacts section
    fn write_primary_contacts(
        &self,
        output: &mut String,
        results: &AbuseResults,
    ) -> Result<(), std::fmt::Error> {
        if results.contacts.is_empty() {
            writeln!(output)?;
            writeln!(
                output,
                "  {} {}",
                self.styled("⚠️", &self.styles.warning),
                self.styled("No direct abuse contacts found", &self.styles.warning)
            )?;
            return Ok(());
        }

        writeln!(output)?;
        writeln!(
            output,
            "  {}",
            self.styled("📮 Primary Abuse Contacts", &self.styles.subheader)
        )?;
        writeln!(output)?;

        for (i, contact) in results.contacts.iter().enumerate() {
            writeln!(
                output,
                "    {} {}",
                self.styled(&format!("{}.", i + 1), &self.styles.muted),
                self.styled(&contact.email, &self.styles.email)
            )?;

            if let Some(ref domain) = contact.metadata.domain {
                writeln!(
                    output,
                    "       {} Domain: {}",
                    self.styled("├─", &self.styles.muted),
                    self.styled(domain, &self.styles.muted)
                )?;
            }

            if contact.metadata.is_abuse_specific {
                writeln!(
                    output,
                    "       {} {}",
                    self.styled("├─", &self.styles.muted),
                    self.styled("✓ Abuse-specific address", &self.styles.success)
                )?;
            }

            let source_text = self.format_contact_source(&contact.source);
            writeln!(
                output,
                "       {} Source: {}",
                self.styled("└─", &self.styles.muted),
                self.styled(&source_text, &self.styles.info)
            )?;

            if i < results.contacts.len() - 1 {
                writeln!(output)?;
            }
        }

        Ok(())
    }

    /// Write escalation path section
    #[allow(dead_code)]
    fn write_escalation_path(
        &self,
        output: &mut String,
        path: &EscalationPath,
    ) -> Result<(), std::fmt::Error> {
        writeln!(output)?;
        writeln!(output)?;
        writeln!(
            output,
            "  {}",
            self.styled("🔄 Escalation Path", &self.styles.subheader)
        )?;
        writeln!(
            output,
            "  {}",
            self.styled("(If primary contacts don't respond)", &self.styles.muted)
        )?;
        writeln!(output)?;

        let recommended_contacts = path.get_recommended_order();

        for (level, contact) in recommended_contacts.iter().enumerate() {
            if contact.contact_type == crate::escalation::EscalationContactType::DirectAbuse {
                continue; // Skip direct abuse as it's shown in primary section
            }

            let level_num = level;
            let icon = contact.contact_type.icon();
            let type_name = contact.contact_type.display_name();

            writeln!(
                output,
                "    {} {} {}",
                self.styled(
                    &format!("Level {}:", level_num),
                    &self.styles.escalation_level
                ),
                icon,
                self.styled(type_name, &self.styles.bold)
            )?;

            writeln!(
                output,
                "       {} Organization: {}",
                self.styled("├─", &self.styles.muted),
                self.styled(&contact.organization, &self.styles.organization)
            )?;

            writeln!(
                output,
                "       {} Organization: {}",
                self.styled("├─", &self.styles.muted),
                self.styled(&contact.organization, &self.styles.organization)
            )?;

            if let Some(ref email) = contact.email {
                writeln!(
                    output,
                    "       {} Email: {}",
                    self.styled("├─", &self.styles.muted),
                    self.styled(email, &self.styles.email)
                )?;
            }

            if let Some(ref form) = contact.web_form {
                writeln!(
                    output,
                    "       {} Web Form: {}",
                    self.styled("├─", &self.styles.muted),
                    self.styled(form, &self.styles.url)
                )?;
            }

            if let Some(ref response_expectation) = contact.response_expectation {
                writeln!(
                    output,
                    "       {} Response Expectation: {}",
                    self.styled("├─", &self.styles.muted),
                    self.styled(response_expectation, &self.styles.info)
                )?;
            }

            if !contact.notes.is_empty() {
                for note in &contact.notes {
                    writeln!(
                        output,
                        "       {} Note: {}",
                        self.styled("└─", &self.styles.muted),
                        self.styled(note, &self.styles.info)
                    )?;
                }
            }

            writeln!(output)?;
        }

        // ASN info (if available)
        if let Some(ref asn_info) = path.asn_info {
            self.write_asn_info(output, asn_info)?;
        }

        Ok(())
    }

    /// Write dual escalation paths section for String output
    fn write_dual_escalation_paths_string(
        &self,
        output: &mut String,
        dual_paths: &DualEscalationPath,
    ) -> Result<(), std::fmt::Error> {
        writeln!(output)?;

        // Email Infrastructure Path
        writeln!(
            output,
            "  {}",
            self.styled(
                "📧 EMAIL INFRASTRUCTURE ESCALATION PATH",
                &self.styles.subheader
            )
        )?;
        writeln!(
            output,
            "  {}",
            self.styled("(For stopping email sending abuse)", &self.styles.muted)
        )?;
        writeln!(output)?;

        for (level_num, contact) in dual_paths.email_infrastructure.contacts.iter().enumerate() {
            let icon = contact.contact_type.icon();
            let type_name = contact.contact_type.display_name();

            writeln!(
                output,
                "    {} {} {}",
                self.styled(
                    &format!("Level {}:", level_num),
                    &self.styles.escalation_level
                ),
                icon,
                self.styled(type_name, &self.styles.bold)
            )?;

            self.write_contact_details_string(output, contact)?;
        }

        // Sender Hosting Path (if available)
        if let Some(ref hosting_path) = dual_paths.sender_hosting {
            if !hosting_path.contacts.is_empty() {
                writeln!(output)?;
                writeln!(
                    output,
                    "  {}",
                    self.styled("☁️ SENDER HOSTING ESCALATION PATH", &self.styles.subheader)
                )?;
                writeln!(
                    output,
                    "  {}",
                    self.styled("(For stopping website/business abuse)", &self.styles.muted)
                )?;

                if let Some(ref domain) = dual_paths.sender_domain {
                    writeln!(
                        output,
                        "  {} Based on sender domain: {}",
                        self.styled("└─", &self.styles.muted),
                        self.styled(domain, &self.styles.organization)
                    )?;
                }
                writeln!(output)?;

                for (level_num, contact) in hosting_path.contacts.iter().enumerate() {
                    let icon = contact.contact_type.icon();
                    let type_name = contact.contact_type.display_name();

                    writeln!(
                        output,
                        "    {} {} {}",
                        self.styled(
                            &format!("Level {}:", level_num),
                            &self.styles.escalation_level
                        ),
                        icon,
                        self.styled(type_name, &self.styles.bold)
                    )?;

                    self.write_contact_details_string(output, contact)?;
                }
            }
        }

        Ok(())
    }

    /// Write contact details for String output
    fn write_contact_details_string(
        &self,
        output: &mut String,
        contact: &crate::escalation::EscalationContact,
    ) -> Result<(), std::fmt::Error> {
        writeln!(
            output,
            "       {} Organization: {}",
            self.styled("├─", &self.styles.muted),
            self.styled(&contact.organization, &self.styles.organization)
        )?;

        if let Some(ref email) = contact.email {
            writeln!(
                output,
                "       {} Email: {}",
                self.styled("├─", &self.styles.muted),
                self.styled(email, &self.styles.email)
            )?;
        }

        if let Some(ref form) = contact.web_form {
            writeln!(
                output,
                "       {} Web Form: {}",
                self.styled("├─", &self.styles.muted),
                self.styled(form, &self.styles.url)
            )?;
        }

        if let Some(ref response_expectation) = contact.response_expectation {
            writeln!(
                output,
                "       {} Response Expectation: {}",
                self.styled("├─", &self.styles.muted),
                self.styled(response_expectation, &self.styles.info)
            )?;
        }

        if !contact.notes.is_empty() {
            for note in &contact.notes {
                writeln!(
                    output,
                    "       {} Note: {}",
                    self.styled("└─", &self.styles.muted),
                    self.styled(note, &self.styles.info)
                )?;
            }
        }

        writeln!(output)?;
        Ok(())
    }

    /// Write cloud provider information
    #[allow(dead_code)]
    fn write_cloud_provider_info(
        &self,
        output: &mut String,
        cloud_info: &crate::escalation::CloudProviderInfo,
    ) -> Result<(), std::fmt::Error> {
        writeln!(
            output,
            "  {}",
            self.styled("☁️  Cloud Provider Details", &self.styles.subheader)
        )?;
        writeln!(output)?;
        writeln!(
            output,
            "    {} Provider: {}",
            self.styled("├─", &self.styles.muted),
            self.styled(&cloud_info.provider, &self.styles.organization)
        )?;

        if let Some(ref abuse_form) = cloud_info.abuse_form {
            writeln!(
                output,
                "    {} Abuse Form: {}",
                self.styled("├─", &self.styles.muted),
                self.styled(abuse_form, &self.styles.url)
            )?;
        }

        if let Some(ref region) = cloud_info.region {
            writeln!(
                output,
                "    {} Region: {}",
                self.styled("└─", &self.styles.muted),
                self.styled(region, &self.styles.info)
            )?;
        }

        writeln!(output)?;
        Ok(())
    }

    /// Write ASN information
    #[allow(dead_code)]
    fn write_asn_info(
        &self,
        output: &mut String,
        asn_info: &crate::escalation::AsnInfo,
    ) -> Result<(), std::fmt::Error> {
        writeln!(
            output,
            "  {}",
            self.styled("🌐 Network Information (ASN)", &self.styles.subheader)
        )?;
        writeln!(output)?;
        writeln!(
            output,
            "    {} ASN: {} ({})",
            self.styled("├─", &self.styles.muted),
            self.styled(&format!("AS{}", asn_info.asn), &self.styles.bold),
            self.styled(&asn_info.name, &self.styles.organization)
        )?;

        if let Some(ref country) = asn_info.country {
            writeln!(
                output,
                "    {} Country: {}",
                self.styled("├─", &self.styles.muted),
                self.styled(country, &self.styles.info)
            )?;
        }

        writeln!(
            output,
            "    {} Registry: {}",
            self.styled("└─", &self.styles.muted),
            self.styled(&asn_info.registry, &self.styles.info)
        )?;

        writeln!(output)?;
        Ok(())
    }

    /// Write footer with metadata and tips
    fn write_footer(
        &self,
        output: &mut String,
        results: &AbuseResults,
    ) -> Result<(), std::fmt::Error> {
        writeln!(output)?;
        writeln!(
            output,
            "{}",
            self.styled(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                &self.styles.muted
            )
        )?;

        // Query statistics
        if results.metadata.dns_queries > 0 || results.metadata.whois_servers_queried > 0 {
            writeln!(
                output,
                "  {} Query Statistics:",
                self.styled("📊", &self.styles.info)
            )?;

            if results.metadata.dns_queries > 0 {
                writeln!(
                    output,
                    "    {} DNS queries performed: {}",
                    self.styled("├─", &self.styles.muted),
                    self.styled(&results.metadata.dns_queries.to_string(), &self.styles.bold)
                )?;
            }

            if results.metadata.whois_servers_queried > 0 {
                writeln!(
                    output,
                    "    {} WHOIS servers queried: {}",
                    self.styled("├─", &self.styles.muted),
                    self.styled(
                        &results.metadata.whois_servers_queried.to_string(),
                        &self.styles.bold
                    )
                )?;
            }

            if let Some(duration) = results.metadata.duration_ms {
                writeln!(
                    output,
                    "    {} Total time: {}ms",
                    self.styled("└─", &self.styles.muted),
                    self.styled(&duration.to_string(), &self.styles.bold)
                )?;
            }

            writeln!(output)?;
        }

        // Warnings (if any)
        if !results.metadata.warnings.is_empty() {
            writeln!(
                output,
                "  {} Warnings:",
                self.styled("⚠️", &self.styles.warning)
            )?;
            for warning in &results.metadata.warnings {
                writeln!(
                    output,
                    "    {} {}",
                    self.styled("•", &self.styles.warning),
                    self.styled(warning, &self.styles.warning)
                )?;
            }
            writeln!(output)?;
        }

        // Tips section
        writeln!(
            output,
            "  {}",
            self.styled("💡 Tips for Effective Abuse Reporting:", &self.styles.info)
        )?;
        writeln!(
            output,
            "    {} Be specific about the abuse (include timestamps, URLs, etc.)",
            self.styled("•", &self.styles.info)
        )?;
        writeln!(
            output,
            "    {} Follow the escalation path if initial contacts don't respond",
            self.styled("•", &self.styles.info)
        )?;
        writeln!(
            output,
            "    {} Keep records of all communications for follow-up",
            self.styled("•", &self.styles.info)
        )?;
        writeln!(
            output,
            "    {} Allow 2-3 business days for initial response",
            self.styled("•", &self.styles.info)
        )?;

        writeln!(
            output,
            "{}",
            self.styled(
                "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━",
                &self.styles.muted
            )
        )?;

        Ok(())
    }

    /// Format contact source with appropriate styling
    fn format_contact_source(&self, source: &ContactSource) -> String {
        match source {
            ContactSource::Whois { .. } => "WHOIS database".to_string(),
            ContactSource::DnsSoa { .. } => "DNS SOA record".to_string(),
            ContactSource::AbuseNet => "abuse.net database".to_string(),
            ContactSource::ReverseDns { .. } => "Reverse DNS lookup".to_string(),
            ContactSource::EmlHeaders { .. } => "EML header analysis".to_string(),
            ContactSource::Provider { .. } => "Service provider".to_string(),
            ContactSource::Unknown => "Multiple sources".to_string(),
        }
    }

    /// Print results to stdout with proper error handling
    #[allow(dead_code)]
    pub fn print_results_with_escalation(
        &self,
        results: &AbuseResults,
        escalation_path: Option<&EscalationPath>,
    ) -> io::Result<()> {
        let formatted = self
            .format_results_with_escalation(results, escalation_path)
            .map_err(|e| io::Error::other(format!("{}", e)))?;
        print!("{}", formatted);
        io::stdout().flush()?;
        Ok(())
    }

    /// Print results with dual escalation paths to stdout
    pub fn print_results_with_dual_escalation(
        &self,
        results: &AbuseResults,
        dual_escalation: Option<&DualEscalationPath>,
    ) -> io::Result<()> {
        let formatted = self
            .format_results_with_dual_escalation(results, dual_escalation)
            .map_err(|e| io::Error::other(format!("{}", e)))?;
        print!("{}", formatted);
        io::stdout().flush()?;
        Ok(())
    }
}

impl Default for StyledFormatter {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::output::{AbuseContact, ContactMetadata, QueryMetadata};

    fn create_test_results() -> AbuseResults {
        AbuseResults {
            ip: "8.8.8.8".parse().unwrap(),
            contacts: vec![AbuseContact {
                email: "abuse@example.com".to_string(),
                confidence: 85,
                source: ContactSource::Whois {
                    server: "test".to_string(),
                },
                metadata: ContactMetadata {
                    domain: Some("example.com".to_string()),
                    is_abuse_specific: true,
                    filtered: false,
                    notes: vec![],
                },
            }],
            metadata: QueryMetadata {
                from_eml: false,
                eml_file: None,
                hostname: Some("dns.google".to_string()),
                dns_queries: 5,
                whois_servers_queried: 2,
                abuse_net_queried: true,
                duration_ms: Some(1250),
                warnings: vec![],
                source_priorities: vec![],
            },
        }
    }

    #[test]
    fn test_styled_formatter_creation() {
        let formatter = StyledFormatter::new();
        assert!(formatter.use_colors || !atty::is(atty::Stream::Stdout));
    }

    #[test]
    fn test_contact_source_formatting() {
        let formatter = StyledFormatter::without_colors();

        assert_eq!(
            formatter.format_contact_source(&ContactSource::Whois {
                server: "test".to_string()
            }),
            "WHOIS database"
        );
        assert_eq!(
            formatter.format_contact_source(&ContactSource::DnsSoa {
                domain: "test".to_string()
            }),
            "DNS SOA record"
        );
    }

    #[test]
    fn test_results_formatting() {
        let formatter = StyledFormatter::without_colors();
        let results = create_test_results();

        let output = formatter
            .format_results_with_escalation(&results, None)
            .unwrap();

        assert!(output.contains("8.8.8.8"));
        assert!(output.contains("abuse@example.com"));
        assert!(output.contains("dns.google"));
    }
}
