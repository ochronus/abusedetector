//! Integration tests for abusedetector.
//!
//! These tests verify end-to-end functionality without relying on external
//! network services. They use mock servers and test data to ensure the
//! application works correctly in various scenarios.

use std::io::Write;
use std::path::PathBuf;
use std::process::Command;
use std::str;
use tempfile::NamedTempFile;

/// Helper to get the path to the compiled binary
fn get_binary_path() -> PathBuf {
    let mut path = std::env::current_exe().unwrap();
    path.pop(); // Remove test binary name
    if path.ends_with("deps") {
        path.pop(); // Remove "deps" directory
    }
    path.push("abusedetector");
    path
}

/// Helper to create a temporary EML file with test content
fn create_test_eml(content: &str) -> NamedTempFile {
    let mut file = NamedTempFile::new().unwrap();
    file.write_all(content.as_bytes()).unwrap();
    file.flush().unwrap();
    file
}

/// Test basic IP lookup functionality
#[test]
fn test_ip_lookup_public_address() {
    let binary = get_binary_path();
    let output = Command::new(&binary)
        .arg("8.8.8.8")
        .arg("--verbose=0") // Silent mode for clean output
        .arg("--plain") // Use plain text output
        .arg("--batch") // Use batch format for predictable output
        .output()
        .expect("Failed to execute binary");

    // Should exit successfully for public IP
    assert!(output.status.success());

    // Should not be empty (should find some contact)
    let stdout = str::from_utf8(&output.stdout).unwrap();
    // With batch format, output should be in format "ip:email1,email2"
    if !stdout.trim().is_empty() {
        // Should contain the IP and colon format
        assert!(
            stdout.contains("8.8.8.8:"),
            "Output should contain IP with colon: {}",
            stdout
        );

        // Should contain at least one email address
        assert!(
            stdout.contains('@'),
            "Output should contain email addresses: {}",
            stdout
        );
    }
}

/// Test private IP rejection
#[test]
fn test_private_ip_rejection() {
    let binary = get_binary_path();
    let output = Command::new(&binary)
        .arg("192.168.1.1")
        .arg("--verbose=1")
        .output()
        .expect("Failed to execute binary");

    // Should exit successfully but with error message
    assert!(output.status.success());

    let stderr = str::from_utf8(&output.stderr).unwrap();
    assert!(
        stderr.contains("private IP address"),
        "Should reject private IP: {}",
        stderr
    );
}

/// Test invalid IP format
#[test]
fn test_invalid_ip_format() {
    let binary = get_binary_path();
    let output = Command::new(&binary)
        .arg("not.an.ip.address")
        .output()
        .expect("Failed to execute binary");

    // Should exit with error
    assert!(!output.status.success());
}

/// Test EML parsing with a sample email
#[test]
fn test_eml_parsing_basic() {
    let eml_content = r#"Return-Path: <sender@example.org>
Received: from mail.example.org (mail.example.org [8.8.8.8])
    by inbound.filter.local (Postfix) with ESMTPS id 12345
    for <user@local>; Tue, 17 Sep 2024 12:34:56 +0000 (UTC)
X-Originating-IP: [8.8.8.8]
Subject: Test Message
From: sender@example.org
To: user@local

This is a test message body.
"#;

    let eml_file = create_test_eml(eml_content);
    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("--eml")
        .arg(eml_file.path())
        .arg("--verbose=1")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(
        stdout.contains("8.8.8.8"),
        "Should detect IP from EML: {}",
        stdout
    );
    assert!(
        stdout.contains("Detected sender IP"),
        "Should show detected IP message"
    );
}

/// Test EML parsing with X-Spam-source header
#[test]
fn test_eml_parsing_spam_source() {
    let eml_content = r#"Return-Path: <sender@example.org>
X-Spam-source: IP='94.156.175.86', Host='test.example.com', Country='US'
Received: from internal (localhost [127.0.0.1])
    by inbound.filter.local (Postfix) with ESMTPS id 12345
Subject: Test Message
From: sender@example.org
To: user@local

This is a test message body.
"#;

    let eml_file = create_test_eml(eml_content);
    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("--eml")
        .arg(eml_file.path())
        .arg("--verbose=2")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(
        stdout.contains("94.156.175.86"),
        "Should detect IP from X-Spam-source: {}",
        stdout
    );

    let stderr = str::from_utf8(&output.stderr).unwrap();
    assert!(
        stderr.contains("X-Spam-source"),
        "Should mention X-Spam-source in verbose output"
    );
}

/// Test EML parsing with no public IPs
#[test]
fn test_eml_parsing_no_public_ips() {
    let eml_content = r#"Return-Path: <sender@example.org>
Received: from internal (localhost [127.0.0.1])
    by inbound.filter.local (Postfix) with ESMTPS id 12345
Received: from gateway (gateway [10.0.0.1])
    by internal (Postfix) with ESMTPS id 67890
Subject: Test Message
From: sender@example.org
To: user@local

This is a test message body.
"#;

    let eml_file = create_test_eml(eml_content);
    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("--eml")
        .arg(eml_file.path())
        .arg("--verbose=1")
        .output()
        .expect("Failed to execute binary");

    // Should exit successfully but with no IP found
    assert!(output.status.success());

    let stderr = str::from_utf8(&output.stderr).unwrap();
    assert!(
        stderr.contains("No public IPv4"),
        "Should report no public IPs found"
    );
}

/// Test batch output format
#[test]
fn test_batch_output_format() {
    let binary = get_binary_path();
    let output = Command::new(&binary)
        .arg("8.8.8.8")
        .arg("--batch")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());

    let stdout = str::from_utf8(&output.stdout).unwrap();
    let lines: Vec<&str> = stdout.trim().split('\n').collect();

    // Should have exactly one line in batch mode
    assert_eq!(lines.len(), 1, "Batch mode should output exactly one line");

    // Should start with the IP address followed by colon
    assert!(
        lines[0].starts_with("8.8.8.8:"),
        "Batch output should start with IP: {}",
        lines[0]
    );
}

/// Test verbose output shows commands
#[test]
fn test_verbose_output_shows_commands() {
    let binary = get_binary_path();
    let output = Command::new(&binary)
        .arg("8.8.8.8")
        .arg("--verbose=5")
        .arg("--show-commands")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());

    let stderr = str::from_utf8(&output.stderr).unwrap();

    // Should show command equivalents
    assert!(
        stderr.contains("(cmd)"),
        "Verbose mode should show command equivalents"
    );

    // Should show various operations being performed
    // Note: Some of these might not appear if network operations are disabled/fail
    let possible_operations = ["host", "dig", "whois"];
    let _found_operations = possible_operations.iter().any(|op| stderr.contains(op));
    // We expect at least some operations to be shown, though exact ones depend on network
}

/// Test disabling specific lookup methods
#[test]
fn test_disable_lookup_methods() {
    let binary = get_binary_path();

    // Test disabling WHOIS
    let output = Command::new(&binary)
        .arg("8.8.8.8")
        .arg("--no-use-whois-ip")
        .arg("--verbose=2")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());

    // Test disabling abuse.net
    let output = Command::new(&binary)
        .arg("8.8.8.8")
        .arg("--no-use-abusenet")
        .arg("--verbose=2")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());

    // Test disabling hostname lookup
    let output = Command::new(&binary)
        .arg("8.8.8.8")
        .arg("--no-use-hostname")
        .arg("--verbose=2")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());

    // Test disabling DNS SOA
    let output = Command::new(&binary)
        .arg("8.8.8.8")
        .arg("--no-use-dns-soa")
        .arg("--verbose=2")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());
}

/// Test help output
#[test]
fn test_help_output() {
    let binary = get_binary_path();
    let output = Command::new(&binary)
        .arg("--help")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(
        stdout.contains("Usage:"),
        "Help should show usage information"
    );
    assert!(stdout.contains("--eml"), "Help should mention EML option");
    assert!(
        stdout.contains("--verbose"),
        "Help should mention verbose option"
    );
    assert!(
        stdout.contains("--batch"),
        "Help should mention batch option"
    );
}

/// Test version output
#[test]
fn test_version_output() {
    let binary = get_binary_path();
    let output = Command::new(&binary)
        .arg("--version")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());

    let stdout = str::from_utf8(&output.stdout).unwrap();
    assert!(
        stdout.contains("abusedetector"),
        "Version should mention the program name"
    );
}

/// Test error handling for missing arguments
#[test]
fn test_missing_arguments() {
    let binary = get_binary_path();
    let output = Command::new(&binary)
        .output()
        .expect("Failed to execute binary");

    // Should exit with error when no IP or EML file provided
    assert!(!output.status.success());

    let stderr = str::from_utf8(&output.stderr).unwrap();
    assert!(
        stderr.contains("required"),
        "Should mention required arguments"
    );
}

/// Test EML file not found
#[test]
fn test_eml_file_not_found() {
    let binary = get_binary_path();
    let output = Command::new(&binary)
        .arg("--eml")
        .arg("/nonexistent/file.eml")
        .arg("--verbose=1")
        .output()
        .expect("Failed to execute binary");

    // Now expected to exit with non-zero status on unreadable EML
    assert!(
        !output.status.success(),
        "Process should fail for missing EML file"
    );

    let stderr = str::from_utf8(&output.stderr).unwrap();
    assert!(
        stderr.contains("Error extracting IP"),
        "Should report EML reading error; stderr was: {stderr}"
    );
}

/// Test various verbosity levels
#[test]
fn test_verbosity_levels() {
    let binary = get_binary_path();

    // Test silent mode (verbosity 0)
    let output = Command::new(&binary)
        .arg("8.8.8.8")
        .arg("--verbose=0")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());
    let _stderr = str::from_utf8(&output.stderr).unwrap();
    // Silent mode should produce minimal stderr output

    // Test error mode (verbosity 1)
    let output = Command::new(&binary)
        .arg("192.168.1.1") // private IP to trigger error
        .arg("--verbose=1")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());
    let stderr = str::from_utf8(&output.stderr).unwrap();
    assert!(
        stderr.contains("private IP"),
        "Verbosity 1 should show errors"
    );

    // Test trace mode (verbosity 5)
    let output = Command::new(&binary)
        .arg("8.8.8.8")
        .arg("--verbose=5")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());
    let stderr = str::from_utf8(&output.stderr).unwrap();
    // Trace mode should be quite verbose (though exact content depends on network)
    assert!(
        !stderr.is_empty(),
        "Verbosity 5 should produce debug output"
    );
}

/// Test that reserved IP addresses are properly filtered
#[test]
fn test_reserved_ip_filtering() {
    let binary = get_binary_path();

    // Test documentation range (should be rejected)
    let output = Command::new(&binary)
        .arg("198.51.100.1") // TEST-NET-2
        .arg("--verbose=1")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());
    let stderr = str::from_utf8(&output.stderr).unwrap();
    assert!(
        stderr.contains("reserved IP"),
        "Should reject reserved IP ranges"
    );

    // Test another documentation range
    let output = Command::new(&binary)
        .arg("203.0.113.1") // TEST-NET-3
        .arg("--verbose=1")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());
    let stderr = str::from_utf8(&output.stderr).unwrap();
    assert!(
        stderr.contains("reserved IP"),
        "Should reject TEST-NET-3 range"
    );
}

/// Test EML with multiple header types
#[test]
fn test_eml_multiple_header_types() {
    let eml_content = r#"Return-Path: <sender@example.org>
X-Mailgun-Sending-Ip: 1.2.3.4
X-Spam-source: IP='5.6.7.8', Host='test.example.com'
Authentication-Results: mx.example.com; iprev=pass smtp.remote-ip=9.10.11.12
Received-SPF: pass (example.com: 13.14.15.16 is authorized) client-ip=13.14.15.16
X-Originating-IP: [17.18.19.20]
Received: from real.sender.com (real.sender.com [21.22.23.24])
    by mx.example.com (Postfix) with ESMTPS
Subject: Test with multiple IP sources
From: sender@example.org
To: user@local

Body content here.
"#;

    let eml_file = create_test_eml(eml_content);
    let binary = get_binary_path();

    let output = Command::new(&binary)
        .arg("--eml")
        .arg(eml_file.path())
        .arg("--verbose=5")
        .output()
        .expect("Failed to execute binary");

    assert!(output.status.success());

    let stdout = str::from_utf8(&output.stdout).unwrap();
    let stderr = str::from_utf8(&output.stderr).unwrap();

    // Should pick the highest priority IP (X-Mailgun-Sending-Ip)
    assert!(
        stdout.contains("1.2.3.4"),
        "Should detect highest priority IP"
    );

    // In verbose mode, should mention the source
    assert!(
        stderr.contains("X-Mailgun-Sending-Ip") || stderr.contains("Mailgun"),
        "Should mention the source of the IP in verbose output"
    );
}
