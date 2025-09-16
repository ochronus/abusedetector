//! Performance benchmarks for abusedetector components.
//!
//! These benchmarks measure the performance of critical parsing and
//! processing operations to ensure the tool remains fast even with
//! large inputs or high-frequency usage.

use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use std::io::Write;
use std::net::Ipv4Addr;
use tempfile::NamedTempFile;

// Import the modules we want to benchmark
use abusedetector::emails::EmailSet;
use abusedetector::eml;
use abusedetector::netutil;

/// Sample EML content for benchmarking
const SAMPLE_EML: &str = r#"Return-Path: <sender@example.org>
Received: from mail.example.org (mail.example.org [8.8.8.8])
    by inbound.filter.local (Postfix) with ESMTPS id 12345
    for <user@local>; Tue, 17 Sep 2024 12:34:56 +0000 (UTC)
Received: from laptop (cpe-94-156-175-86.example.net [94.156.175.86])
    by mail.example.org (Postfix) with ESMTPSA id 77777
    for <user@local>; Tue, 17 Sep 2024 12:34:10 +0000 (UTC)
X-Originating-IP: [94.156.175.86]
X-Spam-source: IP='94.156.175.86', Host='example.com', Country='US'
Authentication-Results: example.com; iprev=pass smtp.remote-ip=94.156.175.86
Received-SPF: pass (example.com: 94.156.175.86 is authorized) client-ip=94.156.175.86
Subject: Test Message
From: sender@example.org
To: user@local
Content-Type: text/plain

This is the body of the test message.
It contains some sample content for benchmarking.
"#;

/// Large EML content with many Received headers for stress testing
fn generate_large_eml(num_received_headers: usize) -> String {
    let mut eml = String::with_capacity(SAMPLE_EML.len() + num_received_headers * 200);

    eml.push_str("Return-Path: <sender@example.org>\n");

    // Add many Received headers with different IPs
    for i in 0..num_received_headers {
        let ip_part = (i % 254) + 1;
        eml.push_str(&format!(
            "Received: from host{}.example.com (host{}.example.com [1.2.3.{}])\n",
            i, i, ip_part
        ));
        eml.push_str("    by relay.example.com (Postfix) with ESMTPS\n");
        eml.push_str(&format!(
            "    id ABC{}; Mon, 1 Jan 2024 00:00:00 +0000\n",
            i
        ));
    }

    eml.push_str("X-Originating-IP: [94.156.175.86]\n");
    eml.push_str("Subject: Large Test Message\n");
    eml.push_str("From: sender@example.org\n");
    eml.push_str("To: user@local\n");
    eml.push('\n');
    eml.push_str("This is a test message with many headers.\n");

    eml
}

/// Benchmark EML IP extraction with different input sizes
fn bench_eml_parsing(c: &mut Criterion) {
    let mut group = c.benchmark_group("eml_parsing");

    // Benchmark small EML
    group.bench_function("small_eml", |b| {
        b.iter(|| eml::parse_eml_origin_ip(black_box(SAMPLE_EML)))
    });

    // Benchmark medium EML with 50 Received headers
    let medium_eml = generate_large_eml(50);
    group.bench_function("medium_eml_50_headers", |b| {
        b.iter(|| eml::parse_eml_origin_ip(black_box(&medium_eml)))
    });

    // Benchmark large EML with 200 Received headers
    let large_eml = generate_large_eml(200);
    group.bench_function("large_eml_200_headers", |b| {
        b.iter(|| eml::parse_eml_origin_ip(black_box(&large_eml)))
    });

    // Benchmark EML file reading and parsing
    group.bench_function("eml_file_parsing", |b| {
        let mut temp_file = NamedTempFile::new().unwrap();
        temp_file.write_all(SAMPLE_EML.as_bytes()).unwrap();
        temp_file.flush().unwrap();

        b.iter(|| eml::parse_eml_origin_ip_from_path(black_box(temp_file.path())))
    });

    group.finish();
}

/// Benchmark IP classification functions
fn bench_ip_classification(c: &mut Criterion) {
    let mut group = c.benchmark_group("ip_classification");

    let test_ips = vec![
        "8.8.8.8".parse::<Ipv4Addr>().unwrap(),       // Public
        "192.168.1.1".parse::<Ipv4Addr>().unwrap(),   // Private
        "127.0.0.1".parse::<Ipv4Addr>().unwrap(),     // Loopback
        "169.254.1.1".parse::<Ipv4Addr>().unwrap(),   // Link-local
        "10.0.0.1".parse::<Ipv4Addr>().unwrap(),      // Private
        "172.16.0.1".parse::<Ipv4Addr>().unwrap(),    // Private
        "94.156.175.86".parse::<Ipv4Addr>().unwrap(), // Public
        "203.0.113.1".parse::<Ipv4Addr>().unwrap(),   // Documentation (reserved)
    ];

    group.bench_function("is_private", |b| {
        b.iter(|| {
            for ip in &test_ips {
                black_box(netutil::is_private(*ip));
            }
        })
    });

    group.bench_function("is_reserved", |b| {
        b.iter(|| {
            for ip in &test_ips {
                black_box(netutil::is_reserved(*ip));
            }
        })
    });

    group.bench_function("parse_ipv4", |b| {
        let ip_strings = vec![
            "8.8.8.8",
            "192.168.1.1",
            "127.0.0.1",
            "169.254.1.1",
            "10.0.0.1",
            "172.16.0.1",
            "94.156.175.86",
            "203.0.113.1",
        ];

        b.iter(|| {
            for ip_str in &ip_strings {
                let _ = black_box(netutil::parse_ipv4(ip_str));
            }
        })
    });

    group.finish();
}

/// Benchmark email processing operations
fn bench_email_processing(c: &mut Criterion) {
    let mut group = c.benchmark_group("email_processing");

    // Create test data
    let test_emails = [
        "abuse@example.com",
        "security@example.org",
        "hostmaster@example.net",
        "postmaster@example.info",
        "admin@example.biz",
        "support@example.co.uk",
        "noc@example.de",
        "cert@example.fr",
    ];

    group.bench_function("emailset_operations", |b| {
        b.iter(|| {
            let mut email_set = EmailSet::new();

            // Add emails with various confidence scores
            for (i, email) in test_emails.iter().enumerate() {
                email_set.add_candidate(email);
                email_set.add_with_conf(email, i as u32 + 1);
                email_set.bump(email);
            }

            // Finalize the set
            let _results = email_set.finalize(Default::default());

            black_box(_results);
        })
    });

    // Benchmark with different numbers of emails
    for &num_emails in &[10, 50, 100, 500] {
        group.bench_with_input(
            BenchmarkId::new("emailset_scaling", num_emails),
            &num_emails,
            |b, &num_emails| {
                let emails: Vec<String> = (0..num_emails)
                    .map(|i| format!("contact{}@example{}.com", i, i % 10))
                    .collect();

                b.iter(|| {
                    let mut email_set = EmailSet::new();

                    for email in &emails {
                        email_set.add_with_conf(email, 1);
                    }

                    let _results = email_set.finalize(Default::default());
                    black_box(_results);
                })
            },
        );
    }

    group.finish();
}

/// Benchmark domain extraction and analysis
fn bench_domain_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("domain_operations");

    let test_hostnames = vec![
        "mail.example.com",
        "mx.subdomain.example.org",
        "a.b.c.d.e.f.g.example.net",
        "host.example.co.uk",
        "server.example.com.au",
        "simple.example.de",
        "complex.multi.level.domain.example.info",
        "94.156.175.86.in-addr.arpa",
    ];

    group.bench_function("domain_extraction", |b| {
        b.iter(|| {
            for hostname in &test_hostnames {
                black_box(netutil::domain_of(hostname));
            }
        })
    });

    group.bench_function("ipv4_to_inaddr", |b| {
        let test_ips = vec![
            "8.8.8.8".parse::<Ipv4Addr>().unwrap(),
            "94.156.175.86".parse::<Ipv4Addr>().unwrap(),
            "1.2.3.4".parse::<Ipv4Addr>().unwrap(),
            "255.255.255.255".parse::<Ipv4Addr>().unwrap(),
        ];

        b.iter(|| {
            for ip in &test_ips {
                black_box(netutil::ipv4_to_inaddr(*ip));
            }
        })
    });

    group.finish();
}

/// Benchmark regex operations used in parsing
fn bench_regex_operations(c: &mut Criterion) {
    let mut group = c.benchmark_group("regex_operations");

    // Test email extraction regex performance
    let sample_whois_text = r#"
Organization: Example Corp
Address: 123 Main St
City: Example City
Country: US
Phone: +1-555-0123
Email: abuse@example.com
Email: hostmaster@example.com
Email: noc@example.com
Registrar WHOIS Server: whois.example.com
Registrar URL: http://www.example.com
Updated Date: 2024-01-01T00:00:00Z
Creation Date: 2020-01-01T00:00:00Z
Expiration Date: 2025-01-01T00:00:00Z
"#;

    group.bench_function("whois_email_extraction", |b| {
        use regex::Regex;
        let email_regex = Regex::new(r"(?i)([A-Z0-9._%+\-]+@[A-Z0-9.\-]+\.[A-Z]{2,})").unwrap();

        b.iter(|| {
            let mut emails = Vec::new();
            for cap in email_regex.captures_iter(black_box(sample_whois_text)) {
                emails.push(cap[1].to_ascii_lowercase());
            }
            black_box(emails);
        })
    });

    // Test IP extraction regex performance
    let sample_received_header = "Received: from mail.example.com (mail.example.com [94.156.175.86]) by mx.local (Postfix) with ESMTPS id ABC123";

    group.bench_function("ip_extraction_from_received", |b| {
        use regex::Regex;
        let ip_regex = Regex::new(r"(?i)\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b").unwrap();

        b.iter(|| {
            let mut ips = Vec::new();
            for cap in ip_regex.captures_iter(black_box(sample_received_header)) {
                if let Ok(ip) = cap[1].parse::<Ipv4Addr>() {
                    ips.push(ip);
                }
            }
            black_box(ips);
        })
    });

    group.finish();
}

/// Benchmark throughput with varying input sizes
fn bench_throughput(c: &mut Criterion) {
    let mut group = c.benchmark_group("throughput");
    group.throughput(Throughput::Bytes(SAMPLE_EML.len() as u64));

    group.bench_function("eml_parsing_throughput", |b| {
        b.iter(|| eml::parse_eml_origin_ip(black_box(SAMPLE_EML)))
    });

    // Benchmark with different EML sizes
    for &size in &[1, 10, 50, 100] {
        let large_eml = generate_large_eml(size);
        group.throughput(Throughput::Bytes(large_eml.len() as u64));

        group.bench_with_input(
            BenchmarkId::new("eml_parsing_by_size", size),
            &large_eml,
            |b, eml_content| b.iter(|| eml::parse_eml_origin_ip(black_box(eml_content))),
        );
    }

    group.finish();
}

/// Benchmark memory usage patterns
fn bench_memory_usage(c: &mut Criterion) {
    let mut group = c.benchmark_group("memory_usage");

    // Test memory efficiency of EmailSet operations
    group.bench_function("emailset_memory_efficiency", |b| {
        b.iter(|| {
            let mut sets = Vec::new();

            // Create multiple EmailSets to test memory allocation patterns
            for i in 0..100 {
                let mut email_set = EmailSet::new();
                for j in 0..10 {
                    email_set.add_candidate(format!("user{}@example{}.com", j, i));
                    email_set.bump(format!("user{}@example{}.com", j, i));
                }
                sets.push(email_set);
            }

            // Process all sets
            let mut all_results = Vec::new();
            for email_set in sets {
                all_results.push(email_set.finalize(Default::default()));
            }

            black_box(all_results);
        })
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_eml_parsing,
    bench_ip_classification,
    bench_email_processing,
    bench_domain_operations,
    bench_regex_operations,
    bench_throughput,
    bench_memory_usage
);

criterion_main!(benches);
