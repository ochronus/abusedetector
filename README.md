# abusedetector

A fast, privacy‑respecting command‑line tool to discover the most appropriate abuse / security reporting email address for a given IPv4 address or for the originating sender of an email message (`.eml` file).

It correlates multiple data sources (WHOIS, DNS, message metadata) and applies sensible heuristics to prefer provider / network abuse contacts over generic or registry addresses.

---

## Key Features

- Direct IPv4 lookup (`abusedetector <ip>`)
- `.eml` mode to extract the originating public sender IP (`--eml path/to/message.eml`)
- Reverse DNS hostname analysis
- SOA (Start of Authority) lookup to infer responsible mailbox from RNAME
- WHOIS chain traversal with referral following (ARIN, RIPE, APNIC, etc.)
- abuse.net enrichment (optional)
- Confidence scoring and filtering heuristics
- Batch mode (machine‑parsable output)
- Clear separation of modules (CLI, WHOIS, DNS, EML parsing, scoring)
- Fast asynchronous networking (Tokio)
- Minimal external dependencies beyond DNS + WHOIS + regex

---

## Installation

From a local clone:

```
git clone https://your.repo/abusedetector.git
cd abusedetector
cargo build --release
```

(Optional) Install into your Cargo bin path:

```
cargo install --path .
```

This provides the executable `abusedetector` on your `$PATH`.

---

## Quick Start

Look up an address:

```
abusedetector 46.4.15.45
```

Parse an email file and automatically extract the sender IP:

```
abusedetector --eml "samples/message.eml"
```

Verbose (trace) mode to see all internal steps:

```
abusedetector --verbose=5 8.8.8.8
```

Batch (script‑friendly) output:

```
abusedetector --batch 46.4.15.45
# Example output:
# 46.4.15.45:abuse@example.net
```

---

## Command Line Options

| Option | Description |
| ------ | ----------- |
| `<ip>` | Target IPv4 address (omit when using `--eml`) |
| `--eml <FILE>` | Use an `.eml` file; extract originating sender IP |
| `--verbose <n>` | Verbosity: 0 (silent), 1 (errors), 2 (warnings), 5 (trace) |
| `--no-use-hostname` | Skip reverse DNS hostname heuristics |
| `--no-use-abusenet` | Skip abuse.net WHOIS queries |
| `--no-use-dns-soa` | Skip SOA/RNAME discovery |
| `--no-use-whois-ip` | Skip IP WHOIS chain traversal |
| `--show-commands` | Print approximate shell equivalents (whois/dig/host) |
| `--batch` | Emit single-line `ip:addr1,addr2,...` |
| `--cache <DIR>` | (Reserved for future implementation) |
| `--cache-expire <secs>` | (Reserved for future implementation) |

---

## How It Works (Pipeline Overview)

1. Input Resolution  
   - Direct IP or extracted from `.eml` headers (priority order: specialized provider headers like `X-Mailgun-Sending-Ip`, “spam” source headers, Authentication-Results remote IP markers, SPF client IP, fallback to Received chain chronology & provider heuristics).

2. Sanity Filtering  
   - Rejects private (RFC1918) and broadly reserved / special-use ranges.

3. Reverse DNS (PTR)  
   - Obtains candidate hostname; can guide guesses or domain scoping.

4. SOA Discovery  
   - Walks parent domains and reverse in-addr.arpa labels; converts SOA RNAME into an email (first dot becomes @).

5. WHOIS Traversal  
   - Starts at ARIN; follows referrals; extracts plausible abuse / hostmaster / security emails via pattern scanning.

6. abuse.net (optional)  
   - Queries domain directory service for curated abuse contacts.

7. Normalization & Heuristics  
   - Lowercases, strips trailing dots, deduplicates.  
   - Filters out registry / infrastructure addresses (`ripe.net`, `iana.org`, etc.).  
   - If any `abuse@` addresses exist, restricts output to those.  
   - In non-verbose non-batch mode, typically returns the most relevant single address.

8. Output  
   - Human-friendly default vs. machine‑parsable batch mode.

---

## EML Mode Details

Priority sources for the originating public IPv4:

1. `X-Mailgun-Sending-Ip`
2. `X-Spam-source: IP='x.x.x.x'`
3. `smtp.remote-ip=...` inside Authentication / ARC headers
4. `Received-SPF: ... client-ip=...`
5. `X-Originating-IP:`
6. Walk through `Received:` headers (bottom-most public hop), with a provider keyword bias (`mailgun`, `sendgrid`, `amazonses`, `sparkpost`).

Private or reserved addresses are ignored unless no public candidate exists (in which case resolution fails).

The detected sender IP is always printed when using `--eml` for transparency.

---

## Examples

Basic WHOIS-based discovery:

```
abusedetector 8.8.8.8
```

Trace every stage:

```
abusedetector --verbose=5 --show-commands 8.8.8.8
```

EML-derived:

```
abusedetector --eml ~/mail/raw/sample.eml
```

Batch integration in a shell script:

```
while read ip; do
  abusedetector --batch "$ip"
done < ip_list.txt
```

---

## Exit Behavior

- Returns `0` on successful run (even if no address found; absence is signaled in stderr under verbosity ≥1).
- Returns `0` early when the target IP is private/reserved (message printed if verbosity ≥1).
- Non-fatal network timeouts are treated as partial data (best-effort approach).

---

## Limitations / Future Enhancements

| Area | Current State | Potential Improvement |
|------|---------------|-----------------------|
| Caching | Not yet implemented | On-disk WHOIS/DNS TTL-aware cache |
| Blacklist | Not implemented | User-provided patterns to exclude emails |
| IPv6 | Not supported | Full AAAA / IPv6 WHOIS + reverse parsing |
| EML Parsing | Heuristic, IPv4 only | Structured parsing & IPv6 + ARC trust scoring |
| Domain Derivation | Simple suffix heuristic | Public Suffix List integration |
| Output Formats | Plain text / batch line | JSON / YAML / machine-friendly exit codes |
| Confidence Scoring | Linear increments | Weighted scoring (source reliability model) |

---

## Security & Privacy Notes

- No persistence of queried data (unless future caching is enabled).
- Performs network lookups (WHOIS, DNS); ensure you are comfortable with outbound queries.
- Does not execute untrusted code; processing is text-only.
- Avoid running against sensitive or internal addresses unless intended.

---

## Design Overview (Modules)

| Module | Responsibility |
|--------|----------------|
| `cli.rs` | Argument parsing, verbosity helpers |
| `netutil.rs` | IP classification, reverse DNS, domain heuristics |
| `whois.rs` | WHOIS + abuse.net lookups and email extraction |
| `emails.rs` | Email candidate collection, normalization, heuristics |
| `eml.rs` | Originating IP extraction from `.eml` headers |
| `main.rs` | Orchestration pipeline |

---

## Troubleshooting

| Symptom | Possible Cause | Action |
|---------|----------------|--------|
| No output | All candidates filtered | Run with `--verbose=5` |
| Only registry addresses shown | Heuristics removed them | Use `--verbose=5` to inspect raw findings |
| Slow responses | WHOIS timeouts or rate limits | Retry; consider future caching |
| Incorrect sender IP in EML mode | Header injection / atypical path | Share sample anonymized header for improvement |
| No hostname | PTR record missing | This is common; reverse DNS is optional heuristic |

---

## Contributing

1. Fork & branch: feature / fix naming encouraged.
2. Write focused commits; add tests where possible (unit tests already exist for parsing layers).
3. Run `cargo fmt && cargo clippy -- -D warnings` before submitting (add clippy config if you enforce).
4. Open a PR with context and reproduction steps if fixing a parsing discrepancy.

---

## Roadmap (Short List)

- JSON output mode
- Efficient on-disk cache
- Blacklist / whitelist configuration file
- IPv6 support
- Public suffix powered domain reduction
- Optional ASN lookup integration

---

## License

(Choose and state a license here — e.g. MIT / Apache-2.0. If omitted, consumers will be uncertain. Add a LICENSE file to formalize.)

---

## Disclaimer

This tool provides best‑effort discovery. Always validate the chosen abuse contact via authoritative sources (RIR portal, provider abuse page) before escalation, especially for legal or urgent incident reporting.

---

## Acknowledgments

Thanks to the open WHOIS & DNS infrastructure communities and operators who maintain accessible registries.

---

## Quick Reference (Cheat Sheet)

```
abusedetector 1.2.3.4                 # Simple lookup
abusedetector --eml mail.eml          # Derive from email
abusedetector --batch 1.2.3.4         # Script-friendly output
abusedetector --verbose=5 1.2.3.4     # Full trace
abusedetector --no-use-whois-ip 1.2.3.4
abusedetector --no-use-abusenet 1.2.3.4
```

---

Feel free to open issues for edge cases, false positives, or enhancement ideas.