# IPv6 Support in abusedetector

## Overview

The abusedetector tool now supports both IPv4 and IPv6 addresses for abuse contact discovery. This enhancement allows users to find appropriate abuse reporting email addresses for IPv6 infrastructure, which is increasingly important as networks transition to IPv6.

## Features

### Direct IPv6 Lookup
You can now query IPv6 addresses directly:

```bash
# Microsoft Outlook IPv6
abusedetector 2a01:111:f403:200a::620

# Google DNS IPv6
abusedetector 2001:4860:4860::8888

# Cloudflare DNS IPv6
abusedetector 2606:4700:4700::1111
```

### EML File Processing
The tool automatically detects and processes IPv6 addresses found in email headers:

```bash
abusedetector --eml suspicious_email.eml
```

If the originating IP extracted from the email is IPv6, it will be processed just like IPv4 addresses.

### Output Formats
All existing output formats support IPv6:

```bash
# Standard output
abusedetector 2a01:111:f403:200a::620

# JSON output
abusedetector 2a01:111:f403:200a::620 --json

# Batch format
abusedetector 2a01:111:f403:200a::620 --batch

# YAML output
abusedetector 2a01:111:f403:200a::620 --yaml
```

## Technical Implementation

### IPv6 WHOIS Support
The tool intelligently routes IPv6 WHOIS queries to the appropriate Regional Internet Registry (RIR) based on address prefixes:

- **RIPE NCC**: `2001::/16`, `2a00::/12` (Europe/Middle East/Central Asia)
- **ARIN**: `2600::/12`, `2610::/12`, `2620::/12` (North America)
- **APNIC**: `2400::/12` (Asia-Pacific)
- **LACNIC**: `2800::/12` (Latin America/Caribbean)
- **AfriNIC**: `2c00::/12` (Africa)

### IPv6 Reverse DNS
Reverse DNS lookups work properly for IPv6 addresses, creating the correct `.ip6.arpa` queries:

```
2a01:111:f403:200a::620 → 0.2.6.0.0.0.0.0.0.0.0.0.0.0.0.0.a.0.0.2.3.0.4.f.1.1.1.0.1.0.a.2.ip6.arpa
```

### Private and Reserved Range Detection
The tool correctly identifies IPv6 private and reserved ranges:

- **Unique Local Addresses (ULA)**: `fc00::/7`
- **Link-Local**: `fe80::/10`
- **Loopback**: `::1/128`
- **Multicast**: `ff00::/8`

## Examples

### Microsoft Outlook IPv6
```bash
$ abusedetector 2a01:111:f403:200a::620

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  🚨 Abuse Contacts for IP 2a01:111:f403:200a::620
  🌐 Hostname: mail-mw2nam12on20620.outbound.protection.outlook.com.
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  📮 Primary Abuse Contacts

    1. abuse@outlook.com
       ├─ Domain: outlook.com
       ├─ ✓ Abuse-specific address
       └─ Source: Multiple sources
```

### Google DNS IPv6
```bash
$ abusedetector 2001:4860:4860::8888 --batch
2001:4860:4860::8888:abuse@dns.google
```

### JSON Output
```bash
$ abusedetector 2a01:111:f403:200a::620 --json
{
  "input": {
    "ip_address": "2a01:111:f403:200a::620",
    "ip_source": "direct_input",
    "input_method": "direct_ip",
    "hostname": "mail-mw2nam12on20620.outbound.protection.outlook.com."
  },
  "primary_contacts": [
    {
      "email": "abuse@outlook.com",
      "domain": "outlook.com",
      "contact_type": "abuse",
      "is_abuse_specific": true
    }
  ]
}
```

## Migration Notes

### Backward Compatibility
- All existing IPv4 functionality remains unchanged
- Command-line interface is identical
- Output formats are consistent between IPv4 and IPv6

### API Changes
For developers using the library API:
- `analyze_ip()` now accepts `IpAddr` instead of `Ipv4Addr`
- All data structures use `IpAddr` for IP address fields
- EML parsing automatically handles both IPv4 and IPv6 extraction

### Updated CLI Help
The command-line help text now reflects IPv6 support:

```
Target IP address (IPv4 or IPv6, e.g., 203.0.113.10 or 2a01:111:f403:200a::620)
```

## Testing

The IPv6 implementation includes comprehensive test coverage:

- Unit tests for IPv6 address parsing and validation
- Integration tests for IPv6 WHOIS queries
- End-to-end tests with real IPv6 addresses
- EML parsing tests with IPv6 extraction

Run the test suite to verify IPv6 functionality:

```bash
cargo test
```

## Known Limitations

1. **IPv6 WHOIS Coverage**: Some IPv6 ranges may have limited WHOIS information compared to mature IPv4 allocations
2. **Reverse DNS**: Not all IPv6 addresses have reverse DNS entries configured
3. **Regional Differences**: IPv6 abuse contact practices may vary by region

## Future Enhancements

- Enhanced IPv6-specific abuse contact discovery heuristics
- Support for IPv6 prefix-based organization identification
- Integration with IPv6-specific abuse databases
- Improved escalation paths for IPv6 infrastructure

## Contributing

When contributing IPv6-related improvements:

1. Ensure all functions accept `IpAddr` rather than protocol-specific types
2. Test with addresses from different RIRs
3. Consider IPv6-specific edge cases (scope IDs, zone indices, etc.)
4. Update documentation to reflect IPv6 examples