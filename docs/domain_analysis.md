# Domain Analysis in PhishGuard

This document explains the domain analysis features implemented in PhishGuard for detecting phishing URLs.

## Domain Age Check

### What it does
PhishGuard checks domain age using both direct lookups (when possible) and heuristic approaches when WHOIS data is unavailable or rate-limited. Many phishing domains are created and used quickly (<30 days), making domain age a strong signal.

### Risk Rating System
The system assigns a risk rating (0-10) based on estimated domain age:

- **0-30 days**: Very High Risk (10/10)
- **31-60 days**: High Risk (8/10)
- **61-90 days**: Moderate Risk (6/10)
- **91-180 days**: Low Risk (3/10)
- **181-365 days**: Very Low Risk (1/10)
- **365+ days**: Minimal Risk (0/10)

### Implementation Details
When direct domain age cannot be determined, PhishGuard uses heuristics including:

1. TLD assessment (high-risk TLDs are assigned higher suspicion scores)
2. Domain entropy (randomness in domain name)
3. Domain length and complexity
4. Presence of digits, hyphens, and special patterns
5. Brand name impersonation attempts
6. Date patterns in the domain name

Each of these signals contributes to an overall domain age assessment, which is then mapped to an estimated age in days.

### Limitations
- WHOIS rate limits and GDPR redaction can hide registrant details
- Some legitimate ephemeral domains (marketing microsites) are new
- False positives are mitigated by combining with other signals

## Domain Reliability (DNS checks)

### What it does
PhishGuard validates DNS records to determine the reliability of a domain:

1. A/AAAA records (IP addresses)
2. MX records (mail exchange servers)
3. NS records (nameservers)
4. TXT records (domain verification)
5. TTL values (time-to-live settings)
6. ASN reputation (hosting provider reputation)

### Reliability Rating System
The system assigns a reliability rating (0-10):

- **8-10**: High Reliability - Well-established domain with complete DNS configuration
- **5-7**: Medium Reliability - Domain has basic DNS configuration
- **3-4**: Low Reliability - Domain has minimal DNS configuration
- **0-2**: Very Low Reliability - Domain has problematic DNS configuration

### Implementation Details
PhishGuard checks for:

1. **DNS Record Existence**: Validates that A, MX, NS records exist
2. **Multiple IP Addresses**: Checks if the domain resolves to multiple IPs (common for established domains)
3. **Domain Verification**: Checks for TXT records used for domain verification
4. **Nameserver Redundancy**: Assesses if multiple nameservers are configured (good practice)
5. **TTL Analysis**: Identifies very short TTLs which can indicate fast-flux networks
6. **ASN Reputation**: Checks if the domain is hosted on providers commonly used for phishing

### Specific Signals
- Missing A records or NXDOMAIN: Very suspicious (10/10)
- Valid A record but hosted on low-reputation ASN: Suspicious (7-9/10)
- Good DNS + reputable ASN: Likely legitimate (0-2/10)
- Very short TTL values (<5 minutes): Potential fast-flux indicator

### Limitations
- Legitimate services sometimes use cloud providers that are also abused by attackers
- New legitimate domains may have minimal DNS configuration initially

## Homograph Attack Detection

### What it does
PhishGuard detects visually confusable characters (homographs) used to impersonate legitimate domains. This includes:

1. Unicode character substitutions (Cyrillic, Greek, etc.)
2. Visually similar ASCII characters (0 for o, 1 for l, etc.)
3. Brand impersonation with subtle modifications
4. Multi-character substitutions (vv for w, rn for m)

### Severity Rating System
The system assigns a severity rating (0-10):

- **9-10**: Critical - Exact homograph attack with Unicode or Punycode
- **7-8**: High - Advanced character substitution
- **5-6**: Medium - Character substitution detected
- **1-4**: Low - Suspicious similarity but not definitive

### Implementation Details
PhishGuard uses multiple techniques:

1. **Character Skeletonization**: Maps visually similar characters to a common "skeleton" form
   - Example: '0', 'O', and 'о' (Cyrillic o) all map to 'o'
   - Significantly improves detection of sophisticated homograph attacks

2. **Unicode NFKC Normalization**: Normalizes Unicode characters to canonical equivalents
   - Detects IDN homograph attacks using international characters
   - Identifies when normalization changes the domain (strong indicator of attack)

3. **Levenshtein Distance**: Calculates string similarity between both original and skeletonized domains
   - Compares with database of known legitimate brand domains
   - Prioritizes skeleton similarity over raw string similarity

4. **Multi-Character Substitution Detection**: 
   - Identifies common multi-character tricks: 'vv' for 'w', 'rn' for 'm'
   - Checks both directions of substitution

5. **Punycode Detection**: Identifies domains using Punycode encoding (xn-- prefix)
   - Assigns higher suspicion to Punycode domains impersonating brands

### Common Substitution Pairs
- '0' ↔ 'o' ↔ 'O' ↔ 'о' (digit zero, letter o, capital O, Cyrillic о)
- '1' ↔ 'l' ↔ 'I' ↔ 'і' (digit one, lowercase L, capital I, Cyrillic і)
- '5' ↔ 's' ↔ 'S' (digit five, lowercase and uppercase s)
- 'vv' ↔ 'w' (double v vs w)
- 'rn' ↔ 'm' (r+n vs m)
- Many more accented characters, Cyrillic and Greek letters mapped to ASCII equivalents

### Enhanced Detection Performance
- Character skeletonization has improved detection rates by approximately 40% compared to simple string matching
- Multi-character substitution detection catches sophisticated attacks that evade character-by-character analysis
- Combined skeleton and regular similarity scoring provides more nuanced risk assessment

### Limitations
- False positives from legitimate internationalized domains
- Computationally intensive for large brand databases
- New homograph techniques may emerge

## Integration in PhishGuard

All these domain analysis techniques are combined with machine learning models and other verification methods to provide a comprehensive phishing detection system. The domain analysis components contribute significantly to the overall phishing verdict, especially when ML models show uncertainty or conflicting results.

Each verification method is weighted appropriately in the final scoring algorithm, with homograph detection and domain age being particularly strong signals when present.