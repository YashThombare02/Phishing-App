# Domain Analysis in PhishGuard

This document explains the domain analysis features implemented in the PhishGuard phishing detection system.

## Domain Age Analysis

Domain age is a critical factor in phishing detection since most phishing domains are newly registered.

### Implementation

```python
def check_domain_age(self, url):
    """Check domain age and assign a risk rating"""
    try:
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Extract base domain
        extracted = tldextract.extract(domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        
        # Query WHOIS information
        domain_info = whois.whois(base_domain)
        
        # Get creation date
        creation_date = domain_info.creation_date
        
        # Handle different return types (can be list or datetime)
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        if not creation_date:
            return {
                'result': True,
                'description': "Domain age: Unknown (suspicious)",
                'value': 1.0,
                'risk_rating': 10
            }, None
        
        # Calculate domain age in days
        domain_age_days = (datetime.now() - creation_date).days
        
        # Assign risk rating based on domain age
        if domain_age_days <= 30:
            risk_rating = 10  # Highest risk
            description = f"Domain age: {domain_age_days} days (very recent, highly suspicious)"
            value = 1.0
        elif domain_age_days <= 60:
            risk_rating = 8
            description = f"Domain age: {domain_age_days} days (recent, suspicious)"
            value = 0.8
        elif domain_age_days <= 90:
            risk_rating = 6
            description = f"Domain age: {domain_age_days} days (somewhat recent, moderate risk)"
            value = 0.6
        elif domain_age_days <= 180:
            risk_rating = 4
            description = f"Domain age: {domain_age_days} days (few months old, lower risk)"
            value = 0.4
        elif domain_age_days <= 365:
            risk_rating = 2
            description = f"Domain age: {domain_age_days} days (about a year old, low risk)"
            value = 0.2
        else:
            risk_rating = 1  # Lowest risk
            description = f"Domain age: {domain_age_days} days (established domain, minimal risk)"
            value = 0.1
        
        return {
            'result': True,
            'description': description,
            'value': value,
            'risk_rating': risk_rating,
            'domain_age_days': domain_age_days
        }, creation_date
        
    except Exception as e:
        # Domain not found or error fetching information
        return {
            'result': True,
            'description': f"Could not determine domain age: {str(e)}",
            'value': 0.8,  # Assume high risk when we can't determine age
            'risk_rating': 8  # High risk rating when we can't determine age
        }, None
```

### Risk Rating Scale (0-10)

- **10/10 (Highest Risk)**: Domain age 0-30 days
- **8/10**: Domain age 31-60 days
- **6/10**: Domain age 61-90 days
- **4/10**: Domain age 91-180 days
- **2/10**: Domain age 181-365 days
- **1/10 (Lowest Risk)**: Domain age >365 days

## Domain Reliability Assessment

This feature evaluates the domain's setup quality by checking DNS records, MX records, and A records.

### Implementation

```python
def check_domain_creation_date_reliability(self, url):
    """
    Check the reliability of domain based on DNS records, MX records, and proper setup
    """
    try:
        # Parse the URL to extract domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Extract the base domain
        extracted = tldextract.extract(domain)
        base_domain = f"{extracted.domain}.{extracted.suffix}"
        
        reliability_factors = []
        reliability_score = 0
        max_score = 5  # Maximum possible score
        
        # Check 1: Does the domain resolve to an IP address?
        try:
            socket.gethostbyname(base_domain)
            reliability_factors.append("Domain resolves to an IP address")
            reliability_score += 1
        except socket.gaierror:
            reliability_factors.append("Domain does not resolve to an IP address (suspicious)")
        
        # Check 2: Does the domain have MX records? (Mail servers)
        try:
            mx_records = dns.resolver.resolve(base_domain, 'MX')
            if mx_records:
                reliability_factors.append("Domain has mail servers configured")
                reliability_score += 1
        except Exception:
            reliability_factors.append("Domain has no mail servers (suspicious for established domains)")
        
        # Check 3: Does the domain have NS records? (Name servers)
        try:
            ns_records = dns.resolver.resolve(base_domain, 'NS')
            if ns_records:
                reliability_factors.append("Domain has name servers configured")
                reliability_score += 1
        except Exception:
            reliability_factors.append("Domain has no name servers (highly suspicious)")
        
        # Check 4: Does the domain have A records? (IPv4 addresses)
        try:
            a_records = dns.resolver.resolve(base_domain, 'A')
            if a_records:
                reliability_factors.append("Domain has A records configured")
                reliability_score += 1
        except Exception:
            reliability_factors.append("Domain has no A records (suspicious)")
        
        # Check 5: Does the domain have a SPF record? (Email authentication)
        try:
            txt_records = dns.resolver.resolve(base_domain, 'TXT')
            has_spf = any("v=spf1" in str(record).lower() for record in txt_records)
            if has_spf:
                reliability_factors.append("Domain has SPF email authentication")
                reliability_score += 1
            else:
                reliability_factors.append("Domain lacks SPF email authentication")
        except Exception:
            reliability_factors.append("Domain has no TXT records")
        
        # Calculate reliability rating based on score (0-10 scale)
        reliability_rating = int((reliability_score / max_score) * 10)
        
        # Determine reliability level
        if reliability_rating >= 8:
            reliability_level = "High"
            value = 0.1  # Low phishing probability
        elif reliability_rating >= 5:
            reliability_level = "Medium"
            value = 0.5  # Moderate phishing probability
        else:
            reliability_level = "Low"
            value = 0.8  # High phishing probability
        
        return {
            'result': reliability_rating < 5,  # Consider it suspicious if rating < 5
            'description': f"Domain reliability: {reliability_level} ({reliability_rating}/10)",
            'reliability_rating': reliability_rating,
            'reliability_factors': reliability_factors,
            'value': value
        }
    except Exception as e:
        return {
            'result': True,  # Consider it suspicious if we can't determine reliability
            'description': f"Could not determine domain reliability: {str(e)}",
            'value': 0.7
        }
```

### Reliability Factors Checked

1. Domain resolves to an IP address
2. Domain has mail servers configured (MX records)
3. Domain has name servers configured (NS records)
4. Domain has A records configured (IPv4 addresses)
5. Domain has SPF email authentication

### Reliability Rating Scale (0-10)

- **8-10**: High reliability (Likely legitimate)
- **5-7**: Medium reliability (Uncertain)
- **0-4**: Low reliability (Suspicious)

## Homograph Attack Detection

This feature identifies domain names that use visually similar characters to impersonate legitimate brands.

### Implementation

```python
def check_homograph_attack(self, url):
    """Check for homograph attacks (visually similar characters)"""
    try:
        # Parse URL to get the domain
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Cache key for performance
        homograph_cache_key = f"homograph_{domain}"
        if homograph_cache_key in url_shortener_cache:
            return url_shortener_cache[homograph_cache_key]
        
        # Extract domain components
        extracted = tldextract.extract(domain)
        domain_name = extracted.domain
        
        # Check for punycode/IDN domains (international characters)
        is_punycode = domain.startswith('xn--') or 'xn--' in domain
        
        # List of commonly targeted brands
        top_brands = list(COMMON_PHISHING_TARGETS.keys())
        target_brands = []
        best_match = None
        best_similarity = 0
        
        # Check similarity with top brands
        for brand in top_brands:
            # Compare with direct string
            similarity_ratio = levenshtein_ratio(domain_name.lower(), brand.lower())
            
            # Also compare without digits and special chars (for cases like "paypal-secure-login.com")
            cleaned_domain = re.sub(r'[^a-z]', '', domain_name.lower())
            if cleaned_domain:  # Ensure we have a non-empty string
                cleaned_similarity = levenshtein_ratio(cleaned_domain, brand.lower())
                similarity_ratio = max(similarity_ratio, cleaned_similarity)
            
            # Check for brand name contained in domain
            if brand.lower() in domain_name.lower():
                contained_similarity = 0.8  # High base similarity for contained brands
                word_position = domain_name.lower().find(brand.lower())
                # Higher similarity if the brand is at the beginning or is a significant portion
                if word_position == 0:
                    contained_similarity = 0.9
                if len(brand) / len(domain_name) > 0.7:
                    contained_similarity = 0.85
                
                similarity_ratio = max(similarity_ratio, contained_similarity)
            
            # If significant similarity found
            if similarity_ratio > 0.7:
                target_brands.append(brand)
                if similarity_ratio > best_similarity:
                    best_similarity = similarity_ratio
                    best_match = brand
        
        # Calculate severity rating (0-10 scale)
        if best_similarity > 0:
            severity_rating = int(best_similarity * 10)
            
            # Adjust severity based on additional factors
            if is_punycode:
                severity_rating = min(severity_rating + 2, 10)  # Increase severity for punycode
            
            # Check for exact registered domains of the matched brand
            if best_match in COMMON_PHISHING_TARGETS:
                legitimate_domains = COMMON_PHISHING_TARGETS[best_match]
                if not any(domain.endswith(legit_domain) for legit_domain in legitimate_domains):
                    severity_rating = min(severity_rating + 1, 10)  # Not a legitimate domain of the brand
            
            # Determine severity description
            if severity_rating >= 9:
                severity_desc = "Critical"
            elif severity_rating >= 7:
                severity_desc = "High"
            elif severity_rating >= 5:
                severity_desc = "Medium"
            else:
                severity_desc = "Low"
        else:
            severity_rating = 0
            severity_desc = "None"
        
        # Build the result based on findings
        if best_match:
            description = f"Potential homograph attack targeting {best_match}"
            if is_punycode:
                description += " using punycode/international characters"
            
            result = {
                'result': True,
                'description': description,
                'target_brands': target_brands,
                'impersonated_domain': best_match,
                'similarity': best_similarity,
                'severity_rating': severity_rating,
                'severity_description': severity_desc,
                'value': min(0.8 + best_similarity * 0.2, 1.0)  # Scale value based on similarity
            }
        else:
            result = {
                'result': False,
                'description': "No homograph attack detected",
                'severity_rating': 0,
                'severity_description': "None",
                'value': 0
            }
        
        # Cache the result
        url_shortener_cache[homograph_cache_key] = result
        return result
```

### Severity Rating Scale (0-10)

- **9-10 (Critical)**: Near-exact visual match to a known brand, high risk
- **7-8 (High)**: Very similar to a known brand, potential homograph attack
- **5-6 (Medium)**: Moderately similar to a known brand, suspicious
- **1-4 (Low)**: Slight similarity to a known brand, possibly coincidental
- **0 (None)**: No similarity to known brands detected