# Feature Extraction in PhishGuard

This document details the 60 features extracted for advanced phishing detection in the PhishGuard system.

## Feature Index

### Basic URL Features (0-9)
- **0**: URL length (total characters)
- **1**: Domain length (characters in domain)
- **2**: Path length (characters in path)
- **3**: Number of dots in URL
- **4**: Number of slashes in URL
- **5**: Number of digits in URL
- **6**: Number of special characters
- **7**: Contains IP address (boolean)
- **8**: Contains @ symbol (boolean)
- **9**: Contains port number (boolean)

### Domain-Specific Features (10-19)
- **10**: TLD is common (.com, .org, etc.) (boolean)
- **11**: Number of subdomains
- **12**: Domain contains hyphen (boolean)
- **13**: Domain contains underscore (boolean)
- **14**: Domain entropy (randomness measure)
- **15**: Domain length to subdomain count ratio
- **16**: Domain contains brand name (boolean)
- **17**: Domain is IDN/punycode (boolean)
- **18**: Domain vowel count
- **19**: Domain consonant count

### Path and Query Features (20-29)
- **20**: Path depth (number of directories)
- **21**: Number of query parameters
- **22**: Contains suspicious file extension (boolean)
- **23**: Path contains suspicious keywords (boolean)
- **24**: Path entropy (randomness measure)
- **25**: Query entropy (randomness measure)
- **26**: Maximum query parameter length
- **27**: Average query parameter length
- **28**: Query contains suspicious parameters (boolean)
- **29**: Path contains non-ASCII characters (boolean)

### Certificate and Security Features (30-39)
- **30**: Uses HTTPS (boolean)
- **31**: Certificate age (days)
- **32**: Certificate issuer is well-known (boolean)
- **33**: Certificate matches domain (boolean)
- **34**: Certificate expiration within 30 days (boolean)
- **35**: Domain has SPF record (boolean)
- **36**: Domain has DMARC record (boolean)
- **37**: Domain has DKIM records (boolean)
- **38**: Domain resolves properly (boolean)
- **39**: Domain has MX records (boolean)

### Content and Redirection Features (40-49)
- **40**: URL contains redirection (boolean)
- **41**: Number of redirections
- **42**: Page has login form (boolean)
- **43**: Login form submits to different domain (boolean)
- **44**: Page contains password field (boolean)
- **45**: Page uses obfuscated JavaScript (boolean)
- **46**: Page contains invisible elements (boolean)
- **47**: Page contains deceptive elements (boolean)
- **48**: Favicon matches domain (boolean)
- **49**: Title matches domain (boolean)

### Advanced Lexical Features (50-59)
- **50**: Vowel to consonant ratio
- **51**: Repeating characters count
- **52**: Average word length in domain
- **53**: Domain character diversity ratio
- **54**: Shannon entropy of domain
- **55**: Token count in URL
- **56**: Maximum consecutive digits
- **57**: N-gram character analysis (trigrams)
- **58**: Domain length (without TLD)
- **59**: Domain entropy (without TLD)

## Implementation Details

### Example: Entropy Calculation
```python
def _calculate_entropy(self, text):
    """Calculate Shannon entropy of a string"""
    if not text:
        return 0
    
    # Count character frequencies
    char_counts = Counter(text.lower())
    
    # Calculate entropy
    text_length = len(text)
    entropy = -sum((count / text_length) * np.log2(count / text_length) 
                   for count in char_counts.values())
    
    # Normalize to 0-1 range (max entropy for a-z0-9 is ~5)
    return min(entropy / 5.0, 1.0)
```

### Example: Vowel/Consonant Ratio Calculation
```python
def _calculate_vowel_ratio(self, text):
    """Calculate the ratio of vowels to total characters"""
    if not text:
        return 0
    
    vowels = set('aeiou')
    vowel_count = sum(1 for char in text.lower() if char in vowels)
    
    return vowel_count / len(text)
```

## Feature Importance

The most significant features for phishing detection (based on feature importance):

1. Domain entropy (14)
2. URL length (0)
3. Path length (2)
4. Domain contains brand name (16)
5. Uses HTTPS (30)
6. Path entropy (24)
7. Domain age (implied by 31)
8. N-gram character analysis (57)
9. Domain vowel to consonant ratio (50)
10. Number of redirections (41)

## Model Usage

These features are used in two separate models:
- **UCI Model**: Uses a subset of 30 features (0-29)
- **Advanced Model**: Uses all 60 features (0-59)

The combined prediction from both models provides a more robust detection system with enhanced confidence metrics.