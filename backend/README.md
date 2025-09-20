# PhishGuard - Advanced Phishing Detection System

PhishGuard is a comprehensive phishing detection system that uses multiple verification methods, including machine learning models, to identify potential phishing URLs.

## Features

### Domain Analysis
- **Domain Age Check**: Rates domains based on age (0-10 risk scale)
  - 0-30 days: 10/10 risk
  - 31-60 days: 8/10 risk
  - 61-90 days: 6/10 risk
  - 91-180 days: 4/10 risk
  - 181-365 days: 2/10 risk
  - >365 days: 1/10 risk

- **Domain Reliability Assessment**: Checks DNS records, MX records, and A records
  - Evaluates if domain is properly configured
  - Assesses if email services are set up (legitimate domains typically have proper email configuration)
  - Verifies if domain resolves to proper IP addresses

- **Homograph Attack Detection**: Identifies domain names that use visually similar characters
  - Implements severity rating based on visual similarity (0-10 scale)
  - Detects punycode/IDN homograph attacks
  - Identifies typosquatting attempts

### Machine Learning Features (60 Features)

#### Lexical Features
- URL length
- Domain length
- Path length
- Number of subdomains
- Number of special characters
- Presence of IP address
- TLD analysis
- Vowel/consonant ratio analysis
- Special character frequency
- Digit frequency
- Character n-gram analysis

#### Entropy Features
- Shannon entropy calculation for detecting randomness in domains
- Token entropy
- Character distribution entropy

#### Brand Impersonation Features
- Brand name detection
- Visual similarity scoring
- Edit distance calculation
- Trie-based prefix matching

#### Security Features
- HTTPS presence
- Certificate validation
- SSL/TLS version checking
- Security term detection

#### Advanced Features
- N-gram character analysis (bigrams, trigrams)
- Token counting and analysis
- Repeating character detection
- Directory depth analysis
- Query parameter analysis

### Model Confidence Metrics
- Model difference calculation
- Model agreement confidence
- Weighted confidence calculation
- Enhanced confidence metrics
- Explanations based on model agreement level

### Anomaly Detection
- Isolation Forest-based outlier detection
- Statistical analysis of URL patterns
- Unsupervised learning approach
- Anomaly scoring on 0-1 scale
- Zero-day phishing detection

## Technical Implementation

### Machine Learning Models
- UCI Model: 30 features, based on UCI phishing dataset
- Advanced Model: 60 features, more sophisticated analysis

### API Endpoints
- `/api/analyze`: Main endpoint for URL analysis
- `/api/stats`: Statistics about system usage
- `/api/history`: Recent detection history

### Detection Methods
- Google Safe Browsing API
- Domain age verification
- Content analysis
- Machine learning models
- Homograph detection
- URL shortener detection
- Suspicious authentication pattern detection

## Usage

```python
# Example API call
response = requests.post('http://localhost:5000/api/analyze', json={'url': 'https://example.com'})
result = response.json()

# Check if URL is phishing
is_phishing = result['final_verdict']
confidence = result['confidence']
```

## Documentation

See the docs folder for detailed information on specific features:
- [Model Confidence Metrics](docs/model_confidence_metrics.md)
- [Domain Analysis](docs/domain_analysis.md)
- [Feature Extraction](docs/feature_extraction.md)
- [Anomaly Detection](docs/anomaly_detection.md)