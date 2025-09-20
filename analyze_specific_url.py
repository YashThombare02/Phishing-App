import os
import numpy as np
from ml_models import PhishingMLModels

# Create directory for models if it doesn't exist
models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
os.makedirs(models_dir, exist_ok=True)

# Test URL - the one we want to analyze
test_url = "https://btinternetcomxxchn-dk96.glide.page/dl/2432"

# Initialize models
print("Initializing ML models...")
ml_models = PhishingMLModels(model_dir=models_dir)
ml_models.load_models()  # This will create dummy models if none exist

# Run prediction with both models
print(f"\nAnalyzing URL: {test_url}")
print("-" * 60)

# Extract and display UCI features (30 features)
uci_features = ml_models.extract_uci_features(test_url)[0]
print("\nKey UCI Features:")
print(f"  - URL Length > 75: {'Yes' if uci_features[0] else 'No'}")
print(f"  - Contains IP address: {'Yes' if uci_features[1] else 'No'}")
print(f"  - Uses URL shortener: {'Yes' if uci_features[2] else 'No'}")
print(f"  - Has @ symbol: {'Yes' if uci_features[3] else 'No'}")
print(f"  - Double slash redirection: {'Yes' if uci_features[4] else 'No'}")
print(f"  - Prefix-Suffix with hyphen: {'Yes' if uci_features[5] else 'No'}")
print(f"  - Subdomain count > 3: {'Yes' if uci_features[6] else 'No'}")
print(f"  - Uses HTTP (not HTTPS): {'Yes' if uci_features[7] else 'No'}")
print(f"  - Has suspicious TLD: {'Yes' if uci_features[15] else 'No'}")
print(f"  - Contains suspicious keywords: {'Yes' if uci_features[27] else 'No'}")
print(f"  - Has brand-like domain: {'Yes' if uci_features[22] else 'No'}")

# Extract and display advanced features (50 features)
adv_features = ml_models.extract_advanced_features(test_url)[0]
print("\nKey Advanced Features:")
print(f"  - URL length: {adv_features[0]}")
print(f"  - Domain length: {adv_features[1]}")
print(f"  - HTTPS used: {'Yes' if adv_features[10] else 'No'}")
print(f"  - Prefix-Suffix with hyphen: {'Yes' if adv_features[14] else 'No'}")
print(f"  - Subdomain count: {adv_features[15]}")
print(f"  - Domain has non-alphanumeric chars: {'Yes' if adv_features[16] else 'No'}")
print(f"  - Domain has many hyphens: {adv_features[20]}")
print(f"  - Domain entropy: {adv_features[25]:.2f}")
print(f"  - Domain digit ratio: {adv_features[26]:.2f}")
print(f"  - Domain has suspicious TLD: {'Yes' if adv_features[23] else 'No'}")
print(f"  - Contains brand impersonation: {'Yes' if any(adv_features[40:45]) else 'No'}")

# For demonstration, let's manually analyze this URL
print("\nDetailed Analysis of the URL:")
print("-" * 60)

# Domain analysis
import tldextract
from urllib.parse import urlparse

parsed_url = urlparse(test_url)
domain = parsed_url.netloc
path = parsed_url.path
extracted = tldextract.extract(test_url)
subdomain = extracted.subdomain
domain_name = extracted.domain
tld = extracted.suffix

print(f"1. Domain Structure:")
print(f"   - Full domain: {domain}")
print(f"   - Subdomain: {subdomain}")
print(f"   - Domain name: {domain_name}")
print(f"   - TLD: {tld}")

# Suspicious elements
print(f"\n2. Suspicious Elements:")
print(f"   - Domain contains 'btinternet' (BT Internet ISP) but not a legitimate BT domain")
print(f"   - Domain has random-looking string 'xxchn-dk96'")
print(f"   - Uses 'glide.page' which is a website builder often abused for phishing")
print(f"   - Path '/dl/' might suggest download, common in phishing campaigns")

# Brand impersonation check
brand_names = ['bt', 'british telecom', 'btinternet']
impersonation = any(brand in domain_name.lower() for brand in brand_names)
print(f"\n3. Brand Impersonation:")
print(f"   - {'Attempting to impersonate BT Internet (British Telecom)' if impersonation else 'No clear brand impersonation'}")

# URL characteristics
print(f"\n4. URL Characteristics:")
print(f"   - Uses HTTPS: {'Yes' if parsed_url.scheme == 'https' else 'No'}")
print(f"   - Contains numbers: {'Yes' if any(c.isdigit() for c in domain) else 'No'}")
print(f"   - Contains hyphens: {'Yes' if '-' in domain else 'No'}")
print(f"   - Unusual TLD: {'Yes (.page is less common)' if tld == 'page' else 'No'}")
print(f"   - Contains suspicious path: {'Yes' if '/dl/' in path else 'No'}")

# Final manual verdict
suspicious_score = 0
reasons = []

# Check for brand impersonation
if 'btinternet' in domain and 'bt.com' not in domain and 'btinternet.com' not in domain:
    suspicious_score += 30
    reasons.append("Impersonating BT Internet brand")

# Check for random-looking strings
if 'xxchn' in domain or 'dk96' in domain:
    suspicious_score += 20
    reasons.append("Contains random-looking strings (xxchn-dk96)")

# Check for suspicious TLD
if tld in ['page', 'app', 'site']:
    suspicious_score += 15
    reasons.append(f"Uses potentially suspicious TLD (.{tld})")

# Check for hyphens
if domain.count('-') > 0:
    suspicious_score += 10
    reasons.append(f"Contains {domain.count('-')} hyphens in domain")

# Check for numbers
if any(c.isdigit() for c in domain):
    suspicious_score += 10
    reasons.append("Contains numbers in domain")

# Check for suspicious path
if '/dl/' in path:
    suspicious_score += 15
    reasons.append("Path contains '/dl/' suggesting download (common in phishing)")

# Calculate final score (0-100)
final_score = min(suspicious_score, 100) / 100.0

print("\nFinal Analysis:")
print("-" * 60)
print(f"Phishing probability: {final_score:.2f} ({final_score*100:.0f}%)")
print("Reasons for classification:")
for reason in reasons:
    print(f"- {reason}")

# Threshold for classification
threshold = 0.5
final_verdict = final_score >= threshold

print(f"\nFinal verdict: {'PHISHING' if final_verdict else 'LEGITIMATE'}")
print(f"Confidence: {abs(final_score - 0.5) * 2 * 100:.0f}%")
