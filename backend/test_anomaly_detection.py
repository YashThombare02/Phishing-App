"""
Test script for anomaly detection in PhishGuard
This script tests the Isolation Forest-based anomaly detection on various URLs
"""

import sys
import os
import numpy as np
from urllib.parse import urlparse
import requests

# Add parent directory to path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Try to import our modules
try:
    from outlier_detection import URLOutlierDetector
    from ml_models import PhishingMLModels
except ImportError as e:
    print(f"Error importing modules: {str(e)}")
    print("Make sure you're running this script from the backend directory")
    sys.exit(1)

# Test URLs
test_urls = [
    # Normal URLs (should have low anomaly scores)
    "https://www.google.com",
    "https://amazon.com/products/electronics",
    "https://youtube.com/watch?v=dQw4w9WgXcQ",
    "https://github.com/microsoft/vscode",
    
    # Slightly unusual URLs (may have medium anomaly scores)
    "https://bit.ly/3xR5tZ9",
    "https://example-subdomain.myshopify.com",
    "https://my-site.blogspot.com/2023/09/post.html",
    
    # Likely phishing URLs (should have high anomaly scores)
    "https://amaz0n-secure-login.com/signin",
    "https://paypa1-verification.net/verify/account",
    "https://x7k9j2lp0o5.tk/banking/login",
    "https://www.secure-login-validate-account.com/",
    "https://m1crosoft-update.cc/windows/security",
]

def extract_features(url):
    """Simple feature extraction for demo purposes"""
    features = np.zeros(15)
    
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    
    # Basic URL features
    features[0] = len(url)
    features[1] = len(domain)
    features[2] = len(path)
    features[3] = url.count('.')
    features[4] = url.count('/')
    features[5] = url.count('-')
    features[6] = domain.count('-')
    features[7] = domain.count('.')
    features[8] = 1 if 'www' in domain else 0
    features[9] = sum(c.isdigit() for c in domain) / max(len(domain), 1)
    features[10] = 1 if any(word in url.lower() for word in ['login', 'signin', 'verify', 'secure']) else 0
    features[11] = 1 if any(word in url.lower() for word in ['account', 'password', 'update', 'confirm']) else 0
    features[12] = 1 if 'https' in url else 0
    features[13] = sum(not c.isalnum() for c in domain) / max(len(domain), 1)
    features[14] = len(path.split('/'))
    
    return features.reshape(1, -1)

def main():
    print("PhishGuard Anomaly Detection Test\n")
    print("=" * 60)
    
    # Create and train the anomaly detector
    print("\nInitializing Isolation Forest...")
    detector = URLOutlierDetector(n_estimators=100, contamination=0.1)
    
    # Create some "normal" training data (legitimate URLs)
    print("Creating training data for the detector...")
    normal_urls = [
        "https://google.com",
        "https://youtube.com",
        "https://facebook.com",
        "https://amazon.com",
        "https://microsoft.com",
        "https://apple.com",
        "https://github.com",
        "https://stackoverflow.com",
        "https://wikipedia.org",
        "https://twitter.com",
        "https://instagram.com",
        "https://linkedin.com",
        "https://netflix.com",
        "https://wordpress.com",
        "https://yahoo.com",
        "https://cnn.com",
        "https://nytimes.com",
        "https://reddit.com",
        "https://bbc.com",
        "https://ebay.com"
    ]
    
    # Extract features for normal URLs
    normal_features = np.vstack([extract_features(url) for url in normal_urls])
    
    # Train the detector
    print(f"Training on {len(normal_urls)} legitimate URLs...\n")
    detector.fit(normal_features)
    
    # Test on our URLs
    print("Testing URLs for anomalies:")
    print("-" * 60)
    
    for url in test_urls:
        # Extract features
        features = extract_features(url)
        
        # Get anomaly score
        anomaly_score = float(detector.predict_anomaly_score(features)[0])
        is_outlier = bool(detector.predict_is_outlier(features)[0])
        
        # Determine category based on score
        if anomaly_score > 0.8:
            category = "HIGH ANOMALY"
        elif anomaly_score > 0.6:
            category = "MEDIUM ANOMALY"
        else:
            category = "NORMAL"
        
        # Print results
        print(f"\nURL: {url}")
        print(f"Anomaly Score: {anomaly_score:.4f}")
        print(f"Is Outlier: {'Yes' if is_outlier else 'No'}")
        print(f"Category: {category}")
        print("-" * 60)
    
    print("\nTest complete!")

if __name__ == "__main__":
    main()