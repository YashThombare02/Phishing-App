import requests
import sys
import json

def check_url(url):
    """Check a URL against the phishing detection API."""
    try:
        print(f"\nChecking URL: {url}")
        response = requests.post(
            "http://localhost:5000/api/detect",
            json={"url": url},
            timeout=10
        )
        
        if response.status_code == 200:
            result = response.json()
            is_phishing = result.get("final_verdict", False)
            confidence = result.get("confidence", 0)
            
            print("\n" + "="*80)
            print(f"VERDICT: {'PHISHING' if is_phishing else 'LEGITIMATE'} (Confidence: {confidence:.2f}%)")
            print("="*80)
            
            print("\nVerification Methods:")
            methods = result.get("verification_methods", {})
            for method_name, method_data in methods.items():
                if method_name != "domain_created":
                    print(f"  - {method_name}: {'Suspicious' if method_data.get('result', False) else 'Safe'}")
                    print(f"      {method_data.get('description', '')}")
            
            # Print additional checks we've added
            print("\nAdditional Checks:")
            print(f"  - Has suspicious auth patterns: {result.get('has_suspicious_auth', False)}")
            print(f"  - Domain age reliability: {result.get('domain_age_reliability', 'Unknown')}")
            print(f"  - Phishing score: {result.get('phishing_score', 'N/A')}")
            print(f"  - Threshold: {result.get('threshold', 'N/A')}")
            
            print("\nExplanations:")
            for explanation in result.get("explanations", []):
                print(f"  - {explanation}")
            
            print("\nFeatures Extracted:")
            print("  UCI Features (first 5):")
            for i, feature in enumerate(result.get("features_extracted", {}).get("uci_features", [])[:5]):
                print(f"    - Feature {i}: {feature}")
            
            print("  Advanced Features (first 5):")
            for i, feature in enumerate(result.get("features_extracted", {}).get("advanced_features", [])[:5]):
                print(f"    - Feature {i}: {feature}")
            
            return is_phishing, confidence
        else:
            print(f"Error: API returned status code {response.status_code}")
            return None, None
    except Exception as e:
        print(f"Error checking URL: {str(e)}")
        return None, None

def main():
    if len(sys.argv) < 2:
        print("Usage: python check_url.py <url>")
        print("Example: python check_url.py https://www.google.com")
        return
    
    url = sys.argv[1]
    check_url(url)

if __name__ == "__main__":
    main()
