import requests
import json
import sys

def test_phishing_url(url):
    """Test a URL against our enhanced PhishGuard system"""
    try:
        # Update this URL if your backend is running on a different port
        api_url = "http://localhost:5000/api/detect"
        response = requests.post(api_url, json={"url": url})
        
        if response.status_code == 200:
            data = response.json()
            
            # Print result
            print(f"\nTesting URL: {url}")
            print("="*80)
            
            if data["final_verdict"]:
                print(f"VERDICT: PHISHING (Confidence: {data['confidence']:.2f}%)")
            else:
                print(f"VERDICT: LEGITIMATE (Confidence: {data['confidence']:.2f}%)")
            print("="*80)
            
            # Print verification methods
            print("Verification Methods:")
            for name, method in data["verification_methods"].items():
                if name != "domain_created":  # Skip domain creation date
                    result = "Suspicious" if method["result"] else "Safe"
                    print(f"  - {name}: {result}")
                    print(f"      {method['description']}")
            
            # Print explanations
            if data["explanations"]:
                print("Explanations:")
                for explanation in data["explanations"]:
                    print(f"  - {explanation}")
            
            # Print features
            if "features_extracted" in data:
                print("Features Extracted:")
                print("  UCI Features (first 10):")
                for i, feature in enumerate(data["features_extracted"]["uci_features"]):
                    print(f"    - Feature {i}: {feature}")
                
                print("  Advanced Features (first 10):")
                for i, feature in enumerate(data["features_extracted"]["advanced_features"]):
                    print(f"    - Feature {i}: {feature}")
                    
            return data["final_verdict"]
        else:
            print(f"Error: {response.status_code}")
            print(response.text)
            return None
    
    except Exception as e:
        print(f"Error testing URL: {str(e)}")
        return None

if __name__ == "__main__":
    # Get URL from command line or use default test URL
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = "http://paypal-secure-login.com"  # Default test URL
    
    test_phishing_url(url)
