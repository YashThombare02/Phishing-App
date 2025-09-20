import requests
import json

def analyze_url(url):
    """
    Analyze a URL using the phishing detection API
    """
    try:
        response = requests.post(
            "http://localhost:5000/api/detect",
            json={"url": url}
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        print(f"Error analyzing URL: {e}")
        return None

if __name__ == "__main__":
    url_to_check = "https://btinternetcomxxchn-dk96.glide.page/dl/2432"
    print(f"Analyzing URL: {url_to_check}")
    
    result = analyze_url(url_to_check)
    
    if result:
        print("\n=== PHISHING ANALYSIS RESULTS ===")
        print(f"URL: {result.get('url')}")
        print(f"Final Verdict: {'PHISHING' if result.get('final_verdict') else 'LEGITIMATE'}")
        print(f"Confidence: {result.get('confidence')}%")
        
        print("\n=== VERIFICATION METHODS ===")
        verification_methods = result.get('verification_methods', {})
        for method_name, method_data in verification_methods.items():
            result_status = "Suspicious" if method_data.get('result') else "Clean"
            print(f"{method_name.replace('_', ' ').title()}: {result_status}")
            print(f"  - {method_data.get('description')}")
            
        print("\n=== EXPLANATIONS ===")
        for explanation in result.get('explanations', []):
            print(f"- {explanation}")
        
        print("\n=== FEATURES EXTRACTED ===")
        features = result.get('features_extracted', {})
        print(f"UCI Features: {features.get('uci_features')}")
        print(f"Advanced Features: {features.get('advanced_features')}")
    else:
        print("Failed to analyze URL.")