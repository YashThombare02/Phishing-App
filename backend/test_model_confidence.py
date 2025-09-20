import requests
import json

# Test URLs
urls = [
    "https://www.google.com",            # Legitimate site (both models should agree)
    "https://phishingsite1234567.com",   # Likely phishing (both models should agree)
    "https://amaz0n-secure.com",         # Brand impersonation (models might disagree)
    "https://login-account-verify.xyz"   # Suspicious URL (models might disagree)
]

print("PhishGuard Model Confidence Test\n")
print("=" * 50)

for url in urls:
    print(f"\nTesting URL: {url}")
    print("-" * 50)
    
    try:
        # Call the analyze API
        response = requests.post("http://localhost:5000/api/analyze", json={"url": url})
        result = response.json()
        
        # Extract relevant information
        verdict = "PHISHING" if result.get("final_verdict") else "LEGITIMATE"
        confidence = result.get("confidence", 0)
        
        # Get model confidence metrics
        model_confidence = result.get("verification_methods", {}).get("model_confidence", {})
        model_diff = model_confidence.get("model_difference", 0)
        model_agreement = model_confidence.get("model_agreement_confidence", 0)
        enhanced_confidence = model_confidence.get("enhanced_confidence", 0)
        
        # Get individual model scores
        uci_model = result.get("verification_methods", {}).get("uci_model", {})
        adv_model = result.get("verification_methods", {}).get("advanced_model", {})
        
        # Print results
        print(f"Verdict: {verdict} (Confidence: {confidence:.2f}%)")
        print(f"UCI Model: {'PHISHING' if uci_model.get('result') else 'LEGITIMATE'} (Value: {uci_model.get('value', 0):.3f})")
        print(f"Advanced Model: {'PHISHING' if adv_model.get('result') else 'LEGITIMATE'} (Value: {adv_model.get('value', 0):.3f})")
        print("\nModel Confidence Metrics:")
        print(f"  - Model Difference: {model_diff:.3f}")
        print(f"  - Agreement Confidence: {model_agreement:.3f}")
        print(f"  - Enhanced Confidence: {enhanced_confidence:.3f}")
        
        # Print explanations
        print("\nExplanations:")
        for explanation in result.get("explanations", []):
            if "ML models" in explanation:
                print(f"  * {explanation}")
        
    except Exception as e:
        print(f"Error: {str(e)}")
    
    print("-" * 50)

print("\nTest complete!")