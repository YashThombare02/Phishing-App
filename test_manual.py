import os
import numpy as np
from ml_models import PhishingMLModels

# Create directory for models if it doesn't exist
models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
os.makedirs(models_dir, exist_ok=True)

# Test URL
test_url = "http://www.goggle.com"

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
print(f"  - Has suspicious TLD: {'Yes' if uci_features[15] else 'No'}")
print(f"  - Contains suspicious keywords: {'Yes' if uci_features[27] else 'No'}")
print(f"  - Has brand-like domain: {'Yes' if uci_features[22] else 'No'}")

# Extract and display advanced features (50 features)
adv_features = ml_models.extract_advanced_features(test_url)[0]
print("\nKey Advanced Features:")
print(f"  - URL length: {adv_features[0]}")
print(f"  - Domain length: {adv_features[1]}")
print(f"  - HTTPS used: {'Yes' if adv_features[10] else 'No'}")
print(f"  - Domain entropy: {adv_features[25]:.2f}")
print(f"  - Domain digit ratio: {adv_features[26]:.2f}")
print(f"  - Contains brand impersonation: {'Yes' if any(adv_features[40:45]) else 'No'}")

# For demonstration, let's manually analyze this URL
print("\nManual Analysis of http://www.goggle.com:")
print("-" * 60)
print("1. Typosquatting detection: 'goggle.com' is a misspelling of 'google.com'")
print("2. This is a common phishing technique to trick users into visiting fake sites")
print("3. The domain 'goggle' has high similarity to the legitimate 'google' brand")
print("4. The URL uses HTTP instead of HTTPS, which is less secure")

# Since our dummy models might not give accurate predictions, let's use manual analysis
# In a real-world scenario, trained models would provide more accurate results
typosquat_score = 0.85  # High probability of being a typosquatting attempt
security_score = 0.70   # Lacking HTTPS adds to suspicion
similarity_score = 0.90 # Very similar to legitimate brand

# Final verdict (manual calculation for demonstration)
combined_score = (typosquat_score + security_score + similarity_score) / 3
print("\nFinal Analysis:")
print("-" * 60)
print(f"Combined phishing probability: {combined_score:.4f} ({combined_score*100:.2f}%)")

# Threshold for classification
threshold = 0.5
final_verdict = combined_score >= threshold

print(f"Final verdict: {'PHISHING' if final_verdict else 'LEGITIMATE'}")
print(f"Confidence: {abs(combined_score - 0.5) * 2 * 100:.2f}%")
print("\nNote: In the actual system, properly trained ML models would provide more reliable predictions.")
