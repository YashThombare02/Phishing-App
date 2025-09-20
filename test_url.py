import os
from ml_models import PhishingMLModels

# Test URL
test_url = "http://www.goggle.com"

# Initialize models
print("Initializing ML models...")
models_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "models")
ml_models = PhishingMLModels(model_dir=models_dir)
ml_models.load_models()

# Run prediction with both models
print(f"\nAnalyzing URL: {test_url}")
print("-" * 60)

# UCI model prediction (30 features)
uci_pred, uci_prob = ml_models.predict_uci_model(test_url)
print(f"UCI Model Analysis (30 features):")
print(f"  - Prediction: {'Phishing' if uci_pred else 'Legitimate'}")
print(f"  - Confidence: {uci_prob:.4f} ({uci_prob*100:.2f}%)")

# Extract and display some key UCI features
uci_features = ml_models.extract_uci_features(test_url)[0]
print("\nKey UCI Features:")
print(f"  - URL Length > 75: {'Yes' if uci_features[0] else 'No'}")
print(f"  - Contains IP address: {'Yes' if uci_features[1] else 'No'}")
print(f"  - Uses URL shortener: {'Yes' if uci_features[2] else 'No'}")
print(f"  - Has @ symbol: {'Yes' if uci_features[3] else 'No'}")
print(f"  - Has suspicious TLD: {'Yes' if uci_features[15] else 'No'}")
print(f"  - Contains suspicious keywords: {'Yes' if uci_features[27] else 'No'}")
print(f"  - Has brand-like domain: {'Yes' if uci_features[22] else 'No'}")

# Advanced model prediction (50 features)
adv_pred, adv_prob = ml_models.predict_advanced_model(test_url)
print(f"\nAdvanced Model Analysis (50 features):")
print(f"  - Prediction: {'Phishing' if adv_pred else 'Legitimate'}")
print(f"  - Confidence: {adv_prob:.4f} ({adv_prob*100:.2f}%)")

# Extract and display some key advanced features
adv_features = ml_models.extract_advanced_features(test_url)[0]
print("\nKey Advanced Features:")
print(f"  - URL length: {adv_features[0]}")
print(f"  - Domain length: {adv_features[1]}")
print(f"  - HTTPS used: {'Yes' if adv_features[10] else 'No'}")
print(f"  - Domain entropy: {adv_features[25]:.2f}")
print(f"  - Domain digit ratio: {adv_features[26]:.2f}")
print(f"  - Contains brand impersonation: {'Yes' if any(adv_features[40:45]) else 'No'}")

# Final verdict
# We combine both models with a weighted approach
# Advanced model gets higher weight (0.6) than UCI model (0.4)
combined_score = 0.4 * uci_prob + 0.6 * adv_prob
print("\nFinal Analysis:")
print("-" * 60)
print(f"Combined phishing probability: {combined_score:.4f} ({combined_score*100:.2f}%)")

# Threshold for classification
threshold = 0.5
final_verdict = combined_score >= threshold

print(f"Final verdict: {'PHISHING' if final_verdict else 'LEGITIMATE'}")
print(f"Confidence: {abs(combined_score - 0.5) * 2 * 100:.2f}%")
