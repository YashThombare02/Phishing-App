# Enhanced Phishing Detection Models

This directory contains enhanced machine learning models for detecting phishing URLs with high accuracy.

## Models Overview

Two primary machine learning models are used for phishing detection:

1. **UCI Random Forest Model**
   - Based on the UCI Phishing Websites Dataset features
   - Uses 30 carefully engineered features
   - Optimized for accuracy and minimal false negatives

2. **Advanced XGBoost Model**
   - Uses 60 comprehensive features for deeper analysis
   - Designed to detect sophisticated phishing attempts
   - Higher dimensionality allows for more nuanced pattern recognition

## Training the Models

The models can be trained using the provided datasets:

### Automatic Training (Recommended)

Run the batch file to automatically train both models:

```
train_enhanced_models.bat
```

### Manual Training

You can also train the models manually:

```
python train_models.py
```

## Required Datasets

The training requires at least one of the following dataset configurations:

1. Combined dataset: `data/combined_urls.csv` with columns:
   - `url`: The URL to analyze
   - `is_phishing`: 1 for phishing, 0 for legitimate

2. Separate datasets:
   - `data/legitimate_urls.csv`: Legitimate URLs
   - `data/uci_dataset.csv`: Phishing website features

## Features Engineering

The models extract numerous features including:

- URL structure analysis (length, subdomains, special characters)
- Domain characteristics (age, registration info, entropy)
- Suspicious keywords detection
- Authentication pattern recognition
- Brand impersonation detection
- Path and query analysis

## Performance Expectations

With the enhanced features and optimized parameters, the models are expected to achieve:

- UCI Model: ~95% accuracy
- Advanced Model: ~97% accuracy
- Combined with other verification methods: >98% accuracy

## Usage in the System

The models are automatically used by the PhishGuard system when analyzing URLs. The detection workflow includes:

1. URL is submitted for analysis
2. Features are extracted from the URL
3. Both models make predictions
4. Results are combined with other verification methods
5. Final verdict is determined based on weighted scores

## Model Confidence Calibration

The system includes calibration to ensure more aggressive detection of phishing URLs, with a bias toward minimizing false negatives (undetected phishing) even at the cost of some false positives.

## Whitelisting

A whitelist mechanism is included to prevent false positives for well-known legitimate sites.