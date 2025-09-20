# Model Confidence Metrics in PhishGuard

This document explains the model confidence metrics implemented in the PhishGuard phishing detection system.

## Overview

PhishGuard uses two machine learning models for phishing detection:
1. **UCI Model**: A basic model trained on the UCI dataset with 30 features
2. **Advanced Model**: An enhanced model with 60 features for deeper analysis

To improve reliability, we've implemented model confidence metrics that analyze both models' predictions and provide insights into their agreement/disagreement.

## Metrics Implemented

### 1. Model Difference

This metric calculates the absolute difference between the probability scores of both models:

```python
model_difference = abs(uci_model_value - advanced_model_value)
```

A small difference indicates strong agreement between models, while a large difference suggests they disagree about the classification.

### 2. Model Agreement Confidence

This metric normalizes the model difference to a 0-1 scale, where 1 indicates perfect agreement:

```python
model_agreement_confidence = 1.0 - (model_difference / 1.0)
```

### 3. Weighted Confidence

This combines both model probabilities with appropriate weights:

```python
weighted_confidence = (uci_model_value * 0.4) + (advanced_model_value * 0.6)
```

The advanced model is given more weight (0.6) because it uses more features.

### 4. Enhanced Confidence

This metric intelligently adjusts confidence based on model agreement:

```python
if model_difference < 0.2:
    # Models agree - use the higher confidence value
    enhanced_confidence = max(uci_model_value, advanced_model_value)
else:
    # Models disagree - use a weighted average but reduce confidence
    enhanced_confidence = weighted_confidence * (0.8 - (model_difference * 0.3))
```

When models agree, we use the higher confidence value. When they disagree, we reduce confidence proportionally.

## Integration

These metrics are incorporated into the detection process:

1. The `_calculate_model_confidence_difference` method calculates all metrics
2. Results are added to the verification methods dictionary
3. The metrics are factored into the weighted scoring system (6% weight)
4. Explanations are generated based on model agreement level
5. All metrics are included in the API response

## Interpretation

- **Strong Agreement (difference < 0.1)**: High reliability in the prediction
- **Moderate Agreement (difference < 0.3)**: Reasonable reliability
- **Disagreement (difference >= 0.3)**: Caution - models have conflicting opinions

## Benefit

This approach provides several advantages:
- Improved reliability by considering model consensus
- Better explanations for users about prediction confidence
- Ability to flag unusual cases where models disagree
- Enhanced overall system confidence calculation