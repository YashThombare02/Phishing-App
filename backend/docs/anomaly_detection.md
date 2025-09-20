# Anomaly Detection in PhishGuard

This document explains the anomaly detection feature implemented in the PhishGuard phishing detection system.

## Overview

Anomaly detection uses statistical methods to identify URLs that exhibit unusual patterns compared to legitimate URLs. This provides an additional layer of protection against novel phishing techniques that may not be captured by rule-based methods or traditional ML models.

## Implementation

PhishGuard uses an Isolation Forest algorithm for anomaly detection, which identifies outliers by isolating observations in the feature space.

```python
class URLOutlierDetector:
    """Detects anomalous URLs using Isolation Forest algorithm"""
    
    def __init__(self, n_estimators=100, contamination=0.1, random_state=42):
        """Initialize the outlier detector"""
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state
        )
        self.is_fitted = False
        
    def fit(self, X):
        """Fit the model on training data"""
        self.model.fit(X)
        self.is_fitted = True
    
    def predict_anomaly_score(self, X):
        """Calculate anomaly score for a URL"""
        if not self.is_fitted:
            return 0.5
        
        try:
            # Get raw decision function (negative is more anomalous)
            decision_scores = self.model.decision_function(X)
            
            # Convert to anomaly scores (0-1 range, higher is more anomalous)
            anomaly_scores = 1 - (1 / (1 + np.exp(-decision_scores)))
            
            return anomaly_scores
        except Exception as e:
            return 0.5  # Return neutral score on error
```

## Integration with PhishGuard

The anomaly detection feature is integrated into the PhishGuard workflow:

1. The outlier detector is initialized and trained during application startup
2. For each URL analysis, the `check_anomaly_score` method is called
3. The anomaly score is included in the verification methods with a 5% weight
4. Explanations are generated based on the anomaly score level

## Anomaly Score Interpretation

- **High Score (> 0.8)**: URL is highly unusual compared to normal patterns
- **Medium Score (0.6-0.8)**: URL has some unusual characteristics
- **Low Score (< 0.6)**: URL shows normal patterns

## Sample Usage

```python
# Get anomaly score for a URL
anomaly_result = phishing_detector.check_anomaly_score(url)

# Interpret the result
if anomaly_result['result']:
    print(f"Anomaly detected: {anomaly_result['description']}")
    print(f"Score: {anomaly_result['value']}")
else:
    print("No anomalies detected")
```

## Advantages of Anomaly Detection

1. **Zero-day Detection**: Can detect novel phishing techniques that haven't been seen before
2. **Unsupervised Learning**: No need for labeled examples of each attack type
3. **Complementary Signal**: Provides an independent verification method to supplement other checks
4. **Statistical Rigor**: Based on mathematical outlier detection rather than heuristics

## Limitations

1. **Training Data Quality**: Performance depends on having representative legitimate URLs for training
2. **False Positives**: Legitimate but unusual URLs may be flagged
3. **Interpretability**: Less explainable than rule-based methods

## Future Enhancements

1. **Online Learning**: Update the model as new legitimate URLs are confirmed
2. **Feature-level Anomalies**: Identify which specific features are anomalous
3. **Clustering**: Group similar anomalous URLs to identify attack campaigns