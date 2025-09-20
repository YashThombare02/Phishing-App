"""
Isolation Forest module for detecting outlier/anomalous URLs.
This module provides a way to identify URLs that are statistically unusual
compared to known legitimate URLs.
"""

import numpy as np
from sklearn.ensemble import IsolationForest

class URLOutlierDetector:
    """Detects anomalous URLs using Isolation Forest algorithm"""
    
    def __init__(self, n_estimators=100, contamination=0.1, random_state=42):
        """
        Initialize the outlier detector
        
        Args:
            n_estimators (int): Number of trees in the forest
            contamination (float): Expected proportion of outliers in the dataset
            random_state (int): Random seed for reproducibility
        """
        self.model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state
        )
        self.is_fitted = False
        
    def fit(self, X):
        """
        Fit the model on training data
        
        Args:
            X (numpy.ndarray): Training data of shape (n_samples, n_features)
        """
        self.model.fit(X)
        self.is_fitted = True
    
    def predict_anomaly_score(self, X):
        """
        Calculate anomaly score for a URL
        Higher score means more anomalous/suspicious
        
        Args:
            X (numpy.ndarray): Feature vector(s) of shape (n_samples, n_features)
            
        Returns:
            float: Anomaly score normalized to 0-1 range, where 1 is most anomalous
        """
        if not self.is_fitted:
            # Return a neutral score if model not fitted
            return 0.5
        
        try:
            # Get raw decision function (negative is more anomalous)
            decision_scores = self.model.decision_function(X)
            
            # Convert to anomaly scores (0-1 range, higher is more anomalous)
            # Decision function returns negative values for outliers
            anomaly_scores = 1 - (1 / (1 + np.exp(-decision_scores)))
            
            return anomaly_scores
        except Exception as e:
            print(f"Error calculating anomaly score: {str(e)}")
            return 0.5  # Return neutral score on error
            
    def predict_is_outlier(self, X):
        """
        Predict if a URL is an outlier
        
        Args:
            X (numpy.ndarray): Feature vector(s) of shape (n_samples, n_features)
            
        Returns:
            bool: True if URL is predicted as an outlier, False otherwise
        """
        if not self.is_fitted:
            return False
            
        try:
            # -1 for outliers, 1 for inliers
            predictions = self.model.predict(X)
            # Convert to boolean (True for outliers)
            return predictions < 0
        except Exception as e:
            print(f"Error predicting outlier: {str(e)}")
            return False