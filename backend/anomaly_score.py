def check_anomaly_score(self, url):
    """
    Calculate anomaly/outlier score for a URL using Isolation Forest
    
    Args:
        url (str): URL to analyze
        
    Returns:
        dict: Result containing anomaly score and explanation
    """
    try:
        # Check if outlier detection is available
        if not outlier_detection_available or 'outlier_detector' not in models:
            return {
                'result': False,
                'description': "Anomaly detection not available",
                'value': 0.5  # Neutral score
            }
        
        # Get features
        features = self.extract_advanced_features(url)
        
        # Calculate anomaly score
        anomaly_detector = models['outlier_detector']
        try:
            # Handle different return types safely
            anomaly_score_result = anomaly_detector.predict_anomaly_score(features)
            is_outlier_result = anomaly_detector.predict_is_outlier(features)
            
            # Handle if returned value is a single number or array
            if hasattr(anomaly_score_result, '__getitem__'):
                anomaly_score = float(anomaly_score_result[0])
            else:
                anomaly_score = float(anomaly_score_result)
                
            if hasattr(is_outlier_result, '__getitem__'):
                is_outlier = bool(is_outlier_result[0])
            else:
                is_outlier = bool(is_outlier_result)
        except Exception as e:
            # If any calculation fails, use a neutral score
            anomaly_score = 0.5
            is_outlier = False
            print(f"Error calculating anomaly details: {str(e)}")
        
        # Determine description based on score
        if anomaly_score > 0.8:
            description = f"URL shows highly unusual patterns (anomaly score: {anomaly_score:.2f})"
            result = True
        elif anomaly_score > 0.6:
            description = f"URL has some unusual characteristics (anomaly score: {anomaly_score:.2f})"
            result = True
        else:
            description = f"URL shows normal patterns (anomaly score: {anomaly_score:.2f})"
            result = False
        
        return {
            'result': result,
            'description': description,
            'value': anomaly_score,
            'is_outlier': is_outlier
        }
    except Exception as e:
        return {
            'result': False,
            'description': f"Error calculating anomaly score: {str(e)}",
            'value': 0.5  # Neutral score
        }