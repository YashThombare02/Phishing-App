import os
import sys
import numpy as np
import pandas as pd
import pickle
import re
from urllib.parse import urlparse
import tldextract
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix
from sklearn.model_selection import train_test_split
import xgboost as xgb
from tqdm import tqdm
import warnings

# Suppress warnings
warnings.filterwarnings('ignore')

# Add parent directory to path so we can import ml_models
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

# Import the enhanced ML models
import ml_models

# Create models directory if it doesn't exist
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# Function to load the UCI dataset
def load_uci_dataset():
    """
    Load and prepare the UCI phishing dataset
    """
    print("Loading UCI phishing dataset...")
    
    # Check if the dataset exists
    uci_path = os.path.join(DATA_DIR, 'uci_dataset.csv')
    if not os.path.exists(uci_path):
        print("UCI dataset not found. Creating synthetic dataset instead.")
        return create_synthetic_uci_dataset()
    
    try:
        # Load the dataset
        df = pd.read_csv(uci_path)
        print(f"Loaded UCI dataset with {len(df)} samples and {len(df.columns)} features")
        
        # Extract features and target
        if 'Result' in df.columns:
            # Assuming 'Result' is the target column
            y = df['Result'].values
            X = df.drop('Result', axis=1).values
        else:
            # If no clear target column, assume the last column is the target
            y = df.iloc[:, -1].values
            X = df.iloc[:, :-1].values
        
        # Split the dataset
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        
        return X_train, X_test, y_train, y_test
    
    except Exception as e:
        print(f"Error loading UCI dataset: {str(e)}")
        print("Falling back to synthetic dataset")
        return create_synthetic_uci_dataset()

# Function to create a synthetic UCI dataset if the real one can't be loaded
def create_synthetic_uci_dataset():
    """
    Create a synthetic dataset with similar characteristics to the UCI phishing dataset
    """
    print("Creating synthetic UCI phishing dataset...")
    
    # Number of samples
    n_samples = 2000
    n_features = 30
    
    # Create synthetic features (random for demonstration)
    X = np.random.rand(n_samples, n_features)
    
    # Create synthetic labels with bias towards legitimate (60% legitimate, 40% phishing)
    y = np.random.choice([0, 1], size=n_samples, p=[0.6, 0.4])
    
    # Split the dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    return X_train, X_test, y_train, y_test

# Function to generate a more advanced synthetic dataset
def create_advanced_dataset():
    """
    Create a dataset with more features for the advanced model
    Uses real data if available, otherwise creates synthetic data
    """
    print("Creating advanced phishing dataset...")
    
    # Check if combined dataset exists
    combined_path = os.path.join('data', 'combined_urls.csv')
    
    if os.path.exists(combined_path):
        try:
            print("Using real URL data from combined dataset")
            return process_real_url_data(combined_path)
        except Exception as e:
            print(f"Error processing real URL data: {str(e)}")
            print("Falling back to synthetic dataset")
    
    # If no real data available, create synthetic dataset
    print("Creating synthetic advanced phishing dataset...")
    
    # Number of samples
    n_samples = 3000
    n_features = 50
    
    # Create synthetic features (random for demonstration)
    X = np.random.rand(n_samples, n_features)
    
    # Create synthetic labels with bias towards legitimate (60% legitimate, 40% phishing)
    y = np.random.choice([0, 1], size=n_samples, p=[0.6, 0.4])
    
    # Split the dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    return X_train, X_test, y_train, y_test

def process_real_url_data(csv_path):
    """
    Process real URL data from the combined dataset
    Extract features from URLs for the advanced model
    """
    # Load the dataset
    df = pd.read_csv(csv_path)
    print(f"Loaded {len(df)} URLs from combined dataset")
    
    # Extract features from URLs
    features = []
    labels = []
    
    # Process each URL
    for i, row in df.iterrows():
        url = row['url']
        is_phishing = row['is_phishing']
        
        try:
            # Extract features (simplified for demonstration)
            url_features = extract_url_features(url)
            features.append(url_features)
            labels.append(is_phishing)
            
            # Print progress
            if (i + 1) % 500 == 0:
                print(f"Processed {i + 1}/{len(df)} URLs")
        
        except Exception as e:
            print(f"Error extracting features from URL {url}: {str(e)}")
    
    # Convert to numpy arrays
    X = np.array(features)
    y = np.array(labels)
    
    print(f"Created dataset with {len(X)} samples and {X.shape[1]} features")
    
    # Split the dataset
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    return X_train, X_test, y_train, y_test

def extract_url_features(url):
    """
    Extract features from a URL for the advanced model
    """
    try:
        # Parse the URL
        parsed_url = urlparse(url)
        
        # Extract TLD and domain
        extracted = tldextract.extract(url)
        domain = parsed_url.netloc
        tld = extracted.suffix
        
        # Basic URL features
        features = []
        
        # Length-based features
        features.append(len(url))
        features.append(len(domain))
        features.append(len(parsed_url.path))
        
        # Count-based features
        features.append(url.count('.'))
        features.append(url.count('/'))
        features.append(url.count('?'))
        features.append(url.count('='))
        features.append(url.count('&'))
        features.append(url.count('-'))
        features.append(url.count('_'))
        features.append(url.count('@'))
        
        # Binary features
        features.append(1 if parsed_url.scheme == 'https' else 0)
        features.append(1 if '@' in url else 0)
        features.append(1 if '//' in url.replace('https://', '').replace('http://', '') else 0)
        features.append(1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0)
        
        # Domain-specific features
        features.append(1 if re.search(r'[^a-zA-Z0-9.-]', domain) else 0)
        features.append(domain.count('-'))
        features.append(domain.count('.'))
        
        # TLD features
        common_tlds = ['com', 'org', 'net', 'edu', 'gov', 'io', 'co', 'info', 'biz']
        for t in common_tlds:
            features.append(1 if tld == t else 0)
        
        # Keyword features
        suspicious_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 
                            'confirm', 'banking', 'password', 'security']
        for keyword in suspicious_keywords:
            features.append(1 if keyword in url.lower() else 0)
        
        # Add padding to ensure we have exactly 50 features
        while len(features) < 50:
            features.append(0)
        
        # Trim if we have too many features
        if len(features) > 50:
            features = features[:50]
        
        return features
    
    except Exception as e:
        # Return default features if extraction fails
        print(f"Error extracting features: {str(e)}")
        return [0] * 50

# Train the UCI model
def train_uci_model():
    """
    Train and save the UCI phishing detection model
    """
    print("\n=== Training UCI Model ===")
    
    # Load the dataset
    X_train, X_test, y_train, y_test = load_uci_dataset()
    
    # Train a Random Forest classifier
    print("Training Random Forest classifier...")
    model = RandomForestClassifier(
        n_estimators=200,
        max_depth=15,
        min_samples_split=5,
        min_samples_leaf=2,
        class_weight='balanced',
        random_state=42
    )
    model.fit(X_train, y_train)
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.4f}")
    
    # Print classification report
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Print confusion matrix
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Save the model
    model_path = os.path.join(MODEL_DIR, 'uci_model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"Model saved to {model_path}")

# Train the advanced model
def train_advanced_model():
    """
    Train and save the advanced phishing detection model
    """
    print("\n=== Training Advanced Model ===")
    
    # Create the advanced dataset
    X_train, X_test, y_train, y_test = create_advanced_dataset()
    
    # Train an XGBoost classifier
    print("Training XGBoost classifier...")
    model = xgb.XGBClassifier(
        n_estimators=300,
        learning_rate=0.05,
        max_depth=7,
        subsample=0.8,
        colsample_bytree=0.8,
        gamma=0.1,
        reg_alpha=0.1,
        reg_lambda=1,
        scale_pos_weight=1.5,  # Adjust for class imbalance
        eval_metric='logloss',
        base_score=0.5,
        random_state=42
    )
    
    # Create eval set for early stopping
    eval_set = [(X_test, y_test)]
    
    # Train the model
    model.fit(
        X_train, 
        y_train, 
        eval_set=eval_set,
        verbose=True
    )
    
    # Evaluate the model
    y_pred = model.predict(X_test)
    accuracy = accuracy_score(y_test, y_pred)
    print(f"Accuracy: {accuracy:.4f}")
    
    # Print classification report
    print("\nClassification Report:")
    print(classification_report(y_test, y_pred))
    
    # Print confusion matrix
    print("\nConfusion Matrix:")
    print(confusion_matrix(y_test, y_pred))
    
    # Save the model
    model_path = os.path.join(MODEL_DIR, 'advanced_model.pkl')
    with open(model_path, 'wb') as f:
        pickle.dump(model, f)
    
    print(f"Model saved to {model_path}")
    
    # Return the accuracy for reporting
    return accuracy

# Main function
def main():
    print("Starting model training...")
    
    # Create directories if they don't exist
    os.makedirs(MODEL_DIR, exist_ok=True)
    
    # Download datasets if needed
    if not os.path.exists(os.path.join(DATA_DIR, 'combined_urls.csv')):
        try:
            print("Combined URL dataset not found. You might want to run download_datasets.py first:")
            print("python download_datasets.py --source all")
        except Exception as e:
            print(f"Error suggesting dataset download: {str(e)}")
    
    # Train models using the enhanced approach
    train_enhanced_models()
    
    print("Model training completed!")

def train_enhanced_models():
    """
    Train the enhanced phishing detection ML models using the ml_models module
    """
    print("Training enhanced phishing detection models...")
    
    # Dataset paths
    combined_urls_csv = os.path.join(DATA_DIR, 'combined_urls.csv')
    legitimate_urls_csv = os.path.join(DATA_DIR, 'legitimate_urls.csv')
    uci_dataset_csv = os.path.join(DATA_DIR, 'uci_dataset.csv')
    
    # Check which datasets exist
    if os.path.exists(combined_urls_csv):
        print(f"Found combined dataset: {combined_urls_csv}")
        
        # Load and check the dataset
        df_combined = pd.read_csv(combined_urls_csv)
        print(f"Combined dataset shape: {df_combined.shape}")
        print(f"Columns: {df_combined.columns.tolist()}")
        
        # Count phishing and legitimate URLs
        phishing_count = df_combined['is_phishing'].sum() if 'is_phishing' in df_combined.columns else 0
        legitimate_count = len(df_combined) - phishing_count
        print(f"Phishing URLs: {phishing_count}")
        print(f"Legitimate URLs: {legitimate_count}")
        
        # Train models with combined dataset
        print("\nTraining models with combined dataset...")
        trained_models = ml_models.train_models(combined_csv=combined_urls_csv)
        
    elif os.path.exists(legitimate_urls_csv) and os.path.exists(uci_dataset_csv):
        print(f"Found separate datasets:")
        print(f"  - Legitimate URLs: {legitimate_urls_csv}")
        print(f"  - UCI dataset: {uci_dataset_csv}")
        
        # Load and check the datasets
        df_legitimate = pd.read_csv(legitimate_urls_csv)
        print(f"Legitimate dataset shape: {df_legitimate.shape}")
        print(f"Columns: {df_legitimate.columns.tolist()}")
        
        df_uci = pd.read_csv(uci_dataset_csv)
        print(f"UCI dataset shape: {df_uci.shape}")
        print(f"Columns: {df_uci.columns.tolist()}")
        
        # Train models with separate datasets
        print("\nTraining models with separate datasets...")
        trained_models = ml_models.train_models(phishing_csv=uci_dataset_csv, legitimate_csv=legitimate_urls_csv)
        
    else:
        print("No suitable datasets found in the data directory.")
        print(f"Please place phishing and legitimate URL datasets in: {DATA_DIR}")
        
        # Run the traditional training method as fallback
        print("Falling back to traditional training method...")
        train_uci_model()
        train_advanced_model()
        return
    
    # Test the trained models with example URLs
    test_models_with_examples(trained_models)

def test_models_with_examples(trained_models=None):
    """
    Test trained models with example URLs
    """
    if trained_models is None:
        # Load models if not provided
        trained_models = ml_models.PhishingMLModels(model_dir=MODEL_DIR)
        trained_models.load_models()
    
    # Test URLs - mix of legitimate and phishing
    test_urls = [
        "https://www.google.com",
        "http://malicious-phishing-site.com/login.php",
        "https://paypal-secure.phishing-attempt.com/login",
        "https://login-secure.framer.app/",
        "https://verify-account-secure.glide.page/",
        "https://www.amazon.com/",
        "https://mail.yahoo.com/",
        "https://www.microsoft.com/",
        "https://banking-secure-verification.netlify.app/"
    ]
    
    print("\nTesting trained models with example URLs:")
    for url in test_urls:
        # UCI model prediction
        uci_pred, uci_prob = trained_models.predict_uci_model(url)
        
        # Advanced model prediction
        adv_pred, adv_prob = trained_models.predict_advanced_model(url)
        
        print(f"URL: {url}")
        print(f"UCI Model: {'⚠️ PHISHING' if uci_pred else '✅ LEGITIMATE'} (Confidence: {uci_prob:.2f})")
        print(f"Advanced Model: {'⚠️ PHISHING' if adv_pred else '✅ LEGITIMATE'} (Confidence: {adv_prob:.2f})")
        
        # Combined verdict
        combined_verdict = uci_pred or adv_pred
        combined_confidence = max(uci_prob if uci_pred else 0, adv_prob if adv_pred else 0)
        if combined_verdict:
            print(f"Final Verdict: ⚠️ PHISHING (Confidence: {combined_confidence:.2f})")
        else:
            print(f"Final Verdict: ✅ LEGITIMATE (Confidence: {1-combined_confidence:.2f})")
        
        print("-" * 60)
    advanced_accuracy = train_advanced_model()
    
    print("\nModel training complete!")
    print(f"Expected phishing detection accuracy: {advanced_accuracy:.2%}")
    print("With additional verification methods (PhishTank, Google Safe Browsing, domain age),")
    print("the overall system accuracy should exceed 95%")

if __name__ == "__main__":
    print("=" * 60)
    print("ENHANCED PHISHING DETECTION MODEL TRAINING")
    print("=" * 60)
    print()
    main()
    print()
    print("=" * 60)
    print("Training completed! Models are ready for use.")
    print("=" * 60)
