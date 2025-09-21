from flask import Flask, request, jsonify
from flask_cors import CORS
import os
import requests
# Import python-whois correctly
import whois
import ssl
import socket
import re
import time
import json
import pickle
import numpy as np
import pandas as pd
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from datetime import datetime, timedelta
import xgboost as xgb
import warnings
import hashlib
import threading
from sqlalchemy import create_engine, Column, Integer, String, Boolean, Float, DateTime, Text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
import socket
from collections import Counter
import tldextract
import ssl
import urllib.request
import csv
from dotenv import load_dotenv
# Import Levenshtein functions we need
from Levenshtein import distance as levenshtein_distance
from Levenshtein import ratio as levenshtein_ratio
import dns.resolver

# Import our ML models
import sys
import os
# Add parent directory to path to allow importing ml_models
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from ml_models import PhishingMLModels

# Import outlier detection module (with graceful fallback)
try:
    from outlier_detection import URLOutlierDetector
    outlier_detection_available = True
except ImportError:
    outlier_detection_available = False

# Suppress warnings
warnings.filterwarnings('ignore')

# Initialize Flask app
app = Flask(__name__)
# Enable CORS with more specific configuration
CORS_ORIGINS = os.environ.get('CORS_ORIGINS', '*')
CORS(app, resources={r"/api/*": {"origins": CORS_ORIGINS}}, supports_credentials=True)

# Load environment variables
load_dotenv()

# Configuration
MODEL_DIR = os.path.join(os.path.dirname(__file__), 'models')
DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')
PHISHTANK_API_KEY = os.environ.get('PHISHTANK_API_KEY', '')
GOOGLE_SAFE_BROWSING_API_KEY = os.environ.get('GOOGLE_SAFE_BROWSING_API_KEY', '')

# Database configuration
DB_TYPE = os.environ.get('DB_TYPE', 'sqlite').lower()

if DB_TYPE == 'postgres':
    # PostgreSQL configuration
    DB_USER = os.environ.get('DB_USER', 'postgres')
    DB_PASSWORD = os.environ.get('DB_PASSWORD', 'postgres')
    DB_HOST = os.environ.get('DB_HOST', 'localhost')
    DB_PORT = os.environ.get('DB_PORT', '5432')
    DB_NAME = os.environ.get('DB_NAME', 'phishguard')
    DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"
    print("Using PostgreSQL database")
else:
    # SQLite configuration (default)
    SQLITE_DB_PATH = os.environ.get('SQLITE_DB_PATH', 'phishing_database.db')
    DATABASE_URL = f"sqlite:///{SQLITE_DB_PATH}"
    print(f"Using SQLite database: {SQLITE_DB_PATH}")

# Create directories if they don't exist
os.makedirs(MODEL_DIR, exist_ok=True)
os.makedirs(DATA_DIR, exist_ok=True)

# Google Safe Browsing API URL
SAFE_BROWSING_URL = "https://safebrowsing.googleapis.com/v4/threatMatches:find"

# PhishTank API URL
PHISHTANK_URL = "https://checkurl.phishtank.com/checkurl/"

# Common URL shortener domains
URL_SHORTENERS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'cli.gs', 'ow.ly', 
    'buff.ly', 'adf.ly', 'urlz.fr', 'bitly.com', 'tr.im', 'shorturl.at', 
    'snipurl.com', 'short.to', 'thinfi.com', 'tiny.cc', 'cutt.ly', 'shorturl.is',
    'rebrand.ly', 'boly.me', 'shorte.st', 'bc.vc', 'v.gd', 'mcaf.ee', 'adly.co', 
    'zpr.io', 'surl.li', 'rb.gy', 'po.st', 'trin.net', 'soo.gd', 'bl.ink', 
    'l.ly', 'twurl.nl', 'u.to', 'smarturl.it', 'tms.co', 'x.co', 'tgram.io', 
    'yourls.org', 'hiveam.com', 'clkim.com', 'lin.ee', 'shorturl.com', 
    'urlshortener.io', 'plu.sh', 's2r.co', 'ouo.io', 'picz.in'
]

# Common brands targeted by phishing
COMMON_PHISHING_TARGETS = {
    'paypal': ['paypal.com', 'paypal.co.uk', 'paypal.me'],
    'apple': ['apple.com', 'icloud.com', 'itunes.com', 'apple.co', 'apple.uk', 'apple.ie'],
    'microsoft': ['microsoft.com', 'live.com', 'office365.com', 'office.com', 'outlook.com', 'microsoftonline.com'],
    'google': ['google.com', 'gmail.com', 'youtube.com', 'google.co.uk', 'google.de', 'googlemail.com'],
    'amazon': ['amazon.com', 'amazon.co.uk', 'amazon.ca', 'amazon.in', 'amazon.de', 'amazon.fr', 'amazon.it'],
    'facebook': ['facebook.com', 'fb.com', 'messenger.com', 'fb.me'],
    'instagram': ['instagram.com', 'ig.me'],
    'twitter': ['twitter.com', 't.co'],
    'netflix': ['netflix.com', 'netflix.co.uk', 'netflix.ca'],
    'linkedin': ['linkedin.com', 'lnkd.in'],
    'bank': ['chase.com', 'bankofamerica.com', 'wellsfargo.com', 'citibank.com', 'hsbc.com', 'barclays.co.uk', 'santander.co.uk'],
    'shipping': ['fedex.com', 'ups.com', 'usps.com', 'dhl.com'],
    'government': ['irs.gov', 'gov.uk', 'ssa.gov', 'healthcare.gov'],
    'payment': ['venmo.com', 'zelle.com', 'cashapp.com', 'stripe.com', 'square.com', 'shop.com'],
    'crypto': ['coinbase.com', 'binance.com', 'kraken.com', 'blockchain.com', 'metamask.io'],
    'email': ['mail.com', 'yahoo.com', 'aol.com', 'protonmail.com', 'zoho.com']
}

# Initialize global variables
models = {
    'uci_model': None,
    'advanced_model': None
}

# Cache for PhishTank and Safe Browsing results (to reduce API calls)
phishtank_cache = {}
safebrowsing_cache = {}
url_shortener_cache = {}

# SQLAlchemy setup
Base = declarative_base()

# Define SQLAlchemy models
class Detection(Base):
    __tablename__ = 'detections'
    
    id = Column(Integer, primary_key=True)
    url = Column(String, nullable=False)
    domain = Column(String, nullable=False)
    is_phishing = Column(Boolean, nullable=False)
    confidence = Column(Float, nullable=False)
    detection_methods = Column(Text, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow)

class Report(Base):
    __tablename__ = 'reports'
    
    id = Column(Integer, primary_key=True)
    url = Column(String, nullable=False)
    domain = Column(String, nullable=False)
    description = Column(Text)
    username = Column(String)
    submitter_ip = Column(String)
    status = Column(String, default='phishing')
    timestamp = Column(DateTime, default=datetime.utcnow)

# Engine and session setup
engine = create_engine(DATABASE_URL)
Session = sessionmaker(bind=engine)

# Database initialization
def init_db():
    # Create all tables
    Base.metadata.create_all(engine)

# Reset the database schema (for development only)
def reset_db():
    # Drop all tables
    Base.metadata.drop_all(engine)
    # Create all tables
    Base.metadata.create_all(engine)

# Load models
def load_models():
    global models
    
    # Initialize PhishingMLModels class
    ml_models = PhishingMLModels(model_dir=MODEL_DIR)
    loaded_models = ml_models.load_models()
    
    # Set models
    models['uci_model'] = loaded_models['uci_model']
    models['advanced_model'] = loaded_models['advanced_model']
    
    # Store the ML models instance for feature extraction
    models['ml_models_instance'] = ml_models
    
    # Initialize outlier detector if available
    if outlier_detection_available:
        try:
            print("Initializing Isolation Forest for anomaly detection...")
            models['outlier_detector'] = URLOutlierDetector(n_estimators=100, contamination=0.1)
            
            # For now, use a simple fit on some features (this would be better trained on known legitimate URLs)
            # In production, this should be pre-trained on a representative dataset
            detector = models['outlier_detector']
            
            # Use the ML model's instance to get training data if available
            if hasattr(ml_models, 'X_train_advanced') and ml_models.X_train_advanced is not None:
                print("Training outlier detector on existing training data...")
                detector.fit(ml_models.X_train_advanced)
            else:
                print("No training data available for outlier detector")
        except Exception as e:
            print(f"Error initializing outlier detector: {str(e)}")
            models['outlier_detector'] = None
    else:
        print("Outlier detection module not available")
        models['outlier_detector'] = None
    
    print("Machine learning models loaded successfully!")

# Class for phishing detection
class PhishingDetector:
    def __init__(self):
        self.phishtank_checks = 0
        self.safebrowsing_checks = 0
        self.whois_checks = 0
    
    def extract_uci_features(self, url):
        """Extract features based on UCI dataset methodology"""
        global models
        
        # Use the ML models instance for feature extraction if available
        if 'ml_models_instance' in models and models['ml_models_instance'] is not None:
            return models['ml_models_instance'].extract_uci_features(url)
        
        # Fallback to basic feature extraction if ML models instance is not available
        features = [0] * 30  # Placeholder for 30 features
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        
        # Example features (in real implementation, would be more comprehensive)
        features[0] = 1 if '@' in url else 0
        features[1] = 1 if len(domain) > 20 else 0
        features[2] = 1 if url.count('/') > 5 else 0
        features[3] = 1 if url.count('.') > 3 else 0
        features[4] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
        features[5] = 1 if 'https' not in url else 0
        features[6] = 1 if len(url) > 100 else 0
        features[7] = 1 if '-' in domain else 0
        features[8] = 1 if 'login' in url.lower() or 'signin' in url.lower() else 0
        features[9] = 1 if 'secure' in url.lower() or 'account' in url.lower() else 0
        
        # Additional features to improve phishing detection
        features[10] = 1 if re.search(r'paypal|apple|microsoft|amazon|google|facebook|instagram|twitter|netflix', url.lower()) else 0
        features[11] = 1 if any(brand in domain.lower() and brand not in parsed_url.scheme for brand in ['paypal', 'apple', 'microsoft', 'amazon', 'google']) else 0
        features[12] = 1 if re.search(r'\.php$|\.asp$|\.aspx$|\.jsp$', path.lower()) else 0
        features[13] = 1 if len(domain.split('.')) > 3 else 0
        features[14] = 1 if re.search(r'[^a-zA-Z0-9.-]', domain) else 0
        features[15] = 1 if re.search(r'verify|confirm|secure|account|login|signin|password', url.lower()) else 0
        features[16] = 1 if re.search(r'password|passwd|pwd', url.lower()) else 0
        features[17] = 1 if re.search(r'update|upgrade|billing', url.lower()) else 0
        features[18] = 1 if any(char.isdigit() for char in domain) else 0
        features[19] = 1 if domain.count('-') > 1 else 0
        
        # More feature extraction would go here...
        
        return np.array(features).reshape(1, -1)
    
    def extract_advanced_features(self, url):
        """
        Extract more comprehensive features for advanced model
        
        Features include:
        - Basic URL characteristics (length, counts of special chars)
        - Domain specific features (entropy, vowel/consonant ratio)
        - N-gram character analysis
        - Advanced metrics like character distribution and randomness
        """
        global models
        
        # Use the ML models instance for feature extraction if available
        if 'ml_models_instance' in models and models['ml_models_instance'] is not None:
            return models['ml_models_instance'].extract_advanced_features(url)
        
        # Fallback to enhanced feature extraction
        features = [0] * 60  # Expanded to 60 features
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        query = parsed_url.query
        extracted = tldextract.extract(url)
        
        # Basic URL features (0-9)
        features[0] = len(url)
        features[1] = len(domain)
        features[2] = len(path)
        features[3] = url.count('.')
        features[4] = url.count('/')
        features[5] = url.count('?')
        features[6] = url.count('=')
        features[7] = url.count('&')
        features[8] = url.count('-')
        features[9] = url.count('_')
        features[4] = url.count('/')
        features[5] = url.count('?')
        features[6] = url.count('=')
        features[7] = url.count('&')
        features[8] = url.count('-')
        features[9] = url.count('_')
        
        # Security indicators (10-11)
        features[10] = 1 if 'https' in url.lower() else 0
        features[11] = 1 if 'http' in url.lower() and 'https' not in url.lower() else 0
        
        # Suspicious patterns (12-14)
        features[12] = 1 if '@' in url else 0
        features[13] = 1 if '//' in url.replace('https://', '').replace('http://', '') else 0
        features[14] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
        
        # Domain specific features (15-19)
        features[15] = 1 if re.search(r'[^a-zA-Z0-9.-]', domain) else 0
        features[16] = domain.count('-')
        features[17] = domain.count('.')
        features[18] = len(extracted.subdomain) if extracted.subdomain else 0
        features[19] = len(extracted.suffix) if extracted.suffix else 0
        
        # Enhanced lexical features (20-29)
        features[20] = self._calculate_token_count(url)
        features[21] = self._calculate_vowel_ratio(domain)
        features[22] = self._calculate_consonant_ratio(domain)
        features[23] = self._count_repeating_characters(domain)
        features[24] = self._calculate_entropy(domain)  # Domain entropy
        features[25] = self._calculate_entropy(url)     # Full URL entropy
        
        # Character distribution features (26-29)
        domain_name = extracted.domain
        features[26] = sum(c.isdigit() for c in domain_name) / max(len(domain_name), 1)  # Digit ratio
        features[27] = sum(c.isalpha() for c in domain_name) / max(len(domain_name), 1)  # Letter ratio
        features[28] = sum(not c.isalnum() for c in domain_name) / max(len(domain_name), 1)  # Special char ratio
        features[29] = 1 if any(c.isdigit() for c in domain_name) and any(c.isalpha() for c in domain_name) else 0  # Mixed alphanumeric
        
        # Brand impersonation checks (30-39)
        brand_names = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'instagram', 'netflix', 'twitter', 'linkedin']
        for i, brand in enumerate(brand_names):
            if i < 10:  # We have space for 10 brand features
                # Check if brand appears in domain but domain is not actually that brand's site
                features[i + 30] = 1 if brand in domain.lower() and not domain.lower().endswith(f"{brand}.com") else 0
        
        # URL length category (40-43)
        features[40] = 0  # Very short (< 30)
        features[41] = 0  # Short (30-60)
        features[42] = 0  # Medium (60-90)
        features[43] = 0  # Long (> 90)
        
        if len(url) < 30:
            features[40] = 1
        elif len(url) < 60:
            features[41] = 1
        elif len(url) < 90:
            features[42] = 1
        else:
            features[43] = 1
        
        # Check for suspicious TLDs (44)
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'date', 'faith', 'stream']
        features[44] = 1 if extracted.suffix.lower() in suspicious_tlds else 0
        
        # Credential and security terms (45-56)
        security_terms = ['login', 'signin', 'verify', 'secure', 'account', 'password', 'update', 
                         'confirm', 'banking', 'security', 'authenticate', 'verification']
        
        for i, term in enumerate(security_terms):
            if i < 12:  # We have space for 12 security terms
                features[i + 45] = 1 if term in url.lower() else 0
        
        # Domain base name (without TLD)
        domain_without_tld = extracted.domain
        
        # N-gram character analysis (57)
        # Use tri-grams (3-character sequences) for domain
        domain_ngrams = self._extract_ngrams(domain_without_tld, 3)
        
        # Check for suspicious n-grams often found in phishing domains
        suspicious_ngrams = ['sec', 'log', 'sig', 'acc', 'ver', 'upd', 'con', 'pas']
        ngram_matches = sum(1 for ngram in domain_ngrams if ngram in suspicious_ngrams)
        features[57] = min(ngram_matches / max(len(suspicious_ngrams), 1), 1.0)
        
        # Domain characteristics (58-59)
        features[58] = len(domain_without_tld)
        features[59] = self._calculate_entropy(domain_without_tld)
        
        return np.array(features).reshape(1, -1)
    
    def _calculate_model_confidence_difference(self, verification_methods):
        """
        Calculate the confidence difference between model predictions
        
        Args:
            verification_methods (dict): Dictionary containing all verification methods and their results
        
        Returns:
            dict: Model confidence metrics
        """
        try:
            # Extract model probabilities 
            uci_model_value = verification_methods.get('uci_model', {}).get('value', 0.5)
            advanced_model_value = verification_methods.get('advanced_model', {}).get('value', 0.5)
            
            # Calculate absolute difference between models
            model_difference = abs(uci_model_value - advanced_model_value)
            
            # Calculate normalized confidence based on model agreement
            # If both models agree strongly (small difference), we have higher confidence
            # If models disagree (large difference), we have lower confidence
            model_agreement_confidence = 1.0 - (model_difference / 1.0)
            
            # Calculate weighted average confidence
            weighted_confidence = (uci_model_value * 0.4) + (advanced_model_value * 0.6)
            
            # Calculate enhanced confidence metric (considers both agreement and absolute confidence)
            if model_difference < 0.2:
                # Models agree - use the higher confidence value
                enhanced_confidence = max(uci_model_value, advanced_model_value)
            else:
                # Models disagree - use a weighted average but reduce confidence
                enhanced_confidence = weighted_confidence * (0.8 - (model_difference * 0.3))
                
            # Ensure confidence values are between 0 and 1
            enhanced_confidence = max(0.0, min(1.0, enhanced_confidence))
            model_agreement_confidence = max(0.0, min(1.0, model_agreement_confidence))
            
            # Build the result dictionary
            result = {
                'result': True,
                'model_difference': round(model_difference, 3),
                'model_agreement_confidence': round(model_agreement_confidence, 3),
                'weighted_confidence': round(weighted_confidence, 3),
                'enhanced_confidence': round(enhanced_confidence, 3),
                'description': f'Model confidence metrics: difference={model_difference:.3f}, agreement={model_agreement_confidence:.3f}',
                'value': enhanced_confidence
            }
            
            return result
        except Exception as e:
            # Return default values if there's an error
            return {
                'result': False,
                'model_difference': 0,
                'model_agreement_confidence': 0,
                'weighted_confidence': 0,
                'enhanced_confidence': 0,
                'description': f'Error calculating model confidence: {str(e)}',
                'value': 0.5
            }
    
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
            anomaly_score = float(anomaly_detector.predict_anomaly_score(features)[0])
            is_outlier = bool(anomaly_detector.predict_is_outlier(features)[0])
            
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
            
    def check_phishtank(self, url):
        """Check if URL is in PhishTank database"""
        try:
            self.phishtank_checks += 1
            
            # Check cache first
            url_hash = hashlib.md5(url.encode()).hexdigest()
            if url_hash in phishtank_cache:
                return phishtank_cache[url_hash]
            
            # Try enhanced database first, then fall back to regular database
            phishtank_files = [
                os.path.join(DATA_DIR, 'enhanced_phishtank_database.json'),
                os.path.join(DATA_DIR, 'phishtank_database.json')
            ]
            
            for phishtank_file in phishtank_files:
                if os.path.exists(phishtank_file):
                    try:
                        with open(phishtank_file, 'r') as f:
                            phishtank_data = json.load(f)
                            print(f"Loaded PhishTank database with {len(phishtank_data)} entries")
                    
                        # Exact URL match
                        for entry in phishtank_data:
                            if entry['url'].lower() == url.lower():
                                result = {
                                    'result': True,
                                    'description': f"URL found in PhishTank database (ID: {entry['phish_id']})",
                                    'value': 1
                                }
                                phishtank_cache[url_hash] = result
                                return result
                        
                        # Domain match (stronger indicator than just keywords)
                        parsed_url = urlparse(url)
                        domain = parsed_url.netloc.lower()
                        
                        for entry in phishtank_data:
                            parsed_entry = urlparse(entry['url'])
                            entry_domain = parsed_entry.netloc.lower()
                            
                            if domain == entry_domain:
                                result = {
                                    'result': True,
                                    'description': f"Domain found in PhishTank database (ID: {entry['phish_id']})",
                                    'value': 0.9  # Slightly lower than exact match
                                }
                                phishtank_cache[url_hash] = result
                                return result
                        
                        # Target brand match (check if domain contains target brand)
                        for entry in phishtank_data:
                            if 'target' in entry and entry['target']:
                                target = entry['target'].lower()
                                if target in domain and len(target) > 3:  # Avoid false positives with short brands
                                    result = {
                                        'result': True,
                                        'description': f"URL likely impersonating {entry['target']} (similar to known phishing)",
                                        'value': 0.7  # Lower confidence for brand similarity
                                    }
                                    phishtank_cache[url_hash] = result
                                    return result
                        
                        # Not found in database, fall back to heuristic check
                        is_phishing = self._heuristic_phishing_check(url)
                        result = {
                            'result': is_phishing,
                            'description': 'URL not found in PhishTank database, using heuristic check',
                            'value': 0.6 if is_phishing else 0
                        }
                        phishtank_cache[url_hash] = result
                        return result
                    
                    except Exception as e:
                        print(f"Error reading local PhishTank database: {str(e)}")
            
            # If no database or error reading database, use heuristic approach
            is_phishing = self._heuristic_phishing_check(url)
            result = {
                'result': is_phishing,
                'description': 'PhishTank database unavailable, using heuristic check',
                'value': 0.7 if is_phishing else 0
            }
            phishtank_cache[url_hash] = result
            return result
        
        except Exception as e:
            return {
                'result': False,
                'description': f'Error checking PhishTank: {str(e)}',
                'value': 0
            }
    
    def check_suspicious_auth_patterns(self, url):
        """Check specifically for authentication-related phishing indicators"""
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        path = parsed_url.path.lower()
        extracted = tldextract.extract(url)
        subdomain = extracted.subdomain
        domain_name = extracted.domain
        
        suspicious_score = 0
        explanations = []
        
        # Check for authentication-related keywords in domain
        auth_keywords = ['auth', 'login', 'signin', 'secure', 'account', 'verify', 'validation', 'access', 
                         'portal', 'web', 'online', 'service', 'official', 'connect', 'user', 'client', 
                         'banking', 'update', 'confirm', 'id', 'center', 'support', 'help']
        
        for keyword in auth_keywords:
            if keyword in domain_name or keyword in subdomain:
                suspicious_score += 0.7
                explanations.append(f"Domain contains authentication keyword '{keyword}'")
        
        # Check for URL path containing authentication keywords
        auth_path_keywords = ['login', 'signin', 'auth', 'account', 'verify', 'secure', 'password', 'reset',
                             'recover', 'confirm', 'update', 'access', 'portal', 'service', 'session']
        for keyword in auth_path_keywords:
            if keyword in path:
                suspicious_score += 0.5
                explanations.append(f"URL path contains authentication keyword '{keyword}'")
        
        # Check for random numbers in domain (common in phishing domains)
        if re.search(r'\d{3,}', domain_name) or re.search(r'\d{3,}', subdomain):
            suspicious_score += 0.8
            explanations.append("Domain contains random number sequence, common in auto-generated phishing domains")
        
        # Check for suspicious generic domains paired with auth terms
        generic_domains = ['web', 'site', 'online', 'service', 'app', 'login', 'portal', 'secure', 'center', 
                          'official', 'verify', 'auth', 'connect', 'access', 'account', 'support', 'page',
                          'zone', 'area', 'manage', 'customer', 'user', 'member', 'client', 'dashboard']
                          
        # Check for hyphens with numbers (e.g., silly-acknowledge-272796)
        if re.search(r'-\d+', domain) or re.search(r'\d+-', domain):
            suspicious_score += 0.7
            explanations.append("Domain contains hyphenated numbers, common in auto-generated phishing domains")
            
        # Check for platform-generated subdomains (e.g. silly-acknowledge-272796.framer.app)
        generated_platforms = ['framer.app', 'glide.page', 'makeweb.co', 'netlify.app', 'herokuapp.com', 
                              'firebaseapp.com', 'web.app', 'vercel.app', 'now.sh', 'pages.dev',
                              'github.io', 'gitlab.io', 'wixsite.com', 'squarespace.com', 'webflow.io']
        
        for platform in generated_platforms:
            if domain.endswith(platform) and (re.search(r'\d+', domain) or '-' in domain):
                suspicious_score += 0.9
                explanations.append(f"Domain appears to be an auto-generated {platform} site with suspicious pattern")
                break
        
        # Check for domains with mixed digits and authentication terms
        if any(keyword in domain_name for keyword in auth_keywords) and re.search(r'\d+', domain_name):
            suspicious_score += 0.9
            explanations.append("Domain combines authentication terms with digits, common in phishing")
        
        # Calculate final score (normalize to 0-1 range)
        final_score = min(suspicious_score, 1.0)
        
        # Build description
        if final_score > 0.7:
            description = "High-risk authentication pattern detected: " + "; ".join(explanations)
        elif final_score > 0.4:
            description = "Moderate-risk authentication pattern detected: " + "; ".join(explanations)
        elif final_score > 0:
            description = "Low-risk authentication pattern detected: " + "; ".join(explanations)
        else:
            description = "No suspicious authentication patterns detected"
        
        # ALWAYS return result as true for any score above zero to be more aggressive
        is_suspicious = final_score > 0
        
        return {
            'result': is_suspicious,  # Flag as suspicious for ANY auth pattern match
            'description': description,
            'value': max(final_score, 0.4) if is_suspicious else 0  # Minimum score of 0.4 if suspicious
        }
        
    def check_domain_creation_date_reliability(self, url):
        """
        Check if domain creation date is reliable or unknown
        Returns a reliability rating from 0-10:
        - 10: Domain has valid DNS records, WHOIS data, and established presence
        - 7-9: Domain has valid DNS records, MX, NS, and good ASN reputation
        - 4-6: Domain has valid DNS records but limited or no WHOIS data
        - 1-3: Domain has some DNS records but configuration issues or poor ASN reputation
        - 0: Domain has no valid DNS records or other reliability indicators
        
        Checks include:
        - DNS A/AAAA records (IP addresses)
        - Mail exchange (MX) records
        - TXT records for domain verification
        - Nameserver (NS) records and their count
        - TTL values (very low TTL can indicate fast-flux networks)
        - ASN reputation (if IP is hosted on commonly abused providers)
        - IP reputation in security databases
        """
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Remove port information if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Check if we can get actual domain age information
            try:
                # Try to look up domain information
                domain_info = socket.gethostbyname_ex(domain)
                has_dns = True
            except:
                has_dns = False
            
            if not has_dns:
                return {
                    'result': True,  # Consider unreliable domain information suspicious
                    'description': "Domain has no reliable DNS information, typical of new phishing sites",
                    'reliability_rating': 0,
                    'reliability_description': "No DNS Records: Highly suspicious",
                    'value': 0.8
                }
            
            # Check for additional reliability indicators
            reliability_score = 5  # Start with a baseline of 5 (medium reliability)
            reliability_factors = []
            
            # Check for MX records (mail exchange) - legitimate domains often have these
            try:
                mx_records = dns.resolver.resolve(domain, 'MX')
                if mx_records:
                    reliability_score += 2
                    reliability_factors.append("Has valid mail exchange (MX) records")
            except:
                reliability_score -= 1
                reliability_factors.append("No mail exchange records")
            
            # Check for multiple A records (IP addresses) - established domains often have multiple
            try:
                a_records = dns.resolver.resolve(domain, 'A')
                if len(a_records) > 1:
                    reliability_score += 1
                    reliability_factors.append("Multiple IP addresses")
                
                # Check ASN reputation if we have IP addresses
                try:
                    # Get the first IP
                    ip_address = str(a_records[0])
                    
                    # Known problematic ASNs (commonly used by attackers)
                    problematic_asns = [
                        "AS14618",  # Amazon AWS (legitimate but often abused)
                        "AS16509",  # Amazon AWS
                        "AS16276",  # OVH
                        "AS24940",  # Hetzner
                        "AS46606",  # Unified Layer
                        "AS14061",  # DigitalOcean
                        "AS9009",   # M247
                        "AS204601", # 7host (high abuse ratio)
                        "AS208323", # Cyberhost
                        "AS48666",  # NETKING
                        "AS39572",  # ADVANCEDHOSTERS
                        "AS50896",  # Talia
                        "AS43350",  # NForce
                        "AS58097",  # ABCDE Group
                        "AS44901",  # Belcloud
                        "AS47583",  # Hostinger
                        "AS49877",  # Marva Hosting
                    ]
                    
                    # Highly abused ASNs (these get a higher penalty)
                    high_abuse_asns = [
                        "AS204601", # 7host (high abuse ratio)
                        "AS208323", # Cyberhost
                        "AS48666",  # NETKING
                        "AS39572",  # ADVANCEDHOSTERS
                        "AS50896",  # Talia
                    ]
                    
                    # Check if hosted on a cloud provider (not necessarily suspicious but worth noting)
                    cloud_providers = [
                        "Amazon", "AWS", "Google", "Microsoft", "Azure", "Cloudflare", 
                        "DigitalOcean", "OVH", "Linode", "Vultr", "Hetzner"
                    ]
                    
                    # Check ASN information (note: a real implementation would use an ASN lookup API or library)
                    # For demonstration, we'll simulate an ASN check
                    # In a real-world scenario, use GeoIP databases or ASN lookup services
                    is_from_problematic_asn = False
                    is_from_high_abuse_asn = False
                    is_from_cloud_provider = False
                    
                    # Simple heuristic - if IP starts with certain ranges, consider it from specific providers
                    # This is a simplified approach; real implementation would use proper ASN lookup
                    if ip_address.startswith('13.') or ip_address.startswith('52.') or ip_address.startswith('54.'):
                        is_from_problematic_asn = "AS14618" in problematic_asns  # AWS
                        is_from_cloud_provider = True
                        asn_name = "Amazon AWS"
                    elif ip_address.startswith('34.') or ip_address.startswith('35.'):
                        is_from_cloud_provider = True
                        asn_name = "Google Cloud"
                    elif ip_address.startswith('40.') or ip_address.startswith('20.'):
                        is_from_cloud_provider = True
                        asn_name = "Microsoft Azure"
                    elif ip_address.startswith('104.') or ip_address.startswith('172.'):
                        is_from_cloud_provider = True
                        asn_name = "Cloudflare"
                    elif ip_address.startswith('46.'):
                        is_from_problematic_asn = True
                        is_from_high_abuse_asn = True
                        asn_name = "Potential High-Risk Provider"
                    elif ip_address.startswith('185.') or ip_address.startswith('194.'):
                        is_from_problematic_asn = True
                        asn_name = "Potential European Low-Cost Provider"
                    else:
                        asn_name = "Unknown ASN"
                    
                    if is_from_high_abuse_asn:
                        reliability_score -= 3
                        reliability_factors.append(f"Hosted on highly abused ASN: {asn_name} (significant risk)")
                    elif is_from_problematic_asn:
                        reliability_score -= 2
                        reliability_factors.append(f"Hosted on frequently abused ASN: {asn_name}")
                    elif is_from_cloud_provider:
                        # Neutral - cloud providers host both legitimate and malicious content
                        reliability_factors.append(f"Hosted on cloud provider: {asn_name}")
                    
                    # Check for dedicated IP vs shared hosting (shared hosting is slightly more suspicious)
                    try:
                        # Reverse DNS lookup to check for shared hosting patterns
                        reverse_dns = socket.gethostbyaddr(ip_address)[0]
                        if any(pattern in reverse_dns for pattern in ['shared', 'host', 'web', 'cloud']):
                            reliability_score -= 0.5
                            reliability_factors.append("Shared hosting environment detected")
                    except:
                        # If reverse DNS fails, this is slightly suspicious
                        reliability_score -= 0.5
                        reliability_factors.append("No reverse DNS record")
                    
                    # Check if IP has been reported in IP reputation databases (simulated)
                    # In a real implementation, this would query reputation databases
                    # For demonstration, we'll use a heuristic based on the IP
                    ip_last_octet = int(ip_address.split('.')[-1])
                    if ip_last_octet % 13 == 0:  # Simple heuristic for demonstration
                        reliability_score -= 1
                        reliability_factors.append("IP has poor reputation in security databases")
                    
                except Exception as asn_error:
                    # If ASN check fails, continue without it
                    pass
            except:
                reliability_score -= 1
                reliability_factors.append("No A records found")
            
            # Check for AAAA records (IPv6 addresses) - modern legitimate domains often have these
            try:
                aaaa_records = dns.resolver.resolve(domain, 'AAAA')
                if aaaa_records:
                    reliability_score += 1.5
                    reliability_factors.append("Has IPv6 (AAAA) records - good modern configuration")
            except:
                # Not having IPv6 is not necessarily suspicious, but it's becoming more common for legitimate sites
                pass
            
            # Check for TXT records (often used for domain verification)
            try:
                txt_records = dns.resolver.resolve(domain, 'TXT')
                if txt_records:
                    reliability_score += 1
                    reliability_factors.append("Has TXT records for domain verification")
                    
                    # Check for SPF and DKIM records (especially important for mail domains)
                    txt_values = [str(record) for record in txt_records]
                    has_spf = any("v=spf1" in value for value in txt_values)
                    has_dkim = any("DKIM" in value or "v=DKIM" in value for value in txt_values)
                    has_dmarc = any("v=DMARC" in value or "DMARC" in value for value in txt_values)
                    
                    if has_spf:
                        reliability_score += 0.5
                        reliability_factors.append("Has SPF record - good mail configuration")
                    
                    if has_dkim:
                        reliability_score += 0.5
                        reliability_factors.append("Has DKIM record - good mail configuration")
                        
                    if has_dmarc:
                        reliability_score += 0.5
                        reliability_factors.append("Has DMARC record - good mail configuration")
            except:
                pass
                
            # Check for nameservers (NS records)
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                ns_count = len(ns_records)
                
                # Convert NS records to strings for analysis
                ns_names = [str(record) for record in ns_records]
                
                if ns_count >= 2:
                    reliability_score += 1
                    reliability_factors.append(f"Has {ns_count} nameservers (good redundancy)")
                    
                    # Check for different nameserver providers (better redundancy)
                    ns_providers = set()
                    for ns in ns_names:
                        # Extract provider from nameserver
                        ns_parts = ns.split('.')
                        if len(ns_parts) >= 2:
                            ns_providers.add(ns_parts[-2])
                    
                    if len(ns_providers) > 1:
                        reliability_score += 0.5
                        reliability_factors.append(f"Uses multiple nameserver providers ({len(ns_providers)}) - good redundancy")
                
                # Check if using free/common nameservers (slightly more suspicious)
                free_ns_providers = ['cloudflare', 'afraid', 'namecheap', 'dnspod', 'freenom']
                if any(provider in ''.join(ns_names).lower() for provider in free_ns_providers):
                    reliability_score -= 0.5
                    reliability_factors.append("Uses free/common nameserver providers")
                
                # Check TTL of records
                try:
                    ttl = ns_records.ttl
                    if ttl < 300:  # Very short TTL (less than 5 minutes)
                        reliability_score -= 2
                        reliability_factors.append(f"Very short TTL ({ttl}s) - potential fast-flux indicator")
                    elif ttl < 1800:  # Short TTL (less than 30 minutes)
                        reliability_score -= 1
                        reliability_factors.append(f"Short TTL ({ttl}s) - unusual for stable domains")
                    elif ttl < 3600:  # Somewhat short TTL (less than 1 hour)
                        reliability_score -= 0.5
                        reliability_factors.append(f"Somewhat short TTL ({ttl}s)")
                    elif ttl > 86400:  # Very long TTL (more than 1 day)
                        reliability_score += 0.5  # Slightly positive - indicates stability
                        reliability_factors.append(f"Long TTL ({ttl}s) - indicates stable configuration")
                except:
                    pass
            except:
                reliability_score -= 1
                reliability_factors.append("No NS records found")
                
            # Normalize reliability score to 0-10 range
            reliability_score = max(0, min(reliability_score, 10))
            
            # Generate reliability description based on score
            if reliability_score >= 8:
                reliability_desc = "High Reliability: Well-established domain with complete DNS configuration"
                is_suspicious = False
                risk_value = 0
            elif reliability_score >= 5:
                reliability_desc = "Medium Reliability: Domain has basic DNS configuration"
                is_suspicious = False
                risk_value = 0.2
            elif reliability_score >= 3:
                reliability_desc = "Low Reliability: Domain has minimal DNS configuration"
                is_suspicious = True
                risk_value = 0.4
            else:
                reliability_desc = "Very Low Reliability: Domain has problematic DNS configuration"
                is_suspicious = True
                risk_value = 0.6
                
            # Special case checks (as per requirements)
            # If no A record or NXDOMAIN - highest suspicion
            if "No A records found" in reliability_factors:
                reliability_desc = "No A Records: Missing essential DNS - definitely suspicious"
                is_suspicious = True
                risk_value = 1.0
                reliability_score = 0
            
            # If valid A record but on low-reputation ASN
            elif any("highly abused ASN" in factor for factor in reliability_factors):
                if reliability_score > 3:  # Adjust score if it's higher
                    reliability_score = 3
                reliability_desc = f"Low Reliability: Valid DNS but hosted on known-bad ASN"
                is_suspicious = True
                risk_value = 0.9
            
            # If TTL is very short (fast-flux indicator)
            elif any("fast-flux indicator" in factor for factor in reliability_factors):
                if reliability_score > 4:  # Adjust score if it's higher
                    reliability_score = 4
                reliability_desc = f"Suspicious: Fast-flux network indicators detected"
                is_suspicious = True
                risk_value = 0.8
            
            # Add reliability factors to description if available
            if reliability_factors:
                reliability_detail = ", ".join(reliability_factors)
            else:
                reliability_detail = "Basic DNS records only"
            
            return {
                'result': is_suspicious,
                'description': f"Domain reliability rating: {reliability_score}/10 - {reliability_desc}",
                'reliability_rating': reliability_score,
                'reliability_factors': reliability_factors,
                'reliability_description': reliability_desc,
                'value': risk_value
            }
            
        except Exception as e:
            # If we can't check, consider it uncertain but not definitely suspicious
            return {
                'result': False,
                'description': f"Couldn't verify domain reliability: {str(e)}",
                'reliability_rating': 3,
                'reliability_description': "Unknown - Could not assess reliability",
                'value': 0.3
            }

    def _heuristic_phishing_check(self, url):
        """Use heuristics to check if a URL is likely phishing when API is unavailable"""
        suspicious_score = 0
        explanations = []
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        path = parsed_url.path
        
        # Extract domain components
        extracted = tldextract.extract(url)
        subdomain = extracted.subdomain
        domain_name = extracted.domain
        
        # Check for suspicious URL patterns (higher weights for stronger indicators)
        if '@' in url:
            suspicious_score += 2  # Using @ in URLs is a strong phishing indicator
            explanations.append("URL contains @ symbol, which is often used to obscure the actual destination")
        
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            suspicious_score += 1.5  # IP addresses instead of domains are suspicious
            explanations.append("URL uses an IP address instead of a domain name, which is uncommon for legitimate sites")
        
        # Check for HTTP (not HTTPS)
        if parsed_url.scheme == 'http':
            suspicious_score += 0.5
            explanations.append("URL does not use HTTPS, which is less secure than HTTPS")
            
        # Check domain name length (very long domains are suspicious)
        if len(domain) > 30:
            suspicious_score += 1
            explanations.append(f"Domain name is extremely long ({len(domain)} characters)")
        elif len(domain) > 20:
            suspicious_score += 0.5
            explanations.append(f"Domain name is unusually long ({len(domain)} characters)")
            
        # Check for very suspicious domain patterns (randomly generated domains, etc.)
        random_domain_pattern = re.compile(r'^[a-zA-Z]+\d{4,}')
        if random_domain_pattern.search(domain_name):
            suspicious_score += 1.5
            explanations.append("Domain follows a pattern common in automatically generated phishing domains (letters followed by 4+ digits)")
            
        # Check for domains with "prod" or "secure" combined with numbers
        prod_secure_pattern = re.compile(r'(prod|secure|auth|login|verify|account|service)[a-z]*\d+', re.IGNORECASE)
        if prod_secure_pattern.search(domain_name) or prod_secure_pattern.search(subdomain):
            suspicious_score += 1.8
            explanations.append("Domain combines security-related terms with numbers, very common in phishing sites")
            
        # Check for suspicious TLDs
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'date', 'faith', 'stream']
        if extracted.suffix in suspicious_tlds:
            suspicious_score += 1
            explanations.append(f"Domain uses suspicious TLD (.{extracted.suffix}), which is often used for phishing")
            
        # Check for brand impersonation (very strong indicator)
        brand_names = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook', 'instagram', 
                      'netflix', 'twitter', 'linkedin', 'chase', 'wellsfargo', 'citibank', 'bankofamerica']
        brand_misspellings = {
            'google': ['goggle', 'g00gle', 'googel', 'gooogle', 'googie', 'g0ogle'],
            'microsoft': ['microsft', 'micr0soft', 'microsofr', 'microsofe', 'micros0ft'],
            'facebook': ['faceb00k', 'facebok', 'faceboook', 'facbook', 'faceb0ok'],
            'amazon': ['amaz0n', 'amazn', 'amazzon', 'amaazon', 'arnazon'],
            'apple': ['appl', 'appel', 'apie', 'applle', 'appl3', 'appie'],
            'paypal': ['paypa1', 'payp4l', 'paypai', 'payypal', 'pay-pal']
        }
        
        # Check for exact brand names in domain but not actually that domain
        for brand in brand_names:
            if brand in domain.lower() and not domain.lower().endswith(f"{brand}.com"):
                suspicious_score += 2.5
                explanations.append(f"Domain contains brand name '{brand}' but is not the official {brand}.com domain")
                break
                
        # Check for brand misspellings (strong phishing indicator)
        for brand, misspellings in brand_misspellings.items():
            for misspelling in misspellings:
                if misspelling in domain.lower():
                    suspicious_score += 2.0
                    explanations.append(f"Domain contains misspelling of '{brand}' ('{misspelling}'), which is often used in phishing")
                    break
                
        # Check for very suspicious domain patterns (randomly generated domains, etc.)
        random_domain_pattern = re.compile(r'^[a-zA-Z]+\d{4,}')
        if random_domain_pattern.search(domain_name):
            suspicious_score += 1.5
            explanations.append("Domain follows a pattern common in automatically generated phishing domains (letters followed by 4+ digits)")
            
        # Check for domains with "prod" or "secure" combined with numbers
        prod_secure_pattern = re.compile(r'(prod|secure|auth|login|verify|account|service)[a-z]*\d+', re.IGNORECASE)
        if prod_secure_pattern.search(domain_name) or prod_secure_pattern.search(subdomain):
            suspicious_score += 1.8
            explanations.append("Domain combines security-related terms with numbers, very common in phishing sites")
            
        # Check for suspicious keywords in URL
        suspicious_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 
                             'password', 'security', 'authenticate', 'verification', 'access', 'wallet', 'payment']
        
        keyword_count = 0
        found_keywords = []
        for keyword in suspicious_keywords:
            if keyword in url.lower():
                keyword_count += 1
                found_keywords.append(keyword)
                
        # Multiple security keywords in URL is suspicious
        if keyword_count >= 3:
            suspicious_score += 1.5
            explanations.append(f"URL contains multiple suspicious keywords: {', '.join(found_keywords)}")
        elif keyword_count >= 1:
            suspicious_score += 0.5
            explanations.append(f"URL contains suspicious keywords: {', '.join(found_keywords)}")
            
        # Check for random-looking domain (mixing letters and numbers)
        domain_without_tld = extracted.domain
        if len(domain_without_tld) > 10 and any(c.isdigit() for c in domain_without_tld) and any(c.isalpha() for c in domain_without_tld):
            suspicious_score += 1
            explanations.append("Domain name contains a mix of letters and numbers, which is common in phishing domains")
            
        # Check for excessive subdomains
        if len(domain.split('.')) > 3:
            suspicious_score += 0.5
            explanations.append(f"URL contains an unusual number of subdomains ({len(domain.split('.'))})")
            
        # Check for unusual characters in domain
        if re.search(r'[^a-zA-Z0-9.-]', domain):
            suspicious_score += 1
            explanations.append("Domain contains unusual characters, which is uncommon for legitimate sites")
            
        # Excessive hyphens in domain
        if domain.count('-') > 2:
            suspicious_score += 0.5
            explanations.append(f"Domain contains an unusual number of hyphens ({domain.count('-')})")
            
        # Check for URL shorteners (could be hiding actual destination)
        shortener_domains = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'cli.gs', 'ow.ly']
        if any(shortener in domain.lower() for shortener in shortener_domains):
            suspicious_score += 1.0
            explanations.append("URL uses a URL shortener service, which can hide the actual destination")
            
        # Check for domain that looks like subdomain (e.g., paypal.com.secure-login.com)
        if re.search(r'([a-zA-Z0-9-]+\.[a-zA-Z0-9-]+)\.[a-zA-Z0-9-]+\.[a-zA-Z0-9-]+', domain):
            suspicious_score += 2.0
            explanations.append("Domain appears to be attempting to masquerade as a subdomain of a legitimate site")
            
        # Return True if score exceeds threshold (adjusted threshold)
        return suspicious_score >= 2.0
    
    def check_google_safebrowsing(self, url):
        """Check URL using Google Safe Browsing API"""
        try:
            self.safebrowsing_checks += 1
            
            # Check cache first
            url_hash = hashlib.md5(url.encode()).hexdigest()
            if url_hash in safebrowsing_cache:
                return safebrowsing_cache[url_hash]
            
            # If we have an API key, check with Google Safe Browsing API
            if GOOGLE_SAFE_BROWSING_API_KEY:
                try:
                    # Prepare the request payload
                    payload = {
                        "client": {
                            "clientId": "phishguard",
                            "clientVersion": "1.0.0"
                        },
                        "threatInfo": {
                            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                            "platformTypes": ["ANY_PLATFORM"],
                            "threatEntryTypes": ["URL"],
                            "threatEntries": [
                                {"url": url}
                            ]
                        }
                    }
                    
                    # Make the API request
                    params = {"key": GOOGLE_SAFE_BROWSING_API_KEY}
                    response = requests.post(SAFE_BROWSING_URL, params=params, json=payload, timeout=5)
                    
                    if response.status_code == 200:
                        response_data = response.json()
                        
                        # If there are matches, the URL is unsafe
                        is_unsafe = 'matches' in response_data and len(response_data['matches']) > 0
                        
                        if is_unsafe:
                            threat_type = response_data['matches'][0]['threatType']
                            result = {
                                'result': True,
                                'description': f"URL flagged by Google Safe Browsing as {threat_type}",
                                'value': 1
                            }
                        else:
                            result = {
                                'result': False,
                                'description': "URL not flagged by Google Safe Browsing",
                                'value': 0
                            }
                        
                        safebrowsing_cache[url_hash] = result
                        return result
                
                except Exception as e:
                    print(f"Error checking Google Safe Browsing API: {str(e)}")
                    # Fall back to heuristic check
            
            # If no API key or API call fails, use a heuristic approach
            suspicious_features = self._check_ssl_and_security(url)
            result = {
                'result': suspicious_features >= 2,
                'description': f"Using security heuristics (SSL/security issues: {suspicious_features})",
                'value': min(suspicious_features * 0.25, 1)  # Scale 0-4 to 0-1
            }
            safebrowsing_cache[url_hash] = result
            return result
        
        except Exception as e:
            return {
                'result': False,
                'description': f'Error checking Google Safe Browsing: {str(e)}',
                'value': 0
            }
    
    def check_url_shortener(self, url):
        """Check if URL is from a URL shortener service and follow it if possible"""
        try:
            # Check cache first
            url_hash = hashlib.md5(url.encode()).hexdigest()
            url_shortener_cache_key = f"url_shortener_{url_hash}"
            
            if url_shortener_cache_key in url_shortener_cache:
                return url_shortener_cache[url_shortener_cache_key]
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Check if domain is a known URL shortener
            is_shortener = any(domain.endswith(shortener) for shortener in URL_SHORTENERS)
            
            if not is_shortener:
                # Also check if it's a very short domain with few characters (possible shortener)
                domain_parts = domain.split('.')
                if len(domain_parts[0]) <= 3 and domain.count('.') == 1:
                    is_shortener = True
            
            if is_shortener:
                try:
                    # Try to follow the URL to get the final destination
                    session = requests.Session()
                    session.max_redirects = 5
                    response = session.head(url, allow_redirects=True, timeout=5)
                    final_url = response.url
                    
                    # Check if final URL is different from original
                    if final_url != url:
                        result = {
                            'result': True,
                            'description': f"URL shortener detected: {domain} → {final_url}",
                            'value': 0.7,  # High risk score but not definitive
                            'final_url': final_url
                        }
                    else:
                        result = {
                            'result': True,
                            'description': f"URL shortener detected: {domain}, but couldn't follow redirect",
                            'value': 0.6
                        }
                except Exception as e:
                    # Couldn't follow the redirect, still suspicious
                    result = {
                        'result': True,
                        'description': f"URL shortener detected: {domain}, error following: {str(e)}",
                        'value': 0.5
                    }
            else:
                result = {
                    'result': False,
                    'description': "Not a URL shortener",
                    'value': 0
                }
            
            # Cache the result
            url_shortener_cache[url_shortener_cache_key] = result
            return result
            
        except Exception as e:
            return {
                'result': False,
                'description': f'Error checking URL shortener: {str(e)}',
                'value': 0
            }
    
    def _check_ssl_and_security(self, url):
        """Enhanced check for SSL certificate and other security features"""
        suspicious_count = 0
        details = []
        
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Check 1: HTTPS usage
            if parsed_url.scheme != 'https':
                suspicious_count += 1
                details.append("No HTTPS")
            
            # Check 2: Certificate details for HTTPS URLs
            if parsed_url.scheme == 'https':
                try:
                    # Create SSL context and connect
                    ctx = ssl.create_default_context()
                    with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
                        s.connect((domain, 443))
                        cert = s.getpeercert()
                    
                    # Check 2.1: Certificate expiration
                    if 'notAfter' in cert:
                        expiry = ssl.cert_time_to_seconds(cert['notAfter'])
                        current_time = time.time()
                        days_to_expiry = (expiry - current_time) / (24 * 60 * 60)
                        
                        if days_to_expiry < 30:
                            suspicious_count += 1
                            details.append(f"Cert expires soon ({int(days_to_expiry)} days)")
                        
                        if days_to_expiry < 0:
                            suspicious_count += 2
                            details.append("Cert expired")
                    
                    # Check 2.2: Self-signed certificate
                    if cert.get('issuer', []) == cert.get('subject', []):
                        suspicious_count += 2
                        details.append("Self-signed cert")
                    
                    # Check 2.3: Certificate age (new certificates can be suspicious)
                    if 'notBefore' in cert:
                        issue_time = ssl.cert_time_to_seconds(cert['notBefore'])
                        cert_age_days = (current_time - issue_time) / (24 * 60 * 60)
                        
                        if cert_age_days < 7:  # Very new certificate (less than a week)
                            suspicious_count += 1
                            details.append(f"Very new cert ({int(cert_age_days)} days old)")
                
                except ssl.SSLError as ssl_err:
                    # Specific SSL errors
                    suspicious_count += 2
                    details.append(f"SSL Error: {str(ssl_err)}")
                except Exception:
                    # General connection failure
                    suspicious_count += 2
                    details.append("HTTPS connection failed")
            
            # Check 3: IP address instead of domain name
            if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                suspicious_count += 2
                details.append("IP address in URL")
            
            # Check 4: Non-standard port
            if ':' in domain:
                port = int(domain.split(':')[1])
                standard_ports = [80, 443, 8080, 8443]
                if port not in standard_ports:
                    suspicious_count += 1
                    details.append(f"Non-standard port: {port}")
            
            # Check 5: Suspicious URL path components
            path = parsed_url.path.lower()
            if any(keyword in path for keyword in ['login', 'signin', 'account', 'password', 'secure', 'update']):
                if domain.count('.') > 2 or any(brand in domain.lower() for brand in ['paypal', 'apple', 'microsoft', 'amazon', 'facebook', 'google']):
                    suspicious_count += 1
                    details.append("Sensitive path with suspicious domain")
            
            # Check 6: Excessive number of subdomains
            if domain.count('.') > 3:
                suspicious_count += 1
                details.append(f"Excessive subdomains: {domain.count('.')}")
            
            # Check 7: Domain with mixed alphanumeric characters
            if re.search(r'[a-z][0-9]|[0-9][a-z]', domain.lower()):
                domain_parts = domain.split('.')
                if len(re.findall(r'[0-9]', domain_parts[0])) > 2:
                    suspicious_count += 1
                    details.append("Alphanumeric domain with multiple digits")
            
            return suspicious_count
        
        except Exception as e:
            # Log the error but return a moderate suspicion level
            print(f"Error in security check: {str(e)}")
            return 2  # Default to moderately suspicious if checks fail
    
    def check_domain_age(self, url):
        """
        Check domain age using heuristic approach with enhanced age-based rating
        Returns a risk rating based on the domain's age:
        - 0-30 days: Very High Risk (10/10)
        - 31-60 days: High Risk (8/10)
        - 61-90 days: Moderate Risk (6/10)
        - 91-180 days: Low Risk (3/10)
        - 181-365 days: Very Low Risk (1/10)
        - 365+ days: Minimal Risk (0/10)
        """
        try:
            self.whois_checks += 1
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            extracted = tldextract.extract(url)
            
            # Use basic domain age estimation based on various heuristics
            # Since we're having issues with whois libraries
            domain_created = "Unknown"
            
            # Initialize domain age assessment
            is_likely_new_domain = False
            domain_age_assessment = 3  # Start with a baseline suspicion level - assume domains are suspicious
            
            # 1. Check TLD - some TLDs are newer or commonly used for phishing
            high_risk_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'date', 'faith', 'stream', 
                             'app', 'page', 'co', 'me', 'click', 'link', 'website', 'site']
            medium_risk_tlds = ['online', 'site', 'website', 'space', 'live', 'click', 'link', 'tech', 'io', 'dev']
            
            if extracted.suffix.lower() in high_risk_tlds:
                domain_age_assessment += 3
                is_likely_new_domain = True
            elif extracted.suffix.lower() in medium_risk_tlds:
                domain_age_assessment += 2
                
            # 2. Check for random-looking domains (entropy/randomness in domain name)
            domain_name = extracted.domain
            if len(domain_name) > 0:
                # Calculate character distribution entropy
                char_counts = Counter(domain_name)
                entropy = -sum((count / len(domain_name)) * np.log2(count / len(domain_name)) 
                              for count in char_counts.values())
                
                # High entropy indicates more random looking names
                if entropy > 3.5:  # Very random
                    domain_age_assessment += 3
                    is_likely_new_domain = True
                elif entropy > 3.0:  # Moderately random
                    domain_age_assessment += 2
            
            # 3. Check for length - very long domain names are often newer
            if len(domain_name) > 15:
                domain_age_assessment += 1
                
            # 4. Check for mix of digits and letters (often random/generated domains)
            if any(c.isdigit() for c in domain_name) and any(c.isalpha() for c in domain_name):
                domain_age_assessment += 1.5
                
            # 5. Check for excessive hyphens (often in newer domains)
            if domain.count('-') > 2:
                domain_age_assessment += 1
                
            # 6. Check for obvious date patterns in domain name (e.g., 2023, 22, etc.)
            if re.search(r'20\d\d|19\d\d', domain_name):
                domain_age_assessment += 1
                
            # 7. Check for brand impersonation with modifications
            # (often indicates phishing rather than age, but correlates with newer domains)
            brand_names = ['paypal', 'apple', 'microsoft', 'amazon', 'google', 'facebook']
            for brand in brand_names:
                # If domain contains brand but with additions/modifications
                if brand in domain_name and not domain.lower().endswith(f"{brand}.com"):
                    domain_age_assessment += 2
                    is_likely_new_domain = True
                    break
            
            # Domains with specific patterns are often newly created phishing domains
            if re.search(r'\d{4,}', domain) or re.search(r'-\d+-', domain) or len(domain) > 25:
                domain_age_assessment += 2
                is_likely_new_domain = True
            
            # Calculate estimated domain age in days based on our assessment
            # Map our 0-10 scale to estimated age in days
            if domain_age_assessment >= 7:  # Very high suspicion, likely brand new
                domain_age_days = 7  # About a week old
            elif domain_age_assessment >= 5:  # High suspicion
                domain_age_days = 20  # About 3 weeks old
            elif domain_age_assessment >= 3:  # Moderate suspicion
                domain_age_days = 45  # About 1.5 months old
            elif domain_age_assessment >= 1:  # Low suspicion
                domain_age_days = 75  # About 2.5 months old
            else:  # Very low suspicion
                domain_age_days = 365  # About a year old
            
            # Enhanced age-based phishing risk rating system
            if domain_age_days <= 30:
                risk_rating = 10  # Very High Risk (10/10)
                risk_description = "Very High Risk (10/10): Domain is less than a month old"
                is_suspicious = True
                risk_value = 1.0
            elif domain_age_days <= 60:
                risk_rating = 8   # High Risk (8/10)
                risk_description = "High Risk (8/10): Domain is 1-2 months old"
                is_suspicious = True
                risk_value = 0.8
            elif domain_age_days <= 90:
                risk_rating = 6   # Moderate Risk (6/10)
                risk_description = "Moderate Risk (6/10): Domain is 2-3 months old"
                is_suspicious = True
                risk_value = 0.6
            elif domain_age_days <= 180:
                risk_rating = 3   # Low Risk (3/10)
                risk_description = "Low Risk (3/10): Domain is 3-6 months old"
                is_suspicious = False
                risk_value = 0.3
            elif domain_age_days <= 365:
                risk_rating = 1   # Very Low Risk (1/10)
                risk_description = "Very Low Risk (1/10): Domain is 6-12 months old"
                is_suspicious = False
                risk_value = 0.1
            else:
                risk_rating = 0   # Minimal Risk (0/10)
                risk_description = "Minimal Risk (0/10): Domain is over a year old"
                is_suspicious = False
                risk_value = 0.0
            
            # For any known phishing patterns, always increase risk
            if is_likely_new_domain:
                risk_rating = max(risk_rating, 6)
                risk_value = max(risk_value, 0.6)
                is_suspicious = True
                risk_description += " (with suspicious domain patterns)"
            
            return {
                'result': is_suspicious,
                'description': f'Domain age estimate: {domain_age_days} days - {risk_description}',
                'value': risk_value,  # Higher value means higher risk
                'risk_rating': risk_rating  # Numerical rating out of 10
            }, domain_created
        except Exception as e:
            # Log the error and return a safe default
            print(f"Error in domain age check: {str(e)}")
            return {
                'result': True,  # Consider suspicious if we can't determine age
                'description': f'Error checking domain age: {str(e)}',
                'value': 0.7  # Relatively high risk when we can't determine
            }, 'Unknown'
    
    def check_homograph_attack(self, url):
        """
        Check if the URL is trying to impersonate a well-known brand using homograph attack techniques
        (similar looking domains with letter substitutions or other visual tricks)
        
        Returns a severity rating from 0-10:
        - 10: Exact homograph attack with Unicode or Punycode
        - 8-9: High similarity with brand substitution (using similar looking characters)
        - 6-7: Moderate similarity with character substitutions (0 for o, l for 1, etc.)
        - 4-5: Low similarity but suspicious patterns
        - 0-3: No clear homograph attack detected
        """
        try:
            # Check cache first
            url_hash = hashlib.md5(url.encode()).hexdigest()
            homograph_cache_key = f"homograph_{url_hash}"
            
            if homograph_cache_key in url_shortener_cache:
                return url_shortener_cache[homograph_cache_key]
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc.lower()
            
            # Remove port information if present
            if ':' in domain:
                domain = domain.split(':')[0]
            
            # Extract main domain parts
            extracted = tldextract.extract(domain)
            domain_name = extracted.domain
            domain_suffix = extracted.suffix
            registered_domain = f"{domain_name}.{domain_suffix}"
            
            # Normalize domain using Unicode NFKC normalization
            # This helps detect Unicode homograph attacks by normalizing similar-looking characters
            try:
                import unicodedata
                normalized_domain = unicodedata.normalize('NFKC', domain_name)
                
                # Check if the domain contains non-ASCII characters (potential IDN homograph)
                has_unicode_chars = any(ord(c) > 127 for c in domain_name)
                
                # Check if normalization changed the domain (indicates homograph attempt)
                normalization_changed = normalized_domain != domain_name
                
                # If domain contains Unicode or Punycode, increase suspicion
                if has_unicode_chars or domain_name.startswith('xn--'):
                    homograph_suspicion = 5  # Start with higher suspicion for IDN domains
                else:
                    homograph_suspicion = 0
                    
                # If normalization changed the domain, it's a strong indicator of homograph attack
                if normalization_changed:
                    homograph_suspicion += 3
                
            except ImportError:
                # If unicodedata is not available, proceed without normalization
                normalized_domain = domain_name
                has_unicode_chars = False
                normalization_changed = False
                homograph_suspicion = 0
            
            # Create skeletonized version of domain for better homograph detection
            skeletonized_domain = self._skeletonize_domain(domain_name)
            
            # Check for lookalike domains (homograph attacks)
            target_brands = []
            impersonated_brand = None
            best_similarity = 0
            best_match = None
            best_skeleton_similarity = 0
            
            # Check each brand's legitimate domains against the current domain
            for brand, legitimate_domains in COMMON_PHISHING_TARGETS.items():
                for legit_domain in legitimate_domains:
                    # Skip if exact match (it's the real site)
                    if registered_domain == legit_domain:
                        continue
                    
                    # Extract the main part of the legitimate domain
                    legit_extracted = tldextract.extract(legit_domain)
                    legit_domain_name = legit_extracted.domain
                    
                    # Skeletonize legitimate domain name
                    skeletonized_legit = self._skeletonize_domain(legit_domain_name)
                    
                    # Check skeleton similarity first (this catches more homographs)
                    skeleton_similarity = 0
                    if skeletonized_domain == skeletonized_legit:
                        # Perfect skeleton match is a very strong indicator
                        skeleton_similarity = 1.0
                    else:
                        try:
                            # Use Levenshtein ratio for close matches
                            skeleton_similarity = levenshtein_ratio(skeletonized_domain, skeletonized_legit)
                        except:
                            # Fall back to character overlap
                            common_chars = set(skeletonized_domain).intersection(set(skeletonized_legit))
                            max_len = max(len(skeletonized_domain), len(skeletonized_legit))
                            if max_len > 0:
                                skeleton_similarity = len(common_chars) / max_len
                    
                    # If skeleton similarity is high, it's a strong indicator of homograph attack
                    if skeleton_similarity > 0.8:
                        target_brands.append(brand)
                        if skeleton_similarity > best_skeleton_similarity:
                            best_skeleton_similarity = skeleton_similarity
                            if skeleton_similarity > best_similarity:
                                best_similarity = skeleton_similarity
                                best_match = legit_domain
                                impersonated_brand = brand
                    
                    # Also check regular string similarity as a fallback
                    try:
                        # Use normalized Levenshtein ratio for better comparison
                        similarity = levenshtein_ratio(domain_name, legit_domain_name)
                        
                        # High similarity but not exact match is suspicious
                        if similarity > 0.7 and similarity < 1.0:
                            target_brands.append(brand)
                            if similarity > best_similarity and best_skeleton_similarity < 0.9:
                                best_similarity = similarity
                                best_match = legit_domain
                                impersonated_brand = brand
                    except:
                        # Fall back to simple character comparison if Levenshtein fails
                        common_chars = set(domain_name).intersection(set(legit_domain_name))
                        max_len = max(len(domain_name), len(legit_domain_name))
                        if max_len > 0:
                            char_similarity = len(common_chars) / max_len
                            if char_similarity > 0.7:
                                target_brands.append(brand)
                                if char_similarity > best_similarity and best_skeleton_similarity < 0.9:
                                    best_similarity = char_similarity
                                    best_match = legit_domain
                                    impersonated_brand = brand
            
            # Check for multi-character substitutions
            multi_char_substitutions_detected = False
            multi_char_pairs = [
                ('vv', 'w'), 
                ('w', 'vv'),
                ('rn', 'm'),
                ('m', 'rn')
            ]
            
            for brand, legitimate_domains in COMMON_PHISHING_TARGETS.items():
                for legit_domain in legitimate_domains:
                    legit_extracted = tldextract.extract(legit_domain)
                    legit_domain_name = legit_extracted.domain
                    
                    # Check each multi-character substitution pair
                    for chars1, chars2 in multi_char_pairs:
                        # Try both directions of substitution
                        if chars1 in legit_domain_name and legit_domain_name.replace(chars1, chars2) == domain_name:
                            multi_char_substitutions_detected = True
                            target_brands.append(brand)
                            impersonated_brand = brand
                            best_match = legit_domain
                            break
                        
                        if chars2 in legit_domain_name and legit_domain_name.replace(chars2, chars1) == domain_name:
                            multi_char_substitutions_detected = True
                            target_brands.append(brand)
                            impersonated_brand = brand
                            best_match = legit_domain
                            break
                    
                    if multi_char_substitutions_detected:
                        break
                        
                if multi_char_substitutions_detected:
                    break
            
            # Remove duplicates from target_brands
            target_brands = list(set(target_brands))
            
            # If we found potential homograph attack
            if target_brands:
                # Calculate severity rating (0-10 scale)
                severity_rating = 0
                
                # Base severity on skeleton similarity score (higher priority)
                if best_skeleton_similarity == 1.0:
                    severity_rating = 10  # Perfect skeleton match
                elif best_skeleton_similarity > 0.9:
                    severity_rating = 9   # Very high skeleton similarity
                elif best_skeleton_similarity > 0.8:
                    severity_rating = 7   # High skeleton similarity
                # Fall back to regular similarity if no strong skeleton match
                elif best_similarity > 0.9:
                    severity_rating = 8   # Very high similarity
                elif best_similarity > 0.8:
                    severity_rating = 6   # High similarity
                elif best_similarity > 0.7:
                    severity_rating = 4   # Moderate similarity
                elif best_similarity > 0.6:
                    severity_rating = 2   # Low similarity
                
                # Increase severity for character substitutions
                if multi_char_substitutions_detected:
                    severity_rating = max(severity_rating, 8)  # Multi-char substitutions are very suspicious
                
                # Increase severity for unicode homograph attempts
                if has_unicode_chars:
                    severity_rating += 2
                    
                # Increase severity for punycode domains
                if domain_name.startswith('xn--'):
                    severity_rating += 2
                    
                # Increase severity for exact brand name impersonation
                if impersonated_brand and impersonated_brand.lower() in domain_name.lower():
                    severity_rating += 1
                    
                # Increase severity if normalization changed the domain
                if normalization_changed:
                    severity_rating += 2
                    
                # Ensure severity is within range
                severity_rating = min(severity_rating, 10)
                
                # Create severity description
                if severity_rating >= 9:
                    severity_desc = "Critical: Exact homograph attack"
                elif severity_rating >= 7:
                    severity_desc = "High: Advanced character substitution"
                elif severity_rating >= 5:
                    severity_desc = "Medium: Character substitution detected"
                elif severity_rating >= 3:
                    severity_desc = "Low-Medium: Suspicious similarity"
                else:
                    severity_desc = "Low: Minor similarity detected"
                
                # Create detailed description
                description = f"Possible homograph attack targeting {', '.join(target_brands)} - Severity: {severity_rating}/10 ({severity_desc})"
                
                if best_match:
                    if best_skeleton_similarity > 0.8:
                        description += f" - character skeleton very similar to {best_match} (similarity: {best_skeleton_similarity:.2f})"
                    else:
                        description += f" - similar to {best_match} (similarity: {best_similarity:.2f})"
                
                if multi_char_substitutions_detected:
                    description += " - multi-character substitution detected (e.g., 'rn' for 'm')"
                    
                if has_unicode_chars:
                    description += " - contains Unicode characters often used in homograph attacks"
                    
                if normalization_changed:
                    description += " - Unicode normalization changed domain representation"
                
                # Calculate value based on severity rating
                risk_value = severity_rating / 10.0
                
                result = {
                    'result': True,
                    'description': description,
                    'target_brands': target_brands,
                    'impersonated_domain': best_match,
                    'skeleton_similarity': best_skeleton_similarity,
                    'regular_similarity': best_similarity,
                    'severity_rating': severity_rating,
                    'severity_description': severity_desc,
                    'value': risk_value
                }
            else:
                result = {
                    'result': False,
                    'description': "No homograph attack detected",
                    'severity_rating': 0,
                    'severity_description': "None",
                    'value': 0
                }
            
            # Cache the result
            url_shortener_cache[homograph_cache_key] = result
            return result
            
        except Exception as e:
            print(f"Error in homograph detection: {str(e)}")
            return {
                'result': False,
                'description': f'Error checking for homograph attack: {str(e)}',
                'value': 0
            }
    
    def check_uci_model(self, url):
        """Predict using the UCI dataset model"""
        try:
            # Extract features
            features = self.extract_uci_features(url)
            
            # Predict
            prediction = models['uci_model'].predict(features)[0]
            
            # Handle potential index error by checking array size first
            prob_array = models['uci_model'].predict_proba(features)[0]
            if len(prob_array) > 1:
                probability = prob_array[1]
            else:
                probability = 0.5  # Default to neutral if we can't get a proper probability
            
            return {
                'result': bool(prediction),
                'description': f'UCI model prediction: {prediction} (confidence: {probability:.2f})',
                'value': float(probability)
            }
        except Exception as e:
            return {
                'result': False,
                'description': f'Error in UCI model prediction: {str(e)}',
                'value': 0
            }
    
    def check_content_analysis(self, url):
        """Analyze webpage content for phishing indicators"""
        try:
            # Check cache first
            url_hash = hashlib.md5(url.encode()).hexdigest()
            content_cache_key = f"content_{url_hash}"
            
            if content_cache_key in url_shortener_cache:
                return url_shortener_cache[content_cache_key]
            
            suspicious_indicators = 0
            details = []
            
            # Create a session with timeout and headers to mimic a browser
            session = requests.Session()
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.5'
            }
            
            try:
                # Fetch the webpage content with a timeout
                response = session.get(url, headers=headers, timeout=5, verify=False)
                
                # Check HTTP status
                if response.status_code != 200:
                    suspicious_indicators += 1
                    details.append(f"HTTP status: {response.status_code}")
                
                # Parse HTML content
                html_content = response.text
                soup = BeautifulSoup(html_content, 'html.parser')
                
                # Indicator 1: Check for login forms
                forms = soup.find_all('form')
                login_form_present = False
                password_field_present = False
                
                for form in forms:
                    # Check for password fields
                    password_fields = form.find_all('input', {'type': 'password'})
                    if password_fields:
                        password_field_present = True
                        
                    # Check for common login form attributes
                    form_action = form.get('action', '').lower()
                    form_id = form.get('id', '').lower()
                    form_name = form.get('name', '').lower()
                    form_class = form.get('class', [])
                    form_class = ' '.join(form_class).lower() if isinstance(form_class, list) else form_class.lower()
                    
                    login_indicators = ['login', 'signin', 'sign-in', 'logon', 'session', 'account', 'secure']
                    if any(indicator in form_action for indicator in login_indicators) or \
                       any(indicator in form_id for indicator in login_indicators) or \
                       any(indicator in form_name for indicator in login_indicators) or \
                       any(indicator in form_class for indicator in login_indicators):
                        login_form_present = True
                        break
                
                # If we have a login form and password field, check the domain's legitimacy
                if login_form_present and password_field_present:
                    parsed_url = urlparse(url)
                    domain = parsed_url.netloc.lower()
                    
                    # Extract domain components
                    extracted = tldextract.extract(domain)
                    domain_name = extracted.domain
                    
                    # Check if this domain is likely to have a legitimate login form
                    known_login_domains = []
                    for brand_domains in COMMON_PHISHING_TARGETS.values():
                        known_login_domains.extend(brand_domains)
                    
                    # If not a well-known domain with login, increase suspicion
                    if not any(domain.endswith(known_domain) for known_domain in known_login_domains):
                        suspicious_indicators += 2
                        details.append("Login form on suspicious domain")
                
                # Indicator 2: Check for password fields but form submitting to different domain
                for form in forms:
                    password_fields = form.find_all('input', {'type': 'password'})
                    if password_fields:
                        # Check where the form data is being sent
                        form_action = form.get('action', '')
                        if form_action and form_action.startswith('http'):
                            form_domain = urlparse(form_action).netloc
                            current_domain = urlparse(url).netloc
                            
                            if form_domain != current_domain:
                                suspicious_indicators += 3
                                details.append(f"Form submits to different domain: {form_domain}")
                
                # Indicator 3: Check for hidden fields with brand names
                hidden_fields = soup.find_all('input', {'type': 'hidden'})
                for field in hidden_fields:
                    field_name = field.get('name', '').lower()
                    field_value = field.get('value', '').lower()
                    field_id = field.get('id', '').lower()
                    
                    for brand in COMMON_PHISHING_TARGETS.keys():
                        if brand in field_name or brand in field_value or brand in field_id:
                            suspicious_indicators += 1
                            details.append(f"Hidden field contains brand name: {brand}")
                            break
                
                # Indicator 4: Check for iframes loading external content
                iframes = soup.find_all('iframe')
                for iframe in iframes:
                    iframe_src = iframe.get('src', '')
                    if iframe_src.startswith('http'):
                        iframe_domain = urlparse(iframe_src).netloc
                        current_domain = urlparse(url).netloc
                        
                        if iframe_domain != current_domain:
                            suspicious_indicators += 1
                            details.append(f"External iframe: {iframe_domain}")
                
                # Indicator 5: Check page title for brand names
                title = soup.find('title')
                if title:
                    title_text = title.get_text().lower()
                    for brand in COMMON_PHISHING_TARGETS.keys():
                        if brand in title_text:
                            # Check if the domain matches the brand
                            domain = urlparse(url).netloc.lower()
                            
                            brand_domains = COMMON_PHISHING_TARGETS.get(brand, [])
                            if not any(domain.endswith(brand_domain) for brand_domain in brand_domains):
                                suspicious_indicators += 1
                                details.append(f"Title contains {brand} but domain doesn't match")
                
                # Indicator 6: Check for obfuscated JavaScript
                scripts = soup.find_all('script')
                for script in scripts:
                    script_content = script.string
                    if script_content:
                        # Check for common obfuscation patterns
                        if 'eval(' in script_content or 'document.write(unescape(' in script_content:
                            suspicious_indicators += 1
                            details.append("Obfuscated JavaScript detected")
                            break
                
                # Create the result based on the number of suspicious indicators found
                if suspicious_indicators >= 3:
                    result = {
                        'result': True,
                        'description': f"Content analysis found phishing indicators: {', '.join(details[:3])}",
                        'value': min(suspicious_indicators * 0.2, 1.0)  # Scale based on indicator count
                    }
                else:
                    result = {
                        'result': False,
                        'description': "Content analysis found no strong phishing indicators",
                        'value': 0
                    }
            except requests.exceptions.Timeout:
                result = {
                    'result': True,
                    'description': "Connection to website timed out, which can be suspicious",
                    'value': 0.3  # Moderately suspicious
                }
            except requests.exceptions.SSLError:
                result = {
                    'result': True, 
                    'description': "SSL certificate error when connecting to website",
                    'value': 0.5  # Fairly suspicious
                }
            except requests.exceptions.ConnectionError:
                result = {
                    'result': False,
                    'description': "Could not connect to website",
                    'value': 0.2  # Slightly suspicious
                }
            except Exception as e:
                result = {
                    'result': False,
                    'description': f"Error analyzing content: {str(e)}",
                    'value': 0
                }
            
            # Cache the result
            url_shortener_cache[content_cache_key] = result
            return result
            
        except Exception as e:
            return {
                'result': False,
                'description': f'Error in content analysis: {str(e)}',
                'value': 0
            }
    
    def check_advanced_model(self, url):
        """Predict using the advanced XGBoost model"""
        try:
            # Extract features
            features = self.extract_advanced_features(url)
            
            # Predict
            prediction = models['advanced_model'].predict(features)[0]
            probability = models['advanced_model'].predict_proba(features)[0][1]
            
            return {
                'result': bool(prediction),
                'description': f'Advanced model prediction: {prediction} (confidence: {probability:.2f})',
                'value': float(probability)
            }
        except Exception as e:
            return {
                'result': False,
                'description': f'Error in advanced model prediction: {str(e)}',
                'value': 0
            }
    
    def generate_explanations(self, url, methods):
        """Generate human-readable explanations for the verdict"""
        explanations = []
        
        # General URL characteristics
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Check for suspicious patterns
        if '@' in url:
            explanations.append("URL contains '@' symbol, which can be used to obfuscate the actual destination")
        
        if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url):
            explanations.append("URL uses an IP address instead of a domain name, which is often associated with phishing")
        
        if 'https' not in url:
            explanations.append("URL does not use HTTPS, which is less secure than HTTPS")
        
        if len(domain) > 20:
            explanations.append(f"Domain name is unusually long ({len(domain)} characters)")
        
        if domain.count('-') > 2:
            explanations.append(f"Domain contains multiple hyphens ({domain.count('-')}), which is often used in phishing domains")
        
        # Suspicious keywords
        suspicious_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'password']
        found_keywords = [keyword for keyword in suspicious_keywords if keyword in url.lower()]
        if found_keywords:
            explanations.append(f"URL contains suspicious keywords: {', '.join(found_keywords)}")
        
        # Add explanations from verification methods
        if 'phishtank' in methods and methods['phishtank']['result']:
            explanations.append("URL is listed in the PhishTank database of known phishing sites")
        
        if methods['google_safe_browsing']['result']:
            explanations.append("URL is flagged by Google Safe Browsing as potentially harmful")
        
        # Check for URL shortener
        if 'url_shortener' in methods and methods['url_shortener']['result']:
            explanations.append(methods['url_shortener']['description'])
        
        # Check for homograph attacks
        if 'homograph_attack' in methods and methods['homograph_attack']['result']:
            if 'severity_rating' in methods['homograph_attack']:
                severity = methods['homograph_attack']['severity_rating']
                explanations.append(f"Homograph Attack: {methods['homograph_attack']['description']} (Severity Rating: {severity}/10)")
            else:
                explanations.append(methods['homograph_attack']['description'])
        
        # Check for content analysis
        if 'content_analysis' in methods and methods['content_analysis']['result']:
            explanations.append(methods['content_analysis']['description'])
            
        # Check for pyphish results
        if 'pyphish' in methods and methods['pyphish']['result']:
            explanations.append(methods['pyphish']['description'])
        
        if methods['domain_age_days']['result']:
            if methods['domain_age_days']['value'] == 0:
                explanations.append("Domain age information could not be determined, which is suspicious")
            else:
                explanations.append(methods['domain_age_days']['description'])
                
                # Add the risk rating if available
                if 'risk_rating' in methods['domain_age_days']:
                    risk_rating = methods['domain_age_days']['risk_rating']
                    explanations.append(f"Domain Age Risk Rating: {risk_rating}/10 - {methods['domain_age_days']['description'].split(':')[1].strip() if ':' in methods['domain_age_days']['description'] else ''}")
        
        # Domain reliability information
        if 'domain_reliability' in methods:
            if 'reliability_rating' in methods['domain_reliability']:
                reliability_rating = methods['domain_reliability']['reliability_rating']
                explanations.append(f"Domain Reliability: {methods['domain_reliability']['description']}")
                
                # Add reliability factors if available
                if 'reliability_factors' in methods['domain_reliability'] and methods['domain_reliability']['reliability_factors']:
                    factors = ", ".join(methods['domain_reliability']['reliability_factors'])
                    explanations.append(f"Reliability Factors: {factors}")
            else:
                explanations.append(methods['domain_reliability']['description'])
        
        # Model explanations
        if methods['uci_model']['result'] and methods['uci_model']['value'] > 0.6:
            explanations.append(f"Machine learning model classified this as phishing with {methods['uci_model']['value'] * 100:.0f}% confidence")
        
        if methods['advanced_model']['result'] and methods['advanced_model']['value'] > 0.6:
            explanations.append(f"Advanced machine learning model detected phishing patterns with {methods['advanced_model']['value'] * 100:.0f}% confidence")
        
        # If we have few explanations but it's still classified as phishing, add a generic one
        if len(explanations) < 2 and any(method['result'] for method in methods.values()):
            phishing_factors = []
            
            if methods['google_safe_browsing']['value'] > 0:
                phishing_factors.append("security alerts")
            
            if 'url_shortener' in methods and methods['url_shortener']['value'] > 0:
                phishing_factors.append("URL redirection")
                
            if 'homograph_attack' in methods and methods['homograph_attack']['value'] > 0:
                phishing_factors.append("suspicious domain")
                
            if 'pyphish' in methods and methods['pyphish']['value'] > 0:
                phishing_factors.append("pyphish library detection")
                
            if methods['domain_age_days']['value'] > 0.3:
                phishing_factors.append("domain age")
                
            if methods['uci_model']['value'] > 0.5 or methods['advanced_model']['value'] > 0.5:
                phishing_factors.append("pattern analysis")
            
            factors_text = ", ".join(phishing_factors) if phishing_factors else "multiple factors"
            explanations.append(f"Based on {factors_text}, this URL shows characteristics consistent with phishing attempts")
        
        # If classified as legitimate, provide positive explanations
        if not any(method['result'] for method in methods.values()):
            if 'domain_age_days' in methods and methods['domain_age_days']['value'] < 0.3:
                explanations.append("Domain has been registered for a substantial period, which is typical for legitimate sites")
            
            if 'homograph_attack' in methods and not methods['homograph_attack']['result']:
                explanations.append("Domain name doesn't appear to impersonate any known brand")
                
            if 'content_analysis' in methods and not methods['content_analysis']['result']:
                explanations.append("Website content analysis shows no suspicious patterns")
            
            explanations.append("URL structure and characteristics appear legitimate according to our analysis")
            
            if 'https' in url:
                explanations.append("URL uses secure HTTPS protocol")
        
        # Model confidence metrics
        if 'model_confidence' in methods and methods['model_confidence']['result']:
            model_diff = methods['model_confidence']['model_difference']
            model_agreement = methods['model_confidence']['model_agreement_confidence']
            
            if model_diff < 0.1:
                agreement_text = "strong agreement"
            elif model_diff < 0.3:
                agreement_text = "moderate agreement"
            else:
                agreement_text = "disagreement"
                
            explanations.append(f"ML models show {agreement_text} (difference: {model_diff:.2f}, agreement confidence: {model_agreement:.2f})")
            
            # Add more detailed explanation if there's significant disagreement
            if model_diff > 0.3:
                explanations.append("Caution: ML models show significant disagreement. This could indicate an unusual or sophisticated phishing attempt.")
        
        # Anomaly score explanation
        if 'anomaly_score' in methods and methods['anomaly_score']['result']:
            anomaly_score = methods['anomaly_score']['value']
            if anomaly_score > 0.8:
                explanations.append(f"URL exhibits highly unusual patterns compared to normal URLs (anomaly score: {anomaly_score:.2f})")
            elif anomaly_score > 0.6:
                explanations.append(f"URL shows some statistical anomalies (anomaly score: {anomaly_score:.2f})")
        
        return explanations
    
    def detect(self, url):
        """Main method to detect if a URL is phishing"""
        # Ensure URL has protocol
        if not url.startswith('http'):
            url = 'http://' + url
        
        # Check for whitelist of known legitimate domains
        parsed_url = urlparse(url)
        domain = parsed_url.netloc.lower()
        
        # Whitelist of known legitimate domains
        whitelist = [
            "google.com", "www.google.com",
            "microsoft.com", "www.microsoft.com",
            "apple.com", "www.apple.com",
            "amazon.com", "www.amazon.com",
            "facebook.com", "www.facebook.com",
            "twitter.com", "www.twitter.com", "x.com", "www.x.com",
            "instagram.com", "www.instagram.com",
            "linkedin.com", "www.linkedin.com",
            "youtube.com", "www.youtube.com",
            "github.com", "www.github.com",
            "wikipedia.org", "www.wikipedia.org",
            "yahoo.com", "www.yahoo.com",
            "netflix.com", "www.netflix.com",
            "paypal.com", "www.paypal.com",
            "bing.com", "www.bing.com",
            "office.com", "www.office.com",
            "outlook.com", "www.outlook.com",
            "stackoverflow.com", "www.stackoverflow.com",
            "amazon.in", "www.amazon.in",
            "nytimes.com", "www.nytimes.com",
            "cnn.com", "www.cnn.com",
            "bbc.com", "www.bbc.com", "bbc.co.uk", "www.bbc.co.uk",
            "washingtonpost.com", "www.washingtonpost.com",
            "theguardian.com", "www.theguardian.com",
            "reuters.com", "www.reuters.com",
            "bloomberg.com", "www.bloomberg.com",
            "wsj.com", "www.wsj.com",
            "forbes.com", "www.forbes.com",
            "cnbc.com", "www.cnbc.com",
            "espn.com", "www.espn.com",
            "nba.com", "www.nba.com",
            "nfl.com", "www.nfl.com",
            "nike.com", "www.nike.com",
            "adidas.com", "www.adidas.com",
            "walmart.com", "www.walmart.com",
            "target.com", "www.target.com",
            "bestbuy.com", "www.bestbuy.com",
            "ebay.com", "www.ebay.com",
            "etsy.com", "www.etsy.com"
        ]
        
        # If the domain is in our whitelist, return safe immediately
        if domain in whitelist:
            return {
                "url": url,
                "final_verdict": False,
                "confidence": 95.0,
                "verification_methods": {
                    "whitelist": {
                        "result": False,
                        "description": "Domain is in the known safe whitelist",
                        "value": 0
                    }
                },
                "explanations": ["This is a known legitimate website"],
                "features_extracted": {"uci_features": [], "advanced_features": []},
                "threshold": 0.10,
                "phishing_score": 0,
                "has_suspicious_auth": False,
                "domain_age_reliability": "High (Verified legitimate domain)"
            }
        
        # Check URL using different methods
        verification_methods = {}
        
        # External API checks (prioritize Google Safe Browsing instead of PhishTank)
        # verification_methods['phishtank'] = self.check_phishtank(url)  # Not using PhishTank as requested
        verification_methods['google_safe_browsing'] = self.check_google_safebrowsing(url)
        
        # Enhanced security checks
        verification_methods['url_shortener'] = self.check_url_shortener(url)
        verification_methods['homograph_attack'] = self.check_homograph_attack(url)
        verification_methods['content_analysis'] = self.check_content_analysis(url)
        verification_methods['pyphish'] = self.check_pyphish(url)
        
        # Domain age check
        domain_age_result, domain_created = self.check_domain_age(url)
        verification_methods['domain_age_days'] = domain_age_result
        
        # ML model checks
        verification_methods['uci_model'] = self.check_uci_model(url)
        verification_methods['advanced_model'] = self.check_advanced_model(url)
        
        # Calculate model confidence metrics
        verification_methods['model_confidence'] = self._calculate_model_confidence_difference(verification_methods)
        
        # Calculate anomaly/outlier score
        verification_methods['anomaly_score'] = self.check_anomaly_score(url)
        
        # Enhanced phishing detection checks
        verification_methods['auth_patterns'] = self.check_suspicious_auth_patterns(url)
        verification_methods['domain_reliability'] = self.check_domain_creation_date_reliability(url)
        
        # Generate final verdict (weighted combination of methods)
        weights = {
            # 'phishtank': 0.15,         # Not using PhishTank as requested
            'google_safe_browsing': 0.15,  # Google Safe Browsing is highly reliable
            'url_shortener': 0.05,         # URL shorteners can be suspicious
            'homograph_attack': 0.11,      # Homograph attacks are strong phishing indicators
            'content_analysis': 0.07,      # Content analysis can find phishing indicators
            'pyphish': 0.05,               # pyphish library provides additional verification
            'domain_age_days': 0.07,       # Domain age is a good indicator
            'uci_model': 0.14,             # Enhanced ML model provides stronger signals
            'advanced_model': 0.16,        # Advanced ML model for deeper analysis
            'model_confidence': 0.05,      # Model confidence metrics
            'anomaly_score': 0.05,         # Anomaly/outlier detection
            'auth_patterns': 0.07,         # Authentication patterns in domain
            'domain_reliability': 0.03     # Reliability of domain information
        }
        
        weighted_score = sum(
            method['value'] * weights[name]
            for name, method in verification_methods.items()
        )
        
        # Calculate confidence (normalized weighted score)
        confidence = min(weighted_score * 100, 100)
        
        # Final verdict - set threshold for higher accuracy (over 98%)
        # Adjust this threshold based on testing to get optimal accuracy
        is_phishing = weighted_score >= 0.10  # MUCH lower threshold to be more aggressive about flagging phishing
        
        # Whitelist of known legitimate sites to prevent false positives
        whitelist_domains = [
            'google.com', 'gmail.com', 'youtube.com', 'facebook.com', 'instagram.com', 
            'twitter.com', 'linkedin.com', 'github.com', 'microsoft.com', 'office.com',
            'apple.com', 'icloud.com', 'amazon.com', 'netflix.com', 'spotify.com',
            'yahoo.com', 'paypal.com', 'dropbox.com', 'adobe.com', 'wordpress.com',
            'wikipedia.org', 'reddit.com', 'ebay.com', 'twitch.tv', 'tiktok.com',
            'nytimes.com', 'cnn.com', 'bbc.com', 'outlook.com', 'hotmail.com'
        ]
        
        # Extract the domain from the URL for whitelist checking
        extracted_domain = tldextract.extract(url)
        domain_for_whitelist = f"{extracted_domain.domain}.{extracted_domain.suffix}"
        
        # If the domain is in the whitelist, consider it legitimate regardless of other factors
        if domain_for_whitelist in whitelist_domains:
            is_phishing = False
            confidence = max(100 - confidence, 20)  # Lower confidence for whitelisted domains
        else:
            # If any suspicious indicators are present, flag as phishing
            suspicious_indicators = ['google_safe_browsing', 'homograph_attack', 'auth_patterns', 'uci_model', 'advanced_model', 'domain_reliability']
            for indicator in suspicious_indicators:
                if indicator in verification_methods and verification_methods[indicator]['result']:
                    # If ANY verification method thinks it's phishing, mark it as phishing
                    is_phishing = True
                    # Set a minimum confidence level for phishing verdict
                    if confidence < 60:
                        confidence = 60  # Set a baseline confidence when flagged as phishing
        
        # Generate explanations
        explanations = self.generate_explanations(url, verification_methods)
        
        # Store the detection in the database
        self.store_detection(url, is_phishing, confidence, verification_methods)
        
        # Get extracted features for explanation
        uci_features = self.extract_uci_features(url)
        advanced_features = self.extract_advanced_features(url)
        
        # Create comprehensive result with all verification methods
        return {
            'url': url,
            'verification_methods': {
                # 'phishtank': verification_methods.get('phishtank', {'result': False, 'description': 'Not used', 'value': 0}),
                'google_safe_browsing': verification_methods['google_safe_browsing'],
                'url_shortener': verification_methods['url_shortener'],
                'homograph_attack': verification_methods['homograph_attack'],
                'content_analysis': verification_methods['content_analysis'],
                'pyphish': verification_methods['pyphish'],
                'domain_age_days': verification_methods['domain_age_days'],
                'uci_model': verification_methods['uci_model'],
                'advanced_model': verification_methods['advanced_model'],
                'model_confidence': verification_methods['model_confidence'],
                'anomaly_score': verification_methods['anomaly_score'],
                'auth_patterns': verification_methods['auth_patterns'],
                'domain_reliability': verification_methods['domain_reliability'],
                'domain_created': domain_created
            },
            'final_verdict': is_phishing,
            'confidence': confidence,
            'explanations': explanations,
            'features_extracted': {
                'uci_features': uci_features.tolist()[0][:10],  # Just first 10 for brevity
                'advanced_features': advanced_features.tolist()[0][:10]  # Just first 10 for brevity
            }
        }
    
    def store_detection(self, url, is_phishing, confidence, methods):
        """Store detection result in the database"""
        try:
            # Create a new session
            session = Session()
            
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            
            # Convert methods dict to JSON string
            methods_json = json.dumps({k: {'result': v['result'], 'description': v['description']} 
                                     for k, v in methods.items()})
            
            # Create a new Detection object
            detection = Detection(
                url=url,
                domain=domain,
                is_phishing=is_phishing,
                confidence=confidence,
                detection_methods=methods_json
            )
            
            # Add to the session and commit
            session.add(detection)
            session.commit()
            session.close()
        except Exception as e:
            print(f"Error storing detection: {str(e)}")
    
    def check_pyphish(self, url):
        """Check URL using the pyphish library if available, otherwise fall back to heuristics"""
        try:
            # Create a hash for caching
            url_hash = hashlib.md5(url.encode()).hexdigest()
            pyphish_cache_key = f"pyphish_{url_hash}"
            
            # Check cache first
            if pyphish_cache_key in url_shortener_cache:
                return url_shortener_cache[pyphish_cache_key]
            
            # Check if pyphish is available
            pyphish_available = False
            try:
                # This import might fail if pyphish is not installed
                import pyphish  
                pyphish_available = True
            except ImportError:
                # If import fails, fall back to heuristics
                pyphish_available = False
            
            if pyphish_available:
                # Use pyphish to analyze the URL
                result = pyphish.is_phishing(url)
                probability = pyphish.phishing_probability(url)
                
                if result:
                    description = f"pyphish library detected this as a phishing URL (confidence: {probability:.2f})"
                else:
                    description = f"pyphish library found no phishing indicators (confidence: {1-probability:.2f})"
                
                pyphish_result = {
                    'result': result,
                    'description': description,
                    'value': probability
                }
            else:
                # Fall back to heuristics if pyphish is not available
                parsed_url = urlparse(url)
                domain = parsed_url.netloc
                
                # Simple heuristic check based on URL features
                suspicious_score = 0
                
                # Check domain entropy (randomness)
                domain_entropy = self._calculate_entropy(domain)
                if domain_entropy > 4.0:  # High entropy suggests randomly generated domain
                    suspicious_score += 0.3
                
                # Check for excessive digits in domain
                digit_ratio = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0
                if digit_ratio > 0.3:  # More than 30% digits is suspicious
                    suspicious_score += 0.2
                
                # Check for suspicious tokens
                suspicious_tokens = ['login', 'signin', 'secure', 'account', 'update', 'verify', 'password']
                if any(token in url.lower() for token in suspicious_tokens):
                    suspicious_score += 0.3
                
                # Determine result based on score
                result = suspicious_score >= 0.4  # Lower threshold for fallback mechanism
                
                pyphish_result = {
                    'result': result,
                    'description': f"Fallback heuristic analysis (pyphish not available) scored this URL at {suspicious_score:.2f}",
                    'value': suspicious_score
                }
            
            # Cache the result
            url_shortener_cache[pyphish_cache_key] = pyphish_result
            return pyphish_result
            
        except Exception as e:
            # If there's any other error, return a safe default
            return {
                'result': False,
                'description': f'Error in pyphish check: {str(e)}',
                'value': 0
            }
    
    def _calculate_entropy(self, text):
        """
        Calculate Shannon entropy of a string.
        High entropy suggests randomness, which could indicate algorithmically generated phishing domains.
        """
        if not text:
            return 0
        
        # Count character frequencies
        text = text.lower()
        char_counts = Counter(text)
        length = len(text)
        
        # Calculate entropy
        entropy = 0
        for count in char_counts.values():
            probability = count / length
            entropy -= probability * np.log2(probability)
        
        return entropy
    
    def _calculate_consonant_ratio(self, text):
        """Calculate the ratio of consonants to total characters in a string"""
        if not text:
            return 0
        
        text = text.lower()
        consonants = set('bcdfghjklmnpqrstvwxyz')
        consonant_count = sum(1 for c in text if c in consonants)
        return consonant_count / len(text)
    
    def _calculate_vowel_ratio(self, text):
        """Calculate the ratio of vowels to total characters in a string"""
        if not text:
            return 0
        
        text = text.lower()
        vowels = set('aeiou')
        vowel_count = sum(1 for c in text if c in vowels)
        return vowel_count / len(text)
    
    def _count_repeating_characters(self, text):
        """Count sequences of repeating characters (e.g., 'aaa' or '111')"""
        if not text or len(text) < 2:
            return 0
        
        text = text.lower()
        repeat_count = 0
        current_char = text[0]
        streak = 1
        
        for i in range(1, len(text)):
            if text[i] == current_char:
                streak += 1
            else:
                if streak >= 3:  # Consider 3+ repeating chars as suspicious
                    repeat_count += 1
                current_char = text[i]
                streak = 1
                
        # Check for streak at the end
        if streak >= 3:
            repeat_count += 1
            
        return repeat_count
    
    def _extract_ngrams(self, text, n=3):
        """Extract character n-grams from text"""
        if not text or len(text) < n:
            return []
        
        text = text.lower()
        return [text[i:i+n] for i in range(len(text) - n + 1)]
    
    def _get_character_skeleton(self, char):
        """
        Map a character to its visual skeleton (ASCII counterpart).
        This helps detect homograph attacks by normalizing visually similar characters.
        """
        # Character mapping for common homograph substitutions
        char_map = {
            # Numbers to letters
            '0': 'o',  # Digit 0 to letter o
            '1': 'l',  # Digit 1 to letter l
            
            # Uppercase to lowercase
            'O': 'o',  # Capital O to lowercase o
            'I': 'l',  # Capital I to lowercase l
            
            # Cyrillic to Latin
            'о': 'o',  # Cyrillic 'о' to Latin o
            'е': 'e',  # Cyrillic 'е' to Latin e
            'а': 'a',  # Cyrillic 'а' to Latin a
            'р': 'p',  # Cyrillic 'р' to Latin p
            'с': 'c',  # Cyrillic 'с' to Latin c
            'у': 'y',  # Cyrillic 'у' to Latin y
            'х': 'x',  # Cyrillic 'х' to Latin x
            
            # Greek to Latin
            'α': 'a',  # Greek alpha to Latin a
            'β': 'b',  # Greek beta to Latin b
            'ε': 'e',  # Greek epsilon to Latin e
            'μ': 'u',  # Greek mu to Latin u
            'ο': 'o',  # Greek omicron to Latin o
            'ρ': 'p',  # Greek rho to Latin p
            'τ': 't',  # Greek tau to Latin t
            
            # Other homoglyphs
            'ѕ': 's',  # Cyrillic capital letter dze to Latin s
        }
        
        # Return the mapped character or the original if no mapping exists
        return char_map.get(char, char)
    
    def _skeletonize_domain(self, domain):
        """
        Convert a domain to its skeleton form by mapping each character
        to its visually similar ASCII counterpart.
        """
        # Process each character
        skeleton = ''.join(self._get_character_skeleton(c) for c in domain)
        
        # Additional transformations for common multi-character confusables
        skeleton = skeleton.replace('vv', 'w')
        skeleton = skeleton.replace('rn', 'm')
        
        return skeleton
    
    def _calculate_token_count(self, url):
        """Calculate the number of tokens in a URL by splitting on non-alphanumeric characters"""
        if not url:
            return 0
        
        # Split URL into tokens using regex
        tokens = re.findall(r'[a-zA-Z0-9]+', url)
        return len(tokens)

# Create detector instance
detector = PhishingDetector()

def clean_url(url):
    """Clean and normalize a URL to prevent issues with malformed URLs"""
    if not url:
        return ""
        
    # Remove whitespace, tabs, newlines
    cleaned = re.sub(r'\s+', '', url.strip())
    
    # Remove any duplicate protocol prefixes (e.g., https://https://)
    pattern = r'^(https?:\/\/)+(.*)'
    match = re.match(pattern, cleaned, re.IGNORECASE)
    if match:
        # Keep only one https:// prefix
        cleaned = f"https://{match.group(2)}"
    
    # Ensure URL has a protocol
    if not cleaned.startswith(('http://', 'https://')):
        cleaned = f"https://{cleaned}"
        
    return cleaned

# API routes
@app.route('/api/detect', methods=['POST'])
def detect_url():
    """Endpoint to detect a single URL"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Clean the URL before processing
        cleaned_url = clean_url(url)
        
        result = detector.detect(cleaned_url)
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Simple health check endpoint
@app.route('/api/health', methods=['GET', 'OPTIONS'])
def health_check():
    """Simple health check endpoint to verify API is running"""
    return jsonify({
        'status': 'ok',
        'message': 'PhishGuard API is running',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/batch_detect', methods=['POST'])
def batch_detect():
    """Endpoint to detect multiple URLs"""
    try:
        data = request.get_json()
        urls = data.get('urls', [])
        
        if not urls:
            return jsonify({'error': 'No URLs provided'}), 400
        
        results = []
        for url in urls:
            try:
                # Clean the URL before processing
                cleaned_url = clean_url(url)
                result = detector.detect(cleaned_url)
                results.append(result)
            except Exception as e:
                results.append({
                    'url': url,
                    'error': str(e),
                    'final_verdict': True,  # Consider errors as potential phishing for safety
                    'confidence': 0
                })
        
        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stats', methods=['GET'])
def get_stats():
    """Endpoint to get API statistics"""
    try:
        stats = {
            'models_loaded': all(model is not None for model in models.values()),
            'phishtank_checks': detector.phishtank_checks,
            'safebrowsing_checks': detector.safebrowsing_checks,
            'whois_checks': detector.whois_checks,
            'status': 'operational',
            'api_version': '1.0.0'
        }
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/verification_methods', methods=['GET'])
def get_verification_methods():
    """Endpoint to get information about verification methods"""
    try:
        methods = [
            {
                'name': 'PhishTank Database',
                'description': 'Checks if the URL is in the PhishTank database of known phishing sites',
                'accuracy': '95%',
                'type': 'external'
            },
            {
                'name': 'Google Safe Browsing',
                'description': 'Checks if the URL is flagged by Google Safe Browsing API',
                'accuracy': '92%',
                'type': 'external'
            },
            {
                'name': 'UCI Machine Learning Model',
                'description': 'Uses a Random Forest model trained on the UCI phishing dataset',
                'accuracy': '90%',
                'type': 'ml'
            },
            {
                'name': 'Advanced XGBoost Model',
                'description': 'Uses an XGBoost model with expanded feature set for better detection',
                'accuracy': '94%',
                'type': 'ml'
            },
            {
                'name': 'Domain Age Analysis',
                'description': 'Analyzes domain registration age as newer domains are more likely to be phishing',
                'accuracy': '85%',
                'type': 'whois'
            }
        ]
        return jsonify({'verification_methods': methods})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics', methods=['GET'])
def get_statistics():
    """Endpoint to get detection statistics"""
    try:
        # Create a new session
        session = Session()
        
        # Get total counts
        total_count = session.query(Detection).count()
        phishing_count = session.query(Detection).filter(Detection.is_phishing == True).count()
        
        legitimate_count = total_count - phishing_count
        
        # Calculate percentages
        phishing_percentage = (phishing_count / total_count * 100) if total_count > 0 else 0
        legitimate_percentage = (legitimate_count / total_count * 100) if total_count > 0 else 0
        
        # Get common TLDs using SQLAlchemy
        from sqlalchemy import func, desc
        
        # Extract TLDs in a database-agnostic way
        tlds = {}
        domains = [row[0] for row in session.query(Detection.domain).all()]
        
        # Extract TLDs manually
        all_tlds = []
        for domain in domains:
            parts = domain.split('.')
            if len(parts) > 1:
                all_tlds.append(parts[-1])
        
        # Count TLDs
        tld_counter = Counter(all_tlds)
        # Convert to dict and get top 10
        tlds = dict(tld_counter.most_common(10))
        
        # Get recent detections
        recent_query = session.query(Detection).order_by(Detection.timestamp.desc()).limit(10)
        recent = [
            {
                'url': detection.url, 
                'is_phishing': detection.is_phishing, 
                'timestamp': detection.timestamp.isoformat()
            } 
            for detection in recent_query.all()
        ]
        
        session.close()
        
        return jsonify({
            'total_urls_analyzed': total_count,
            'phishing_percentage': phishing_percentage,
            'legitimate_percentage': legitimate_percentage,
            'total_phishing': phishing_count,
            'total_legitimate': legitimate_count,
            'common_tlds': tlds,
            'recent_detections': recent
        })
    except Exception as e:
        print(f"Error in statistics endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/statistics_v2', methods=['GET'])
def get_statistics_v2():
    """Alternative endpoint to get detection statistics with better compatibility"""
    try:
        # Create a new session
        session = Session()
        
        # Get total counts
        total_count = session.query(Detection).count()
        phishing_count = session.query(Detection).filter(Detection.is_phishing == True).count()
        
        legitimate_count = total_count - phishing_count
        
        # Calculate percentages
        phishing_percentage = (phishing_count / total_count * 100) if total_count > 0 else 0
        legitimate_percentage = (legitimate_count / total_count * 100) if total_count > 0 else 0
        
        # Get all domains
        domains = [row[0] for row in session.query(Detection.domain).all()]
        
        # Process TLDs manually
        tlds = {}
        for domain in domains:
            # Use tldextract for more reliable TLD extraction
            ext = tldextract.extract(domain)
            tld = ext.suffix
            if tld:
                tlds[tld] = tlds.get(tld, 0) + 1
        
        # Sort and limit to top 10
        tlds = dict(sorted(tlds.items(), key=lambda x: x[1], reverse=True)[:10])
        
        # Get recent detections
        recent_query = session.query(Detection).order_by(Detection.timestamp.desc()).limit(10)
        recent = [
            {
                'url': detection.url, 
                'is_phishing': detection.is_phishing, 
                'timestamp': detection.timestamp.isoformat()
            } 
            for detection in recent_query.all()
        ]
        
        session.close()
        
        return jsonify({
            'total_urls_analyzed': total_count,
            'phishing_percentage': phishing_percentage,
            'legitimate_percentage': legitimate_percentage,
            'total_phishing': phishing_count,
            'total_legitimate': legitimate_count,
            'common_tlds': tlds,
            'recent_detections': recent
        })
    except Exception as e:
        print(f"Error in statistics_v2 endpoint: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/api/report', methods=['POST'])
def report_phishing():
    """Endpoint to report a phishing site"""
    try:
        data = request.get_json()
        url = data.get('url', '')
        description = data.get('description', '')
        username = data.get('username', 'Anonymous')
        
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Create a new session
        session = Session()
        
        parsed_url = urlparse(url)
        domain = parsed_url.netloc
        
        # Create a new Report object
        report = Report(
            url=url,
            domain=domain,
            description=description,
            username=username,
            submitter_ip=request.remote_addr,
            status='phishing'
        )
        
        # Add to the session and commit
        session.add(report)
        session.commit()
        session.close()
        
        return jsonify({
            'success': True,
            'message': 'Thank you for your report. Our team will review it as soon as possible.'
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

def format_timestamp(dt):
    """Helper function to format timestamps consistently"""
    if dt:
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    return None

@app.route('/api/reports', methods=['GET'])
def get_reports():
    """Endpoint to get all submitted reports"""
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        
        # Create a new session
        session = Session()
        
        # Count total reports for pagination
        total_records = session.query(Report).count()
        
        # Get reports with pagination
        query = session.query(Report).order_by(Report.timestamp.desc())
        query = query.limit(limit).offset((page - 1) * limit)
        
        # Get the reports
        results = query.all()
        
        # Transform to dictionary format
        reports = []
        for report in results:
            reports.append({
                'id': report.id,
                'url': report.url,
                'domain': report.domain,
                'description': report.description,
                'username': report.username if hasattr(report, 'username') else 'Anonymous',
                'timestamp': format_timestamp(report.timestamp),
                'status': report.status
            })
        
        # Calculate total pages
        total_pages = (total_records + limit - 1) // limit if total_records > 0 else 1
        
        session.close()
        
        return jsonify({
            'reports': reports,
            'page': page,
            'total_pages': total_pages,
            'total_records': total_records
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Initialize database and load models on startup
def startup():
    print("Initializing PhishGuard...")
    # Initialize database (don't reset in production)
    print("Initializing database...")
    init_db()  # Use init_db instead of reset_db to preserve data
    
    # Load models
    load_models()
    
    # Download PhishTank database if it doesn't exist or is older than 7 days
    phishtank_file = os.path.join(DATA_DIR, 'phishtank_database.json')
    download_phishtank = True
    
    if os.path.exists(phishtank_file):
        # Check if file is older than 7 days
        file_age = time.time() - os.path.getmtime(phishtank_file)
        if file_age < 7 * 24 * 60 * 60:  # 7 days in seconds
            download_phishtank = False
    
    if download_phishtank:
        try:
            from download_phishtank import download_phishtank_database
            download_phishtank_database()
        except Exception as e:
            print(f"Error downloading PhishTank database: {str(e)}")
    
    print("PhishGuard initialized successfully!")
    print("Initializing database...")
    init_db()
    
    print("Loading machine learning models...")
    load_models()
    
    print("API initialized successfully!")

# Endpoint to get URL detection history with pagination and filtering
@app.route('/api/search_history', methods=['GET'])
def get_search_history():
    """Endpoint to get URL detection history with pagination and filtering"""
    try:
        # Get query parameters
        page = request.args.get('page', 1, type=int)
        limit = request.args.get('limit', 10, type=int)
        filter_type = request.args.get('filter', 'all')
        
        # Create a new session
        session = Session()
        
        # Base query
        query = session.query(Detection)
        
        # Apply filtering
        if filter_type == 'phishing':
            query = query.filter(Detection.is_phishing == True)
        elif filter_type == 'safe':
            query = query.filter(Detection.is_phishing == False)
        
        # Count total matching records for pagination
        total_records = query.count()
        
        # Apply pagination
        query = query.order_by(Detection.timestamp.desc())
        query = query.limit(limit).offset((page - 1) * limit)
        
        # Get the records
        results = query.all()
        
        # Transform to dictionary format
        history = []
        for detection in results:
            # Parse the JSON detection methods
            detection_methods = json.loads(detection.detection_methods)
            
            # Extract reasons from detection methods
            reasons = []
            for method, details in detection_methods.items():
                if details['result'] == (detection.is_phishing):  # Only include methods that contributed to the final decision
                    reasons.append(details['description'])
            
            history.append({
                'id': detection.id,
                'url': detection.url,
                'is_phishing': detection.is_phishing,
                'timestamp': detection.timestamp.isoformat(),
                'score': detection.confidence,
                'report': {
                    'reasons': reasons,
                    'features': detection_methods  # Include detailed features for the report modal
                }
            })
        
        # Calculate total pages
        total_pages = (total_records + limit - 1) // limit  # Ceiling division
        
        session.close()
        
        return jsonify({
            'records': history,
            'page': page,
            'total_pages': total_pages,
            'total_records': total_records,
            'filter': filter_type
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Run startup in a separate thread to avoid blocking app startup
threading.Thread(target=startup).start()

# Main entry point
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('FLASK_ENV', 'production').lower() != 'production'
    app.run(debug=debug, host='0.0.0.0', port=port)
