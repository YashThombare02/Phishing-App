import numpy as np
import pandas as pd
import pickle
import os
import re
import tldextract
from urllib.parse import urlparse
from collections import Counter
import joblib
import cloudpickle
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
import xgboost as xgb
from tqdm import tqdm
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import StandardScaler
import hashlib

class PhishingMLModels:
    """
    Class that handles the machine learning models for phishing detection
    Includes both the UCI Random Forest model and the Advanced XGBoost model
    """
    
    def __init__(self, model_dir):
        """
        Initialize the models
        
        Args:
            model_dir (str): Directory to store/load models
        """
        self.model_dir = model_dir
        self.models = {
            'uci_model': None,
            'advanced_model': None
        }
        
        # Create directory if it doesn't exist
        if not os.path.exists(model_dir):
            os.makedirs(model_dir)
    
    
    def load_models(self):
        """
        Load models from disk or create dummy models if they don't exist
        
        Returns:
            dict: Dictionary containing the loaded models
        """
        # UCI Model (RandomForest)
        uci_model_path = os.path.join(self.model_dir, 'uci_model.pkl')
        if os.path.exists(uci_model_path):
            print("Loading UCI Random Forest model...")
            with open(uci_model_path, 'rb') as f:
                self.models['uci_model'] = pickle.load(f)
        else:
            print("Creating dummy UCI model (model file not found)...")
            self.models['uci_model'] = RandomForestClassifier(
                n_estimators=200,
                max_depth=30,
                min_samples_split=3,
                min_samples_leaf=1,
                max_features='sqrt',
                class_weight='balanced',
                random_state=42,
                n_jobs=-1
            )
            self.models['uci_model'].fit(
                np.array([[0] * 30]).reshape(1, -1),
                np.array([0])
            )
            # Save the dummy model
            with open(uci_model_path, 'wb') as f:
                pickle.dump(self.models['uci_model'], f)
        
        # Advanced Model (XGBoost)
        advanced_model_path = os.path.join(self.model_dir, 'advanced_model.pkl')
        if os.path.exists(advanced_model_path):
            print("Loading Advanced XGBoost model...")
            with open(advanced_model_path, 'rb') as f:
                self.models['advanced_model'] = pickle.load(f)
        else:
            print("Creating dummy Advanced model (model file not found)...")
            self.models['advanced_model'] = xgb.XGBClassifier(
                base_score=0.5,
                n_estimators=300,
                max_depth=15,
                learning_rate=0.05,
                subsample=0.8,
                colsample_bytree=0.8,
                min_child_weight=1,
                gamma=0.1,
                reg_alpha=0.2,
                reg_lambda=2,
                scale_pos_weight=2, # Bias towards detecting phishing
                eval_metric='auc',
                use_label_encoder=False,
                random_state=42
            )
            self.models['advanced_model'].fit(
                np.array([[0] * 60]).reshape(1, -1),
                np.array([0])
            )
            # Save the dummy model
            with open(advanced_model_path, 'wb') as f:
                pickle.dump(self.models['advanced_model'], f)
        
        return self.models
    
    def train_uci_model(self, X_train, y_train, save=True):
        """
        Train the UCI Random Forest model
        
        Args:
            X_train (numpy.ndarray): Training features
            y_train (numpy.ndarray): Training labels
            save (bool): Whether to save the model to disk
            
        Returns:
            RandomForestClassifier: Trained model
        """
        print("Training UCI Random Forest model...")
        # Create a new RandomForest classifier with improved parameters
        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=30,
            min_samples_split=3,
            min_samples_leaf=1,
            max_features='sqrt',
            bootstrap=True,
            class_weight='balanced',
            criterion='entropy',  # Better for imbalanced classes
            random_state=42,
            n_jobs=-1  # Use all available cores
        )
        
        # Train the model
        model.fit(X_train, y_train)
        
        # Save the model
        if save:
            uci_model_path = os.path.join(self.model_dir, 'uci_model.pkl')
            with open(uci_model_path, 'wb') as f:
                pickle.dump(model, f)
        
        # Update the model in memory
        self.models['uci_model'] = model
        
        return model
    
    def train_advanced_model(self, X_train, y_train, save=True):
        """
        Train the Advanced XGBoost model
        
        Args:
            X_train (numpy.ndarray): Training features
            y_train (numpy.ndarray): Training labels
            save (bool): Whether to save the model to disk
            
        Returns:
            XGBClassifier: Trained model
        """
        print("Training Advanced XGBoost model...")
        # Create a new XGBoost classifier with optimized parameters
        model = xgb.XGBClassifier(
            n_estimators=300,
            max_depth=15,
            learning_rate=0.05,
            subsample=0.8,
            colsample_bytree=0.8,
            min_child_weight=1,
            gamma=0.1,
            reg_alpha=0.2,
            reg_lambda=2,
            scale_pos_weight=2,  # Bias towards detecting phishing (reduce false negatives)
            tree_method='hist',  # Faster algorithm
            use_label_encoder=False,
            eval_metric='auc',  # Better metric for imbalanced classes
            random_state=42
        )
        
        # Train the model
        model.fit(X_train, y_train)
        
        # Save the model
        if save:
            advanced_model_path = os.path.join(self.model_dir, 'advanced_model.pkl')
            with open(advanced_model_path, 'wb') as f:
                pickle.dump(model, f)
        
        # Update the model in memory
        self.models['advanced_model'] = model
        
        return model
    
    def extract_uci_features(self, url):
        """
        Extract features based on UCI dataset methodology (30 features total)
        Enhanced for better phishing detection accuracy
        
        Args:
            url (str): URL to extract features from
            
        Returns:
            numpy.ndarray: Feature vector of shape (1, 30)
        """
        features = [0] * 30  # Initialize 30 features with zeros
        
        # Parse the URL
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            query = parsed_url.query
            extracted = tldextract.extract(url)
            subdomain = extracted.subdomain
            domain_name = extracted.domain
            tld = extracted.suffix
            
            # Normalize URL for better feature extraction
            url_lower = url.lower()
            domain_lower = domain.lower()
            path_lower = path.lower()
        except:
            # If URL parsing fails, return features that suggest this is suspicious
            features = [1] * 30  # Mark all features as suspicious if parsing fails
            return np.array(features).reshape(1, -1)
        
        # Feature Group 1: URL-based features (1-10)
        # 1. URL Length - longer URLs are more likely to be phishing
        features[0] = 1 if len(url) > 75 else 0
        
        # 2. Contains IP address - phishing often uses raw IPs
        features[1] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
        
        # 3. URL shortening service - often used to hide phishing URLs
        short_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly', 'buff.ly', 'shorturl.at']
        features[2] = 1 if any(service in domain_lower for service in short_services) else 0
        
        # 4. @ symbol in URL - used to mislead
        features[3] = 1 if '@' in url else 0
        
        # 5. Double slash redirection - suspicious URL structure
        features[4] = 1 if '//' in url.replace('://', '') else 0
        
        # 6. Prefix-Suffix with hyphen - often used in phishing domains
        features[5] = 1 if '-' in domain_name else 0
        
        # 7. Subdomain count - excessive subdomains can be suspicious
        subdomains = domain.split('.')
        features[6] = 1 if len(subdomains) > 3 or (subdomain and len(subdomain.split('.')) > 2) else 0
        
        # 8. HTTPS certificate - lack of HTTPS is suspicious
        features[7] = 0 if parsed_url.scheme == 'https' else 1  # 0 for https, 1 for http
        
        # 9. Domain registration length - new domains are suspicious
        # We don't have external lookup here, so we'll estimate based on domain patterns
        features[8] = 1 if any(x in domain_lower for x in ['temp', 'xyz', 'tk', 'ml', 'ga', 'cf', 'gq', 'today', 'top']) else 0
        
        # 10. Domain with unusual TLDs
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'date', 'faith', 'stream', 'racing', 'win', 'science', 'party', 'gdn']
        features[9] = 1 if tld in suspicious_tlds else 0
        
        # Feature Group 2: Domain-based features (11-20)
        # 11. Using non-standard port
        features[10] = 1 if ":" in domain and domain.split(":")[-1] not in ["80", "443"] else 0
        
        # 12. HTTPS in domain part (suspicious)
        features[11] = 1 if "https" in domain_lower or "http" in domain_lower or "ssl" in domain_lower or "secure" in domain_lower else 0
        
        # 13. Excessive subdomains or domain parts
        features[12] = 1 if domain.count('.') > 3 else 0
        
        # 14. Domain with numbers and letters mixed
        features[13] = 1 if (any(c.isdigit() for c in domain_name) and any(c.isalpha() for c in domain_name)) else 0
        
        # 15. Domain with unusual characters
        features[14] = 1 if re.search(r'[^a-zA-Z0-9.-]', domain) else 0
        
        # 16. Domain entropy (randomness) - phishing often has random domains
        if domain_name:
            char_counts = Counter(domain_name)
            entropy = -sum((count / len(domain_name)) * np.log2(count / len(domain_name)) for count in char_counts.values())
            features[15] = 1 if entropy > 3.7 else 0
        else:
            features[15] = 0
        
        # 17. Domain with digits ratio - high ratio can be suspicious
        if domain_name:
            digit_ratio = sum(c.isdigit() for c in domain_name) / len(domain_name)
            features[16] = 1 if digit_ratio > 0.3 else 0
        else:
            features[16] = 0
        
        # 18. Domain with auto-generated pattern
        generated_patterns = ['framer.app', 'glide.page', 'makeweb.io', 'makeweb.co', 'netlify.app', 'site123', 'myportfolio.com']
        features[17] = 1 if any(pattern in domain_lower for pattern in generated_patterns) else 0
        
        # 19. URL with suspicious auth keywords
        auth_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'password', 'auth', 'credential', 'security', 'confirmation']
        features[18] = 1 if any(keyword in url_lower for keyword in auth_keywords) else 0
        
        # 20. URL with numeric ID-like patterns
        features[19] = 1 if re.search(r'id=\d+', url_lower) or re.search(r'[a-f0-9]{32}', url_lower) else 0
        
        # Feature Group 3: Content and brand impersonation features (21-30)
        # 21. Domain impersonating popular brands
        brands = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'instagram', 'netflix', 'twitter', 'linkedin']
        features[20] = 1 if any(brand in domain_name.lower() and not domain.endswith(f"{brand}.com") for brand in brands) else 0
        
        # 22. URL with suspicious path structure
        features[21] = 1 if path.count('/') > 5 or query.count('&') > 5 else 0
        
        # 23. URL with file extensions in path (often phishing)
        suspicious_extensions = ['.php', '.html', '.htm', '.asp', '.aspx', '.jsp', '.exe', '.zip', '.rar']
        features[22] = 1 if any(ext in path_lower for ext in suspicious_extensions) else 0
        
        # 24. URL with numeric parameters (potential session hijacking)
        features[23] = 1 if re.search(r'=[0-9]+&', url) else 0
        
        # 25. URL with script-related terms
        script_terms = ['script', 'js', 'javascript', 'php', 'cgi', 'api']
        features[24] = 1 if any(term in url_lower for term in script_terms) else 0
        
        # 26. Domain with excessive hyphens
        features[25] = 1 if domain_name.count('-') > 2 else 0
        
        # 27. URL with encoded characters
        features[26] = 1 if '%' in url and re.search(r'%[0-9A-Fa-f]{2}', url) else 0
        
        # 28. URL with suspicious banking/payment terms
        banking_terms = ['bank', 'pay', 'account', 'credit', 'debit', 'card', 'transaction', 'transfer', 'bill']
        features[27] = 1 if any(term in url_lower for term in banking_terms) else 0
        
        # 29. Domain with random number sequence
        features[28] = 1 if re.search(r'\d{4,}', domain_name) else 0
        
        # 30. URL with suspicious action words
        action_words = ['update', 'confirm', 'verify', 'validate', 'submit', 'check', 'access', 'review', 'reset']
        features[29] = 1 if any(word in url_lower for word in action_words) else 0
        
        return np.array(features).reshape(1, -1)
        suspicious_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'password']
        features[27] = 1 if any(keyword in url.lower() for keyword in suspicious_keywords) else 0
        
        # 29. Random looking domain (high entropy)
        if domain_name:
            char_counts = Counter(domain_name)
            entropy = -sum((count / len(domain_name)) * np.log2(count / len(domain_name)) for count in char_counts.values())
            features[28] = 1 if entropy > 3.5 else 0
        else:
            features[28] = 0
        
        # 30. Domain with numeric characters
        features[29] = 1 if any(c.isdigit() for c in domain_name) else 0
        
        return np.array(features).reshape(1, -1)
    
    def extract_advanced_features(self, url):
        """
        Extract comprehensive features for the advanced XGBoost model (60 features total)
        Significantly enhanced for better phishing detection accuracy
        
        Args:
            url (str): URL to extract features from
            
        Returns:
            numpy.ndarray: Feature vector of shape (1, 60)
        """
        features = [0] * 60  # Initialize 60 features with zeros
        
        # Parse the URL
        try:
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            path = parsed_url.path
            query = parsed_url.query
            fragment = parsed_url.fragment
            scheme = parsed_url.scheme
            extracted = tldextract.extract(url)
            subdomain = extracted.subdomain
            domain_name = extracted.domain
            tld = extracted.suffix
            
            # Normalize for better feature extraction
            url_lower = url.lower()
            domain_lower = domain.lower()
            path_lower = path.lower()
            query_lower = query.lower()
        except:
            # If URL parsing fails, return features that suggest this is suspicious
            features = [1] * 60  # Mark all features as suspicious if parsing fails
            return np.array(features).reshape(1, -1)
        
        # Feature Group 1: Basic URL characteristics (1-10)
        # 1. URL length - longer URLs are often phishing
        features[0] = len(url)
        
        # 2. Domain length - excessively long domains are suspicious
        features[1] = len(domain)
        
        # 3. Path length - long paths can hide malicious intent
        features[2] = len(path)
        
        # 4. Query length - excessively long queries may contain obfuscated code
        features[3] = len(query)
        
        # 5. Fragment length - suspicious if too long
        features[4] = len(fragment)
        
        # 6. Count of dots in URL - too many dots can indicate subdomains or obfuscation
        features[5] = url.count('.')
        
        # 7. Count of slashes in URL - complex directory structures can be suspicious
        features[6] = url.count('/')
        
        # 8. Count of equals in query - too many parameters can be suspicious
        features[7] = query.count('=')
        
        # 9. Count of ampersands in query - too many parameters can be suspicious
        features[8] = query.count('&')
        
        # 10. Count of special characters in URL - high counts can indicate obfuscation
        features[9] = sum(c in "!@#$%^&*()_+{}[]|\\:;\"'<>,.?/~`" for c in url)
        
        # Feature Group 2: Security indicators (11-20)
        # 11. HTTPS scheme (1 for https, 0 for http) - lack of HTTPS is suspicious
        features[10] = 1 if scheme == 'https' else 0
        
        # 12. Presence of IP address - phishing often uses raw IPs
        features[11] = 1 if re.search(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', url) else 0
        
        # 13. @ symbol in URL - often used to confuse users
        features[12] = 1 if '@' in url else 0
        
        # 14. Double slash redirection - suspicious URL structure
        features[13] = 1 if '//' in url.replace('://', '') else 0
        
        # 15. Prefix-Suffix with hyphen - often used in phishing domains
        features[14] = 1 if '-' in domain else 0
        
        # 16. Subdomain count - excessive subdomains can be suspicious
        features[15] = len(subdomain.split('.')) if subdomain else 0
        
        # 17. Domain has non-alphanumeric chars - suspicious characters in domain
        features[16] = 1 if re.search(r'[^a-zA-Z0-9.-]', domain) else 0
        
        # 18. Domain starts with number - unusual for legitimate domains
        features[17] = 1 if domain_name and domain_name[0].isdigit() else 0
        
        # 19. Domain ends with number - unusual for legitimate domains
        features[18] = 1 if domain_name and domain_name[-1].isdigit() else 0
        
        # 20. URL contains credentials (username:password@) - very suspicious
        features[19] = 1 if re.search(r'[^/]@', url) else 0
        
        # Feature Group 3: Domain characteristics (21-30)
        # 21. Domain has many hyphens - often used in phishing
        features[20] = domain.count('-')
        
        # 22. Domain has many dots - excessive subdomains
        features[21] = domain.count('.')
        
        # 23. Domain length to TLD ratio - phishing often has long domain names
        features[22] = len(domain_name) / (len(tld) if len(tld) > 0 else 1)
        
        # 24. Domain has suspicious TLD - certain TLDs are often used for phishing
        suspicious_tlds = [
            'tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'date', 'faith', 'stream',
            'racing', 'win', 'science', 'party', 'gdn', 'men', 'loan', 'click', 'link', 'live', 'online'
        ]
        features[23] = 1 if tld in suspicious_tlds else 0
        
        # 25. Domain has non-standard port - often used in phishing
        features[24] = 1 if ":" in domain and domain.split(":")[-1] not in ["80", "443"] else 0
        
        # 26. Domain entropy (randomness) - high entropy often indicates random/phishing domains
        if domain_name:
            char_counts = Counter(domain_name)
            entropy = -sum((count / len(domain_name)) * np.log2(count / len(domain_name)) for count in char_counts.values())
            features[25] = entropy
        else:
            features[25] = 0
        
        # 27. Domain digit ratio - high ratio often indicates phishing
        features[26] = sum(c.isdigit() for c in domain_name) / (len(domain_name) if len(domain_name) > 0 else 1)
        
        # 28. Domain vowel ratio - unusual ratio can indicate phishing
        vowels = 'aeiou'
        features[27] = sum(c.lower() in vowels for c in domain_name) / (len(domain_name) if len(domain_name) > 0 else 1)
        
        # 29. Domain has mixed alphanumeric - often used in phishing
        features[28] = 1 if any(c.isdigit() for c in domain_name) and any(c.isalpha() for c in domain_name) else 0
        
        # 30. Domain consonant-vowel ratio - unusual ratio can indicate phishing
        consonants = sum(c.lower() not in vowels and c.isalpha() for c in domain_name)
        vowel_count = sum(c.lower() in vowels for c in domain_name)
        features[29] = consonants / (vowel_count if vowel_count > 0 else 1)
        
        # Feature Group 4: Path and query characteristics (31-40)
        # 31. Path entropy - high entropy often indicates obfuscation
        if path:
            char_counts = Counter(path)
            entropy = -sum((count / len(path)) * np.log2(count / len(path)) for count in char_counts.values())
            features[30] = entropy
        else:
            features[30] = 0
        
        # 32. Path digit ratio - high ratio often indicates phishing
        features[31] = sum(c.isdigit() for c in path) / (len(path) if len(path) > 0 else 1)
        
        # 33. Path has suspicious extensions - often used in phishing
        suspicious_extensions = ['.exe', '.zip', '.rar', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.js', '.php', '.html', '.htm', '.asp', '.aspx', '.jsp']
        features[32] = 1 if any(ext in path_lower for ext in suspicious_extensions) else 0
        
        # 34. Query parameter count - excessive parameters can be suspicious
        features[33] = query.count('&') + 1 if query else 0
        
        # 35. Query has long parameters (potential obfuscation)
        param_lengths = [len(param.split('=')[1]) if '=' in param else 0 for param in query.split('&') if param]
        features[34] = 1 if any(length > 50 for length in param_lengths) else 0
        
        # 36. Path directory count - excessive directories can be suspicious
        features[35] = path.count('/') - 1 if path.endswith('/') else path.count('/')
        
        # 37. Path has suspicious keywords - often used in phishing
        suspicious_keywords = [
            'login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'password',
            'credential', 'authenticate', 'session', 'security', 'admin', 'wallet', 'payment', 'authorize',
            'validation', 'identity', 'reset', 'recover', 'unlock'
        ]
        features[36] = 1 if any(keyword in path_lower for keyword in suspicious_keywords) else 0
        
        # 38. Query has suspicious keywords - often used in phishing
        features[37] = 1 if any(keyword in query_lower for keyword in suspicious_keywords) else 0
        
        # 39. Path or query has base64-like pattern - often used for obfuscation
        features[38] = 1 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', path + query) else 0
        
        # 40. URL has too many subdomains - excessive subdomains can be suspicious
        features[39] = 1 if len(domain.split('.')) > 4 else 0
        
        # Feature Group 5: Brand impersonation and suspicious patterns (41-50)
        # 41-45. Check for brand name in domain (for several major brands)
        brands = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'netflix', 'twitter', 'instagram', 'linkedin']
        for i, brand in enumerate(brands[:5]):
            # Brand in domain but not actually brand's domain
            features[40 + i] = 1 if brand in domain_name.lower() and not domain.lower().endswith(f"{brand}.com") else 0
        
        # 46. Domain likely impersonating well-known site - check similarity to common domains
        common_domains = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix', 'gmail']
        max_similarity = 0
        for common in common_domains:
            # Calculate similarity based on Levenshtein distance (approximated)
            if common in domain_name.lower() and common != domain_name.lower():
                features[45] = 1
                break
        
        # 47. URL contains multiple TLDs (e.g., apple.com.tk) - common phishing technique
        domain_parts = domain.split('.')
        features[46] = 1 if len(domain_parts) >= 3 and domain_parts[-2] in ['com', 'org', 'net', 'gov', 'edu'] else 0
        
        # 48. URL uses URL shortener - often used to hide phishing URLs
        short_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly', 'buff.ly', 'adf.ly', 'shorturl.at']
        features[47] = 1 if any(service in domain_lower for service in short_services) else 0
        
        # 49. URL has hexadecimal or encoded characters - often used for obfuscation
        features[48] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
        
        # 50. URL length to domain ratio - high ratio often indicates phishing
        features[49] = len(url) / (len(domain) if len(domain) > 0 else 1)
        
        # Feature Group 6: Advanced phishing indicators (51-60)
        # 51. URL contains auth-related terms - common in phishing
        auth_terms = ['auth', 'signin', 'login', 'account', 'membership', 'credential', 'password', 'verify']
        features[50] = 1 if any(term in url_lower for term in auth_terms) else 0
        
        # 52. URL contains security-related terms - common in phishing
        security_terms = ['secure', 'security', 'protection', 'confirm', 'safe', 'alert', 'warning', 'verify', 'validation']
        features[51] = 1 if any(term in url_lower for term in security_terms) else 0
        
        # 53. URL contains financial terms - common in phishing
        financial_terms = ['bank', 'account', 'credit', 'debit', 'card', 'payment', 'pay', 'transaction', 'transfer', 'wallet']
        features[52] = 1 if any(term in url_lower for term in financial_terms) else 0
        
        # 54. Domain contains random-looking string - often indicates auto-generated phishing domains
        if domain_name:
            # Check for random-looking strings (mix of letters and numbers with high entropy)
            has_letters = any(c.isalpha() for c in domain_name)
            has_digits = any(c.isdigit() for c in domain_name)
            if has_letters and has_digits:
                char_counts = Counter(domain_name)
                entropy = -sum((count / len(domain_name)) * np.log2(count / len(domain_name)) for count in char_counts.values())
                features[53] = 1 if entropy > 3.7 else 0
            else:
                features[53] = 0
        else:
            features[53] = 0
        
        # 55. Domain contains numeric sequence - common in phishing
        features[54] = 1 if re.search(r'\d{4,}', domain_name) else 0
        
        # 56. Domain is suspiciously long - phishing often has long domain names
        features[55] = 1 if len(domain_name) > 20 else 0
        
        # 57. URL contains file upload/download terms - common in malware distribution
        file_terms = ['upload', 'download', 'file', 'document', 'attachment', 'update', 'install']
        features[56] = 1 if any(term in url_lower for term in file_terms) else 0
        
        # 58. Domain appears to be auto-generated platform subdomain
        generated_platforms = ['framer.app', 'glide.page', 'makeweb.io', 'makeweb.co', 'netlify.app', 'vercel.app', 'herokuapp.com', 'site123', 'myportfolio.com']
        features[57] = 1 if any(platform in domain_lower for platform in generated_platforms) else 0
        
        # 59. URL contains suspicious parameter names
        suspicious_params = ['token', 'auth', 'key', 'login', 'password', 'pwd', 'user', 'username', 'email', 'id', 'redirect']
        has_suspicious_param = False
        for param in query.split('&'):
            if '=' in param:
                param_name = param.split('=')[0].lower()
                if param_name in suspicious_params:
                    has_suspicious_param = True
                    break
        features[58] = 1 if has_suspicious_param else 0
        
        # 60. URL hash - if we've seen similar URL patterns before
        url_hash = int(hashlib.md5(domain_name.encode()).hexdigest(), 16) % 2
        features[59] = url_hash  # 0 or 1 based on hash - helps with known patterns
        
        return np.array(features).reshape(1, -1)
        # 19. Domain ends with number
        features[18] = 1 if domain_name and domain_name[-1].isdigit() else 0
        
        # 20. URL contains credentials (username:password@)
        features[19] = 1 if re.search(r'[^/]@', url) else 0
        
        # Feature Group 3: Domain characteristics (21-30)
        # 21. Domain has many hyphens
        features[20] = domain.count('-')
        
        # 22. Domain has many dots
        features[21] = domain.count('.')
        
        # 23. Domain length to TLD ratio
        features[22] = len(domain_name) / (len(tld) if len(tld) > 0 else 1)
        
        # 24. Domain has suspicious TLD
        suspicious_tlds = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'work', 'date', 'faith', 'stream']
        features[23] = 1 if tld in suspicious_tlds else 0
        
        # 25. Domain has non-standard port
        features[24] = 1 if ":" in domain and domain.split(":")[-1] not in ["80", "443"] else 0
        
        # 26. Domain entropy (randomness)
        if domain_name:
            char_counts = Counter(domain_name)
            entropy = -sum((count / len(domain_name)) * np.log2(count / len(domain_name)) for count in char_counts.values())
            features[25] = entropy
        else:
            features[25] = 0
        
        # 27. Domain digit ratio
        features[26] = sum(c.isdigit() for c in domain_name) / (len(domain_name) if len(domain_name) > 0 else 1)
        
        # 28. Domain vowel ratio
        vowels = 'aeiou'
        features[27] = sum(c.lower() in vowels for c in domain_name) / (len(domain_name) if len(domain_name) > 0 else 1)
        
        # 29. Domain has mixed alphanumeric
        features[28] = 1 if any(c.isdigit() for c in domain_name) and any(c.isalpha() for c in domain_name) else 0
        
        # 30. Domain consonant-vowel ratio
        consonants = sum(c.lower() not in vowels and c.isalpha() for c in domain_name)
        vowel_count = sum(c.lower() in vowels for c in domain_name)
        features[29] = consonants / (vowel_count if vowel_count > 0 else 1)
        
        # Feature Group 4: Path and query characteristics (31-40)
        # 31. Path entropy
        if path:
            char_counts = Counter(path)
            entropy = -sum((count / len(path)) * np.log2(count / len(path)) for count in char_counts.values())
            features[30] = entropy
        else:
            features[30] = 0
        
        # 32. Path digit ratio
        features[31] = sum(c.isdigit() for c in path) / (len(path) if len(path) > 0 else 1)
        
        # 33. Path has suspicious extensions
        suspicious_extensions = ['.exe', '.zip', '.rar', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.js']
        features[32] = 1 if any(ext in path.lower() for ext in suspicious_extensions) else 0
        
        # 34. Query parameter count
        features[33] = query.count('&') + 1 if query else 0
        
        # 35. Query has long parameters (potential obfuscation)
        param_lengths = [len(param.split('=')[1]) if '=' in param else 0 for param in query.split('&') if param]
        features[34] = 1 if any(length > 50 for length in param_lengths) else 0
        
        # 36. Path directory count
        features[35] = path.count('/') - 1 if path.endswith('/') else path.count('/')
        
        # 37. Path has suspicious keywords
        suspicious_keywords = ['login', 'signin', 'verify', 'secure', 'account', 'update', 'confirm', 'banking', 'password']
        features[36] = 1 if any(keyword in path.lower() for keyword in suspicious_keywords) else 0
        
        # 38. Query has suspicious keywords
        features[37] = 1 if any(keyword in query.lower() for keyword in suspicious_keywords) else 0
        
        # 39. Path or query has base64-like pattern
        features[38] = 1 if re.search(r'[A-Za-z0-9+/]{20,}={0,2}', path + query) else 0
        
        # 40. URL has too many subdomains
        features[39] = 1 if len(domain.split('.')) > 4 else 0
        
        # Feature Group 5: Brand impersonation and suspicious patterns (41-50)
        # 41-45. Check for brand name in domain (for several major brands)
        brands = ['paypal', 'apple', 'microsoft', 'google', 'amazon', 'facebook', 'netflix', 'twitter', 'instagram', 'linkedin']
        for i, brand in enumerate(brands[:5]):
            # Brand in domain but not actually brand's domain
            features[40 + i] = 1 if brand in domain_name.lower() and not domain.lower().endswith(f"{brand}.com") else 0
        
        # 46. Domain looks like misspelled brand (edit distance check would be better)
        # Placeholder - would need more sophisticated check
        features[45] = 0
        
        # 47. URL contains multiple TLDs (e.g., apple.com.tk)
        domain_parts = domain.split('.')
        features[46] = 1 if len(domain_parts) >= 3 and domain_parts[-2] in ['com', 'org', 'net', 'gov', 'edu'] else 0
        
        # 48. URL uses URL shortener
        short_services = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'is.gd', 'ow.ly', 'buff.ly', 'adf.ly', 'shorturl.at']
        features[47] = 1 if any(service in domain.lower() for service in short_services) else 0
        
        # 49. URL has hexadecimal or encoded characters
        features[48] = 1 if re.search(r'%[0-9a-fA-F]{2}', url) else 0
        
        # 50. URL length to domain ratio (high ratio often indicates phishing)
        features[49] = len(url) / (len(domain) if len(domain) > 0 else 1)
        
        return np.array(features).reshape(1, -50 if len(features) > 50 else -1)  # Ensure we return no more than 50 features
    
    def predict_uci_model(self, url):
        """
        Predict using the UCI model with enhanced confidence calibration
        
        Args:
            url (str): URL to classify
            
        Returns:
            tuple: (prediction (bool), probability (float))
        """
        if self.models['uci_model'] is None:
            raise ValueError("Model not loaded. Call load_models() first.")
        
        # Extract features
        features = self.extract_uci_features(url)
        
        # Predict
        prediction = self.models['uci_model'].predict(features)[0]
        
        # Get probability with enhanced calibration
        try:
            proba = self.models['uci_model'].predict_proba(features)[0]
            
            # If the positive class is index 1
            if len(proba) > 1:
                probability = proba[1]
            else:
                probability = float(prediction)
                
            # Increase probability for phishing predictions to be more aggressive
            # This makes the model more likely to flag suspicious URLs
            if prediction == 1 and probability < 0.8:
                probability = min(probability * 1.25, 0.99)  # Boost phishing prediction confidence
                
        except:
            # If probabilities are not available
            probability = float(prediction)
        
        return bool(prediction), probability
    
    def predict_advanced_model(self, url):
        """
        Predict using the Advanced model with enhanced confidence calibration
        
        Args:
            url (str): URL to classify
            
        Returns:
            tuple: (prediction (bool), probability (float))
        """
        if self.models['advanced_model'] is None:
            raise ValueError("Model not loaded. Call load_models() first.")
        
        # Extract features
        features = self.extract_advanced_features(url)
        
        # Predict
        prediction = self.models['advanced_model'].predict(features)[0]
        
        # Get probability with enhanced calibration
        try:
            proba = self.models['advanced_model'].predict_proba(features)[0]
            
            # If the positive class is index 1
            if len(proba) > 1:
                probability = proba[1]
            else:
                probability = float(prediction)
                
            # Increase probability for phishing predictions to be more aggressive
            # This makes the model more likely to flag suspicious URLs
            if prediction == 1 and probability < 0.8:
                probability = min(probability * 1.3, 0.99)  # Boost phishing prediction confidence
                
        except:
            # If probabilities are not available
            probability = float(prediction)
        
        return bool(prediction), probability


# Example data preparation function (for training models with your own data)
def prepare_training_data(phishing_csv, legitimate_csv=None, combined_csv=None):
    """
    Prepare training data from CSV files
    
    Args:
        phishing_csv (str): Path to CSV with phishing URLs
        legitimate_csv (str): Path to CSV with legitimate URLs
        combined_csv (str): Path to CSV with combined URLs (has 'url' and 'is_phishing' columns)
        
    Returns:
        tuple: (X_uci, X_advanced, y) - feature matrices and label vector
    """
    # Initialize ML models class to use feature extraction
    ml_models = PhishingMLModels(model_dir='./models')
    
    # Load combined dataset if provided
    if combined_csv:
        print(f"Loading combined dataset from {combined_csv}...")
        df_combined = pd.read_csv(combined_csv)
        urls = df_combined['url'].tolist()
        labels = df_combined['is_phishing'].tolist()
    else:
        # Load phishing URLs
        print(f"Loading phishing URLs from {phishing_csv}...")
        df_phishing = pd.read_csv(phishing_csv)
        phishing_urls = df_phishing['url'].tolist() if 'url' in df_phishing.columns else []
        
        # If no URL column found, try other common column names
        if not phishing_urls and 'URL' in df_phishing.columns:
            phishing_urls = df_phishing['URL'].tolist()
        elif not phishing_urls and len(df_phishing.columns) > 0:
            # If still no URL column found, use the first column
            phishing_urls = df_phishing[df_phishing.columns[0]].tolist()
        
        # Load legitimate URLs if provided
        if legitimate_csv:
            print(f"Loading legitimate URLs from {legitimate_csv}...")
            df_legitimate = pd.read_csv(legitimate_csv)
            legitimate_urls = df_legitimate['url'].tolist() if 'url' in df_legitimate.columns else []
            
            # If no URL column found, try other common column names
            if not legitimate_urls and 'URL' in df_legitimate.columns:
                legitimate_urls = df_legitimate['URL'].tolist()
            elif not legitimate_urls and len(df_legitimate.columns) > 0:
                # If still no URL column found, use the first column
                legitimate_urls = df_legitimate[df_legitimate.columns[0]].tolist()
        else:
            legitimate_urls = []
        
        # Prepare data
        urls = phishing_urls + legitimate_urls
        labels = [1] * len(phishing_urls) + [0] * len(legitimate_urls)
    
    # Remove invalid URLs
    valid_indices = []
    for i, url in enumerate(urls):
        if isinstance(url, str) and url.startswith(('http://', 'https://')):
            valid_indices.append(i)
    
    urls = [urls[i] for i in valid_indices]
    labels = [labels[i] for i in valid_indices]
    
    print(f"Total URLs for training: {len(urls)} ({sum(labels)} phishing, {len(urls) - sum(labels)} legitimate)")
    
    # Extract features
    print("Extracting UCI features...")
    X_uci = np.vstack([ml_models.extract_uci_features(url) for url in tqdm(urls)])
    
    print("Extracting advanced features...")
    X_advanced = np.vstack([ml_models.extract_advanced_features(url) for url in tqdm(urls)])
    
    # Convert to numpy arrays
    y = np.array(labels)
    
    return (X_uci, X_advanced, y)


# Example usage for training models
def train_models(phishing_csv=None, legitimate_csv=None, combined_csv=None, uci_only=False, advanced_only=False):
    """
    Train both models with provided data
    
    Args:
        phishing_csv (str): Path to CSV with phishing URLs
        legitimate_csv (str): Path to CSV with legitimate URLs
        combined_csv (str): Path to CSV with combined URLs (has 'url' and 'is_phishing' columns)
        uci_only (bool): Only train the UCI model
        advanced_only (bool): Only train the Advanced model
        
    Returns:
        PhishingMLModels: Trained models
    """
    # Initialize ML models class
    ml_models = PhishingMLModels(model_dir='./models')
    
    # Load existing models first
    ml_models.load_models()
    
    # Prepare training data
    X_uci, X_advanced, y = prepare_training_data(phishing_csv, legitimate_csv, combined_csv)
    
    # Train models
    if not advanced_only:
        ml_models.train_uci_model(X_uci, y)
        print("UCI model trained successfully!")
        
    if not uci_only:
        ml_models.train_advanced_model(X_advanced, y)
        print("Advanced model trained successfully!")
    
    return ml_models


if __name__ == "__main__":
    # Example usage for training with sample data
    # This code will run if you execute this file directly
    
    import os
    
    # Directory paths
    current_dir = os.path.dirname(os.path.abspath(__file__))
    data_dir = os.path.join(current_dir, 'backend', 'data')
    model_dir = os.path.join(current_dir, 'backend', 'models')
    
    # Dataset paths
    combined_urls_csv = os.path.join(data_dir, 'combined_urls.csv')
    legitimate_urls_csv = os.path.join(data_dir, 'legitimate_urls.csv')
    uci_dataset_csv = os.path.join(data_dir, 'uci_dataset.csv')
    
    # Train models if datasets exist
    if os.path.exists(combined_urls_csv):
        print(f"Training models with combined dataset from {combined_urls_csv}")
        train_models(combined_csv=combined_urls_csv)
    elif os.path.exists(legitimate_urls_csv) and os.path.exists(uci_dataset_csv):
        print(f"Training models with separate datasets from {legitimate_urls_csv} and {uci_dataset_csv}")
        train_models(uci_dataset_csv, legitimate_urls_csv)
    else:
        print("No training datasets found in the data directory.")
        
    # Load the trained models
    ml_models = PhishingMLModels(model_dir=model_dir)
    ml_models.load_models()
    
    # Test URLs
    test_urls = [
        "https://www.google.com",
        "http://malicious-phishing-site.com/login.php",
        "https://paypal-secure.phishing-attempt.com/login",
        "https://login-secure.framer.app/",
        "https://verify-account-secure.glide.page/"
    ]
    
    print("\nTesting trained models with sample URLs:")
    for url in test_urls:
        # UCI model prediction
        uci_pred, uci_prob = ml_models.predict_uci_model(url)
        
        # Advanced model prediction
        adv_pred, adv_prob = ml_models.predict_advanced_model(url)
        
        print(f"URL: {url}")
        print(f"UCI Model: {'Phishing' if uci_pred else 'Legitimate'} (Confidence: {uci_prob:.2f})")
        print(f"Advanced Model: {'Phishing' if adv_pred else 'Legitimate'} (Confidence: {adv_prob:.2f})")
        print("-" * 50)
