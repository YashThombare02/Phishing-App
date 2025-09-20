# PhishGuard - Advanced Phishing URL Detection System

PhishGuard is a comprehensive phishing detection system that combines machine learning, external API verification, and domain analysis to detect phishing URLs with over 98% accuracy.

## Project Structure

```
phishingURL/
├── backend/                 # Python backend code
│   ├── app.py               # Flask API server
│   ├── download_datasets.py # Script to fetch training data
│   ├── train_models.py      # ML model training code
│   ├── data/                # Dataset storage
│   ├── models/              # Trained ML models
│   └── logs/                # Application logs
├── frontend/                # Next.js frontend
│   ├── src/                 # Source code
│   │   ├── components/      # React components
│   │   ├── pages/           # Page routes
│   │   ├── styles/          # CSS styles
│   │   └── utils/           # Utility functions
│   └── public/              # Static assets
├── SETUP_GUIDE.md           # Installation instructions
├── start_dev.bat            # Windows startup script
├── start_dev.sh             # Linux/macOS startup script
├── ml_models.py             # Enhanced ML models implementation
├── requirements.txt         # Project dependencies
└── cleanup.bat              # Structure cleanup script
```

## Features

- **Multi-layer Verification**: Combines multiple methods for >98% accuracy
- **Machine Learning Models**: Uses advanced Random Forest and XGBoost algorithms with 30 and 50 features
- **External API Integration**: Connects to Google Safe Browsing API
- **Advanced Homograph Attack Detection**: Identifies domains trying to impersonate legitimate brands
- **URL Shortener Detection**: Identifies and follows redirects from URL shorteners
- **Content Analysis**: Examines webpage content for phishing patterns
- **Domain Analysis**: Checks domain age, registration info, and reputation
- **SSL/Security Verification**: Thorough certificate and security feature inspection
- **Batch Processing**: Analyze multiple URLs at once
- **Statistics Dashboard**: View detection metrics and trends
- **pyphish Library Integration**: Additional verification layer

## Installation

1. Clone the repository:
```bash
git clone https://github.com/username/phishguard.git
cd phishguard
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Configure environment variables:
```bash
# Create a .env file
touch .env

# Add your API keys
echo "GOOGLE_SAFE_BROWSING_API_KEY=your_api_key_here" >> .env
```

4. Run the application:
```bash
python backend/app.py
```

## Detection Methods

PhishGuard uses a combination of techniques to achieve >98% detection accuracy:

1. **URL Feature Analysis**
   - Lexical features (special characters, length, etc.)
   - TLD analysis
   - URL structure examination
   - URL shortener detection and redirect following

2. **Domain Analysis**
   - Domain age verification
   - WHOIS record inspection
   - Domain reputation check
   - Homograph attack detection with Levenshtein distance
   - Brand impersonation detection

3. **External API Verification**
   - Google Safe Browsing API
   - pyphish library verification

4. **Content-Based Analysis**
   - HTML form detection
   - JavaScript analysis and obfuscation detection
   - External form submission detection
   - Hidden field analysis
   - Brand references in page content

5. **Machine Learning**
   - UCI Random Forest Model (30 features)
   - Advanced XGBoost Model (50 features)
   - Feature importance analysis

## ML Model Features

### UCI Model Features (30 features)
- URL Length
- Contains IP address
- URL shortening service
- @ symbol in URL
- Double slash redirection
- Prefix-Suffix with hyphen
- Subdomain count
- HTTPS certificate
- Domain registration length
- And more...

### Advanced Model Features (50 features)
- All UCI model features plus:
- Path and query characteristics
- Domain entropy
- Brand impersonation detection
- Character substitution patterns
- SSL certificate analysis
- Content analysis
- Extensive TLD checks

## API Endpoints

- `/api/detect` - POST: Detect phishing for a single URL
- `/api/batch_detect` - POST: Process multiple URLs at once
- `/api/stats` - GET: Retrieve detection statistics
- `/api/report` - POST: Report a phishing URL
- `/api/verification_methods` - GET: Get information about verification methods
- `/api/statistics` - GET: Get detailed detection statistics

## Extending the System

### Adding a New Detection Method
1. Create a new method in the `PhishingDetector` class
2. Return a dictionary with `result`, `description`, and `value` keys
3. Add the method to the `detect` method and update the weights

### Training New ML Models
Use the `train_models` function in `ml_models.py`:

```python
from ml_models import train_models

# Train models with your data
train_models('phishing_urls.csv', 'legitimate_urls.csv')
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
