# PhishGuard - Advanced Phishing URL Detection System

PhishGuard is a comprehensive phishing detection system that combines machine learning, external API verification, and domain analysis to detect phishing URLs with over 95% accuracy.

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
└── cleanup.bat              # Structure cleanup script
```

## Database

PhishGuard uses PostgreSQL for data storage:

- **Detection records**: Stores URL analysis results
- **User reports**: Manages user-submitted phishing reports
- **Statistics**: Provides data for the analytics dashboard

## Features

- **Multi-layer Verification**: Combines multiple methods for high accuracy
- **Machine Learning Models**: Uses Random Forest and XGBoost algorithms
- **External API Integration**: Connects to PhishTank and Google Safe Browsing
- **Domain Analysis**: Checks domain age, registration info, and reputation
- **Content Analysis**: Examines webpage content for phishing patterns
- **Batch Processing**: Analyze multiple URLs at once
- **Statistics Dashboard**: View detection metrics and trends

## Installation

Please follow the instructions in [SETUP_GUIDE.md](SETUP_GUIDE.md) to install and run the application.

## Detection Methods

PhishGuard uses a combination of techniques to achieve >95% detection accuracy:

1. **URL Feature Analysis**
   - Lexical features (special characters, length, etc.)
   - TLD analysis
   - URL structure examination

2. **Domain Analysis**
   - Domain age verification
   - WHOIS record inspection
   - Domain reputation check

3. **External API Verification**
   - PhishTank database check
   - Google Safe Browsing API

4. **Content-Based Analysis**
   - HTML form detection
   - JavaScript analysis
   - Redirection detection

## API Endpoints

- `/api/detect` - POST: Detect phishing for a single URL
- `/api/batch_detect` - POST: Process multiple URLs at once
- `/api/stats` - GET: Retrieve detection statistics
- `/api/report` - POST: Report a phishing URL

## License

This project is licensed under the MIT License - see the LICENSE file for details.
