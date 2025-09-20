# PhishGuard ### 1. Clean Up Project Structure (Optional)

If your project structure has redundant files, run the cleanup script first:

```bash
# Run the cleanup script
.\cleanup.bat
```

### 2. Configure Database (Optional)

By default, the application uses SQLite, which requires no setup. If you want to use PostgreSQL instead:

1. Install PostgreSQL and create a database:
```sql
CREATE DATABASE phishguard;
```

2. Update the `.env` file to use PostgreSQL:
```
# Set database type to postgres
DB_TYPE=postgres

# PostgreSQL Configuration
DB_USER=your_postgres_username
DB_PASSWORD=your_postgres_password
DB_HOST=localhost
DB_PORT=5432
DB_NAME=phishguard
```

### 3. Install Python Dependencieson and Setup Guide

This guide will help you install all dependencies and run the PhishGuard application.

## Prerequisites

- Python 3.8 or newer
- Node.js 16.x or newer
- npm (comes with Node.js)
- PostgreSQL 12 or newer (optional, SQLite is used by default)

## Installation Steps

### 1. Clean Up Project Structure (Optional)

If your project structure has redundant files, run the cleanup script first:

```bash
# Run the cleanup script
cleanup.bat
```

### 2. Install Python Dependencies

Open Command Prompt as Administrator and run:

```bash
# Navigate to the project directory
cd c:\Users\monal\Desktop\phishingURL

# Create a virtual environment (if you don't already have one)
python -m venv venv

# Activate the virtual environment
venv\Scripts\activate

# Install required Python packages
pip install flask==2.3.3 flask-cors==4.0.0 requests==2.31.0 python-whois==0.8.0 beautifulsoup4==4.12.2 numpy==1.25.2 pandas==2.1.0 scikit-learn==1.3.0 xgboost==1.7.6 tldextract==3.4.4 python-dotenv==1.0.0 lxml==4.9.3 joblib==1.3.2 tqdm==4.66.1 certifi==2023.7.22
```

### 2. Run the Start Script

The project already includes a start script that will:
- Activate the virtual environment
- Install dependencies
- Train the ML models
- Start both backend and frontend servers

Simply run:

```bash
# Make sure you're in the project directory
cd c:\Users\monal\Desktop\phishingURL

# Run the start script
start_dev.bat
```

### 3. Access the Application

Once the servers are running:
- Frontend: http://localhost:3000
- Backend API: http://localhost:5000/api

## Manual Setup (Alternative)

If you prefer to start the services manually:

### Backend

```bash
# Navigate to the project directory
cd c:\Users\monal\Desktop\phishingURL

# Activate the virtual environment
venv\Scripts\activate

# Train models (if not already done)
cd backend
python train_models.py

# Start the backend server
python app.py
```

### Frontend

In a new terminal:

```bash
# Navigate to the frontend directory
cd c:\Users\monal\Desktop\phishingURL\frontend

# Install Node.js dependencies (if not already done)
npm install

# Start the frontend development server
npm run dev
```

## Troubleshooting

### Python Module Errors

If you see errors about missing Python modules:

```bash
pip install flask==2.3.3 flask-cors==4.0.0 requests==2.31.0 python-whois==0.8.0 beautifulsoup4==4.12.2 numpy==1.25.2 pandas==2.1.0 scikit-learn==1.3.0 xgboost==1.7.6 tldextract==3.4.4 python-dotenv==1.0.0 lxml==4.9.3 joblib==1.3.2
```

### Node.js Module Errors

If you see errors about missing Node.js modules:

```bash
cd frontend
npm install
```

### Port Conflicts

- If port 3000 is already in use, Next.js will automatically suggest an alternative
- If port 5000 is already in use, you can modify the backend port in app.py

### API Keys (Optional)

For full functionality with external services, create a `.env` file in the backend directory:

```
PHISHTANK_API_KEY=your_api_key_here
GOOGLE_SAFE_BROWSING_API_KEY=your_api_key_here
```

Without these keys, the application will still work using ML models only.
