@echo off
SETLOCAL

echo ===== PhishGuard Development Startup Script =====

:: Check if Python is installed
where python >nul 2>nul
IF %ERRORLEVEL% NEQ 0 (
    echo Python is not installed or not in PATH
    echo Please install Python 3.9 or higher
    exit /b 1
)

:: Check if Node.js is installed
where node >nul 2>nul
IF %ERRORLEVEL% NEQ 0 (
    echo Node.js is not installed or not in PATH
    echo Please install Node.js 16 or higher
    exit /b 1
)

:: Create a virtual environment for the backend if it doesn't exist
IF NOT EXIST backend\venv (
    echo Creating Python virtual environment...
    cd backend
    python -m venv venv
    cd ..
)

:: Activate the virtual environment and install dependencies
echo Activating Python virtual environment and installing dependencies...
call backend\venv\Scripts\activate
cd backend
pip install -r requirements.txt

:: Check for API keys
IF "%PHISHTANK_API_KEY%"=="" (
    echo Warning: PHISHTANK_API_KEY environment variable not set
    echo For full functionality, please set this variable with your PhishTank API key
)

IF "%GOOGLE_SAFE_BROWSING_API_KEY%"=="" (
    echo Warning: GOOGLE_SAFE_BROWSING_API_KEY environment variable not set
    echo For full functionality, please set this variable with your Google Safe Browsing API key
)

:: Train models if they don't exist
IF NOT EXIST backend\models\uci_model.pkl (
    echo Training machine learning models...
    cd backend
    python train_models.py
    cd ..
)

:: Download datasets if they don't exist
IF NOT EXIST backend\data\phishtank_database.json (
    echo Downloading latest PhishTank database...
    cd backend
    python download_datasets.py --source phishtank
    cd ..
)

IF NOT EXIST backend\data\uci_dataset.csv (
    echo Downloading UCI Phishing Websites dataset...
    cd backend
    python download_datasets.py --source uci
    cd ..
)

:: Start the backend in a new window
echo Starting backend server...
start "PhishGuard Backend" cmd /c "call venv\Scripts\activate && python app.py"
cd ..

:: Install frontend dependencies if node_modules doesn't exist
IF NOT EXIST frontend\node_modules (
    echo Installing frontend dependencies...
    cd frontend
    npm install
    cd ..
)

:: Start the frontend in a new window
echo Starting frontend server...
cd frontend
start "PhishGuard Frontend" cmd /c "npm run dev"
cd ..

echo.
echo PhishGuard development environment is now running!
echo Backend: http://localhost:5000
echo Frontend: http://localhost:3000
echo.
echo Press Ctrl+C in each terminal window to stop the servers when done.

ENDLOCAL
