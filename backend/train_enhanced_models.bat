@echo off
echo.
echo ======================================================
echo   Enhanced Phishing Detection Model Training Script
echo ======================================================
echo.

cd %~dp0
echo Current directory: %CD%
echo.

echo Setting up the environment...
echo.

REM Check if Python is installed
python --version >nul 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo Python is not installed or not in PATH!
    echo Please install Python 3.7 or higher and try again.
    exit /b 1
)

REM Install required packages
echo Installing required packages...
pip install -q numpy pandas scikit-learn xgboost tqdm tldextract urllib3 requests
if %ERRORLEVEL% NEQ 0 (
    echo Failed to install required packages!
    exit /b 1
)
echo Required packages installed successfully.
echo.

REM Check for the datasets
echo Checking for datasets...
if not exist "data\combined_urls.csv" (
    if not exist "data\legitimate_urls.csv" (
        echo No datasets found!
        echo Please make sure datasets are available in the data directory.
        echo.
    )
)

REM Train the models
echo Starting model training...
echo This may take several minutes depending on your dataset size.
echo.

python train_models.py

echo.
echo ======================================================
echo   Model training completed!
echo ======================================================
echo.
echo The enhanced phishing detection models are now trained.
echo.
echo To use the new models, restart the backend server:
echo python app.py
echo.

pause