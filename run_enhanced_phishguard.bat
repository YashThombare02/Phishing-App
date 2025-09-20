@echo off
echo Updating PhishGuard with enhanced PhishTank database...
echo.

cd /d "%~dp0"
cd backend

echo Running update_phishtank.py to install enhanced phishing database...
python update_phishtank.py

echo.
echo Restarting backend server with enhanced phishing detection...
echo.

if exist app.py (
    python app.py
) else (
    echo Error: app.py not found in the backend directory
    exit /b 1
)

echo.
echo PhishGuard is now running with enhanced phishing detection capabilities!
echo.
