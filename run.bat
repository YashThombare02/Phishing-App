@echo off
echo PhishGuard Runner Script
echo =====================
echo.

echo 1. Checking for missing dependencies...
call venv\Scripts\activate.bat
pip install -r requirements.txt

echo 2. Starting backend server...
start cmd /k "cd %~dp0 && call venv\Scripts\activate.bat && cd backend && python app.py"

echo 3. Starting frontend server...
start cmd /k "cd %~dp0\frontend && npm run dev"

echo.
echo PhishGuard is now running!
echo - Frontend: http://localhost:3000
echo - Backend API: http://localhost:5000/api
echo.
echo You can close this window now.
