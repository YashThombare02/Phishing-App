@echo off
echo PhishGuard Quick Start Script
echo ===========================
echo.

echo 1. Creating Python virtual environment...
if not exist venv (
    python -m venv venv
)

echo 2. Activating virtual environment...
call venv\Scripts\activate.bat

echo 3. Installing Python dependencies...
pip install -r backend\requirements.txt
pip install sqlalchemy python-dotenv

echo 4. Setting up database (SQLite)...
echo DB_TYPE=sqlite > backend\.env.tmp
echo SQLITE_DB_PATH=phishing_database.db >> backend\.env.tmp
echo. >> backend\.env.tmp
echo # API Keys >> backend\.env.tmp
echo PHISHTANK_API_KEY=your_phishtank_key_here >> backend\.env.tmp
echo GOOGLE_SAFE_BROWSING_API_KEY=your_google_key_here >> backend\.env.tmp

if exist backend\.env (
    echo Keeping existing .env file
) else (
    move backend\.env.tmp backend\.env
)

echo 5. Downloading datasets and training models...
cd backend
python download_datasets.py
python train_models.py

echo 6. Starting backend server...
start cmd /k "call ..\venv\Scripts\activate.bat && python app.py"
cd ..

echo 7. Setting up frontend...
cd frontend
call npm cache clean --force
call npm install

echo 8. Starting frontend server...
start cmd /k "npm run dev"

echo.
echo PhishGuard is now running!
echo - Frontend: http://localhost:3000
echo - Backend API: http://localhost:5000/api
echo.
echo You can close this window now.
