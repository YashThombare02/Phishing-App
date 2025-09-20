@echo off
echo PhishGuard Installation Script
echo =============================
echo.

echo 1. Creating Python virtual environment...
if not exist venv (
    python -m venv venv
    echo Virtual environment created.
) else (
    echo Virtual environment already exists.
)

echo 2. Activating virtual environment...
call venv\Scripts\activate.bat

echo 3. Installing Python dependencies...
pip install -r requirements.txt

echo 4. Setting up frontend dependencies...
cd frontend
call npm install

echo.
echo Installation complete!
echo.
echo To run the application, use:
echo   run.bat
echo.
pause
