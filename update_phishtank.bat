@echo off
echo Updating PhishTank Database...
echo.

cd %~dp0
cd backend
python update_phishtank_database.py

echo.
pause
