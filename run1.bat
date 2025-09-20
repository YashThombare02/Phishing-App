@echo off

echo 2. Starting backend server...
start cmd /k "cd %~dp0 && call venv\Scripts\activate.bat && cd backend && python app.py"

echo 3. Starting frontend server...
start cmd /k "cd %~dp0\frontend && npm run dev"