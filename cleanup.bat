@echo off
echo Cleaning up PhishGuard project structure...

echo.
echo 1. Removing redundant files and folders...
echo ------------------------------

:: Remove src folder (redundant with backend)
if exist src (
    echo Removing redundant src folder...
    rd /s /q src
)

:: Remove duplicate requirements file
if exist requirements.txt (
    echo Moving main requirements to backend if needed...
    if not exist backend\requirements.txt (
        move requirements.txt backend\
    ) else (
        del requirements.txt
    )
)

:: Remove setup scripts if they exist (we have start_dev scripts)
if exist setup.bat (
    echo Removing redundant setup.bat...
    del setup.bat
)

if exist setup.sh (
    echo Removing redundant setup.sh...
    del setup.sh
)

:: Create necessary folders if they don't exist
echo.
echo 2. Creating necessary folders...
echo ------------------------------
if not exist backend\data mkdir backend\data
if not exist backend\models mkdir backend\models
if not exist backend\logs mkdir backend\logs

:: Move data to backend if it exists
if exist data (
    echo Moving data folder contents to backend\data...
    xcopy /s /e /y data\* backend\data\
    rd /s /q data
)

:: Move models to backend if it exists
if exist models (
    echo Moving models folder contents to backend\models...
    xcopy /s /e /y models\* backend\models\
    rd /s /q models
)

:: Move logs to backend if it exists
if exist logs (
    echo Moving logs folder contents to backend\logs...
    xcopy /s /e /y logs\* backend\logs\
    rd /s /q logs
)

echo.
echo 3. Updating README file...
echo ------------------------------
if exist README_NEW.md (
    echo Replacing old README with new structure documentation...
    del README.md
    rename README_NEW.md README.md
)

echo.
echo 4. Project structure cleanup complete!
echo ------------------------------
echo Your PhishGuard project now has a cleaner structure:
echo  - backend/: Contains all Python code, models, and data
echo  - frontend/: Contains the Next.js frontend
echo  - SETUP_GUIDE.md: Installation instructions
echo  - start_dev.bat/.sh: Scripts to start the application
echo.
echo You may now need to update the paths in your code to reflect these changes.
