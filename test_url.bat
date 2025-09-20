@echo off
echo Testing PhishGuard Enhanced Detection
echo.

cd /d "%~dp0\backend"

IF "%~1"=="" (
    echo Testing with default URL (paypal-secure-login.com)
    python test_enhanced_detection.py
) ELSE (
    echo Testing URL: %1
    python test_enhanced_detection.py %1
)

echo.
pause
