@echo off
REM Start the Phishing Detector API Server
REM This script starts the Flask API that powers the Chrome extension

echo.
echo ========================================
echo   Phishing Detector API Server
echo ========================================
echo.

REM Check if Python is installed
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python is not installed or not in PATH
    echo Please install Python 3.8+ from python.org
    pause
    exit /b 1
)

echo Starting API server on http://localhost:5000
echo Press Ctrl+C to stop the server
echo.

REM Change to the phishing-detector directory
cd /d %~dp0

REM Run the API server
python python/api_server.py

REM If we get here, the server crashed
echo.
echo Server stopped (or crashed)
pause
