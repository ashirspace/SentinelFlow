@echo off
echo ===================================================
echo           Starting SentinelFlow SIEM Platform
echo ===================================================

:: 1. Start MongoDB
echo [1/3] Starting MongoDB daemon (port 27017)...
start "SentinelFlow MongoDB" /min "%~dp0.runtime\mongodb-win32-x86_64-windows-4.4.29\bin\mongod.exe" --dbpath "%~dp0.runtime\mongo-data" --bind_ip 127.0.0.1 --port 27017 --logpath "%~dp0.runtime\logs\mongod.log" --logappend

:: Wait 2 seconds for MongoDB
timeout /t 2 /nobreak >nul

:: 2. Start FastAPI Backend
echo [2/3] Starting FastAPI Backend (port 8000)...
start "SentinelFlow Backend" cmd /k "cd /d %~dp0backend && python -m uvicorn server:app --host 127.0.0.1 --port 8000"

:: Wait 3 seconds for backend
timeout /t 3 /nobreak >nul

:: 3. Start React Frontend
echo [3/3] Starting React Frontend (port 3000)...
start "SentinelFlow Frontend" cmd /k "cd /d %~dp0frontend && npm start"

echo.
echo ===================================================
echo SentinelFlow is starting up!
echo - Frontend UI:    http://localhost:3000
echo - Backend API:    http://localhost:8000/api/
echo - API Docs:       http://localhost:8000/docs
echo.
echo Default Credentials:
echo - Admin:   admin@sentinelflow.io   / Admin@12345
echo - Analyst: analyst@sentinelflow.io / Analyst@123
echo ===================================================
timeout /t 5 >nul
