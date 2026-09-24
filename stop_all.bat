@echo off
echo Stopping SentinelFlow services...
taskkill /f /im mongod.exe 2>nul
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":8000" ^| findstr "LISTENING"') do taskkill /f /pid %%a 2>nul
for /f "tokens=5" %%a in ('netstat -aon ^| findstr ":3000" ^| findstr "LISTENING"') do taskkill /f /pid %%a 2>nul
echo SentinelFlow services stopped.
pause
