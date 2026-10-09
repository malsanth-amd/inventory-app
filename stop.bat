@echo off
echo Stopping Inventory Manager server on port 8080...

for /f "tokens=5" %%a in ('netstat -ano ^| findstr :8080 2^>nul') do (
    echo Found PID %%a — terminating...
    taskkill /PID %%a /F >nul 2>&1
)

echo Done. Server stopped.
pause
