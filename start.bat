@echo off
setlocal enabledelayedexpansion
echo Inventory Manager
echo =================

:: Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo ERROR: Python not found. Install Python 3.10+ and try again.
    pause
    exit /b 1
)

:: Install dependencies if needed
if not exist ".venv" (
    echo Setting up virtual environment...
    python -m venv .venv
)
call .venv\Scripts\activate.bat
echo Installing/updating dependencies...
pip install -q -r requirements.txt

:: Resolve LAN IP (first IPv4 that isn't 127.x)
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /i "IPv4"') do (
    set RAW=%%a
    set RAW=!RAW: =!
    if not "!RAW:~0,3!"=="127" (
        if not defined LAN_IP set LAN_IP=!RAW!
    )
)

echo.
echo  Server is running!
echo  -----------------------------------------------
echo  Local  ^(this machine^) : http://localhost:8080
if defined LAN_IP (
    echo  Network ^(other PCs^)   : http://%LAN_IP%:8080
) else (
    echo  Network IP could not be detected automatically.
    echo  Run "ipconfig" and look for your IPv4 address.
)
echo  -----------------------------------------------
echo  Press Ctrl+C to stop the server.
echo.

python server.py
pause
