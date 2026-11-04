@echo off
cd /d "%~dp0"
set DEV_BYPASS_AUTH=1
set BIND_HOST=127.0.0.1
"%~dp0.venv\Scripts\python.exe" -m uvicorn app.main:app --host 127.0.0.1 --port 8000
