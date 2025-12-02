@echo off
cd /d "%~dp0"
echo "Starting production server..."
waitress-serve --host 0.0.0.0 --port 8080 app:app
pause
