@echo off
REM ArgusML Windows Installer
REM Built by Juan Manuel De La Garza

echo ============================================================
echo   ARGUS-ML Windows Installer
echo   Autonomous ML-powered IDPS
echo ============================================================
echo.

REM Check Python
python --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] Python not found. Please install Python 3.12+
    echo Download from: https://www.python.org/downloads/
    pause
    exit /b 1
)
echo [OK] Python found

REM Check pip
pip --version >nul 2>&1
if errorlevel 1 (
    echo [ERROR] pip not found
    pause
    exit /b 1
)
echo [OK] pip found

REM Create virtual environment
echo.
echo [*] Creating virtual environment...
python -m venv argusml-env
call argusml-env\Scripts\activate.bat

REM Install dependencies
echo [*] Installing dependencies...
pip install -r requirements.txt

REM Create directories
echo [*] Creating directories...
mkdir "%APPDATA%\ArgusML\models" 2>nul
mkdir "%APPDATA%\ArgusML\datasets" 2>nul
mkdir "%APPDATA%\ArgusML\output" 2>nul
mkdir "%APPDATA%\ArgusML\rules" 2>nul

REM Check Suricata
echo.
echo [*] Checking Suricata installation...
if exist "C:\Program Files\Suricata\suricata.exe" (
    echo [OK] Suricata found
) else (
    echo [WARNING] Suricata not found
    echo Please install Suricata from: https://suricata.io/download/
    echo ArgusML will still install but needs Suricata to detect threats
)

REM Check Ollama
echo.
echo [*] Checking Ollama installation...
ollama --version >nul 2>&1
if errorlevel 1 (
    echo [WARNING] Ollama not found
    echo For LLM rule generation, install from: https://ollama.ai
    echo Then run: ollama pull llama3
) else (
    echo [OK] Ollama found
    echo [*] Pulling llama3 model...
    ollama pull llama3
)

REM Train models
echo.
echo [*] Training ML models...
python argus_ml.py --train

REM Install as scheduled task
echo.
echo [*] Installing ArgusML as Windows startup task...
python -c "from core.platform_support import install_windows_service; install_windows_service()"

echo.
echo ============================================================
echo   ArgusML Installation Complete!
echo ============================================================
echo.
echo   Dashboard: http://localhost:5002
echo   REST API:  http://localhost:5001
echo.
echo   To start manually: python argus_ml.py
echo   To start dashboard: python dashboard\cloud_dashboard.py
echo   To start API: python dashboard\api.py
echo.
pause
