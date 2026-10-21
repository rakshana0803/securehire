@echo off
REM Start the SecureHire Desktop Security Agent (shows a status window). Requires Python 3.10+ for Windows.
cd /d "%~dp0"
if not exist .venv (
  python -m venv .venv
  .venv\Scripts\python -m pip install -r requirements.txt
)
.venv\Scripts\python -m agent.main %*
