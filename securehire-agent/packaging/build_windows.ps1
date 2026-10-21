# Build a single-file Windows executable of the SecureHire Desktop Security Agent.
# Run from the securehire-agent folder in PowerShell:  .\packaging\build_windows.ps1
$ErrorActionPreference = "Stop"
python -m pip install -r requirements-dev.txt
python -m pytest -q
pyinstaller --noconfirm --onefile --windowed --name securehire-agent `
  --hidden-import uvicorn.logging --hidden-import uvicorn.loops.auto --hidden-import uvicorn.protocols.http.auto `
  --hidden-import uvicorn.lifespan.on `
  run_agent.py
Write-Host "Built dist\securehire-agent.exe"
Write-Host "Optional org config: copy config.example.json to %PROGRAMDATA%\SecureHireAgent\config.json"
