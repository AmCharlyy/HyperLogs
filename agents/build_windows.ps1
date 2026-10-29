$ErrorActionPreference = 'Stop'
python -m pip install --disable-pip-version-check pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --name HyperLogsAgent --paths agents --collect-submodules psutil agents/agent.py
python -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin --name HyperLogsSetup --paths agents agents/setup_gui.py
Write-Host 'Executables ready in dist/: HyperLogsSetup.exe and HyperLogsAgent.exe'
