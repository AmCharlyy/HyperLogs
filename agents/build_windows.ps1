param(
    [string]$ServerUrl = '',
    [string]$CertificatePath = '.runtime\caddy-root.crt'
)
$ErrorActionPreference = 'Stop'
if (-not $ServerUrl -and (Test-Path -LiteralPath '.env')) {
    $entry = Get-Content -LiteralPath '.env' | Where-Object { $_ -match '^HYPERLOGS_PUBLIC_URL=' } | Select-Object -First 1
    if ($entry) { $ServerUrl = ($entry -split '=', 2)[1].Trim() }
}
if (-not $ServerUrl) { $ServerUrl = 'https://localhost:8443' }
if (-not (Test-Path -LiteralPath $CertificatePath)) { throw "Certificate not found: $CertificatePath. Start Caddy and export its root CA first." }
$assetDirectory = Join-Path (Resolve-Path '.').Path 'build\setup-assets'
New-Item -ItemType Directory -Force -Path $assetDirectory | Out-Null
$deploymentPath = Join-Path $assetDirectory 'deployment.json'
@{ server = $ServerUrl } | ConvertTo-Json -Compress | Set-Content -LiteralPath $deploymentPath -Encoding UTF8
python -m pip install --disable-pip-version-check pyinstaller
python -m PyInstaller --noconfirm --clean --onefile --name HyperLogsAgent --paths agents --collect-submodules psutil agents/agent.py
python -m PyInstaller --noconfirm --clean --onefile --windowed --uac-admin --name HyperLogsSetup --paths agents --add-binary "dist\HyperLogsAgent.exe;." --add-data "$CertificatePath;." --add-data "$deploymentPath;." agents/setup_gui.py
Write-Host "Single installer ready: dist/HyperLogsSetup.exe -> $ServerUrl"
