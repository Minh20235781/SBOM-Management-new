# Start two Python ML services for the SBOM dashboard.
# - GNN inference              : http://localhost:8000  (GAT + GCN)
# - RandomForest (Zenodo 13-f) : http://localhost:8002
#
# Each service keeps its model loaded in memory, so subsequent
# /predict calls are fast (no pickle load on every request).
#
# Run from the project root: powershell -ExecutionPolicy Bypass -File .\start_ml_services.ps1

$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
$gnnDir     = Join-Path $projectRoot 'gnn-training'
$rfRealDir  = Join-Path $projectRoot 'ml-zenodo-a\rf'
Set-Location $gnnDir

if (-not (Test-Path 'api\server.py')) {
    Write-Host "[ERROR] api\server.py not found under $gnnDir" -ForegroundColor Red
    exit 1
}
if (-not (Test-Path 'api\rf_server.py')) {
    Write-Host "[ERROR] api\rf_server.py not found under $gnnDir" -ForegroundColor Red
    exit 1
}

Write-Host '============================================================' -ForegroundColor Cyan
Write-Host ' Starting GNN inference on :8000' -ForegroundColor Cyan
Write-Host ' Starting RandomForest (Zenodo 13-f) on :8002' -ForegroundColor Cyan
Write-Host '============================================================' -ForegroundColor Cyan

# Each service in its own PowerShell window
Start-Process -FilePath 'powershell' -ArgumentList @(
    '-NoExit', '-Command', 'uvicorn api.server:app --host 0.0.0.0 --port 8000'
) -WindowStyle Normal -WorkingDirectory $gnnDir

# Zenodo-trained RF: read model+scaler from ml-zenodo-a/rf/ at startup;
# feature order is auto-detected from scaler.n_features_in_ (13).
# Absolute paths via Join-Path so the env vars don't depend on cwd.
$env:RF_MODEL_PATH  = Join-Path $rfRealDir 'random_forest_sbom_real_v2.pkl'
$env:RF_SCALER_PATH = Join-Path $rfRealDir 'scaler_real_v2.pkl'
Start-Process -FilePath 'powershell' -ArgumentList @(
    '-NoExit', '-Command', 'uvicorn api.rf_server:app --host 0.0.0.0 --port 8002'
) -WindowStyle Normal -WorkingDirectory $gnnDir

Write-Host 'Services launched. Close their windows to stop them.' -ForegroundColor Green
