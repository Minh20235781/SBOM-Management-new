@echo off
REM Start three Python ML services for the SBOM dashboard.
REM - GNN inference               : http://localhost:8000  (GAT + GCN)
REM - RandomForest (legacy 7-fe) : http://localhost:8001
REM - RandomForest (Zenodo 13-f) : http://localhost:8002
REM
REM Each service keeps its model loaded in memory, so
REM subsequent /predict calls are fast (no pickle load on
REM every request).
REM
REM Run this from the project root: .\start_ml_services.bat

setlocal

set SCRIPT_DIR=%~dp0
pushd "%SCRIPT_DIR%gnn-training"

if not exist "api\server.py" (
  echo [ERROR] api\server.py not found under %SCRIPT_DIR%gnn-training
  popd
  exit /b 1
)

if not exist "api\rf_server.py" (
  echo [ERROR] api\rf_server.py not found under %SCRIPT_DIR%gnn-training
  popd
  exit /b 1
)

echo ============================================================
echo  Starting GNN inference on :8000
echo  Starting RandomForest (legacy) on :8001
echo  Starting RandomForest (Zenodo 13-f) on :8002
echo  Press Ctrl+C in any window to stop it
echo ============================================================

REM Launch GNN service in its own window
start "GNN inference (:8000)" cmd /k "uvicorn api.server:app --host 0.0.0.0 --port 8000"

REM Launch legacy RandomForest service in its own window
start "RandomForest legacy (:8001)" cmd /k "uvicorn api.rf_server:app --host 0.0.0.0 --port 8001"

REM Launch Zenodo-trained RandomForest service in its own window.
REM Reads the 13-feature model + scaler from ml-zenodo-a/rf/ at startup;
REM feature order is auto-detected from scaler.n_features_in_.
REM
REM Absolute paths (NOT relative) because `start /D` opens a NEW
REM cmd window whose cwd is the script directory, not gnn-training
REM -- relative paths like ..\..\ml-zenodo-a\... would resolve
REM against the wrong root.
set RF_MODEL_PATH=%SCRIPT_DIR%ml-zenodo-a\rf\random_forest_sbom_real_v2.pkl
set RF_SCALER_PATH=%SCRIPT_DIR%ml-zenodo-a\rf\scaler_real_v2.pkl
start "RandomForest Zenodo (:8002)" cmd /k "uvicorn api.rf_server:app --host 0.0.0.0 --port 8002"

popd
endlocal
