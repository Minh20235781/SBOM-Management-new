@echo off
setlocal
set ROOT_DIR=%~dp0
set JAVA_HOME=%USERPROFILE%\.jdks\jdk-21
set PATH=%JAVA_HOME%\bin;%PATH%

echo ============================================================
echo   STARTING SBOM RISK ANALYSIS SYSTEM (ALL SERVICES)
echo ============================================================

echo [1/4] Starting GNN Service on http://localhost:8000...
start "GNN Service (:8000)" /D "%ROOT_DIR%gnn-training" cmd /k "python -m uvicorn api.server:app --host 0.0.0.0 --port 8000"

echo [2/4] Starting RandomForest Service on http://localhost:8002...
set RF_MODEL_PATH=%ROOT_DIR%ml-zenodo-a\rf\random_forest_sbom_real_v2.pkl
set RF_SCALER_PATH=%ROOT_DIR%ml-zenodo-a\rf\scaler_real_v2.pkl
start "RF Service (:8002)" /D "%ROOT_DIR%gnn-training" cmd /k "python -m uvicorn api.rf_server:app --host 0.0.0.0 --port 8002"

echo [3/4] Starting Spring Boot Backend on http://localhost:8080...
start "Backend Spring Boot (:8080)" /D "%ROOT_DIR%demo" cmd /k "mvnw.cmd spring-boot:run"

echo [4/4] Starting Frontend Dashboard on http://localhost:5173...
start "Frontend React (:5173)" /D "%ROOT_DIR%sbom-frontend" cmd /k "npm run dev"

echo ============================================================
echo   All 4 services launched!
echo   - Frontend: http://localhost:5173
echo   - Backend:  http://localhost:8080
echo   - GNN:      http://localhost:8000
echo   - RF:       http://localhost:8002
echo   - H2 DB:    http://localhost:8080/h2-console
echo ============================================================
pause
