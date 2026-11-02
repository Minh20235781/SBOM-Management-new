@echo off
REM Start Spring Boot with GitHub token for higher API rate limit (5000 vs 60 req/h).
REM Edit GITHUB_TOKEN below. Keep this file out of source control.

setlocal

REM >>> Replace this with your actual token <<<
set GITHUB_TOKEN=ghp_REPLACE_ME_WITH_YOUR_TOKEN

REM Optional: forward other env vars the backend already uses.
set SPRING_PROFILES_ACTIVE=%SPRING_PROFILE_ACTIVE%

cd /d "%~dp0"

echo ============================================================
echo  Starting Spring Boot with GITHUB_TOKEN=%GITHUB_TOKEN:~0,8%...
echo ============================================================

mvn spring-boot:run

endlocal
