@echo off
setlocal

rem Build a diagnostic .zgame for the requested Isaac Repentance installation.
rem This script reads the game folder; generated build files stay in this repository.

set "ROOT=%~dp0.."
set "GAME_DIR=C:\TBOIRG\The Binding of Isaac Rebirth Repentance v1.7.9c"
set "OUTPUT=%ROOT%\dist\isaac-repentance-1.7.9c.zgame"
set "WORK_DIR=%ROOT%\.build\isaac-repentance-1.7.9c"

if not exist "%GAME_DIR%\" (
    echo [ZWASM] ERROR: game directory not found:
    echo "%GAME_DIR%"
    exit /b 2
)

if not exist "%ROOT%\dist" mkdir "%ROOT%\dist"
if errorlevel 1 exit /b 2

python "%ROOT%\tools\zwasm_build.py" "%GAME_DIR%" --output "%OUTPUT%" --work-dir "%WORK_DIR%"
if errorlevel 1 (
    echo [ZWASM] Build failed with exit code %errorlevel%.
    exit /b %errorlevel%
)

echo [ZWASM] READY: %OUTPUT%
echo [ZWASM] SHELL: %ROOT%\web\index.html
echo [ZWASM] Next: open the shell and load the package to capture import/runtime diagnostics.
exit /b 0
