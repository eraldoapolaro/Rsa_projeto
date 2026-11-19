@echo off
cd /d "%~dp0"
where py >nul 2>nul
if errorlevel 1 (
    python decifrar.py
) else (
    py -3 decifrar.py
)
if errorlevel 1 pause
