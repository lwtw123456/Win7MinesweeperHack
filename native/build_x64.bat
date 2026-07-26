@echo off
setlocal
cd /d "%~dp0"

cmake -S . -B build -A x64
if errorlevel 1 exit /b 1

cmake --build build --config Release
if errorlevel 1 exit /b 1

copy /Y ^
  "build\Release\MinesweeperWndProcHook.dll" ^
  "..\MinesweeperWndProcHook.dll"
if errorlevel 1 exit /b 1

echo.
echo DLL generated:
echo %CD%\..\MinesweeperWndProcHook.dll
