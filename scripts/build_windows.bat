@echo off
REM ============================================================
REM Windows 构建脚本 - ransom_simulator（amd64 + arm64）
REM 用法: build_windows.bat [encryptor|decryptor|all]
REM ============================================================

setlocal enabledelayedexpansion

set PROJECT_ROOT=%~dp0..
set BUILD_DIR=%PROJECT_ROOT%\build\windows
set CMD_DIR=%PROJECT_ROOT%\cmd

if "%1"=="" set TARGET=all
if "%1"=="encryptor" set TARGET=encryptor
if "%1"=="decryptor" set TARGET=decryptor
if "%1"=="all" set TARGET=all

echo.
echo ============================================================
echo   Ransom Simulator - Windows Build Script (amd64 / arm64)
echo ============================================================
echo.

if not exist "%BUILD_DIR%" mkdir "%BUILD_DIR%"

if "%TARGET%"=="all" goto :build_all
if "%TARGET%"=="encryptor" goto :build_encryptor
if "%TARGET%"=="decryptor" goto :build_decryptor

:build_all
call :build_encryptor
call :build_decryptor
goto :done

:build_encryptor
echo [1/2] Building encryptor for Windows (amd64 + arm64)...
cd /d "%CMD_DIR%\encryptor\windows"
set CGO_ENABLED=0
set GOOS=windows

set GOARCH=amd64
go build -o "%BUILD_DIR%\ransom_simulator.exe" .
if errorlevel 1 goto :build_fail

set GOARCH=arm64
go build -o "%BUILD_DIR%\ransom_simulator_arm64.exe" .
if errorlevel 1 goto :build_fail

set GOARCH=
echo [OK] ransom_simulator.exe / ransom_simulator_arm64.exe built successfully.
goto :eof

:build_decryptor
echo [2/2] Building decryptor for Windows (amd64 + arm64)...
cd /d "%CMD_DIR%\decryptor"
set CGO_ENABLED=0
set GOOS=windows

set GOARCH=amd64
go build -o "%BUILD_DIR%\decryptor.exe" .
if errorlevel 1 goto :build_fail

set GOARCH=arm64
go build -o "%BUILD_DIR%\decryptor_arm64.exe" .
if errorlevel 1 goto :build_fail

set GOARCH=
echo [OK] decryptor.exe / decryptor_arm64.exe built successfully.
goto :eof

:build_fail
echo [FAIL] Build failed (GOARCH=%GOARCH%).
pause
exit /b 1

:done
echo.
echo ============================================================
echo   Build completed! Output directory: %BUILD_DIR%
echo ============================================================
dir /b "%BUILD_DIR%\*.exe"
echo.
pause
endlocal