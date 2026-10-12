@echo off
REM ============================================================
REM Windows 构建脚本 - ransom_simulator
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
echo   Ransom Simulator - Windows Build Script
echo ============================================================
echo.

if "%TARGET%"=="all" goto :build_all
if "%TARGET%"=="encryptor" goto :build_encryptor
if "%TARGET%"=="decryptor" goto :build_decryptor

:build_all
call :build_encryptor
call :build_decryptor
goto :done

:build_encryptor
echo [1/2] Building encryptor for Windows...
cd /d "%CMD_DIR%\encryptor\windows"
go build -o "%BUILD_DIR%\ransom_simulator.exe" .
if %ERRORLEVEL% EQU 0 (
    echo [OK] ransom_simulator.exe built successfully.
) else (
    echo [FAIL] Failed to build ransom_simulator.exe
    pause
    exit /b 1
)
goto :eof

:build_decryptor
echo [2/2] Building decryptor for Windows...
cd /d "%CMD_DIR%\decryptor"
go build -o "%BUILD_DIR%\decryptor.exe" .
if %ERRORLEVEL% EQU 0 (
    echo [OK] decryptor.exe built successfully.
) else (
    echo [FAIL] Failed to build decryptor.exe
    pause
    exit /b 1
)
goto :eof

:done
echo.
echo ============================================================
echo   Build completed! Output directory: %BUILD_DIR%
echo ============================================================
dir /b "%BUILD_DIR%\*.exe"
echo.
pause
endlocal