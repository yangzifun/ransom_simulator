@echo off
REM ============================================================
REM 解密器构建脚本 - ransom_simulator
REM 用法: build_decryptor.bat
REM ============================================================

setlocal

set PROJECT_ROOT=%~dp0..
set BUILD_DIR=%PROJECT_ROOT%\build\decryptor
set CMD_DIR=%PROJECT_ROOT%\cmd\decryptor

echo.
echo ============================================================
echo   Building Decryptor
echo ============================================================
echo.

cd /d "%CMD_DIR%"
go build -o "%BUILD_DIR%\decryptor.exe" .
if %ERRORLEVEL% EQU 0 (
    echo [OK] decryptor.exe built successfully.
    echo Output: %BUILD_DIR%\decryptor.exe
) else (
    echo [FAIL] Build failed.
    exit /b 1
)

echo.
endlocal
