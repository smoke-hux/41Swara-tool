@echo off
REM 41Swara Smart Contract Scanner - Windows Installation Script

setlocal EnableDelayedExpansion

REM Colors (using Windows color codes)
set "RED=[91m"
set "GREEN=[92m"
set "YELLOW=[93m"
set "BLUE=[94m"
set "NC=[0m"

echo.
echo %BLUE%╔══════════════════════════════════════════════════════════╗%NC%
echo %BLUE%║           41Swara Smart Contract Scanner                ║%NC%
echo %BLUE%║              Windows Installation Script                ║%NC%
echo %BLUE%╚══════════════════════════════════════════════════════════╝%NC%
echo.

REM Check if running as administrator
net session >nul 2>&1
if %errorLevel% == 0 (
    echo %GREEN%[INFO]%NC% Running with administrator privileges
    set "ADMIN=1"
) else (
    echo %YELLOW%[WARNING]%NC% Not running as administrator. Installation will be local to user directory.
    set "ADMIN=0"
)

REM Set installation directory
if "%ADMIN%"=="1" (
    set "INSTALL_DIR=%ProgramFiles%\41Swara"
) else (
    set "INSTALL_DIR=%USERPROFILE%\41Swara"
)

echo %BLUE%[INFO]%NC% Installing to: %INSTALL_DIR%

REM Create installation directory
if not exist "%INSTALL_DIR%" (
    mkdir "%INSTALL_DIR%"
    if errorlevel 1 (
        echo %RED%[ERROR]%NC% Failed to create installation directory
        pause
        exit /b 1
    )
)

REM Check if binary exists in current directory
if exist "41swara-scanner-windows.exe" (
    echo %BLUE%[INFO]%NC% Found scanner executable
    copy "41swara-scanner-windows.exe" "%INSTALL_DIR%\41swara-scanner.exe" >nul
    if errorlevel 1 (
        echo %RED%[ERROR]%NC% Failed to copy binary
        pause
        exit /b 1
    )
) else (
    echo %RED%[ERROR]%NC% 41swara-scanner-windows.exe not found in current directory
    echo %YELLOW%[INFO]%NC% Please ensure you have downloaded the Windows executable
    pause
    exit /b 1
)

echo %GREEN%[SUCCESS]%NC% Binary installed to %INSTALL_DIR%

REM Add to PATH (requires admin privileges for system-wide)
echo %BLUE%[INFO]%NC% Configuring PATH...

if "%ADMIN%"=="1" (
    REM System-wide PATH update (requires admin)
    for /f "tokens=2*" %%a in ('reg query "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH 2^>nul') do set "CURRENT_PATH=%%b"
    echo !CURRENT_PATH! | findstr /i "%INSTALL_DIR%" >nul
    if errorlevel 1 (
        reg add "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" /v PATH /t REG_EXPAND_SZ /d "!CURRENT_PATH!;%INSTALL_DIR%" /f >nul
        echo %GREEN%[SUCCESS]%NC% Added to system PATH
    ) else (
        echo %YELLOW%[INFO]%NC% Already in system PATH
    )
) else (
    REM User-specific PATH update
    for /f "tokens=2*" %%a in ('reg query "HKCU\Environment" /v PATH 2^>nul') do set "CURRENT_USER_PATH=%%b"
    if "!CURRENT_USER_PATH!"=="" set "CURRENT_USER_PATH=%PATH%"
    echo !CURRENT_USER_PATH! | findstr /i "%INSTALL_DIR%" >nul
    if errorlevel 1 (
        reg add "HKCU\Environment" /v PATH /t REG_EXPAND_SZ /d "!CURRENT_USER_PATH!;%INSTALL_DIR%" /f >nul
        echo %GREEN%[SUCCESS]%NC% Added to user PATH
    ) else (
        echo %YELLOW%[INFO]%NC% Already in user PATH
    )
)

REM Verify installation
echo %BLUE%[INFO]%NC% Verifying installation...
"%INSTALL_DIR%\41swara-scanner.exe" --help >nul 2>&1
if errorlevel 1 (
    echo %RED%[ERROR]%NC% Installation verification failed
    pause
    exit /b 1
)

echo %GREEN%[SUCCESS]%NC% Installation completed successfully! 🎉
echo.
echo %BLUE%🚀 41Swara Scanner is now installed!%NC%
echo.
echo %GREEN%Quick Start:%NC%
echo   41swara-scanner --path MyContract.sol
echo   41swara-scanner --path contracts --verbose
echo.
echo %GREEN%Professional Audit Report:%NC%
echo   41swara-scanner --audit --project "MyProject" --sponsor "ClientName" --path Contract.sol
echo.
echo %GREEN%Get Help:%NC%
echo   41swara-scanner --help
echo   41swara-scanner --examples
echo.
echo %YELLOW%Note: You may need to restart your command prompt or PowerShell for PATH changes to take effect.%NC%
echo.
echo %BLUE%Documentation: https://github.com/41swara/41Swara-tool%NC%
echo.
pause