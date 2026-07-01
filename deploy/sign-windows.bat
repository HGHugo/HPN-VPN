@echo off
REM Azure Trusted Signing wrapper for Tauri signCommand
REM Called by Tauri with: sign-windows.bat <file-to-sign>

if "%AZURE_CLIENT_ID%"=="" (
    echo SKIP signing - no Azure credentials: %1
    exit /b 0
)

set SIGNTOOL=C:\Program Files (x86)\Windows Kits\10\bin\10.0.26100.0\x64\signtool.exe
set METADATA=%TEMP%\hpn-signing-metadata.json

REM Find dlib
for /r "%CI_PROJECT_DIR%\.signing" %%f in (Azure.CodeSigning.Dlib.dll) do (
    echo %%~dpf | findstr /i "x64" >nul && set DLIB=%%f
)

if not defined DLIB (
    echo ERROR: Azure.CodeSigning.Dlib.dll not found
    exit /b 1
)

REM Retry with exponential backoff + fallback timestamp servers.
REM Microsoft ACS timestamp server occasionally returns transient errors
REM even when Azure-side signing succeeded; cycling through DigiCert /
REM Sectigo / GlobalSign avoids single-provider outage failures.
set TS1=http://timestamp.acs.microsoft.com
set TS2=http://timestamp.digicert.com
set TS3=http://timestamp.sectigo.com
set TS4=http://timestamp.globalsign.com/tsa/r6advanced1

for /L %%A in (1,1,5) do (
    call :try_sign %%A %1
    if not errorlevel 1 exit /b 0
)
echo ERROR: Signing failed for %1 after 5 attempts
exit /b 1

:try_sign
set ATTEMPT=%1
shift
if "%ATTEMPT%"=="1" set TS=%TS1%
if "%ATTEMPT%"=="2" set TS=%TS2%
if "%ATTEMPT%"=="3" set TS=%TS3%
if "%ATTEMPT%"=="4" set TS=%TS4%
if "%ATTEMPT%"=="5" set TS=%TS1%
echo Signing attempt %ATTEMPT%/5 using timestamp server: %TS%
echo Signing: %1
"%SIGNTOOL%" sign /v /fd SHA256 /tr %TS% /td SHA256 /dlib "%DLIB%" /dmdf "%METADATA%" %1
if errorlevel 1 (
    echo Sign attempt %ATTEMPT% failed
    timeout /t %ATTEMPT% /nobreak >nul 2>&1
    exit /b 1
)
echo Signed: %1
exit /b 0
