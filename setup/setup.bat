@echo off
setlocal
cd /d "%~dp0"
title Pure Guard setup
set ADB=adb\adb.exe
echo ================================================
echo   Pure Guard setup (one phone at a time)
echo ================================================
echo 1. On the phone: Settings ^> About phone ^> tap "Build number" 7 times.
echo 2. Developer options: turn on "USB debugging".
echo    Xiaomi/Redmi/POCO: also "Install via USB" and "USB debugging (Security settings)".
echo 3. Plug the phone in and tap "Allow" on the phone.
echo.
echo Waiting for the phone...
%ADB% wait-for-device
:install
echo.
echo Installing Pure Guard...
%ADB% install -r PureGuard.apk <nul
if errorlevel 1 (
  echo Install failed. Xiaomi/Redmi/POCO: turn on "Install via USB" in Developer options, then run this again.
  goto end
)
%ADB% push setup.sh /data/local/tmp/pureguard-setup.sh <nul >nul
%ADB% shell sh /data/local/tmp/pureguard-setup.sh <nul
%ADB% shell rm /data/local/tmp/pureguard-setup.sh <nul
echo.
echo DONE. Finish on the phone: do the Xiaomi steps if shown, then create the unlock password.
:end
echo.
pause
