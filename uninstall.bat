@echo off
setlocal
title Vault Locker - Uninstall
set "APPNAME=Vault Locker"
set "APPDIR=%LOCALAPPDATA%\Programs\%APPNAME%"

echo Removing file association ...
reg delete "HKCU\Software\Classes\.vault" /f >nul 2>&1
reg delete "HKCU\Software\Classes\VaultLocker.File" /f >nul 2>&1

echo Removing Start menu shortcut ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "Remove-Item -ErrorAction SilentlyContinue ([Environment]::GetFolderPath('Programs')+'\Vault Locker.lnk')"

echo Removing program files ...
if exist "%APPDIR%" rmdir /s /q "%APPDIR%"

echo.
echo Done. Your .vault files were NOT deleted.
pause
