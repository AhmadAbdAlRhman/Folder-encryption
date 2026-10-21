@echo off
setlocal
title Vault Locker - Install
set "APPNAME=Vault Locker"
set "SRC=%~dp0%APPNAME%.exe"
set "APPDIR=%LOCALAPPDATA%\Programs\%APPNAME%"
set "EXE=%APPDIR%\%APPNAME%.exe"

if not exist "%SRC%" goto :missing

echo Installing to "%APPDIR%" ...
if not exist "%APPDIR%" mkdir "%APPDIR%"
copy /Y "%SRC%" "%EXE%" >nul
if errorlevel 1 goto :copyfail

echo Registering .vault file type ...
reg add "HKCU\Software\Classes\.vault" /ve /d "VaultLocker.File" /f >nul
reg add "HKCU\Software\Classes\VaultLocker.File" /ve /d "Encrypted Vault" /f >nul
reg add "HKCU\Software\Classes\VaultLocker.File\DefaultIcon" /ve /d "\"%EXE%\",0" /f >nul
reg add "HKCU\Software\Classes\VaultLocker.File\shell\open" /ve /d "Open with Vault Locker" /f >nul
reg add "HKCU\Software\Classes\VaultLocker.File\shell\open\command" /ve /d "\"%EXE%\" \"%%1\"" /f >nul

echo Creating Start menu shortcut ...
powershell -NoProfile -ExecutionPolicy Bypass -Command "$p=[Environment]::GetFolderPath('Programs'); $s=(New-Object -ComObject WScript.Shell).CreateShortcut($p+'\Vault Locker.lnk'); $s.TargetPath='%EXE%'; $s.WorkingDirectory='%APPDIR%'; $s.Save()"

ie4uinit.exe -show >nul 2>&1

echo.
echo Done. Double-click any .vault file to open it with Vault Locker.
echo (If the icon does not refresh right away, sign out and back in.)
pause
exit /b 0

:missing
echo ERROR: "%APPNAME%.exe" was not found next to this script.
echo Copy it from the "dist" folder to the same folder as install.bat.
pause
exit /b 1

:copyfail
echo ERROR: could not copy the file. Close Vault Locker if it is running and try again.
pause
exit /b 1
