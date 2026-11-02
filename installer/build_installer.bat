@echo off
rem Builds installer\build\AdaptiveHoneypot-Setup-1.0.0.exe on Windows.
rem Needs: Python 3.10+ (pip install zstandard) and NSIS 3 (makensis on PATH, https://nsis.sourceforge.io)
cd /d "%~dp0"
if not exist build mkdir build
if not exist build\python\python.exe python fetch_python.py || goto :err
makensis -V2 launcher.nsi || goto :err
makensis -V2 -DSTOP launcher.nsi || goto :err
makensis -V2 installer.nsi || goto :err
echo Done. Installer is in installer\build
exit /b 0
:err
echo Build failed.
exit /b 1
