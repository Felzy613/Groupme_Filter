@echo off
REM Quick build helper for Windows
REM Usage: build.bat
cd /d "%~dp0"
call build_scripts\build_windows.bat
