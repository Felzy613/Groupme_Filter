@echo off
REM Build script for Windows
REM Creates a standalone .exe for Windows
REM Run from project root: build_scripts\build_windows.bat

echo Building GroupMeBlocker for Windows...

REM Check if we're in the right directory
if not exist "src\GroupMe_Blocker.py" (
    echo Error: src\GroupMe_Blocker.py not found. Please run this script from the project root.
    exit /b 1
)

REM Clean previous builds
if exist build rmdir /s /q build
if exist dist rmdir /s /q dist

REM Build the app
pyinstaller --onedir --windowed --name GroupMeBlocker ^
    --hidden-import=tkinter ^
    --hidden-import=cryptography ^
    src\GroupMe_Blocker.py

echo.
echo Build complete!
echo.
echo The app is ready at: .\dist\GroupMeBlocker\GroupMeBlocker.exe
echo.
echo You can now distribute the entire .\dist\GroupMeBlocker folder
echo to other Windows users. They can extract it and run GroupMeBlocker.exe
echo without needing Python installed.
