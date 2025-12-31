# Building & Packaging GroupMeBlocker

This guide explains how to package GroupMeBlocker into standalone executables for macOS and Windows.

## Prerequisites

```bash
pip install -r requirements.txt
pip install pyinstaller
```

## macOS Packaging

### Option 1: Build a Standalone App Bundle (Recommended)

```bash
bash build_macos.sh
```

This creates `dist/GroupMeBlocker.app` which can be:
- Moved to `/Applications/` like any other macOS app
- Double-clicked to run
- Distributed to other macOS users

**Result:** An app bundle that works on any macOS machine with Python 3.11+

### Option 2: Create a DMG Installer

After building the app:

```bash
hdiutil create -volname GroupMeBlocker \
    -srcfolder ./dist/GroupMeBlocker.app \
    -ov -format UDZO GroupMeBlocker.dmg
```

Users can then:
1. Download `GroupMeBlocker.dmg`
2. Open it
3. Drag `GroupMeBlocker.app` to their Applications folder
4. Run it

### Manual Build (Advanced)

```bash
pyinstaller --onedir --windowed \
    --name GroupMeBlocker \
    --hidden-import=tkinter \
    --hidden-import=cryptography \
    GroupMe_Blocker.py
```

## Windows Packaging

### Build a Standalone Executable

**On Windows:**

```cmd
build_windows.bat
```

Or manually:

```cmd
pyinstaller --onedir --windowed ^
    --name GroupMeBlocker ^
    --hidden-import=tkinter ^
    --hidden-import=cryptography ^
    GroupMe_Blocker.py
```

**Result:** `dist/GroupMeBlocker/` folder containing:
- `GroupMeBlocker.exe` - Main executable
- Supporting DLL files and libraries
- Everything needed to run the app

### Distribution

Option A: **Zip the folder**
```cmd
# On Windows, right-click dist/GroupMeBlocker → Send to → Compressed folder
```

Option B: **Use an installer tool** (optional, for more professional distribution):
- [NSIS](https://nsis.sourceforge.io/) - Free, open-source installer
- [Inno Setup](https://jrsoftware.org/isinfo.php) - Easier to use
- [WiX Toolset](https://wixtoolset.org/) - Professional grade

Users can then:
1. Download and extract the zip
2. Run `GroupMeBlocker.exe`
3. No Python installation needed

## Cross-Platform Notes

### macOS to Windows and Vice Versa

PyInstaller builds are **platform-specific**. You must:
- Build on macOS to create the macOS version
- Build on Windows to create the Windows version
- Or use CI/CD (GitHub Actions) to automate builds

### File Sizes

- macOS `.app` bundle: ~60-80 MB (can compress to ~20-30 MB in DMG)
- Windows `.exe` folder: ~50-70 MB (can compress to ~15-25 MB in zip)

The size includes Python runtime, tkinter, and all dependencies.

## Distribution Recommendations

### For macOS Users
1. **Easiest:** Create a DMG installer
   - One click to install
   - Professional appearance
   - Easy to distribute

2. **Alternative:** Create a GitHub release with the `.app` bundle
   - Users download and extract
   - Move to Applications folder
   - Works seamlessly

### For Windows Users
1. **Easiest:** Zip the `dist/GroupMeBlocker/` folder
   - Users extract and run `.exe`
   - No installer needed
   - Simple distribution

2. **Professional:** Create an installer with NSIS or Inno Setup
   - Add to Programs and Features
   - Create Start Menu shortcuts
   - Uninstall support

## Troubleshooting

### "App won't start / crashes"
- Make sure you built on the same OS you're distributing for
- Check that all dependencies are in `requirements.txt`
- Try running from terminal to see error messages

### "Module not found" errors
- Add missing modules to `--hidden-import` in the build command
- Example: `--hidden-import=requests`

### Large file size
- This is normal - includes Python runtime
- Compression (DMG/zip) significantly reduces size for distribution

## GitHub Releases

To distribute your builds:

1. Build both macOS and Windows versions
2. Create a GitHub release
3. Upload:
   - `GroupMeBlocker.dmg` for macOS
   - `GroupMeBlocker-Windows.zip` for Windows
4. Users download and extract

Example release:
```
GroupMeBlocker v1.0.0
- macOS: GroupMeBlocker.dmg (macOS 11+)
- Windows: GroupMeBlocker-Windows.zip (Windows 10+)
```
