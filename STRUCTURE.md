# Project Structure

```
GroupMe/
├── src/                          # Source code
│   └── GroupMe_Blocker.py       # Main application
│
├── build_scripts/               # Build automation
│   ├── build_macos.sh           # macOS build script
│   ├── build_windows.bat        # Windows build script
│   ├── GroupMeBlocker.spec      # PyInstaller config (macOS)
│   └── GroupMeBlocker_Windows.spec  # PyInstaller config (Windows)
│
├── docs/                        # Documentation
│   └── BUILD.md                 # Detailed build & packaging guide
│
├── config/                      # Configuration templates
│   └── accounts_config.example.json  # Example config (no real tokens)
│
├── build/                       # Build artifacts (gitignored)
├── dist/                        # Compiled executables (gitignored)
│
├── README.md                    # Main documentation
├── requirements.txt             # Python dependencies
├── .gitignore                   # Git ignore rules
│
├── build.sh                     # Quick macOS build helper
├── build.bat                    # Quick Windows build helper
│
└── .venv/                       # Virtual environment (gitignored)
```

## Directory Purposes

### `/src`
- Contains the main Python source code
- Single main script: `GroupMe_Blocker.py`

### `/build_scripts`
- PyInstaller spec files for packaging
- Platform-specific build scripts (macOS, Windows)
- Run these via `build.sh` or `build.bat` from project root

### `/docs`
- Detailed documentation for users and developers
- `BUILD.md`: Complete packaging and distribution guide

### `/config`
- Example configuration file (`accounts_config.example.json`)
- Users reference this when setting up the app
- Real configs stored locally (not in repo)

### Root Level
- `README.md`: Main project documentation (quick start, features, security)
- `requirements.txt`: List of Python dependencies
- `.gitignore`: Files/folders to exclude from git
- `build.sh` / `build.bat`: Quick build helpers (call build_scripts internally)

## Workflow

### Development
```bash
# Edit source
nano src/GroupMe_Blocker.py

# Test it
python src/GroupMe_Blocker.py
```

### Building for Distribution
```bash
# macOS
bash build.sh

# Windows (from Windows)
build.bat
```

### Distribution Files
- Generated in `dist/` folder after building
- Pack and upload to GitHub Releases
- Don't commit `dist/` folder

## Files NOT in Repository

The following are safely ignored:

| File | Why |
|------|-----|
| `accounts_config.json` | User's encrypted account configs |
| `encryption.key` | Decryption key for tokens |
| `.env*` | Environment variables with secrets |
| `.venv/` | Virtual environment |
| `dist/` | Build outputs (regenerate per build) |
| `build/` | Build temporary files |
| `.DS_Store` | macOS system files |
| `__pycache__/` | Python cache |

All protected by `.gitignore`.
