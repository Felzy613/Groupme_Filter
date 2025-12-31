#!/bin/bash

# Build script for macOS
# Creates a standalone executable for macOS
# Run from project root: bash build_scripts/build_macos.sh

echo "Building GroupMeBlocker for macOS..."

# Check if we're in the right directory
if [ ! -f "src/GroupMe_Blocker.py" ]; then
    echo "Error: src/GroupMe_Blocker.py not found. Please run this script from the project root."
    exit 1
fi

# Clean previous builds
rm -rf build/ dist/

# Build the app
pyinstaller --onedir --windowed --name GroupMeBlocker \
    --hidden-import=tkinter \
    --hidden-import=cryptography \
    src/GroupMe_Blocker.py

echo ""
echo "✅ Build complete!"
echo ""
echo "The app is ready at: ./dist/GroupMeBlocker/"
echo ""
echo "To create a macOS .app bundle:"
echo "1. The executable is at: ./dist/GroupMeBlocker/GroupMeBlocker"
echo ""
echo "To run it:"
echo "  ./dist/GroupMeBlocker/GroupMeBlocker"
echo ""
echo "To distribute:"
echo "1. Zip the entire dist/GroupMeBlocker folder"
echo "2. Users can extract and run ./GroupMeBlocker/GroupMeBlocker"
