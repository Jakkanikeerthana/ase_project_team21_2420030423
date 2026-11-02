#!/usr/bin/env bash
# Builds installer/build/AdaptiveHoneypot-Setup-1.0.0.exe on Linux/macOS (needs: python3, makensis, pip install zstandard)
set -euo pipefail
cd "$(dirname "$0")"
mkdir -p build
[ -f build/python/python.exe ] || python3 fetch_python.py
makensis -V2 launcher.nsi
makensis -V2 -DSTOP launcher.nsi
makensis -V2 installer.nsi
echo "Done: $(ls build/*.exe)"
