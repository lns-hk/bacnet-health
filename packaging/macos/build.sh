#!/usr/bin/env bash
# Build dist/bacnet-health-<version>-macos-<arch>.zip (unsigned .app). Run from the repo root venv.
set -euo pipefail
cd "$(dirname "$0")/../.."
VERSION=$(python -c "import bacnet_health; print(bacnet_health.__version__)")
ARCH=$(uname -m)
rm -rf build/macos dist/macos
pyinstaller --noconfirm --clean --distpath dist/macos --workpath build/macos packaging/macos/bacnet-health.spec
cp THIRD_PARTY_NOTICES.md dist/macos/ 2>/dev/null || true
cat > dist/macos/README-FIRST.txt <<TXT
bacnet-health ${VERSION} (pre-release) for macOS

1. Move bacnet-health.app to Applications (or anywhere).
2. The app is not signed yet. The first time, right-click (or Control-click) it and choose Open, then Open again.
3. When macOS asks whether bacnet-health may find devices on your local network, click Allow.

bacnet-health only reads. It never changes settings on any device.
TXT
ZIP="dist/bacnet-health-${VERSION}-macos-${ARCH}.zip"
rm -f "$ZIP"
(cd dist/macos && ditto -c -k --keepParent bacnet-health.app "../$(basename "$ZIP")" && zip -q "../$(basename "$ZIP")" README-FIRST.txt THIRD_PARTY_NOTICES.md 2>/dev/null || true)
shasum -a 256 "$ZIP" | tee "$ZIP.sha256"
du -sh dist/macos/bacnet-health.app "$ZIP"
