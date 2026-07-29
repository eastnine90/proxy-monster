#!/usr/bin/env bash
# Build pmontray as a macOS .app bundle.
#
# A bundle is required, not cosmetic: LSUIElement (no Dock icon, no menu bar of its own) and the notification
# entitlement are Info.plist properties, so a bare binary cannot be a proper menu-bar app. It also gives macOS
# a stable identity to attach the Login Item and notification permission to.
#
#   ./build-app.sh                 -> ./dist/pmontray.app
#   ./build-app.sh /Applications   -> installs there
set -euo pipefail

cd "$(dirname "$0")"
DEST="${1:-./dist}"
mkdir -p "$DEST"
# Absolute, because the builds below run in subshells with a different working directory.
DEST="$(cd "$DEST" && pwd)"
APP="$DEST/pmontray.app"
VERSION="$(git -C .. describe --tags --always --dirty 2>/dev/null || echo dev)"

rm -rf "$APP"
mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"

# Bundle pmon INSIDE the app: the tray spawns the daemon by exec'ing a `pmon` binary, so shipping the pair
# together is what keeps the daemon and the front end from skewing.
echo "building pmon…"
(cd ../pmon && go build -o "$APP/Contents/MacOS/pmon" .)
echo "building pmontray…"
go build -ldflags "-X main.version=$VERSION" -o "$APP/Contents/MacOS/pmontray" .

cat > "$APP/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleName</key>
    <string>pmontray</string>
    <key>CFBundleDisplayName</key>
    <string>proxy-monster</string>
    <key>CFBundleIdentifier</key>
    <string>com.ridi.oss.proxymonster.pmontray</string>
    <key>CFBundleVersion</key>
    <string>$VERSION</string>
    <key>CFBundleShortVersionString</key>
    <string>$VERSION</string>
    <key>CFBundleExecutable</key>
    <string>pmontray</string>
    <key>CFBundleIconFile</key>
    <string>icon</string>
    <key>CFBundlePackageType</key>
    <string>APPL</string>
    <!-- Menu-bar-only: no Dock icon, no app menu bar. -->
    <key>LSUIElement</key>
    <true/>
    <key>LSMinimumSystemVersion</key>
    <string>11.0</string>
    <key>NSHighResolutionCapable</key>
    <true/>
</dict>
</plist>
PLIST

# Finder/Login-Items icon. CFBundleIconFile names "icon", so macOS looks for Resources/icon.icns; without it the
# bundle shows a generic icon in Login Items. The menu-bar icon is separate (embedded in the binary).
cp icon.png "$APP/Contents/Resources/icon.png"
if command -v iconutil >/dev/null 2>&1 && command -v sips >/dev/null 2>&1; then
    ICONSET="$(mktemp -d)/icon.iconset"
    mkdir -p "$ICONSET"
    for size in 16 32 128 256 512; do
        sips -z $size $size icon.png --out "$ICONSET/icon_${size}x${size}.png" >/dev/null 2>&1 || true
        sips -z $((size*2)) $((size*2)) icon.png --out "$ICONSET/icon_${size}x${size}@2x.png" >/dev/null 2>&1 || true
    done
    iconutil -c icns "$ICONSET" -o "$APP/Contents/Resources/icon.icns" 2>/dev/null || \
        echo "note: icns generation failed; the bundle will show a generic Finder icon"
fi

# Ad-hoc sign so macOS gives the bundle a stable identity for notifications and the Login Item. Without any
# signature the tray still runs, but notification permission may not stick across rebuilds.
if command -v codesign >/dev/null 2>&1; then
    codesign --force --deep --sign - "$APP" 2>/dev/null || echo "note: ad-hoc signing failed; the app still runs"
fi

echo "built $APP"
echo
echo "run it:            open $APP"
echo "start at login:    System Settings > General > Login Items > add $APP"
echo "bundled CLI:       $APP/Contents/MacOS/pmon"
