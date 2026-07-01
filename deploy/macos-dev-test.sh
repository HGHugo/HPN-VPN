#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# HPN VPN macOS Dev Build & Package
# =============================================================================
#
# Single script to build, embed extension, sign, package (.pkg), and install.
#
# Prerequisites:
#   - Xcode installed with managed signing configured
#   - Extension built at least once in Xcode (Cmd+B on packet-tunnel scheme)
#   - Apple Development certificate in keychain
#
# Usage:
#   ./deploy/macos-dev-test.sh
#
# Options:
#   SKIP_TAURI_BUILD=1    skip Tauri rebuild (use existing .app)
#   SKIP_EXT_BUILD=1      skip extension rebuild (use existing .appex)
#   SKIP_INSTALL=1        skip install to /Applications (just build + pkg)

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TAURI_DIR="$REPO_ROOT/crates/hpn-ui-macos"
TARGET="${TARGET:-aarch64-apple-darwin}"
SIGN_ID="${SIGN_ID:-Apple Development: YOUR NAME (YOUR_TEAM_ID)}"
INSTALLER_SIGN_ID="${INSTALLER_SIGN_ID:-}"
ENTITLEMENTS="$TAURI_DIR/src-tauri/entitlements.plist"
SKIP_TAURI_BUILD="${SKIP_TAURI_BUILD:-0}"
SKIP_EXT_BUILD="${SKIP_EXT_BUILD:-0}"
SKIP_INSTALL="${SKIP_INSTALL:-0}"
VERSION="${VERSION:-0.1.0}"

# Find the Xcode DerivedData for our project.
find_xcode_build() {
    local build_dir
    # Search for "HPN VPN.app" first (current product name), then "macos.app" (legacy)
    for app_name in "HPN VPN.app" "macos.app"; do
        build_dir=$(find "$HOME/Library/Developer/Xcode/DerivedData" \
            -name "$app_name" -path "*/Release/*" -maxdepth 6 2>/dev/null | head -1)
        [ -n "$build_dir" ] && break
        build_dir=$(find "$HOME/Library/Developer/Xcode/DerivedData" \
            -name "$app_name" -path "*/Debug/*" -maxdepth 6 2>/dev/null | head -1)
        [ -n "$build_dir" ] && break
    done
    echo "$build_dir"
}

echo "=== HPN VPN macOS Build v${VERSION} ==="
echo ""

# ── Step 1: Build Rust staticlib ─────────────────────────────────────────────

echo "==> [1/8] Building Rust staticlib (hpn-tunnel-ext)"
cargo build -p hpn-tunnel-ext --target "$TARGET" --release 2>&1 | tail -1
echo "  Done"

# ── Step 2: Build Tauri app ──────────────────────────────────────────────────

if [ "$SKIP_TAURI_BUILD" = "1" ]; then
    echo "==> [2/8] Skipping Tauri build (SKIP_TAURI_BUILD=1)"
else
    echo "==> [2/8] Building Tauri macOS app"
    cd "$TAURI_DIR"
    cargo tauri build --target "$TARGET" --bundles app --no-sign
    cd "$REPO_ROOT"
fi

APP_PATH=$(find "$REPO_ROOT/target/$TARGET/release/bundle/macos" -maxdepth 1 -name "*.app" | head -n1)
[ -n "$APP_PATH" ] || { echo "ERROR: .app not found. Run without SKIP_TAURI_BUILD."; exit 1; }
echo "  App: $APP_PATH"

# ── Step 3: Build extension via Xcode ────────────────────────────────────────

if [ "$SKIP_EXT_BUILD" = "1" ]; then
    echo "==> [3/8] Skipping extension build (SKIP_EXT_BUILD=1)"
else
    echo "==> [3/8] Building Packet Tunnel Extension via Xcode"
    XCODE_PROJECT="$TAURI_DIR/xcode-native/macos/macos.xcodeproj"
    xcodebuild -project "$XCODE_PROJECT" \
        -scheme "packet-tunnel" \
        -configuration Release \
        build 2>&1 | tail -3
fi

XCODE_BUILD=$(find_xcode_build)
[ -n "$XCODE_BUILD" ] || { echo "ERROR: Xcode build not found. Build in Xcode first (Cmd+B)."; exit 1; }
echo "  Xcode build: $XCODE_BUILD"

# ── Step 4: Embed extension + provisioning profile ───────────────────────────

echo "==> [4/8] Embedding extension and provisioning profile"
mkdir -p "$APP_PATH/Contents/PlugIns"
rm -rf "$APP_PATH/Contents/PlugIns/packet-tunnel.appex"
cp -R "$XCODE_BUILD/Contents/PlugIns/packet-tunnel.appex" "$APP_PATH/Contents/PlugIns/"
cp "$XCODE_BUILD/Contents/embedded.provisionprofile" "$APP_PATH/Contents/embedded.provisionprofile"
echo "  Extension + profile embedded"

# ── Step 5: Sign the .app ────────────────────────────────────────────────────

echo "==> [5/8] Signing app with: $SIGN_ID"

# Sign extension first (inside-out signing)
codesign --force --options runtime --timestamp \
    --sign "$SIGN_ID" \
    "$APP_PATH/Contents/PlugIns/packet-tunnel.appex"

# Sign main app
codesign --force --options runtime --timestamp \
    --entitlements "$ENTITLEMENTS" \
    --sign "$SIGN_ID" \
    "$APP_PATH"

codesign --verify --deep --strict "$APP_PATH" && echo "  Signature OK"

# ── Step 6: Build .pkg installer with EULA + background ──────────────────────

echo "==> [6/8] Building .pkg installer"
BUNDLE_DIR=$(dirname "$APP_PATH")
PKG_PATH="$REPO_ROOT/target/HPN-VPN-${VERSION}-arm64.pkg"
UNSIGNED_PKG="$REPO_ROOT/target/HPN-VPN-${VERSION}-arm64-unsigned.pkg"
COMPONENT_PKG="$REPO_ROOT/target/HPN-VPN-component.pkg"
ASSETS_DIR="$REPO_ROOT/deploy/installer-assets"
DIST_XML="$REPO_ROOT/target/distribution.xml"

# Build component package
pkgbuild \
    --root "$BUNDLE_DIR" \
    --identifier "io.hpn.vpn" \
    --version "$VERSION" \
    --install-location "/Applications" \
    "$COMPONENT_PKG" 2>&1

# Create distribution.xml with license and background
cat > "$DIST_XML" << DISTEOF
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="1">
    <title>HPN VPN</title>
    <license file="license.rtf"/>
    <background file="background.png" alignment="bottomleft" scaling="proportional"/>
    <background-darkAqua file="background.png" alignment="bottomleft" scaling="proportional"/>
    <options customize="never" require-scripts="false"/>
    <domains enable_localSystem="true"/>
    <choices-outline>
        <line choice="default">
            <line choice="io.hpn.vpn"/>
        </line>
    </choices-outline>
    <choice id="default"/>
    <choice id="io.hpn.vpn" visible="false">
        <pkg-ref id="io.hpn.vpn"/>
    </choice>
    <pkg-ref id="io.hpn.vpn" version="${VERSION}">HPN-VPN-component.pkg</pkg-ref>
</installer-gui-script>
DISTEOF

# Build product archive with distribution, license, and background
productbuild \
    --distribution "$DIST_XML" \
    --resources "$ASSETS_DIR" \
    --package-path "$REPO_ROOT/target" \
    "$UNSIGNED_PKG" 2>&1

rm -f "$COMPONENT_PKG"

# Sign the .pkg if an installer signing identity is available
if [ -n "$INSTALLER_SIGN_ID" ]; then
    echo "  Signing .pkg with: $INSTALLER_SIGN_ID"
    productsign --sign "$INSTALLER_SIGN_ID" "$UNSIGNED_PKG" "$PKG_PATH"
    rm -f "$UNSIGNED_PKG"
else
    mv "$UNSIGNED_PKG" "$PKG_PATH"
    echo "  (No INSTALLER_SIGN_ID set — .pkg is unsigned)"
fi

PKG_SIZE=$(du -h "$PKG_PATH" | cut -f1)
echo "  Package: $PKG_PATH ($PKG_SIZE)"

# ── Step 7: Install to /Applications ─────────────────────────────────────────

if [ "$SKIP_INSTALL" = "1" ]; then
    echo "==> [7/8] Skipping install (SKIP_INSTALL=1)"
else
    echo "==> [7/8] Installing to /Applications"
    sudo rm -rf "/Applications/HPN VPN.app"
    sudo cp -R "$APP_PATH" "/Applications/HPN VPN.app"
fi

# ── Step 8: Verify ───────────────────────────────────────────────────────────

echo "==> [8/8] Verifying"
[ -f "$PKG_PATH" ] || { echo "ERROR: .pkg not found"; exit 1; }

if [ "$SKIP_INSTALL" != "1" ]; then
    [ -d "/Applications/HPN VPN.app" ] || { echo "ERROR: app not installed"; exit 1; }
    APPEX=$(find "/Applications/HPN VPN.app" -name "*.appex" -maxdepth 3 | head -1)
    [ -n "$APPEX" ] || { echo "ERROR: extension not embedded"; exit 1; }
    PROFILE=$(find "/Applications/HPN VPN.app" -name "embedded.provisionprofile" -maxdepth 2 | head -1)
    [ -n "$PROFILE" ] || { echo "ERROR: provisioning profile not embedded"; exit 1; }
fi

echo ""
echo "============================================================"
echo "  BUILD COMPLETE"
echo "============================================================"
echo ""
echo "  .app:  $APP_PATH"
echo "  .pkg:  $PKG_PATH  ($PKG_SIZE)"
echo ""
if [ "$SKIP_INSTALL" != "1" ]; then
    echo "  Installed: /Applications/HPN VPN.app"
    echo "  Launch:    open '/Applications/HPN VPN.app'"
else
    echo "  Install:   sudo installer -pkg '$PKG_PATH' -target /"
    echo "  Or:        open '$PKG_PATH'"
fi
echo ""
