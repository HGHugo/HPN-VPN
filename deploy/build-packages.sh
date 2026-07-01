#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# HPN VPN — Build .deb and .rpm packages
# =============================================================================
#
# Builds hpn-server and hpn-relay packages for Debian/Ubuntu and RHEL/Alma.
#
# Prerequisites:
#   - Rust toolchain with x86_64-unknown-linux-gnu target
#   - For .deb: dpkg-deb (apt install dpkg-dev)
#   - For .rpm: rpmbuild (apt install rpm) or fpm (gem install fpm)
#   - For cross-compile from macOS: cross (cargo install cross)
#
# Usage:
#   ./deploy/build-packages.sh                    # Build both .deb and .rpm
#   ./deploy/build-packages.sh --deb-only         # Only .deb
#   ./deploy/build-packages.sh --rpm-only         # Only .rpm
#   ./deploy/build-packages.sh --skip-compile     # Use existing binaries

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_DIR="$REPO_ROOT/deploy/packaging"
OUTPUT_DIR="$REPO_ROOT/target/packages"
# Version: from env, git tag, or Cargo.toml
if [ -n "${VERSION:-}" ]; then
    : # use env var as-is
elif [ -n "${CI_COMMIT_TAG:-}" ]; then
    VERSION="${CI_COMMIT_TAG#v}" # strip leading 'v' from v0.1.0
else
    VERSION=$(grep '^version' "$REPO_ROOT/Cargo.toml" | head -1 | sed 's/.*"\(.*\)".*/\1/')
fi
VERSION="${VERSION:-0.1.0}"
REVISION="${REVISION:-1}"
ARCH="amd64"
TARGET="x86_64-unknown-linux-gnu"
SKIP_COMPILE="${SKIP_COMPILE:-0}"
DEB_ONLY="${DEB_ONLY:-0}"
RPM_ONLY="${RPM_ONLY:-0}"

# Parse args
for arg in "$@"; do
    case "$arg" in
        --deb-only)      DEB_ONLY=1 ;;
        --rpm-only)      RPM_ONLY=1 ;;
        --skip-compile)  SKIP_COMPILE=1 ;;
    esac
done

mkdir -p "$OUTPUT_DIR"

echo ""
echo "============================================================"
echo "  HPN VPN Package Build v${VERSION}"
echo "============================================================"
echo ""

# ── Step 1: Compile binaries ────────────────────────────────────────────────

if [ "$SKIP_COMPILE" = "1" ]; then
    echo "==> [1/4] Skipping compilation (--skip-compile)"
else
    echo "==> [1/4] Compiling for ${TARGET}"

    # Check if we need cross (macOS building for Linux)
    if [[ "$(uname)" == "Darwin" ]]; then
        if command -v cross &>/dev/null; then
            echo "  Using 'cross' for cross-compilation"
            CARGO_CMD="cross"
        else
            echo "ERROR: Cross-compiling from macOS requires 'cross'."
            echo "  Install: cargo install cross"
            echo "  Also needs Docker running."
            exit 1
        fi
    else
        CARGO_CMD="cargo"
    fi

    $CARGO_CMD build --release --target "$TARGET" -p hpn-server 2>&1 | tail -3
    echo "  hpn-server compiled"

    $CARGO_CMD build --release --target "$TARGET" -p hpn-relay 2>&1 | tail -3
    echo "  hpn-relay compiled"
fi

BINARY_DIR="$REPO_ROOT/target/${TARGET}/release"

# Verify binaries exist
for bin in hpn-server hpn-relay; do
    if [ ! -f "$BINARY_DIR/$bin" ]; then
        echo "ERROR: $BINARY_DIR/$bin not found"
        echo "  Run without --skip-compile or compile manually first."
        exit 1
    fi
done

echo "  Binaries: $BINARY_DIR/{hpn-server,hpn-relay}"

# ── Step 2: Build .deb packages ─────────────────────────────────────────────

build_deb() {
    local COMPONENT="$1"  # hpn-server or hpn-relay
    local DESCRIPTION="$2"
    local DEB_NAME="${COMPONENT}_${VERSION}-${REVISION}_${ARCH}"
    local DEB_ROOT="$OUTPUT_DIR/deb-staging/${DEB_NAME}"

    echo "  Building ${DEB_NAME}.deb..."

    rm -rf "$DEB_ROOT"
    mkdir -p "$DEB_ROOT/DEBIAN"
    mkdir -p "$DEB_ROOT/usr/bin"
    mkdir -p "$DEB_ROOT/etc/hpn"
    mkdir -p "$DEB_ROOT/lib/systemd/system"
    mkdir -p "$DEB_ROOT/var/lib/hpn"

    # Binary
    cp "$BINARY_DIR/$COMPONENT" "$DEB_ROOT/usr/bin/$COMPONENT"
    chmod 755 "$DEB_ROOT/usr/bin/$COMPONENT"

    # Strip binary (reduce size ~60%)
    strip "$DEB_ROOT/usr/bin/$COMPONENT" 2>/dev/null || true

    # Config template
    if [ "$COMPONENT" = "hpn-server" ]; then
        cp "$PKG_DIR/config/server.toml.example" "$DEB_ROOT/etc/hpn/server.toml.example"
    else
        cp "$PKG_DIR/config/relay.toml.example" "$DEB_ROOT/etc/hpn/relay.toml.example"
    fi

    # Systemd unit
    cp "$PKG_DIR/systemd/${COMPONENT}.service" "$DEB_ROOT/lib/systemd/system/"

    # postinst / prerm / postrm
    cp "$PKG_DIR/scripts/${COMPONENT}.postinst" "$DEB_ROOT/DEBIAN/postinst"
    cp "$PKG_DIR/scripts/${COMPONENT}.prerm" "$DEB_ROOT/DEBIAN/prerm"
    cp "$PKG_DIR/scripts/${COMPONENT}.postrm" "$DEB_ROOT/DEBIAN/postrm"
    chmod 755 "$DEB_ROOT/DEBIAN/postinst" "$DEB_ROOT/DEBIAN/prerm" "$DEB_ROOT/DEBIAN/postrm"

    # conffiles: mark the .example as config so dpkg preserves user edits on upgrade
    if [ "$COMPONENT" = "hpn-server" ]; then
        echo "/etc/hpn/server.toml.example" > "$DEB_ROOT/DEBIAN/conffiles"
    else
        echo "/etc/hpn/relay.toml.example" > "$DEB_ROOT/DEBIAN/conffiles"
    fi

    # DEBIAN/control
    local INSTALLED_SIZE
    INSTALLED_SIZE=$(du -sk "$DEB_ROOT" | cut -f1)

    cat > "$DEB_ROOT/DEBIAN/control" << EOF
Package: ${COMPONENT}
Version: ${VERSION}-${REVISION}
Architecture: ${ARCH}
Maintainer: HMSX Solutions <contact@hmsx.io>
Installed-Size: ${INSTALLED_SIZE}
Depends: libc6 (>= 2.31)
Section: net
Priority: optional
Homepage: https://hpn.hmsx.io
Description: ${DESCRIPTION}
 Post-quantum secure VPN ${COMPONENT#hpn-} powered by ML-KEM + ML-DSA + AES-256-GCM.
 Provides NIST Level 3/5 security against both classical and quantum attacks.
EOF

    # Build .deb
    if fakeroot dpkg-deb --build "$DEB_ROOT" "$OUTPUT_DIR/${DEB_NAME}.deb"; then
        : # success
    elif dpkg-deb --build --root-owner-group "$DEB_ROOT" "$OUTPUT_DIR/${DEB_NAME}.deb"; then
        : # success with root-owner-group
    elif dpkg-deb --build "$DEB_ROOT" "$OUTPUT_DIR/${DEB_NAME}.deb"; then
        : # success without root-owner-group
    else
        echo "  ERROR: dpkg-deb failed. Install: sudo apt install dpkg-dev fakeroot"
        exit 1
    fi

    local SIZE
    SIZE=$(du -h "$OUTPUT_DIR/${DEB_NAME}.deb" | cut -f1)
    echo "  Built: ${DEB_NAME}.deb ($SIZE)"
}

if [ "$RPM_ONLY" != "1" ]; then
    echo ""
    echo "==> [2/4] Building .deb packages"
    build_deb "hpn-server" "HPN Post-Quantum VPN Server"
    build_deb "hpn-relay" "HPN Post-Quantum VPN Relay"
else
    echo "==> [2/4] Skipping .deb (--rpm-only)"
fi

# ── Step 3: Build .rpm packages ─────────────────────────────────────────────

build_rpm() {
    local COMPONENT="$1"
    local DESCRIPTION="$2"
    local RPM_ARCH="x86_64"
    local RPM_NAME="${COMPONENT}-${VERSION}-${REVISION}.el9.${RPM_ARCH}"

    echo "  Building ${RPM_NAME}.rpm..."

    # Build RPM via fpm (requires fpm + rpmbuild)
    if command -v fpm &>/dev/null && command -v rpmbuild &>/dev/null; then
        local STAGING="$OUTPUT_DIR/rpm-staging/${COMPONENT}"
        rm -rf "$STAGING"
        mkdir -p "$STAGING/usr/bin"
        mkdir -p "$STAGING/etc/hpn"
        mkdir -p "$STAGING/lib/systemd/system"

        cp "$BINARY_DIR/$COMPONENT" "$STAGING/usr/bin/$COMPONENT"
        strip "$STAGING/usr/bin/$COMPONENT" 2>/dev/null || true

        if [ "$COMPONENT" = "hpn-server" ]; then
            cp "$PKG_DIR/config/server.toml.example" "$STAGING/etc/hpn/server.toml.example"
        else
            cp "$PKG_DIR/config/relay.toml.example" "$STAGING/etc/hpn/relay.toml.example"
        fi

        cp "$PKG_DIR/systemd/${COMPONENT}.service" "$STAGING/lib/systemd/system/"

        fpm -s dir -t rpm \
            --name "$COMPONENT" \
            --version "$VERSION" \
            --iteration "$REVISION" \
            --architecture "$RPM_ARCH" \
            --description "$DESCRIPTION" \
            --url "https://hpn.hmsx.io" \
            --maintainer "HMSX Solutions <contact@hmsx.io>" \
            --license "AGPL-3.0-or-later" \
            --depends "glibc >= 2.31" \
            --after-install "$PKG_DIR/scripts/${COMPONENT}.postinst" \
            --before-remove "$PKG_DIR/scripts/${COMPONENT}.prerm" \
            --config-files "/etc/hpn/" \
            --package "$OUTPUT_DIR/${RPM_NAME}.rpm" \
            -C "$STAGING" \
            . 2>/dev/null

        local SIZE
        SIZE=$(du -h "$OUTPUT_DIR/${RPM_NAME}.rpm" | cut -f1)
        echo "  Built: ${RPM_NAME}.rpm ($SIZE)"
    else
        echo "  Skipping .rpm for $COMPONENT (requires: sudo apt install rpm && sudo gem install fpm)"
    fi
}

if [ "$DEB_ONLY" != "1" ]; then
    echo ""
    echo "==> [3/4] Building .rpm packages"
    build_rpm "hpn-server" "HPN Post-Quantum VPN Server"
    build_rpm "hpn-relay" "HPN Post-Quantum VPN Relay"
else
    echo "==> [3/4] Skipping .rpm (--deb-only)"
fi

# ── Step 4: Summary ─────────────────────────────────────────────────────────

echo ""
echo "==> [4/4] Package summary"
echo ""

for f in "$OUTPUT_DIR"/*.deb "$OUTPUT_DIR"/*.rpm; do
    [ -f "$f" ] && echo "  $(ls -lh "$f")"
done

echo ""
echo "============================================================"
echo "  BUILD COMPLETE"
echo "============================================================"
echo ""
echo "  Packages in: $OUTPUT_DIR/"
echo ""
echo "  Install on Debian/Ubuntu:"
echo "    sudo dpkg -i ${OUTPUT_DIR}/hpn-server_${VERSION}-${REVISION}_${ARCH}.deb"
echo ""
echo "  Install on RHEL/Alma:"
echo "    sudo rpm -i ${OUTPUT_DIR}/hpn-server-${VERSION}-${REVISION}.el9.x86_64.rpm"
echo ""
echo "  Publish to APT repo:"
echo "    ./deploy/publish-repo.sh"
echo ""
