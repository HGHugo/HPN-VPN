#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# HPN VPN — Upload packages to OVH Object Storage repo
# =============================================================================
#
# Uploads .deb and .rpm packages to the OVH S3-compatible bucket,
# then regenerates APT and YUM repo indexes.
#
# Prerequisites:
#   - s3cmd configured with OVH credentials
#   - reprepro (for APT repo index)
#   - createrepo (for YUM repo index)
#   - GPG key for package signing
#
# Usage:
#   ./deploy/upload-packages.sh

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PKG_DIR="$REPO_ROOT/target/packages"
REPO_DIR="$REPO_ROOT/target/repo"
S3_BUCKET="${S3_BUCKET:-s3://pkg-hpn-io}"
GPG_KEY_ID="${GPG_KEY_ID:-}"

echo ""
echo "============================================================"
echo "  HPN VPN Package Upload"
echo "============================================================"
echo ""

# ── APT Repository ──────────────────────────────────────────────────────────

echo "==> Building APT repository index"

mkdir -p "$REPO_DIR/apt/pool/main/h/hpn-server"
mkdir -p "$REPO_DIR/apt/pool/main/h/hpn-relay"

# Copy .deb files
cp "$PKG_DIR"/hpn-server_*.deb "$REPO_DIR/apt/pool/main/h/hpn-server/" 2>/dev/null || true
cp "$PKG_DIR"/hpn-relay_*.deb "$REPO_DIR/apt/pool/main/h/hpn-relay/" 2>/dev/null || true

if command -v reprepro &>/dev/null; then
    mkdir -p "$REPO_DIR/apt/conf"
    cat > "$REPO_DIR/apt/conf/distributions" << EOF
Origin: HPN
Label: HPN VPN
Codename: stable
Architectures: amd64
Components: main
Description: HPN Post-Quantum VPN packages
EOF

    if [ -n "$GPG_KEY_ID" ]; then
        echo "SignWith: $GPG_KEY_ID" >> "$REPO_DIR/apt/conf/distributions"
    fi

    for deb in "$PKG_DIR"/hpn-*.deb; do
        [ -f "$deb" ] && reprepro -b "$REPO_DIR/apt" includedeb stable "$deb"
    done
    echo "  APT repo index generated"
else
    echo "  WARNING: reprepro not installed. Skipping APT index."
    echo "  Install: apt install reprepro"
fi

# ── YUM Repository ──────────────────────────────────────────────────────────

echo "==> Building YUM repository index"

mkdir -p "$REPO_DIR/rpm/el/9/x86_64"

cp "$PKG_DIR"/hpn-*.rpm "$REPO_DIR/rpm/el/9/x86_64/" 2>/dev/null || true

if command -v createrepo &>/dev/null; then
    createrepo "$REPO_DIR/rpm/el/9/x86_64/"
    echo "  YUM repo index generated"
else
    echo "  WARNING: createrepo not installed. Skipping YUM index."
    echo "  Install: apt install createrepo-c"
fi

# ── GPG public key ──────────────────────────────────────────────────────────

if [ -n "$GPG_KEY_ID" ]; then
    gpg --export --armor "$GPG_KEY_ID" > "$REPO_DIR/gpg"
    echo "  GPG public key exported"
fi

# ── Upload to S3 ────────────────────────────────────────────────────────────

echo "==> Uploading to ${S3_BUCKET}"

if command -v s3cmd &>/dev/null; then
    s3cmd sync "$REPO_DIR/" "$S3_BUCKET/" --acl-public --delete-removed
    echo "  Upload complete"
elif command -v aws &>/dev/null; then
    aws s3 sync "$REPO_DIR/" "$S3_BUCKET/" --acl public-read --delete
    echo "  Upload complete"
else
    echo "  WARNING: Neither s3cmd nor aws CLI found."
    echo "  Install: pip install s3cmd  OR  brew install awscli"
    echo "  Files are ready at: $REPO_DIR/"
fi

echo ""
echo "  Done. Clients can now:"
echo "    apt update && apt install hpn-server"
echo "    dnf install hpn-server"
echo ""
