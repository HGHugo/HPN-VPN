#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# HPN VPN — Publish APT Repository to S3 (OVH Object Storage)
# =============================================================================
#
# Manages a signed APT repository using reprepro and syncs to S3-compatible
# storage (OVH Object Storage) for distribution via pkg.hpn.hmsx.io.
#
# Prerequisites:
#   - reprepro (apt install reprepro)
#   - aws cli (apt install awscli) configured for OVH S3
#   - GPG key for package signing
#   - .deb packages in target/packages/
#
# Environment variables (required):
#   S3_BUCKET        - S3 bucket name (e.g., hpn-packages)
#   S3_ENDPOINT      - S3 endpoint URL (e.g., https://s3.gra.io.cloud.ovh.net)
#   S3_REGION        - S3 region (e.g., gra)
#   AWS_ACCESS_KEY_ID     - S3 access key
#   AWS_SECRET_ACCESS_KEY - S3 secret key
#   GPG_KEY_ID       - GPG key ID for signing (or set in reprepro config)
#
# Usage:
#   ./deploy/publish-repo.sh                      # Add packages + sync to S3
#   ./deploy/publish-repo.sh --init               # Initialize repo + GPG key
#   ./deploy/publish-repo.sh --add-only           # Add packages, don't sync
#   ./deploy/publish-repo.sh --sync-only          # Sync existing repo to S3
#   ./deploy/publish-repo.sh --export-gpg         # Export public GPG key

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
PACKAGES_DIR="$REPO_ROOT/target/packages"
REPO_DIR="$REPO_ROOT/target/apt-repo"
REPO_CONF="$REPO_DIR/conf"
VERSION="${VERSION:-0.1.0}"

# GPG key identity
GPG_KEY_ID="${GPG_KEY_ID:-HPN VPN Package Signing Key}"
GPG_EMAIL="packages@hmsx.io"

# S3 configuration. Default bucket aligned with the production bucket
# served by pkg.hpn.hmsx.io nginx proxy (see HPN-Web/deploy/nginx/
# hpn-pkg.conf:79). The previous default `hpn-packages` drifted out of
# sync after a bucket rename — audit pass on 2026-05-18 detected that
# manual invocations of this script would have uploaded to an
# inexistent bucket, invisible via the public URL.
S3_BUCKET="${S3_BUCKET:-pkg-hpn-io}"
S3_ENDPOINT="${S3_ENDPOINT:-https://s3.gra.io.cloud.ovh.net}"
S3_REGION="${S3_REGION:-gra}"

ADD_ONLY=0
SYNC_ONLY=0
INIT=0
EXPORT_GPG=0

for arg in "$@"; do
    case "$arg" in
        --init)       INIT=1 ;;
        --add-only)   ADD_ONLY=1 ;;
        --sync-only)  SYNC_ONLY=1 ;;
        --export-gpg) EXPORT_GPG=1 ;;
    esac
done

echo ""
echo "============================================================"
echo "  HPN VPN APT Repository Publisher"
echo "============================================================"
echo ""

# ── Helper functions ────────────────────────────────────────────────────────

check_deps() {
    local missing=0
    for cmd in reprepro aws gpg; do
        if ! command -v "$cmd" &>/dev/null; then
            echo "ERROR: '$cmd' not found. Install it first."
            missing=1
        fi
    done
    if [ "$missing" = "1" ]; then
        echo ""
        echo "Install dependencies:"
        echo "  sudo apt install reprepro awscli gnupg createrepo-c"
        exit 1
    fi
    # Optional: createrepo for RPM
    if ! command -v createrepo_c &>/dev/null && ! command -v createrepo &>/dev/null; then
        echo "  NOTE: createrepo not found — RPM repo will be skipped"
        echo "  Install: sudo apt install createrepo-c"
    fi
}

# ── Step 0: Generate GPG key (--init) ───────────────────────────────────────

generate_gpg_key() {
    echo "==> Generating GPG signing key..."

    # Check if key already exists
    if gpg --list-keys "$GPG_EMAIL" &>/dev/null; then
        echo "  GPG key for $GPG_EMAIL already exists."
        GPG_KEY_ID=$(gpg --list-keys --keyid-format long "$GPG_EMAIL" | grep "pub" | head -1 | awk '{print $2}' | cut -d/ -f2)
        echo "  Key ID: $GPG_KEY_ID"
        return
    fi

    # Generate a new key (non-interactive)
    cat > /tmp/hpn-gpg-batch << EOF
%no-protection
Key-Type: RSA
Key-Length: 4096
Subkey-Type: RSA
Subkey-Length: 4096
Name-Real: HPN VPN Package Signing
Name-Email: $GPG_EMAIL
Expire-Date: 2028-12-31
%commit
EOF

    gpg --batch --gen-key /tmp/hpn-gpg-batch
    rm -f /tmp/hpn-gpg-batch

    GPG_KEY_ID=$(gpg --list-keys --keyid-format long "$GPG_EMAIL" | grep "pub" | head -1 | awk '{print $2}' | cut -d/ -f2)
    echo "  Generated GPG key: $GPG_KEY_ID"
    echo ""
    echo "  IMPORTANT: Back up your GPG key!"
    echo "  Export: gpg --export-secret-keys $GPG_EMAIL > hpn-repo-key.gpg"
    echo ""
}

export_gpg_key() {
    echo "==> Exporting public GPG key..."
    local OUTPUT="$REPO_ROOT/target/packages/hpn-repo.gpg"
    gpg --armor --export "$GPG_EMAIL" > "$OUTPUT"
    echo "  Exported to: $OUTPUT"
    echo "  This file must be available at: https://pkg.hpn.hmsx.io/gpg"
}

# ── Step 1: Initialize reprepro repository ──────────────────────────────────

init_repo() {
    echo "==> Initializing APT repository..."

    mkdir -p "$REPO_CONF"

    # distributions file
    cat > "$REPO_CONF/distributions" << EOF
Origin: HMSX Solutions
Label: HPN VPN
Suite: stable
Codename: stable
Architectures: amd64 arm64
Components: main
Description: HPN Post-Quantum VPN packages
SignWith: $GPG_EMAIL
EOF

    # options file
    cat > "$REPO_CONF/options" << EOF
verbose
basedir $REPO_DIR
ask-passphrase
EOF

    echo "  Repository initialized at $REPO_DIR"
    echo "  Distribution: stable"
    echo "  Components: main"
    echo "  Architectures: amd64, arm64"
}

# ── Step 2: Add packages to repository ──────────────────────────────────────

add_packages() {
    echo "==> Adding packages to repository..."

    if [ ! -d "$REPO_CONF" ]; then
        echo "  Repository not initialized. Running init..."
        init_repo
    fi

    local count=0
    for deb in "$PACKAGES_DIR"/*.deb; do
        [ -f "$deb" ] || continue
        echo "  Adding: $(basename "$deb")"
        reprepro -b "$REPO_DIR" includedeb stable "$deb"
        count=$((count + 1))
    done

    if [ "$count" = "0" ]; then
        echo "  WARNING: No .deb files found in $PACKAGES_DIR"
        echo "  Run build-packages.sh first."
        return 1
    fi

    echo "  Added $count package(s)"

    # Also export the GPG public key to the repo
    gpg --armor --export "$GPG_EMAIL" > "$REPO_DIR/gpg"
    echo "  GPG public key exported to repo"
}

# ── Step 2b: Build RPM/YUM repository ───────────────────────────────────────

add_rpm_packages() {
    echo "==> Building YUM/RPM repository..."

    local RPM_REPO="$REPO_DIR/rpm"
    mkdir -p "$RPM_REPO/Packages"

    local count=0
    for rpm in "$PACKAGES_DIR"/*.rpm; do
        [ -f "$rpm" ] || continue
        echo "  Adding: $(basename "$rpm")"
        cp "$rpm" "$RPM_REPO/Packages/"
        count=$((count + 1))
    done

    if [ "$count" = "0" ]; then
        echo "  No .rpm files found — skipping YUM repo"
        return 0
    fi

    # Create repo metadata
    if command -v createrepo &>/dev/null; then
        createrepo --update "$RPM_REPO"
    elif command -v createrepo_c &>/dev/null; then
        createrepo_c --update "$RPM_REPO"
    else
        echo "  WARNING: createrepo not available — RPM metadata not generated"
        echo "  Install: sudo apt install createrepo-c  OR  sudo dnf install createrepo_c"
        return 0
    fi

    # Sign repo metadata
    if [ -f "$RPM_REPO/repodata/repomd.xml" ]; then
        gpg --batch --yes --detach-sign --armor "$RPM_REPO/repodata/repomd.xml" 2>/dev/null || true
    fi

    echo "  RPM repo built with $count package(s)"
}

# ── Step 3: Sync repository to S3 ──────────────────────────────────────────

sync_to_s3() {
    echo "==> Syncing repository to S3..."
    echo "  Bucket: $S3_BUCKET"
    echo "  Endpoint: $S3_ENDPOINT"

    # Validate credentials
    if [ -z "${AWS_ACCESS_KEY_ID:-}" ] || [ -z "${AWS_SECRET_ACCESS_KEY:-}" ]; then
        echo "ERROR: AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set."
        echo "  Export them or add to ~/.aws/credentials"
        exit 1
    fi

    # ────────────────────────────────────────────────────────────────
    # CRITICAL — DO NOT REMOVE THESE EXCLUDES.
    # ────────────────────────────────────────────────────────────────
    #
    # The S3 bucket is shared between TWO independent publishers:
    #
    #   1. THIS script (publish-repo.sh) — manages the Debian/Ubuntu
    #      apt repo + the RHEL/Fedora yum repo. Writes to:
    #        s3://<bucket>/dists/
    #        s3://<bucket>/pool/
    #        s3://<bucket>/db/
    #        s3://<bucket>/conf/
    #        s3://<bucket>/rpm/
    #        s3://<bucket>/gpg                  (the public key file)
    #
    #   2. deploy/release.sh — manages the desktop-client release
    #      artifacts + the Tauri auto-updater manifest. Writes to:
    #        s3://<bucket>/releases/<version>/HPN-VPN-*.{pkg,msi,app.tar.gz}
    #        s3://<bucket>/releases/<version>/*.sig
    #        s3://<bucket>/latest.json          (updater manifest)
    #
    # Before this fix, the sync used `aws s3 sync --delete` against
    # the bucket ROOT — so on every apt/rpm publish, ALL of
    # release.sh's artifacts (every shipped MSI/PKG/.app.tar.gz +
    # latest.json) got deleted because they were "not in
    # target/apt-repo/". The CI run on 2026-05-22 wiped both
    # 0.1.0 and 0.1.1 client binaries plus the updater manifest;
    # the live Download page started returning 403 and the Tauri
    # auto-updater stopped finding the manifest.
    #
    # The fix is to keep `--delete` (needed to garbage-collect old
    # repodata + Packages.gz indexes that reprepro doesn't track
    # itself) but EXCLUDE the release.sh-owned paths so the two
    # publishers stop deleting each other's artifacts.
    #
    # If you ever add a new top-level path under s3://<bucket>/
    # that is NOT managed by this script, ADD IT TO THIS EXCLUDE
    # LIST or move it under one of the script-managed prefixes.
    aws s3 sync "$REPO_DIR/" "s3://$S3_BUCKET/" \
        --endpoint-url "$S3_ENDPOINT" \
        --region "$S3_REGION" \
        --delete \
        --exclude "releases/*" \
        --exclude "latest.json" \
        --acl public-read \
        --no-progress

    echo ""
    echo "  Repository published!"
    echo ""
    echo "  Debian/Ubuntu:"
    echo "    curl -fsSL https://pkg.hpn.hmsx.io/gpg | sudo gpg --dearmor -o /etc/apt/keyrings/hpn.gpg"
    echo "    echo \"deb [signed-by=/etc/apt/keyrings/hpn.gpg] https://pkg.hpn.hmsx.io stable main\" | sudo tee /etc/apt/sources.list.d/hpn.list"
    echo "    sudo apt update && sudo apt install hpn-server"
    echo ""
    echo "  RHEL/AlmaLinux/Rocky:"
    echo "    sudo tee /etc/yum.repos.d/hpn.repo << 'REPO'"
    echo "    [hpn]"
    echo "    name=HPN VPN"
    echo "    baseurl=https://pkg.hpn.hmsx.io/rpm"
    echo "    enabled=1"
    echo "    gpgcheck=1"
    echo "    gpgkey=https://pkg.hpn.hmsx.io/gpg"
    echo "    REPO"
    echo "    sudo dnf install hpn-server"
    echo ""
}

# ── Main ────────────────────────────────────────────────────────────────────

check_deps

if [ "$EXPORT_GPG" = "1" ]; then
    export_gpg_key
    exit 0
fi

if [ "$INIT" = "1" ]; then
    generate_gpg_key
    init_repo
    export_gpg_key
    echo ""
    echo "  Repository initialized. Next steps:"
    echo "  1. Build packages: ./deploy/build-packages.sh"
    echo "  2. Add & publish:  ./deploy/publish-repo.sh"
    exit 0
fi

if [ "$SYNC_ONLY" = "1" ]; then
    sync_to_s3
    exit 0
fi

# Default: add packages + sync
add_packages
add_rpm_packages

if [ "$ADD_ONLY" != "1" ]; then
    sync_to_s3
fi

echo "Done."
