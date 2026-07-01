#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# HPN VPN — Unified release script (audit H14 auto-update)
# =============================================================================
#
# Builds, signs, and publishes a release for both macOS (built locally on
# Apple Silicon) and Windows (.msi provided as input — produced separately
# by GitLab CI or any other Windows-capable host).
#
# Output:
#   s3://pkg-hpn-io/releases/${VERSION}/HPN-VPN-${VERSION}-arm64.pkg
#   s3://pkg-hpn-io/releases/${VERSION}/HPN-VPN-${VERSION}-arm64.app.tar.gz
#   s3://pkg-hpn-io/releases/${VERSION}/HPN-VPN-${VERSION}-arm64.app.tar.gz.sig
#   s3://pkg-hpn-io/releases/${VERSION}/HPN-VPN-${VERSION}-x64.msi
#   s3://pkg-hpn-io/releases/${VERSION}/HPN-VPN-${VERSION}-x64.msi.sig
#   s3://pkg-hpn-io/latest.json                  (Tauri updater manifest)
#
# After the upload, the nginx proxy at pkg.hpn.hmsx.io serves the manifest
# with `Cache-Control: max-age=60`, so installed clients running the audit
# H14 auto-check see the update within ~60 s of upload.
#
# ── Usage ────────────────────────────────────────────────────────────────────
#
#   ./deploy/release.sh <VERSION> [OPTIONS]
#
# Required:
#   <VERSION>             Semver string, e.g. 0.2.0. Must match the version
#                         currently in Cargo.toml workspace + both
#                         tauri.conf.json files (the script verifies).
#
# Options:
#   --msi PATH            Path to the Authenticode-signed Windows .msi.
#                         If omitted, the Windows entry in latest.json is
#                         preserved from the previous release (so a Mac-
#                         only release does NOT regress Windows users).
#   --skip-mac            Skip the macOS build (e.g. you already produced
#                         the .pkg via macos-release.sh earlier).
#                         Still expects the .pkg + .app to be present at
#                         target/HPN-VPN-${VERSION}-arm64.pkg and the .app
#                         under target/aarch64-apple-darwin/release/.
#   --no-publish          Build + sign locally but do NOT upload to S3.
#                         Useful for dry runs / smoke tests.
#   -h, --help            Show this help and exit.
#
# ── Required environment variables ────────────────────────────────────────────
#
#   TAURI_SIGNING_PRIVATE_KEY            Content of ~/.tauri/hpn-prod.key
#                                        (the FILE CONTENT, not a path —
#                                        if you want to read from a file,
#                                        use $(cat ~/.tauri/hpn-prod.key)).
#   TAURI_SIGNING_PRIVATE_KEY_PASSWORD   Password used at `tauri signer
#                                        generate` time. Empty string OK
#                                        if generated with --no-password.
#
# Optional environment variables (passed through to macos-release.sh):
#
#   KEYCHAIN_PROFILE       Notarization profile name (recommended).
#   APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD
#                         Alternative to KEYCHAIN_PROFILE.
#   DEV_ID_APP, DEV_ID_INSTALLER
#                         Signing identity overrides — auto-detected if
#                         unset.
#
# Optional S3 credentials (read from ~/.aws/credentials by default):
#
#   AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
#                         Explicit credentials. Take precedence over the
#                         credentials file.
#
# ── Examples ─────────────────────────────────────────────────────────────────
#
#   # Full release with Windows .msi from CI artifact:
#   TAURI_SIGNING_PRIVATE_KEY="$(cat ~/.tauri/hpn-prod.key)" \
#   TAURI_SIGNING_PRIVATE_KEY_PASSWORD="..." \
#   KEYCHAIN_PROFILE=HPN-NOTARIZATION \
#       ./deploy/release.sh 0.2.0 --msi ~/Downloads/HPN-VPN_0.2.0_x64_en-US.msi
#
#   # Mac-only release (Windows .msi will be added later):
#   ./deploy/release.sh 0.2.0
#
#   # Dry run (build everything, don't push to S3):
#   ./deploy/release.sh 0.2.0 --msi /path/to/x64.msi --no-publish
#
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# ── Defaults ─────────────────────────────────────────────────────────────────

VERSION=""
MSI_PATH=""
SKIP_MAC=0
NO_PUBLISH=0

# S3 layout — these are intentionally hard-coded because they match the
# nginx reverse-proxy config at /etc/nginx/sites-available/hpn-pkg on
# the VPS Web. Changing them requires a coordinated change there too
# (see HPN-Web/deploy/nginx/hpn-pkg.conf for the versioned source of
# truth).
S3_BUCKET="${HPN_S3_BUCKET:-pkg-hpn-io}"
S3_ENDPOINT="${HPN_S3_ENDPOINT:-https://s3.gra.io.cloud.ovh.net}"
S3_REGION="${HPN_S3_REGION:-gra}"
MANIFEST_URL_BASE="https://pkg.hpn.hmsx.io"

# ── Argument parsing ─────────────────────────────────────────────────────────

usage() {
    sed -n '/^# ──/,/^# ==/p' "$0" | sed 's/^# \?//' | head -80
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --msi)         MSI_PATH="$2"; shift 2 ;;
        --skip-mac)    SKIP_MAC=1; shift ;;
        --no-publish)  NO_PUBLISH=1; shift ;;
        -h|--help)     usage; exit 0 ;;
        --*)           echo "ERROR: unknown option: $1" >&2; exit 1 ;;
        *)
            if [ -z "$VERSION" ]; then
                VERSION="$1"
            else
                echo "ERROR: unexpected positional arg: $1" >&2; exit 1
            fi
            shift
            ;;
    esac
done

if [ -z "$VERSION" ]; then
    echo "ERROR: <VERSION> is required" >&2
    echo "Try: $0 --help" >&2
    exit 1
fi

# Validate semver-ish: digits.digits.digits with optional -suffix
if ! echo "$VERSION" | grep -qE '^[0-9]+\.[0-9]+\.[0-9]+(-[a-zA-Z0-9.]+)?$'; then
    echo "ERROR: VERSION '$VERSION' is not a valid semver (e.g. 0.2.0)" >&2
    exit 1
fi

# ── Sanity: tools ────────────────────────────────────────────────────────────

check_tool() {
    if ! command -v "$1" &>/dev/null; then
        echo "ERROR: '$1' not found in PATH. $2" >&2
        exit 1
    fi
}

check_tool "aws"  "Install with: brew install awscli"
check_tool "jq"   "Install with: brew install jq"
check_tool "tar"  "Install with: brew install gnu-tar"
check_tool "node" "Install with: brew install node"

# `tauri signer sign` lives in @tauri-apps/cli — pick whichever copy is
# closest to the repo (the macOS app's local install is the canonical
# one, the Windows app has the same version pinned).
TAURI_CLI=""
for candidate in \
    "$REPO_ROOT/crates/hpn-ui-macos/ui/node_modules/.bin/tauri" \
    "$REPO_ROOT/crates/hpn-ui-windows/ui/node_modules/.bin/tauri" \
    "$(command -v tauri 2>/dev/null || true)"
do
    if [ -x "$candidate" ]; then
        TAURI_CLI="$candidate"
        break
    fi
done

if [ -z "$TAURI_CLI" ]; then
    echo "ERROR: tauri CLI not found." >&2
    echo "       Run: cd crates/hpn-ui-macos/ui && npm install" >&2
    exit 1
fi

# ── Sanity: env ──────────────────────────────────────────────────────────────

if [ -z "${TAURI_SIGNING_PRIVATE_KEY:-}" ]; then
    echo "ERROR: TAURI_SIGNING_PRIVATE_KEY is not set." >&2
    echo "       Export the FILE CONTENT (not the path), e.g.:" >&2
    echo "         export TAURI_SIGNING_PRIVATE_KEY=\"\$(cat ~/.tauri/hpn-prod.key)\"" >&2
    exit 1
fi

# Empty password is fine (allowed if key was generated --no-password),
# but the env var must be defined so the CLI does not prompt.
export TAURI_SIGNING_PRIVATE_KEY
export TAURI_SIGNING_PRIVATE_KEY_PASSWORD="${TAURI_SIGNING_PRIVATE_KEY_PASSWORD:-}"

# ── Sanity: version consistency ──────────────────────────────────────────────

WORKSPACE_VERSION=$(grep -E '^version = ' "$REPO_ROOT/Cargo.toml" \
    | head -1 | cut -d'"' -f2 || true)
if [ "$WORKSPACE_VERSION" != "$VERSION" ]; then
    echo "ERROR: VERSION mismatch." >&2
    echo "       Cargo.toml workspace: $WORKSPACE_VERSION" >&2
    echo "       Requested:            $VERSION" >&2
    echo "       Update Cargo.toml [workspace.package] first." >&2
    exit 1
fi

MAC_TAURI_VERSION=$(jq -r .version \
    "$REPO_ROOT/crates/hpn-ui-macos/src-tauri/tauri.conf.json")
WIN_TAURI_VERSION=$(jq -r .version \
    "$REPO_ROOT/crates/hpn-ui-windows/src-tauri/tauri.conf.json")
if [ "$MAC_TAURI_VERSION" != "$VERSION" ] || \
   [ "$WIN_TAURI_VERSION" != "$VERSION" ]; then
    echo "ERROR: tauri.conf.json version mismatch." >&2
    echo "       macOS:     $MAC_TAURI_VERSION" >&2
    echo "       Windows:   $WIN_TAURI_VERSION" >&2
    echo "       Requested: $VERSION" >&2
    exit 1
fi

# ── Sanity: .msi input (when provided) ───────────────────────────────────────

if [ -n "$MSI_PATH" ]; then
    if [ ! -f "$MSI_PATH" ]; then
        echo "ERROR: --msi path does not exist: $MSI_PATH" >&2
        exit 1
    fi
    # Empty file or under 1 MB is almost certainly not a real .msi
    MSI_SIZE=$(stat -f%z "$MSI_PATH" 2>/dev/null || stat -c%s "$MSI_PATH")
    if [ "$MSI_SIZE" -lt 1048576 ]; then
        echo "ERROR: --msi file is suspiciously small ($MSI_SIZE bytes)." >&2
        exit 1
    fi
fi

# ── Banner ───────────────────────────────────────────────────────────────────

echo "============================================================"
echo "  HPN VPN — Release ${VERSION}"
echo "============================================================"
echo "  Bucket:      s3://${S3_BUCKET} (endpoint ${S3_ENDPOINT})"
echo "  Manifest:    ${MANIFEST_URL_BASE}/latest.json"
echo "  macOS build: $([ "$SKIP_MAC" = "1" ] && echo SKIP || echo YES)"
echo "  Windows MSI: ${MSI_PATH:-<none — will preserve previous manifest entry>}"
echo "  Publish:     $([ "$NO_PUBLISH" = "1" ] && echo DRY-RUN || echo YES)"
echo "============================================================"
echo ""

# ── Release notes ────────────────────────────────────────────────────────────

NOTES_FILE="$REPO_ROOT/release-notes/${VERSION}.md"
if [ -f "$NOTES_FILE" ]; then
    NOTES=$(cat "$NOTES_FILE")
    echo "==> Release notes loaded from $NOTES_FILE"
    echo ""
    echo "$NOTES" | sed 's/^/    /'
    echo ""
else
    NOTES="Release ${VERSION}"
    echo "WARNING: no release-notes/${VERSION}.md found — using default note." >&2
    echo "         Create the file before next release for proper changelog." >&2
    echo ""
fi

# ── macOS build ──────────────────────────────────────────────────────────────

PKG_PATH="$REPO_ROOT/target/HPN-VPN-${VERSION}-arm64.pkg"
APP_PATH="$REPO_ROOT/target/aarch64-apple-darwin/release/bundle/macos/HPN VPN.app"
APP_TARBALL="$REPO_ROOT/target/HPN-VPN-${VERSION}-arm64.app.tar.gz"

if [ "$SKIP_MAC" = "1" ]; then
    echo "==> [macOS] Skipping build (--skip-mac)"
    if [ ! -f "$PKG_PATH" ] || [ ! -d "$APP_PATH" ]; then
        echo "ERROR: --skip-mac but artefacts missing:" >&2
        echo "       Expected: $PKG_PATH" >&2
        echo "       Expected: $APP_PATH" >&2
        exit 1
    fi
else
    echo "==> [macOS] Building signed + notarized .pkg via macos-release.sh"
    "$SCRIPT_DIR/macos-release.sh"
fi

# ── macOS .app.tar.gz (Tauri-updater bundle format) ──────────────────────────
#
# The updater plugin expects a `.app.tar.gz` (the .app bundle, gzipped
# tarball with the .app as the root entry — `--keepParent` semantics).
# The .pkg is for first-install only; updates download the tarball and
# unpack it in place.

echo "==> [macOS] Producing $APP_TARBALL"
rm -f "$APP_TARBALL"

# Use BSD tar from /usr/bin (built-in macOS). The `-s` flag is not
# portable; we use -C / basename to keep the archive root clean. The
# resulting tarball, when extracted, materialises `HPN VPN.app/` at
# the working directory — exactly what tauri-plugin-updater wants.
APP_PARENT="$(dirname "$APP_PATH")"
APP_NAME="$(basename "$APP_PATH")"
/usr/bin/tar -czf "$APP_TARBALL" -C "$APP_PARENT" "$APP_NAME"

APP_TARBALL_SIZE=$(stat -f%z "$APP_TARBALL" 2>/dev/null \
    || stat -c%s "$APP_TARBALL")
echo "    $APP_TARBALL ($(numfmt --to=iec-i --suffix=B "$APP_TARBALL_SIZE" 2>/dev/null \
    || echo "${APP_TARBALL_SIZE}B"))"

# ── Minisign signatures ──────────────────────────────────────────────────────
#
# `tauri signer sign` is a thin wrapper over libsodium minisign with the
# Tauri-specific header format the updater plugin verifies on download.
# Pre-existing .sig files are removed first so we never accidentally
# upload a stale signature from a previous run.
#
# We write the private key to a temp file (mode 600) rather than feeding
# it via `<<< "$KEY"` for two reasons:
#   - zsh / bash here-strings append a trailing `\n`, which makes the
#     CLI's base64 decoder fail at offset 348 with the misleading
#     "Invalid symbol 10" message (10 = ASCII LF). Detected by the
#     audit pass on 2026-05-18.
#   - `--private-key-path` accepts any path; a tempfile with 600 perms
#     is no more leak-prone than process argv (which `-k <value>`
#     would expose to anyone with `ps`).
# The trap below ensures the keyfile is shredded on exit, including on
# SIGINT / SIGTERM / `set -e` abort.

echo "==> [signing] Producing minisign .sig files via Tauri CLI"

KEYFILE=$(mktemp -t hpn-tauri-key.XXXXXXXX)
chmod 600 "$KEYFILE"
# shellcheck disable=SC2064  # we want $KEYFILE to expand at trap-setup time
trap "rm -f '$KEYFILE'" EXIT INT TERM
# `printf '%s'` writes the exact bytes — no trailing newline that
# would corrupt the base64 decode.
printf '%s' "$TAURI_SIGNING_PRIVATE_KEY" > "$KEYFILE"

sign_with_tauri() {
    # $1 = file to sign
    local target="$1"
    rm -f "${target}.sig"
    "$TAURI_CLI" signer sign \
        --private-key-path "$KEYFILE" \
        --password "$TAURI_SIGNING_PRIVATE_KEY_PASSWORD" \
        "$target" 2>&1 \
        | sed 's/^/    /'
    if [ ! -f "${target}.sig" ]; then
        echo "ERROR: tauri signer did not produce ${target}.sig" >&2
        echo "       See the indented CLI output above for the cause." >&2
        exit 1
    fi
}

sign_with_tauri "$APP_TARBALL"

if [ -n "$MSI_PATH" ]; then
    # Copy the .msi into target/ so the final artefact has a
    # predictable filename, then sign the local copy.
    STAGED_MSI="$REPO_ROOT/target/HPN-VPN-${VERSION}-x64.msi"
    cp "$MSI_PATH" "$STAGED_MSI"
    sign_with_tauri "$STAGED_MSI"
fi

echo "    Signatures produced:"
ls -la \
    "${APP_TARBALL}.sig" \
    "${STAGED_MSI:+${STAGED_MSI}.sig}" 2>/dev/null \
    | awk '{print "      " $9 " (" $5 " bytes)"}'

if [ "$NO_PUBLISH" = "1" ]; then
    echo ""
    echo "============================================================"
    echo "  DRY RUN COMPLETE — nothing uploaded"
    echo "============================================================"
    echo "  Re-run without --no-publish to push to S3."
    exit 0
fi

# ── S3 upload ────────────────────────────────────────────────────────────────

aws_cp() {
    # Tiny wrapper to keep all aws invocations consistent.
    # $1 = local path, $2 = s3 key (relative to bucket), $@ = extra aws args
    local local_path="$1"; shift
    local s3_key="$1"; shift
    aws s3 cp "$local_path" "s3://${S3_BUCKET}/${s3_key}" \
        --endpoint-url "$S3_ENDPOINT" \
        --region "$S3_REGION" \
        --acl public-read \
        --quiet \
        "$@"
}

echo "==> [S3] Uploading artefacts to s3://${S3_BUCKET}/releases/${VERSION}/"

PKG_BASENAME="$(basename "$PKG_PATH")"
TARBALL_BASENAME="$(basename "$APP_TARBALL")"

aws_cp "$PKG_PATH"            "releases/${VERSION}/${PKG_BASENAME}"
aws_cp "$APP_TARBALL"         "releases/${VERSION}/${TARBALL_BASENAME}"
aws_cp "${APP_TARBALL}.sig"   "releases/${VERSION}/${TARBALL_BASENAME}.sig"
echo "    macOS .pkg + .app.tar.gz + .sig uploaded"

if [ -n "${STAGED_MSI:-}" ]; then
    MSI_BASENAME="$(basename "$STAGED_MSI")"
    aws_cp "$STAGED_MSI"          "releases/${VERSION}/${MSI_BASENAME}"
    aws_cp "${STAGED_MSI}.sig"    "releases/${VERSION}/${MSI_BASENAME}.sig"
    echo "    Windows .msi + .sig uploaded"
fi

# ── Manifest generation (latest.json) ────────────────────────────────────────
#
# We merge the new release into whatever latest.json currently exists.
# This preserves any platforms NOT being updated this run — typically
# `windows-x86_64` when running a Mac-only release without --msi.

echo "==> [manifest] Generating latest.json"

PREV_MANIFEST="$REPO_ROOT/target/latest.json.previous"
NEW_MANIFEST="$REPO_ROOT/target/latest.json"

# Pull the previous manifest. If the file does not exist (first
# release ever), we start from `{}`.
if aws s3 cp "s3://${S3_BUCKET}/latest.json" "$PREV_MANIFEST" \
        --endpoint-url "$S3_ENDPOINT" --region "$S3_REGION" \
        --quiet 2>/dev/null; then
    echo "    Previous manifest fetched"
else
    echo '{}' > "$PREV_MANIFEST"
    echo "    No previous manifest — starting fresh"
fi

# Read signatures (raw contents of the .sig files, NOT the file paths)
APP_SIG=$(cat "${APP_TARBALL}.sig")
PUB_DATE=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

# Build the new platforms object: start with the previous one
# (preserve other platforms), then overwrite our slots.
JQ_FILTER='
    .version    = $version |
    .notes      = $notes |
    .pub_date   = $pub_date |
    .platforms  = (.platforms // {}) |
    .platforms."darwin-aarch64" = {
        signature: $app_sig,
        url:       $app_url
    }
'

JQ_ARGS=(
    --arg version  "$VERSION"
    --arg notes    "$NOTES"
    --arg pub_date "$PUB_DATE"
    --arg app_sig  "$APP_SIG"
    --arg app_url  "${MANIFEST_URL_BASE}/releases/${VERSION}/${TARBALL_BASENAME}"
)

if [ -n "${STAGED_MSI:-}" ]; then
    MSI_SIG=$(cat "${STAGED_MSI}.sig")
    JQ_FILTER="$JQ_FILTER |
    .platforms.\"windows-x86_64\" = {
        signature: \$msi_sig,
        url:       \$msi_url
    }"
    JQ_ARGS+=(
        --arg msi_sig "$MSI_SIG"
        --arg msi_url "${MANIFEST_URL_BASE}/releases/${VERSION}/${MSI_BASENAME}"
    )
fi

jq "${JQ_ARGS[@]}" "$JQ_FILTER" "$PREV_MANIFEST" > "$NEW_MANIFEST"

echo "    New manifest:"
sed 's/^/      /' "$NEW_MANIFEST" | head -25

# Upload with a 60 s cache header so installed clients see the new
# release within ~1 min. The nginx VPS Web override on `/latest.json`
# also pins origin caching to 60 s (HPN-Web/deploy/nginx/hpn-pkg.conf).
aws s3 cp "$NEW_MANIFEST" "s3://${S3_BUCKET}/latest.json" \
    --endpoint-url "$S3_ENDPOINT" \
    --region "$S3_REGION" \
    --acl public-read \
    --cache-control "public, max-age=60" \
    --content-type "application/json" \
    --quiet

echo "    Uploaded latest.json (cache-control: 60s)"

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo "============================================================"
echo "  RELEASE ${VERSION} PUBLISHED"
echo "============================================================"
echo ""
echo "  Artefacts:"
echo "    ${MANIFEST_URL_BASE}/releases/${VERSION}/${PKG_BASENAME}"
echo "    ${MANIFEST_URL_BASE}/releases/${VERSION}/${TARBALL_BASENAME}"
if [ -n "${MSI_BASENAME:-}" ]; then
    echo "    ${MANIFEST_URL_BASE}/releases/${VERSION}/${MSI_BASENAME}"
fi
echo ""
echo "  Manifest:"
echo "    ${MANIFEST_URL_BASE}/latest.json"
echo ""
echo "  Verify the manifest is reachable (60 s cache delay possible):"
echo "    curl -s ${MANIFEST_URL_BASE}/latest.json | jq ."
echo ""
echo "  Installed clients running v < ${VERSION} will see the popup"
echo "  within ~60 s of their next launch (auto-check fires 3 s after"
echo "  setup; nginx caches the manifest for 60 s)."
echo ""
