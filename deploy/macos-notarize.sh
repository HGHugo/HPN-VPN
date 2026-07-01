#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# HPN VPN macOS — Standalone Notarization Utility
# =============================================================================
#
# Notarizes an existing signed `.pkg` and staples the resulting Apple
# ticket back into it. This is a thin wrapper around `xcrun notarytool`
# that exists for two scenarios:
#
#   1. Re-notarizing a `.pkg` that was already produced by
#      `macos-release.sh` with `NOTARIZE=0` (e.g. CI built the artefact
#      offline and the operator notarizes from a workstation later).
#
#   2. Notarizing a `.pkg` that came from elsewhere — useful for a
#      one-off release re-cut without rebuilding the whole pipeline.
#
# This script does NOT build, sign, or modify the bundle. The input
# `.pkg` MUST already be:
#
#   - Signed with a Developer ID Installer certificate (via
#     `productsign --sign`). Verify with: `pkgutil --check-signature`.
#   - Containing a `.app` whose binaries are themselves signed with
#     Developer ID Application AND Hardened Runtime AND timestamped
#     by Apple's TSA. Verify with: `codesign --verify --deep`.
#
# If those preconditions are NOT met, Apple's notary service rejects
# the submission with a message like "The signature does not include
# a secure timestamp" or "The binary uses an SDK older than the 10.9
# SDK", and you get a useless ticket that won't staple.
#
# ── Usage ────────────────────────────────────────────────────────────────────
#
#   ./deploy/macos-notarize.sh path/to/HPN-VPN-x.y.z-arm64.pkg
#
# ── Required environment (one of two modes) ──────────────────────────────────
#
# Mode 1 — Keychain profile (recommended for repeated local builds):
#
#   KEYCHAIN_PROFILE   Name of a `notarytool store-credentials` profile.
#                      Set up once with:
#                        xcrun notarytool store-credentials "HPN-NOTARIZATION" \
#                            --apple-id "you@example.com" \
#                            --team-id "6Y986MRM6T" \
#                            --password "abcd-efgh-ijkl-mnop"
#
# Mode 2 — Direct credentials (for ephemeral CI runners):
#
#   APPLE_ID           Apple ID email.
#   APPLE_TEAM_ID      10-character team identifier.
#   APPLE_APP_PASSWORD App-specific password (NOT the Apple ID password).
#                      Generate at appleid.apple.com → Sign-In and
#                      Security → App-Specific Passwords.
#
# =============================================================================

PKG_PATH="${1:-}"

if [ -z "$PKG_PATH" ]; then
    echo "Usage: $0 <path-to-pkg>"
    exit 2
fi

if [ ! -f "$PKG_PATH" ]; then
    echo "ERROR: $PKG_PATH not found"
    exit 1
fi

echo "============================================================"
echo "  HPN VPN macOS Notarization"
echo "============================================================"
echo "  Pkg: $PKG_PATH"
echo "============================================================"
echo ""

# ── Pre-flight: verify the pkg is signed before we waste a notary slot ──────

echo "==> [1/3] Pre-flight: pkg signature check"
if ! pkgutil --check-signature "$PKG_PATH" > /tmp/hpn-notarize-sigcheck.log 2>&1; then
    cat /tmp/hpn-notarize-sigcheck.log
    echo "ERROR: Pkg has no Developer ID Installer signature."
    echo "       Run 'productsign --sign \"Developer ID Installer: ...\"' first."
    rm -f /tmp/hpn-notarize-sigcheck.log
    exit 1
fi
tail -5 /tmp/hpn-notarize-sigcheck.log
rm -f /tmp/hpn-notarize-sigcheck.log

# Confirm the signature certificate chain is Apple-rooted (not self-
# signed). Notary will reject self-signed pkgs with an opaque error.
if ! pkgutil --check-signature "$PKG_PATH" | grep -q "Developer ID Installer"; then
    echo "ERROR: Pkg is signed but NOT with a Developer ID Installer cert."
    echo "       Notary will reject this submission."
    exit 1
fi
echo "   OK: signed with Developer ID Installer"

# ── Step 2: Build notarytool credential args ─────────────────────────────────

NOTARY_ARGS=()
if [ -n "${KEYCHAIN_PROFILE:-}" ]; then
    NOTARY_ARGS=(--keychain-profile "$KEYCHAIN_PROFILE")
    echo "==> [2/3] Submitting to Apple notary (using keychain profile '$KEYCHAIN_PROFILE')"
elif [ -n "${APPLE_ID:-}" ] && [ -n "${APPLE_TEAM_ID:-}" ] && [ -n "${APPLE_APP_PASSWORD:-}" ]; then
    NOTARY_ARGS=(
        --apple-id "$APPLE_ID"
        --team-id "$APPLE_TEAM_ID"
        --password "$APPLE_APP_PASSWORD"
    )
    echo "==> [2/3] Submitting to Apple notary (apple-id: $APPLE_ID)"
else
    echo "ERROR: missing notarization credentials. Set either:"
    echo "         KEYCHAIN_PROFILE=<name>"
    echo "       OR all three of:"
    echo "         APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD"
    exit 1
fi

# `--wait` blocks until Apple returns a verdict. Typical latency
# 1-5 minutes; Apple's SLA is "under one hour". `--output-format plist`
# is parser-friendlier than the default human-readable output.
set +e
SUBMIT_OUTPUT=$(xcrun notarytool submit "$PKG_PATH" \
    "${NOTARY_ARGS[@]}" \
    --wait \
    --output-format plist 2>&1)
SUBMIT_RC=$?
set -e

echo "$SUBMIT_OUTPUT" | tail -15

if [ $SUBMIT_RC -ne 0 ]; then
    echo ""
    echo "ERROR: notarytool exited with non-zero status ($SUBMIT_RC)."
    echo "       Common causes:"
    echo "         - Network timeout (retry)"
    echo "         - Invalid app-specific password (regenerate at appleid.apple.com)"
    echo "         - Team ID mismatch with the signing cert"
    exit 1
fi

if ! echo "$SUBMIT_OUTPUT" | grep -q "status: Accepted"; then
    SUBMISSION_ID=$(echo "$SUBMIT_OUTPUT" | grep -E "^[[:space:]]*id:" | head -1 | awk '{print $2}')
    echo ""
    echo "ERROR: Notarization REJECTED by Apple."
    if [ -n "$SUBMISSION_ID" ]; then
        echo "       Fetch the full Apple report with:"
        echo "         xcrun notarytool log $SUBMISSION_ID ${NOTARY_ARGS[*]}"
    fi
    echo ""
    echo "       Most common rejection reasons (fix BEFORE retry):"
    echo "         - 'The binary is not signed with a valid Developer ID':"
    echo "             pkgutil --check-signature was OK, but the .app inside"
    echo "             was signed with Apple Development instead. Re-run"
    echo "             macos-release.sh which uses Developer ID."
    echo "         - 'The executable does not have the hardened runtime enabled':"
    echo "             missing --options runtime in codesign."
    echo "         - 'The signature does not include a secure timestamp':"
    echo "             missing --timestamp in codesign."
    echo "         - 'The signature of the binary is invalid':"
    echo "             entitlements changed after signing — re-sign."
    exit 1
fi

echo "   Notarization: ACCEPTED"

# ── Step 3: Staple the ticket so the pkg works offline ──────────────────────

echo "==> [3/3] Stapling notarization ticket"
xcrun stapler staple "$PKG_PATH"

# Verify Gatekeeper will accept the stapled pkg. This is the SAME
# command macOS runs when the user double-clicks: passing here
# means passing on every Mac running 10.15+.
echo ""
echo "==> Gatekeeper assessment"
spctl --assess --type install --verbose=4 "$PKG_PATH"

echo ""
echo "============================================================"
echo "  NOTARIZED + STAPLED"
echo "============================================================"
echo "  $PKG_PATH"
echo ""
echo "  This pkg is now ready to publish. Users on macOS 10.15+ can"
echo "  download and install it offline (no network required at"
echo "  install time — the staple holds the Apple verdict)."
echo ""
