#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
# HPN VPN macOS Release Build (Developer ID + Notarization)
# =============================================================================
#
# Produces a signed, notarized, stapled `.pkg` ready to publish at
# `pkg.hpn.hmsx.io`. Distribution channel: Developer ID outside the
# Mac App Store. Apple Notarization is REQUIRED for any `.pkg`
# downloaded from the Internet on macOS 10.15+; a non-notarized pkg
# will be Gatekeeper-blocked on the user's machine with the dreaded
# "cannot be opened because the developer cannot be verified" dialog.
#
# This script differs from `macos-dev-test.sh` in three ways:
#
#   1. Uses Developer ID Application certificate (not Apple Development)
#      to sign the `.app` and the embedded `.appex` extension.
#   2. Uses Developer ID Installer certificate to sign the final `.pkg`.
#   3. Submits the signed `.pkg` to Apple notary service via
#      `xcrun notarytool` and staples the resulting ticket back into
#      the package so it works offline.
#
# ── Required environment variables ────────────────────────────────────────────
#
#   DEV_ID_APP        Full common name of the Developer ID Application cert,
#                     e.g. "Developer ID Application: HMSX Solutions (6Y986MRM6T)"
#                     If unset, the script tries to auto-detect the first
#                     "Developer ID Application:" identity in the keychain.
#
#   DEV_ID_INSTALLER  Full common name of the Developer ID Installer cert,
#                     e.g. "Developer ID Installer: HMSX Solutions (6Y986MRM6T)"
#                     Auto-detected from the keychain if unset.
#
# ── Optional environment variables ────────────────────────────────────────────
#
#   NOTARIZE          1 to submit to Apple notary service (default 1).
#                     Set to 0 for a signed-but-unnotarized build (CI smoke
#                     tests, internal QA on a pre-Catalina-style host).
#
#   APPLE_ID          Apple ID email used to authenticate to notary.
#                     Required when NOTARIZE=1 unless KEYCHAIN_PROFILE is set.
#
#   APPLE_TEAM_ID     10-character team identifier (e.g. 6Y986MRM6T).
#                     Required when NOTARIZE=1 unless KEYCHAIN_PROFILE is set.
#
#   APPLE_APP_PASSWORD App-specific password generated at appleid.apple.com
#                      (NOT the Apple ID password). Required when
#                      NOTARIZE=1 unless KEYCHAIN_PROFILE is set. Can be
#                      passed as `@keychain:NAME` to read from the local
#                      keychain entry NAME.
#
#   KEYCHAIN_PROFILE   Alternative to the three vars above — name of a
#                      `notarytool store-credentials` profile, see below.
#                      Recommended for repeated local builds.
#
#   VERSION            Build version (default: read from Cargo.toml).
#
#   TARGET             Rust target triple (default: aarch64-apple-darwin).
#                      Use x86_64-apple-darwin for Intel, or run twice and
#                      lipo together for a universal binary.
#
#   SKIP_TAURI_BUILD   1 to reuse an existing Tauri-built `.app`.
#   SKIP_EXT_BUILD     1 to reuse an existing Xcode-built extension.
#
# ── First-time setup ──────────────────────────────────────────────────────────
#
# Before the first run, store your notary credentials in the keychain so
# subsequent runs don't need APPLE_APP_PASSWORD on the command line:
#
#   xcrun notarytool store-credentials "HPN-NOTARIZATION" \
#       --apple-id "you@example.com" \
#       --team-id "6Y986MRM6T" \
#       --password "abcd-efgh-ijkl-mnop"   # app-specific password
#
# Then run with: KEYCHAIN_PROFILE=HPN-NOTARIZATION ./deploy/macos-release.sh
#
# ── Output ────────────────────────────────────────────────────────────────────
#
# On success:
#   target/HPN-VPN-${VERSION}-${arch}.pkg          notarized + stapled
#   target/HPN-VPN-${VERSION}-${arch}.pkg.sig      Tauri minisign signature
#                                                   (only when prod
#                                                   TAURI_SIGNING_PRIVATE_KEY
#                                                   is set; otherwise absent
#                                                   and the file must be
#                                                   re-signed at publish time)
#
# Verify locally (the same check Gatekeeper runs on the user's mac):
#   spctl --assess --type install target/HPN-VPN-*.pkg
#   # Expected output: "accepted; source=Notarized Developer ID"
#
# =============================================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
TAURI_DIR="$REPO_ROOT/crates/hpn-ui-macos"
TARGET="${TARGET:-aarch64-apple-darwin}"
VERSION="${VERSION:-$(grep -E '^version = ' "$REPO_ROOT/Cargo.toml" | head -1 | cut -d'"' -f2)}"
ARCH="${ARCH:-arm64}"
case "$TARGET" in
    aarch64-*) ARCH="arm64" ;;
    x86_64-*)  ARCH="x86_64" ;;
esac

ENTITLEMENTS="$TAURI_DIR/src-tauri/entitlements.plist"
ASSETS_DIR="$REPO_ROOT/deploy/installer-assets"
SKIP_TAURI_BUILD="${SKIP_TAURI_BUILD:-0}"
SKIP_EXT_BUILD="${SKIP_EXT_BUILD:-0}"
NOTARIZE="${NOTARIZE:-1}"

# ── Helper: locate signing identities ────────────────────────────────────────

auto_detect_identity() {
    # $1 = prefix to grep for, e.g. "Developer ID Application:"
    # $2 = security policy ("codesigning" for app/extension certs,
    #      "basic" for Installer certs — `find-identity -p codesigning`
    #      does NOT list Installer certs, see Apple's TN2206).
    # Pulls the first matching identity from the user's login keychain.
    # Output format: "<hash> "Developer ID Application: HMSX Solutions (6Y986MRM6T)""
    security find-identity -v -p "$2" 2>/dev/null \
        | awk -v prefix="$1" '
            $0 ~ prefix {
                # Capture everything between the first and last double quote
                # on this line. find-identity -v output looks like:
                #   1) DEADBEEF... "Developer ID Application: HMSX (6Y986MRM6T)"
                match($0, /"[^"]+"/);
                if (RLENGTH > 0) {
                    name = substr($0, RSTART + 1, RLENGTH - 2);
                    print name;
                    exit;
                }
            }'
}

DEV_ID_APP="${DEV_ID_APP:-$(auto_detect_identity 'Developer ID Application:' codesigning)}"
DEV_ID_INSTALLER="${DEV_ID_INSTALLER:-$(auto_detect_identity 'Developer ID Installer:' basic)}"

# ── Banner ───────────────────────────────────────────────────────────────────

echo "============================================================"
echo "  HPN VPN macOS Release Build"
echo "============================================================"
echo "  Version:           ${VERSION}"
echo "  Target:            ${TARGET} (${ARCH})"
echo "  App signing:       ${DEV_ID_APP:-<NOT SET>}"
echo "  Installer signing: ${DEV_ID_INSTALLER:-<NOT SET>}"
echo "  Notarize:          ${NOTARIZE}"
echo "============================================================"
echo ""

# ── Sanity checks ────────────────────────────────────────────────────────────

if [ -z "$DEV_ID_APP" ]; then
    echo "ERROR: No Developer ID Application certificate found in the keychain."
    echo "       Either set DEV_ID_APP env var, or import the cert via Keychain Access:"
    echo "         developer.apple.com → Certificates → Developer ID Application"
    exit 1
fi

if [ -z "$DEV_ID_INSTALLER" ]; then
    echo "ERROR: No Developer ID Installer certificate found in the keychain."
    echo "       Either set DEV_ID_INSTALLER env var, or import the cert via Keychain Access:"
    echo "         developer.apple.com → Certificates → Developer ID Installer"
    exit 1
fi

if [ "$NOTARIZE" = "1" ]; then
    if [ -z "${KEYCHAIN_PROFILE:-}" ] && {
        [ -z "${APPLE_ID:-}" ] || [ -z "${APPLE_TEAM_ID:-}" ] || [ -z "${APPLE_APP_PASSWORD:-}" ];
    }; then
        echo "ERROR: Notarization requires either KEYCHAIN_PROFILE, or all three of:"
        echo "       APPLE_ID, APPLE_TEAM_ID, APPLE_APP_PASSWORD."
        echo "       Set NOTARIZE=0 to skip notarization (signed-but-unnotarized build)."
        exit 1
    fi
fi

# ── Step 0: Purge stale dev builds before signing ────────────────────────────
#
# Critical hardening introduced after a Tahoe (macOS 26) field incident
# where sysextd refused activation with the misleading error
#   "no policy, cannot allow apps outside /Applications"
# even on a fully-notarised pkg installed under /Applications.
#
# Root cause: previous Xcode/Tauri dev builds left bundles at
#   ~/Library/Developer/Xcode/DerivedData/macos-*/Build/Products/Release/HPN VPN.app
#   target/<triple>/release/bundle/macos/HPN VPN.app(.staged)
# carrying the same `io.hpn.vpn.macos` CFBundleIdentifier as the
# production bundle but with the legacy `Contents/PlugIns/packet-tunnel.appex`
# layout (pre-systemextension migration).  Spotlight + securityd
# indexed those copies and at OSSystemExtensionRequest time Apple's
# security framework resolved the host bundle through the cached
# DerivedData path instead of /Applications/HPN VPN.app, then rejected
# the request because that path is "outside /Applications".
#
# The only deterministic fix is to never let those stale copies exist
# on the build host in the first place. Removing them here means a
# release build always starts from a clean slate; if the operator
# wants to keep a dev build around, they should do so on a different
# checkout (or Cargo target dir) that never gets opened in Xcode.
#
# `SKIP_TAURI_BUILD=1` and `SKIP_EXT_BUILD=1` opt-out of the
# corresponding rebuilds but NOT out of the cleanup, since the
# cleanup is a safety check, not a build artefact.

echo "==> [0/9] Purging stale dev bundles (DerivedData + target/bundle)"

# Xcode DerivedData for the packet-tunnel project. The directory name
# is suffixed with a stable hash of the absolute project path; a glob
# is the only safe way to find it across operator machines.
DERIVED_DATA_PATTERN="$HOME/Library/Developer/Xcode/DerivedData/macos-*"
shopt -s nullglob
for d in $DERIVED_DATA_PATTERN; do
    if [ -d "$d/Build/Products/Release/HPN VPN.app" ] || \
       [ -d "$d/Build/Products/Release/packet-tunnel.appex" ] || \
       [ -d "$d/Build/Products/Release/packet-tunnel.systemextension" ]; then
        echo "    Removing stale DerivedData: $d"
        rm -rf "$d"
    fi
done
shopt -u nullglob

# Tauri bundle staging directory. `cargo tauri build` produces an
# `.app.staged` first then renames to `.app` on success, but a
# previous interrupted build can leave both lying around with the
# production bundle ID. Wipe the whole macos bundle dir.
BUNDLE_STAGING="$REPO_ROOT/target/$TARGET/release/bundle/macos"
if [ -d "$BUNDLE_STAGING" ]; then
    echo "    Removing stale Tauri bundle: $BUNDLE_STAGING"
    rm -rf "$BUNDLE_STAGING"
fi

# Xcode in-tree build directory. When `xcodebuild` is invoked
# without `-derivedDataPath`, it materialises BUILT_PRODUCTS_DIR at
# `<project>/build/<config>/` instead of DerivedData. A pre-migration
# build of `packet-tunnel` (back when it was still an `.appex`
# App Extension) leaves a `build/Release/packet-tunnel.appex` here
# with the production CFBundleIdentifier `io.hpn.vpn.macos.packet-tunnel`,
# which Spotlight indexes as a valid extension provider for that
# bundle ID. At OSSystemExtensionRequest time, Apple's Security
# framework prefers this in-tree copy over the
# `/Applications/HPN VPN.app/Contents/Library/SystemExtensions/
# packet-tunnel.systemextension` it should be using, evaluates
# `is_in_applications` against `/Users/admin/...`, and rejects.
#
# The Tahoe field incident in May 2026 was traced to exactly this
# directory (caught via
# `mdfind 'kBundleIdentifier == "io.hpn.vpn.macos.packet-tunnel"'`
# returning the in-tree path instead of the production extension).
# The directory is in .gitignore so it is never committed, but it
# survives a `git clean` and persists across release builds — hence
# the explicit purge here.
XCODE_INTREE_BUILD="$TAURI_DIR/xcode-native/macos/build"
if [ -d "$XCODE_INTREE_BUILD" ]; then
    echo "    Removing stale Xcode in-tree build: $XCODE_INTREE_BUILD"
    rm -rf "$XCODE_INTREE_BUILD"
fi
# Same rationale for an in-tree DerivedData created by some Xcode
# versions when the operator opens the project in the IDE while a
# CLI build is running (race condition).
XCODE_INTREE_DD="$TAURI_DIR/xcode-native/macos/DerivedData"
if [ -d "$XCODE_INTREE_DD" ]; then
    echo "    Removing stale in-tree DerivedData: $XCODE_INTREE_DD"
    rm -rf "$XCODE_INTREE_DD"
fi

# Old xcarchive locations that pre-date the systemextension
# migration. These contain a `Contents/PlugIns/packet-tunnel.appex`
# which Spotlight indexes as the canonical extension for
# `io.hpn.vpn.macos.packet-tunnel`. We do NOT delete the entire
# Archives directory (the operator may have valid archives for
# other projects), only the HPN-VPN-specific ones.
shopt -s nullglob
for archive in "$HOME/Library/Developer/Xcode/Archives/"*"/HPN-VPN-"*.xcarchive; do
    if [ -d "$archive" ]; then
        echo "    Removing stale xcarchive: $archive"
        rm -rf "$archive"
    fi
done
shopt -u nullglob

echo "   Done"

# ── Step 1: Build Rust staticlib ─────────────────────────────────────────────

echo "==> [1/9] Building Rust staticlib (hpn-tunnel-ext) for ${TARGET}"
cargo build -p hpn-tunnel-ext --target "$TARGET" --release 2>&1 | tail -1
echo "   Done"

# ── Step 2: Build Tauri app ──────────────────────────────────────────────────

if [ "$SKIP_TAURI_BUILD" = "1" ]; then
    echo "==> [2/9] Skipping Tauri build (SKIP_TAURI_BUILD=1)"
else
    echo "==> [2/9] Building Tauri macOS app (frontend + Rust backend)"
    cd "$TAURI_DIR"
    # `--no-sign` defers signing to this script (which knows about the
    # Developer ID + Hardened Runtime + Network Extension entitlement
    # combination Tauri itself does not handle natively).
    cargo tauri build --target "$TARGET" --bundles app --no-sign
    cd "$REPO_ROOT"
fi

APP_PATH=$(find "$REPO_ROOT/target/$TARGET/release/bundle/macos" -maxdepth 1 -name "*.app" | head -n1)
if [ -z "$APP_PATH" ]; then
    echo "ERROR: Tauri-produced .app not found under target/${TARGET}/release/bundle/macos/"
    echo "       Run without SKIP_TAURI_BUILD to rebuild."
    exit 1
fi
echo "   App: $APP_PATH"

# ── Step 3: Build Packet Tunnel Extension via Xcode ──────────────────────────

XCODE_PROJECT="$TAURI_DIR/xcode-native/macos/macos.xcodeproj"

if [ "$SKIP_EXT_BUILD" = "1" ]; then
    echo "==> [3/9] Skipping extension build (SKIP_EXT_BUILD=1)"
else
    echo "==> [3/9] Building Packet Tunnel Extension via Xcode"
    # We do NOT pass CODE_SIGN_STYLE / DEVELOPMENT_TEAM overrides here.
    # The targets are configured for Manual signing (Developer ID
    # provisioning profiles selected explicitly in Signing &
    # Capabilities) and forcing Automatic on the command line
    # produces "macos has conflicting provisioning settings" errors
    # when the project-level setting and the override disagree.
    #
    # Rationale: Developer ID distribution requires Manual signing
    # because Xcode's automatic-signing flow only knows how to issue
    # Apple Development / Apple Distribution / Mac App Distribution
    # profiles — not Developer ID. The operator selected the right
    # profiles once (per OPERATIONS.md §3 step C); we just respect
    # what they configured.
    #
    # We DO keep the build verbose enough to surface real errors
    # (the previous `tail -3` swallowed crucial 'conflicting
    # provisioning settings' lines that came earlier in the output).
    xcodebuild -project "$XCODE_PROJECT" \
        -scheme "packet-tunnel" \
        -configuration Release \
        build 2>&1 \
        | grep -E "error:|warning:|Build|Compiling|Linking|Codesign|^==>|BUILD" \
        | tail -20
    # Capture the xcodebuild status separately because the pipe above
    # always returns 0 (grep | tail), masking a build failure.
    XCODEBUILD_STATUS=${PIPESTATUS[0]:-${pipestatus[1]:-0}}
    if [ "$XCODEBUILD_STATUS" != "0" ]; then
        echo "ERROR: xcodebuild packet-tunnel failed (exit $XCODEBUILD_STATUS)."
        echo "       Re-run without the script to see the full log:"
        echo "         cd crates/hpn-ui-macos/xcode-native/macos &&"
        echo "         xcodebuild -project macos.xcodeproj -scheme packet-tunnel \\"
        echo "             -configuration Release build"
        exit 1
    fi
fi

# Locate the resulting .appex inside Xcode's DerivedData.
find_xcode_build() {
    local build_dir
    for app_name in "HPN VPN.app" "macos.app"; do
        build_dir=$(find "$HOME/Library/Developer/Xcode/DerivedData" \
            -name "$app_name" -path "*/Release/*" -maxdepth 6 2>/dev/null | head -1)
        [ -n "$build_dir" ] && { echo "$build_dir"; return; }
    done
    echo ""
}

XCODE_BUILD=$(find_xcode_build)
if [ -z "$XCODE_BUILD" ]; then
    echo "ERROR: Xcode-built .app not found in DerivedData."
    echo "       Open the project in Xcode at least once and Cmd+B the"
    echo "       packet-tunnel scheme to seed the DerivedData cache."
    exit 1
fi
echo "   Xcode build: $XCODE_BUILD"

# ── Step 4: Embed extension + provisioning profile into the Tauri .app ──────

echo "==> [4/9] Embedding extension + provisioning profile"

# Apple deprecated the legacy `.appex` ("App Extension") packaging for
# Network Extensions on macOS Developer ID distributions in 2023. The
# Packet Tunnel must now be packaged as a `.systemextension` and embedded
# under Contents/Library/SystemExtensions/ — NOT Contents/PlugIns/.
#
# We auto-detect which format the Xcode build produced so the script
# works during the migration window: a freshly-rebuilt Xcode target
# yields the `.systemextension`, an older cached build still has the
# `.appex`. If both are present, prefer the system extension (the
# legacy path will fail at notarisation anyway with the new
# entitlements).

# Xcode now produces `io.hpn.vpn.macos.packet-tunnel.systemextension`
# directly (via PRODUCT_NAME = bundle identifier in pbxproj — see
# AGENTS.md "Tahoe System Extension" entry for the rationale). We
# still glob for legacy short-name builds in case an older
# DerivedData is around, then prefer the bundle-id-matched name.
SYSEXT_SRC_NEW="$XCODE_BUILD/Contents/Library/SystemExtensions/io.hpn.vpn.macos.packet-tunnel.systemextension"
SYSEXT_SRC_OLD="$XCODE_BUILD/Contents/Library/SystemExtensions/packet-tunnel.systemextension"
APPEX_SRC="$XCODE_BUILD/Contents/PlugIns/packet-tunnel.appex"

# Pick whichever one the current Xcode build actually produced.
if [ -d "$SYSEXT_SRC_NEW" ]; then
    SYSEXT_SRC="$SYSEXT_SRC_NEW"
elif [ -d "$SYSEXT_SRC_OLD" ]; then
    SYSEXT_SRC="$SYSEXT_SRC_OLD"
else
    SYSEXT_SRC="$SYSEXT_SRC_NEW"  # for the error message below
fi

if [ -d "$SYSEXT_SRC" ]; then
    EXT_KIND="systemextension"
    EXT_DEST_DIR="$APP_PATH/Contents/Library/SystemExtensions"
    # Always embed under the bundle-id-matched name regardless of
    # what Xcode produced (Step 4.bis is now a no-op in the modern
    # path but we keep it as a safety net for stale DerivedData).
    EXT_DEST="$EXT_DEST_DIR/io.hpn.vpn.macos.packet-tunnel.systemextension"
    EXT_SRC="$SYSEXT_SRC"
elif [ -d "$APPEX_SRC" ]; then
    EXT_KIND="appex"
    EXT_DEST_DIR="$APP_PATH/Contents/PlugIns"
    EXT_DEST="$EXT_DEST_DIR/packet-tunnel.appex"
    EXT_SRC="$APPEX_SRC"
    echo "   WARNING: legacy .appex extension found in DerivedData."
    echo "            Apple no longer accepts this format for Developer ID"
    echo "            distribution; notarisation WILL be rejected."
    echo "            In Xcode: change packet-tunnel target product type"
    echo "            to 'System Extension' and rebuild."
else
    echo "ERROR: no Packet Tunnel extension found in Xcode build."
    echo "       Expected one of:"
    echo "         $SYSEXT_SRC"
    echo "         $APPEX_SRC"
    echo "       In Xcode, Cmd+B the packet-tunnel scheme to seed DerivedData."
    exit 1
fi

mkdir -p "$EXT_DEST_DIR"
rm -rf "$EXT_DEST"
cp -R "$EXT_SRC" "$EXT_DEST"
echo "   Extension embedded: $EXT_DEST ($EXT_KIND)"

# ── Step 4.bis: Rename extension wrapper to match bundle identifier ──────────
#
# Apple REQUIRES the wrapper bundle filename to match the system extension's
# CFBundleIdentifier (excluding the `.systemextension` suffix). This is
# documented at:
#   https://developer.apple.com/documentation/systemextensions
# and was confirmed on the developer forums by Kevin Elliott (Apple DTS,
# CoreOS/Hardware) in May 2026:
#   https://developer.apple.com/forums/thread/823200
#   https://developer.apple.com/forums/thread/824746
#
# Without this rename, OSSystemExtensionRequest fails silently with the
# *misleading* sysextd log line:
#     "no policy, cannot allow apps outside /Applications"
# and the app receives `OSSystemExtensionErrorDomain code=4 "Extension not
# found in App bundle"`. Per Kevin Elliott, the "no policy" message is
# informational ("I didn't find any MDM policy") and "cannot allow apps
# outside /Applications" means "I'm using the default policy, which is to
# require /Applications" — neither has anything to do with the actual
# rejection reason. The actual reason is that sysextd looked for the
# extension at `Contents/Library/SystemExtensions/<bundle_id>.systemextension`
# and didn't find it because Xcode's default `PRODUCT_NAME=$(TARGET_NAME)`
# produced `packet-tunnel.systemextension` (matching the target name) rather
# than `io.hpn.vpn.macos.packet-tunnel.systemextension` (matching the
# bundle id).
#
# We do the rename HERE (before signing) rather than in the Xcode project
# settings so that the in-IDE Xcode workflow (which most developers use
# for incremental builds) keeps working with the short name. Only the
# release pipeline needs the bundle-id-matched name. The signature is
# computed over the bundle's CONTENTS, not the wrapper filename, so
# renaming after `cp` and before `codesign` is safe.
if [ "$EXT_KIND" = "systemextension" ]; then
    EXT_BUNDLE_ID="io.hpn.vpn.macos.packet-tunnel"
    EXT_DEST_FIXED="$EXT_DEST_DIR/${EXT_BUNDLE_ID}.systemextension"
    if [ "$EXT_DEST" != "$EXT_DEST_FIXED" ]; then
        rm -rf "$EXT_DEST_FIXED"
        mv "$EXT_DEST" "$EXT_DEST_FIXED"
        EXT_DEST="$EXT_DEST_FIXED"
        echo "   Renamed extension wrapper to match bundle identifier:"
        echo "     $(basename "$EXT_DEST")"
        echo "     (Apple requirement, see deploy/macos-release.sh comment)"
    fi
fi

# embedded.provisionprofile is what tells macOS the app is allowed to
# claim the Network Extension entitlement under this Team ID. Without
# it the kernel refuses to load the extension even if codesign succeeds.
if [ -f "$XCODE_BUILD/Contents/embedded.provisionprofile" ]; then
    cp "$XCODE_BUILD/Contents/embedded.provisionprofile" \
       "$APP_PATH/Contents/embedded.provisionprofile"
    echo "   Provisioning profile embedded"
else
    echo "   WARNING: no embedded.provisionprofile found in Xcode build."
    echo "            The extension may fail to load on the user's machine."
    echo "            In Xcode: Signing & Capabilities → check that a"
    echo "                       Developer ID profile is selected for the"
    echo "                       Release config."
fi

# ── Step 5: Sign with Developer ID (inside-out) ──────────────────────────────

echo "==> [5/9] Signing app with Developer ID Application"
echo "         ($DEV_ID_APP)"

# Inside-out signing: the embedded extension is signed BEFORE the
# enclosing .app, otherwise codesign nests an unsigned binary inside
# a signed one and macOS rejects the bundle.
#
# `--options runtime` enables the Hardened Runtime, which is
# REQUIRED by Apple Notarization. Without it, notarytool succeeds
# but Gatekeeper still flags the bundle.
#
# `--timestamp` requests a secure timestamp from Apple's TSA, so the
# signature remains valid past the cert's expiration date.
#
# CRITICAL: codesign(1) does NOT substitute Xcode-style build
# variables in entitlement files. `$(AppIdentifierPrefix)` is taken
# LITERALLY and baked into the signature — `keychain-access-groups`
# ends up with the string "$(AppIdentifierPrefix)io.hpn.vpn" instead
# of the actual "6Y986MRM6T.io.hpn.vpn", which AMFI then compares
# against the profile's "6Y986MRM6T.*" wildcard, fails the match,
# and refuses to launch the app at runtime with error 163 "Launchd
# job spawn failed". Xcode's signing flow does the substitution
# automatically; the command-line tool does not.
#
# Fix: extract the Team ID from the chosen Developer ID Application
# certificate's CN (always the last "(XXXXXXXXXX)" group) and write
# a temporary entitlements file with the substitution applied, then
# point codesign at the temp file. The original tracked file stays
# untouched so the Xcode flow keeps working too.
TEAM_ID=$(echo "$DEV_ID_APP" | grep -oE '\([A-Z0-9]{10}\)' | tr -d '()' | tail -1)
if [ -z "$TEAM_ID" ]; then
    echo "ERROR: could not extract Team ID from signing identity '$DEV_ID_APP'."
    echo "       Expected the CN to end with a 10-character (XXXXXXXXXX) group."
    exit 1
fi

# Substitute $(AppIdentifierPrefix) → "<TeamID>." in BOTH entitlements
# files (host app + extension) before passing them to codesign. We
# re-sign the extension with --entitlements explicitly because (a) the
# Xcode-baked entitlements are sometimes dropped on re-sign, and (b)
# without entitlements at all the extension cannot read the App Group
# container or the shared Keychain — both of which are essential for
# the audit-CRED-1 / audit-H15 boundaries.
EXT_ENTITLEMENTS_SRC="$TAURI_DIR/xcode-native/macos/packet-tunnel/packet_tunnel.entitlements"
TMP_APP_ENT="$REPO_ROOT/target/.entitlements-app.tmp.plist"
TMP_EXT_ENT="$REPO_ROOT/target/.entitlements-ext.tmp.plist"
# Substitute $(AppIdentifierPrefix) → "<TeamID>." in both files. This
# is the placeholder Xcode uses for the team-id-prefixed entitlements
# (com.apple.application-identifier, keychain-access-groups) — the
# release pipeline must do this substitution explicitly because
# codesign(1) does NOT do build-variable substitution itself.
sed "s|\\\$(AppIdentifierPrefix)|${TEAM_ID}.|g" "$ENTITLEMENTS"        > "$TMP_APP_ENT"
sed "s|\\\$(AppIdentifierPrefix)|${TEAM_ID}.|g" "$EXT_ENTITLEMENTS_SRC" > "$TMP_EXT_ENT"

# Inject `com.apple.developer.team-identifier` post-sed via
# `plutil -replace`. We CANNOT put this key in the source plists
# (Xcode rejects in-IDE builds with a provisioning-profile mismatch
# error if any literal value appears for this key before the profile
# is consulted), and codesign(1) does not have a flag to merge an
# additional entitlement at signing time — so we materialise the
# final entitlements plist here, in the temporary copy passed to
# codesign. Xcode's own signing flow does the equivalent injection
# automatically. macOS Tahoe (26.4+) sysextd silently rejects
# Network Extension System Extensions whose binary signature does
# NOT carry this entitlement, with the misleading log line "no
# policy, cannot allow apps outside /Applications" (see AGENTS.md
# "Tahoe System Extension Activation" notes for the full story).
# Use /usr/libexec/PlistBuddy (NOT `plutil -insert`) because plutil
# treats dots in the key path as path separators — it tries to
# navigate `com` → `apple` → `developer` → `team-identifier` as
# nested keys and fails with "Key path not found" on the very first
# segment. PlistBuddy takes the entire string after the leading `:`
# as a literal top-level key, which is what we actually want.
#
# Verified empirically with both `plutil -p` post-write: the key
# ends up at the top level of the plist with the literal name
# `com.apple.developer.team-identifier`, exactly as Apple's notary
# service expects.
/usr/libexec/PlistBuddy -c "Add :com.apple.developer.team-identifier string ${TEAM_ID}" "$TMP_APP_ENT" \
    || { echo "ERROR: failed to inject team-identifier into app entitlements"; exit 1; }
/usr/libexec/PlistBuddy -c "Add :com.apple.developer.team-identifier string ${TEAM_ID}" "$TMP_EXT_ENT" \
    || { echo "ERROR: failed to inject team-identifier into ext entitlements"; exit 1; }
# Convert to binary plist. AMFIUnserializeXML — the kernel-side
# entitlements parser — is stricter than plutil and rejects
# perfectly valid XML plists with HTML-style `<!-- ... -->` comments
# (codesign reports "Failed to parse entitlements: AMFIUnserializeXML:
# syntax error near line N", where N is just before the comment).
# `plutil -convert binary1` strips the comments as a side effect of
# the format change, producing a binary-encoded plist that AMFI
# accepts unconditionally.
plutil -lint "$TMP_APP_ENT" > /dev/null \
    || { echo "ERROR: substituted app entitlements malformed"; exit 1; }
plutil -lint "$TMP_EXT_ENT" > /dev/null \
    || { echo "ERROR: substituted ext entitlements malformed"; exit 1; }
# Round-trip through binary then back to XML to strip HTML-style
# `<!-- ... -->` comments. AMFIUnserializeXML — the kernel-side
# entitlements parser used by codesign — rejects them with the
# unhelpful "syntax error near line N" message even though plutil
# accepts them. The binary plist format has no comment node, so
# converting to binary discards them, and converting back to xml1
# gives codesign a clean canonical document it can parse without
# choking. `plutil` writes back to the same path on -convert.
plutil -convert binary1 "$TMP_APP_ENT" \
    || { echo "ERROR: app entitlements binary conversion failed"; exit 1; }
plutil -convert binary1 "$TMP_EXT_ENT" \
    || { echo "ERROR: ext entitlements binary conversion failed"; exit 1; }
plutil -convert xml1 "$TMP_APP_ENT"
plutil -convert xml1 "$TMP_EXT_ENT"

# INSIDE-OUT signing AND stapling.
#
# Code-signing rule: signature must be applied bottom-up, i.e. nested
# bundles BEFORE their containing bundle. The reason is that the outer
# bundle's seal references the SHA-256 of every nested bundle's
# CodeDirectory; if the inner bundle is re-signed after the outer one,
# the seal of the outer is invalidated.
#
# The same rule applies to STAPLING. `xcrun stapler staple` adds a
# marker to the bundle's resources (and possibly modifies a load
# command in the Mach-O), which causes the bundle's CodeResources to
# change. If we staple a NESTED bundle after the OUTER bundle has been
# signed, the outer bundle's seal will reference the *pre-staple*
# CodeResources of the inner bundle, and `codesign --verify` will
# report "a sealed resource is missing or invalid / file added:
# .../Contents/CodeResources" for the inner bundle.
#
# This was the May 2026 release-pipeline bug: signing was inside-out
# (extension then app), but stapling was outside-only (just the .app),
# which Apple's stapler implementation propagated INTO the extension
# bundle, modifying its CodeResources. Apple Notary Service then
# rejected the .pkg with "The signature of the binary is invalid" for
# the .app's main executable, because verifying the .app's seal
# detected the modified extension.
#
# Fix: do INSIDE-OUT for both signing and stapling.
#
#   1. Sign extension                                       (Step 5.A)
#   2. Notarize extension via zip — Apple emits a ticket    (Step 5.B)
#   3. Staple ticket onto extension                         (Step 5.B)
#   4. Sign the .app — its seal now references the
#      stapled extension's CodeResources                    (Step 5.C)
#   5. Build .pkg, sign .pkg, notarise .pkg, staple .pkg    (Steps 6–9)
#
# At Step 8 the .pkg is submitted to Apple Notary Service: Apple sees
# the extension is already notarised (CDHash matches a previously-
# accepted ticket), and only needs to notarise the .app's main
# executable. The .pkg installer at the user's machine extracts an
# .app whose embedded .systemextension already has its own stapled
# ticket — exactly what sysextd needs on Tahoe (May 2026 incident).

# ── Step 5.A: Sign the extension ─────────────────────────────────────────────

codesign --force \
    --options runtime \
    --timestamp \
    --entitlements "$TMP_EXT_ENT" \
    --sign "$DEV_ID_APP" \
    "$EXT_DEST"
echo "   Extension signed"

# ── Step 5.B: Notarise the extension and staple ticket onto it ───────────────
#
# Apple Notary Service requires submissions to be one of: .app .pkg
# .dmg .zip. A bare .systemextension is not directly accepted, but
# zipping it with `ditto -c -k --keepParent` produces a notarisable
# archive — Apple inspects the bundle structure recursively and emits
# a ticket for the bundle's CDHash. Empirically this works for
# Network Extension System Extensions on Tahoe (May 2026).

if [ "$NOTARIZE" = "1" ]; then
    echo "==> [5.B/9] Notarising extension and stapling ticket onto it"

    EXT_ZIP="$REPO_ROOT/target/HPN-VPN-${VERSION}-${ARCH}-ext.zip"
    rm -f "$EXT_ZIP"
    ditto -c -k --keepParent "$EXT_DEST" "$EXT_ZIP"

    EXT_NOTARY_ARGS=()
    if [ -n "${KEYCHAIN_PROFILE:-}" ]; then
        EXT_NOTARY_ARGS=(--keychain-profile "$KEYCHAIN_PROFILE")
    else
        EXT_NOTARY_ARGS=(
            --apple-id "$APPLE_ID"
            --team-id "$APPLE_TEAM_ID"
            --password "$APPLE_APP_PASSWORD"
        )
    fi

    EXT_NOTARY_OUT=$(xcrun notarytool submit "$EXT_ZIP" \
        "${EXT_NOTARY_ARGS[@]}" --wait 2>&1)
    echo "$EXT_NOTARY_OUT" | tail -10

    EXT_NOTARY_STATUS=$(echo "$EXT_NOTARY_OUT" \
        | grep -oE "status:[[:space:]]*[A-Za-z]+" \
        | tail -1 | awk '{print $NF}')

    if [ "$EXT_NOTARY_STATUS" != "Accepted" ]; then
        EXT_SUB_ID=$(echo "$EXT_NOTARY_OUT" \
            | grep -E "^[[:space:]]*id:" | head -1 | awk '{print $2}')
        echo "ERROR: Extension notarisation status was '$EXT_NOTARY_STATUS' (expected 'Accepted')."
        if [ -n "$EXT_SUB_ID" ]; then
            echo "       Fetch the full Apple report with:"
            echo "         xcrun notarytool log $EXT_SUB_ID --keychain-profile ${KEYCHAIN_PROFILE:-<profile>}"
        fi
        rm -f "$EXT_ZIP"
        exit 1
    fi
    echo "   Extension notarisation: Accepted"

    xcrun stapler staple "$EXT_DEST" \
        || { echo "ERROR: stapler staple on extension failed"; rm -f "$EXT_ZIP"; exit 1; }
    echo "   Ticket stapled onto extension"

    # Defence in depth — fail loud if the staple did not actually
    # land on the extension bundle.
    if ! xcrun stapler validate "$EXT_DEST" 2>&1 | tail -1 \
            | grep -q "validate action worked"; then
        echo "ERROR: extension ticket validation failed after staple"
        xcrun stapler validate "$EXT_DEST" 2>&1 | tail -3
        rm -f "$EXT_ZIP"
        exit 1
    fi
    echo "   Extension ticket verified"

    rm -f "$EXT_ZIP"
else
    echo "==> [5.B/9] Skipping extension notarisation (NOTARIZE=0)"
fi

# ── Step 5.C: Sign the host app ──────────────────────────────────────────────
#
# Signed AFTER the extension has been signed AND stapled, so the seal
# of the .app references the post-staple CodeResources of the
# extension. This is what makes the eventual .pkg notarisation pass:
# Apple verifies the .app's seal and finds the extension's
# CodeResources matches what was sealed.

codesign --force \
    --options runtime \
    --timestamp \
    --entitlements "$TMP_APP_ENT" \
    --sign "$DEV_ID_APP" \
    "$APP_PATH"
echo "   App signed"

rm -f "$TMP_APP_ENT" "$TMP_EXT_ENT"

# Verify the chain — must be VALID at this point. If `--strict`
# reports "a sealed resource is missing or invalid", the inside-out
# ordering is wrong somewhere.
codesign --verify --deep --strict --verbose=2 "$APP_PATH" 2>&1 | tail -5
echo "   Signature chain OK"

# ── Step 6: Build the .pkg installer ─────────────────────────────────────────

echo "==> [6/9] Building .pkg installer"
BUNDLE_DIR=$(dirname "$APP_PATH")
PKG_PATH="$REPO_ROOT/target/HPN-VPN-${VERSION}-${ARCH}.pkg"
UNSIGNED_PKG="$REPO_ROOT/target/HPN-VPN-${VERSION}-${ARCH}-unsigned.pkg"
COMPONENT_PKG="$REPO_ROOT/target/HPN-VPN-component.pkg"
DIST_XML="$REPO_ROOT/target/distribution.xml"

# Force the installer to drop the bundle into `/Applications` and NOT
# into a previously-detected copy at some other path (Time Machine,
# Downloads, a sibling user's home, etc.).
#
# `pkgbuild` by default emits a `<relocate>` block in the component
# whenever the payload contains a `.app`. macOS Installer then walks
# Spotlight / LSDatabase / installation-history to find every prior
# copy of the same bundle identifier and writes the new payload over
# whichever one it finds first. Operators have hit this in the field
# (the user installs into `/Applications` once, then a later install
# silently lands in their previous Downloads folder because that copy
# is still indexed). Closes that footgun by generating a component
# plist with `BundleIsRelocatable=false` and threading it through
# `--component-plist`.
COMPONENT_PLIST="$REPO_ROOT/target/component.plist"
cat > "$COMPONENT_PLIST" << 'COMPEOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<array>
    <dict>
        <key>BundleHasStrictIdentifier</key>
        <true/>
        <key>BundleIsRelocatable</key>
        <false/>
        <key>BundleIsVersionChecked</key>
        <true/>
        <key>BundleOverwriteAction</key>
        <string>upgrade</string>
        <key>RootRelativeBundlePath</key>
        <string>HPN VPN.app</string>
    </dict>
</array>
</plist>
COMPEOF

# Component package (the bundle itself, plus install location).
pkgbuild \
    --root "$BUNDLE_DIR" \
    --component-plist "$COMPONENT_PLIST" \
    --identifier "io.hpn.vpn" \
    --version "$VERSION" \
    --install-location "/Applications" \
    "$COMPONENT_PKG" 2>&1 | tail -1

# Distribution XML — wraps the component pkg with the user-facing
# license + background image. `customize="never"` hides the
# install-options panel; users get a single-click installer.
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

productbuild \
    --distribution "$DIST_XML" \
    --resources "$ASSETS_DIR" \
    --package-path "$REPO_ROOT/target" \
    "$UNSIGNED_PKG" 2>&1 | tail -1

rm -f "$COMPONENT_PKG" "$DIST_XML" "$COMPONENT_PLIST"

# ── Step 7: Sign the .pkg with Developer ID Installer ────────────────────────

echo "==> [7/9] Signing .pkg with Developer ID Installer"
echo "         ($DEV_ID_INSTALLER)"

productsign --sign "$DEV_ID_INSTALLER" --timestamp \
    "$UNSIGNED_PKG" "$PKG_PATH"
rm -f "$UNSIGNED_PKG"

# Verify pkg signature is well-formed BEFORE submitting to notary.
# A bad signature here = notarization rejection 30 minutes later, so
# fail fast.
pkgutil --check-signature "$PKG_PATH" | tail -3
echo "   Pkg signed"

# ── Step 8: Notarization ─────────────────────────────────────────────────────

if [ "$NOTARIZE" = "1" ]; then
    echo "==> [8/9] Submitting to Apple notary service"

    NOTARY_ARGS=()
    if [ -n "${KEYCHAIN_PROFILE:-}" ]; then
        NOTARY_ARGS=(--keychain-profile "$KEYCHAIN_PROFILE")
    else
        NOTARY_ARGS=(
            --apple-id "$APPLE_ID"
            --team-id "$APPLE_TEAM_ID"
            --password "$APPLE_APP_PASSWORD"
        )
    fi

    # `--wait` blocks until Apple returns a verdict. Typical latency
    # is 1-5 minutes; Apple's SLA is "under one hour". On a stalled
    # submission, ctrl-C and retry — Apple does not double-charge.
    #
    # We use the default human-readable output here (NOT --output-format
    # plist) because the plist output renders `status` across two
    # XML lines (`<key>status</key>\n<string>Accepted</string>`)
    # which is much harder to grep reliably than the canonical
    # `status: Accepted` line that the human-readable output prints.
    SUBMIT_OUTPUT=$(xcrun notarytool submit "$PKG_PATH" \
        "${NOTARY_ARGS[@]}" \
        --wait 2>&1)

    echo "$SUBMIT_OUTPUT" | tail -10

    # Extract the FINAL submission status. notarytool prints a few
    # transient lines like "Current status: In Progress" before the
    # final verdict. Match the LAST `status: ...` line so we never
    # mistake a mid-submission state for the verdict.
    FINAL_STATUS=$(echo "$SUBMIT_OUTPUT" \
        | grep -oE "status:[[:space:]]*[A-Za-z]+" \
        | tail -1 \
        | awk '{print $NF}')

    case "$FINAL_STATUS" in
        Accepted)
            echo "   Notarization: ACCEPTED"
            ;;
        Invalid|Rejected)
            echo "ERROR: Notarization $FINAL_STATUS by Apple."
            SUBMISSION_ID=$(echo "$SUBMIT_OUTPUT" \
                | grep -E "^[[:space:]]*id:" | head -1 | awk '{print $2}')
            if [ -n "$SUBMISSION_ID" ]; then
                echo "       Fetch the full Apple report with:"
                echo "         xcrun notarytool log $SUBMISSION_ID --keychain-profile $KEYCHAIN_PROFILE"
            fi
            echo "       Common causes:"
            echo "         - Hardened Runtime not enabled (--options runtime)"
            echo "         - Bundle identifier mismatch with provisioning profile"
            echo "         - Missing entitlements that match the cert's authorized list"
            echo "         - .pkg signature timestamp not from Apple's TSA"
            exit 1
            ;;
        *)
            echo "ERROR: Could not parse notarization verdict from notarytool output."
            echo "       Last status line found: '${FINAL_STATUS:-<empty>}'"
            echo "       Re-fetch via: xcrun notarytool history --keychain-profile $KEYCHAIN_PROFILE"
            exit 1
            ;;
    esac

    # ── Step 9: Staple the notarization ticket ──────────────────────────────

    echo "==> [9/9] Stapling notarization ticket"
    xcrun stapler staple "$PKG_PATH"
    echo "   Ticket stapled"

    # Run Gatekeeper's exact assessment command. The user's machine
    # will run THIS exact check when they double-click the .pkg, so
    # passing here means passing for them.
    if spctl --assess --type install "$PKG_PATH" 2>&1; then
        echo "   spctl: accepted (Gatekeeper will let it install)"
    else
        echo "ERROR: spctl rejected the notarized .pkg. This must be fixed"
        echo "       before publishing — users will see the 'developer cannot"
        echo "       be verified' dialog."
        exit 1
    fi
else
    echo "==> [8/9] Skipping notarization (NOTARIZE=0)"
    echo "==> [9/9] (skipped — no ticket to staple)"
    echo ""
    echo "WARNING: this build is NOT notarized. Gatekeeper will reject it on"
    echo "         the user's machine unless they explicitly bypass the"
    echo "         warning via System Settings → Privacy & Security."
    echo "         DO NOT publish this artefact to pkg.hpn.hmsx.io."
fi

# ── Summary ──────────────────────────────────────────────────────────────────

PKG_SIZE=$(du -h "$PKG_PATH" | cut -f1)
echo ""
echo "============================================================"
echo "  RELEASE BUILD COMPLETE"
echo "============================================================"
echo ""
echo "  .pkg:  $PKG_PATH  ($PKG_SIZE)"
if [ "$NOTARIZE" = "1" ]; then
    echo ""
    echo "  Verified:"
    echo "    pkgutil --check-signature → Developer ID Installer"
    echo "    spctl --assess            → Notarized Developer ID"
    echo ""
    echo "  Next steps:"
    echo "    1. Generate Tauri minisign signature for the auto-updater (if"
    echo "       production keypair is provisioned)."
    echo "    2. Upload to pkg.hpn.hmsx.io:"
    echo "         scp '$PKG_PATH' <user>@<your-server-ip>:/var/www/pkg.hpn.hmsx.io/releases/${VERSION}/"
    echo "    3. Update latest.json manifest to point at the new version."
fi
echo ""
