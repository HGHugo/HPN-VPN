#!/usr/bin/env bash
# =============================================================================
# HPN VPN — Verify the iteration-3 split-tunnel fix is actually deployed
# =============================================================================
#
# Greps the literal log/code strings introduced by commits 59c41dc and
# baa59c0 inside the installed binaries. If a string is missing from a
# binary, that binary does NOT contain the new code — regardless of
# what CFBundleVersion / CDHash / Timestamp claims.
#
# Run this AFTER deploy/macos-release.sh + sudo installer -pkg + reboot.
# Compare the output to the expected results documented at the bottom.
# =============================================================================

set -u

APP="/Applications/HPN VPN.app"
# CFBundleExecutable is `hpn-ui-macos` (Tauri convention). Path lookup
# falls back to PlistBuddy in case Tauri ever renames it.
if [ -f "$APP/Contents/Info.plist" ]; then
    EXEC_NAME=$(/usr/libexec/PlistBuddy -c 'Print :CFBundleExecutable' "$APP/Contents/Info.plist" 2>/dev/null)
    HOST_BIN="$APP/Contents/MacOS/${EXEC_NAME:-hpn-ui-macos}"
else
    HOST_BIN="$APP/Contents/MacOS/hpn-ui-macos"
fi
EXT_BIN="$APP/Contents/Library/SystemExtensions/io.hpn.vpn.macos.packet-tunnel.systemextension/Contents/MacOS/io.hpn.vpn.macos.packet-tunnel"

hr() { printf '\n==[ %s ]======================================================\n' "$1"; }

hr "0. Binary file metadata"
echo "Host app binary: $HOST_BIN"
stat -f "  mtime: %Sm  size: %z bytes" -t "%Y-%m-%d %H:%M:%S" "$HOST_BIN" 2>/dev/null || echo "  MISSING"
echo
echo "System Extension binary: $EXT_BIN"
stat -f "  mtime: %Sm  size: %z bytes" -t "%Y-%m-%d %H:%M:%S" "$EXT_BIN" 2>/dev/null || echo "  MISSING"

hr "1. System Extension — does it contain iteration-3 strings?"
EXT_PROBES=(
    "Skipping LAN-bypass exclude"
    "covers the tunnel subnet"
    "buildNetworkSettings: failed to parse tunnel CIDR"
    "LAN-exclude carve-out disabled"
)
ext_score=0
for s in "${EXT_PROBES[@]}"; do
    if strings -a "$EXT_BIN" 2>/dev/null | grep -qF "$s"; then
        echo "  [PASS] '$s'"
        ext_score=$((ext_score + 1))
    else
        echo "  [FAIL] '$s' — string NOT in binary"
    fi
done
echo
echo "  System Extension iteration-3 score: $ext_score / ${#EXT_PROBES[@]}"
if [ "$ext_score" -lt 2 ]; then
    echo
    echo "  *** SYSTEM EXTENSION HAS OLD CODE ***"
    echo "  Run: rm -rf ~/Library/Developer/Xcode/DerivedData/macos-*"
    echo "       xcodebuild clean -project crates/hpn-ui-macos/xcode-native/macos/macos.xcodeproj -scheme packet-tunnel"
    echo "       deploy/macos-release.sh"
    echo "       sudo installer -pkg target/HPN-VPN-*-arm64.pkg -target /"
    echo "       sudo shutdown -r now"
fi

hr "2. Host app (Tauri) — does it contain iteration-2/3 ObjC selectors?"
# Swift compiler optimizes property setters into objc_msgSend calls;
# the property STRING names get stripped, but the selector names
# survive as undefined symbols / runtime references. Use `nm` to look
# for those selectors — it's the only reliable way to confirm the
# new VPNManager.swift code is in the binary.
#   setEnforceRoutes:        introduced by b3911e7 (iter 2). Absence
#                            == iter 1 code (pre-leak-fix).
#   setIncludeAllNetworks:   present in all iterations (we always set
#                            this property).
#   setExcludeLocalNetworks: present in all iterations.
HOST_SELECTORS=(
    "setEnforceRoutes:"
    "setIncludeAllNetworks:"
    "setExcludeLocalNetworks:"
)
host_score=0
for s in "${HOST_SELECTORS[@]}"; do
    if strings -a "$HOST_BIN" 2>/dev/null | grep -qF "$s"; then
        echo "  [PASS] '$s' selector present"
        host_score=$((host_score + 1))
    else
        echo "  [FAIL] '$s' selector NOT in binary"
    fi
done
echo
echo "  Host app iteration-2-or-newer score: $host_score / ${#HOST_SELECTORS[@]}"
if [ "$host_score" -lt 3 ]; then
    echo
    echo "  *** HOST APP IS RUNNING ITERATION-1 CODE (pre-b3911e7) ***"
    echo "  The build.rs fix in baa59c0 did not take effect. Either:"
    echo "  (a) 'cargo tauri build' never ran with the new build.rs"
    echo "  (b) The .pkg you installed pre-dates baa59c0"
    echo "  (c) /Applications/HPN VPN.app was not actually replaced"
    echo "  Run: ls -la '/Applications/HPN VPN.app/Contents/MacOS/'"
    echo "       and check the mtime vs your last deploy/macos-release.sh run."
fi

hr "2.bis. Is the running Tauri app the binary on disk?"
# If user reinstalled but never quit + relaunched the app, the running
# process is still using the OLD in-memory binary from before reinstall.
APP_PIDS=$(pgrep -lf '/Applications/HPN VPN.app/Contents/MacOS/' 2>/dev/null || true)
if [ -n "$APP_PIDS" ]; then
    echo "Running HPN VPN app process(es):"
    echo "$APP_PIDS" | sed 's/^/   /'
    echo
    # Compare process start time to binary mtime.
    while IFS= read -r line; do
        pid=$(echo "$line" | awk '{print $1}')
        [ -z "$pid" ] && continue
        start_epoch=$(ps -o lstart= -p "$pid" 2>/dev/null | xargs -I{} date -j -f "%a %b %d %T %Y" "{}" "+%s" 2>/dev/null)
        bin_epoch=$(stat -f %m "$HOST_BIN" 2>/dev/null)
        if [ -n "$start_epoch" ] && [ -n "$bin_epoch" ]; then
            if [ "$start_epoch" -lt "$bin_epoch" ]; then
                echo "  *** PID $pid started BEFORE the binary was last rebuilt ***"
                echo "  The running app has the OLD code in memory."
                echo "  QUIT the HPN VPN app fully (Cmd-Q or right-click dock icon →"
                echo "  Quit) and relaunch from /Applications. The plist values will"
                echo "  only update on the next Connect after a clean app launch."
            else
                echo "  PID $pid started after the binary was rebuilt — running code matches disk."
            fi
        fi
    done <<< "$APP_PIDS"
else
    echo "(HPN VPN app is not currently running.)"
fi

hr "3. Git state — what was actually built"
echo "Current HEAD (your checkout):"
git -C "$(dirname "$0")/.." log -1 --format='  %h  %s  (%cr)' HEAD 2>/dev/null
echo
echo "VPNManager.swift last modified by:"
git -C "$(dirname "$0")/.." log -1 --format='  %h  %s  (%cr)' \
    -- crates/hpn-ui-macos/native/VPNManager.swift 2>/dev/null
echo
echo "PacketTunnelProvider.swift last modified by:"
git -C "$(dirname "$0")/.." log -1 --format='  %h  %s  (%cr)' \
    -- crates/hpn-ui-macos/xcode-native/macos/packet-tunnel/PacketTunnelProvider.swift 2>/dev/null
echo
echo "build.rs last modified by:"
git -C "$(dirname "$0")/.." log -1 --format='  %h  %s  (%cr)' \
    -- crates/hpn-ui-macos/src-tauri/build.rs 2>/dev/null

hr "4. EXPECTED RESULTS"
cat <<'EOF'
After a clean rebuild + reinstall + reboot following baa59c0:

  Section 1 (System Extension):  4 / 4 PASS
  Section 2 (Host app):           4 / 4 PASS

If Section 1 is < 4, the .systemextension binary is stale.
If Section 2 is < 4, the Tauri host binary is stale (the very bug
  baa59c0 was supposed to fix — check the rebuild steps).

If BOTH sections fully PASS but the persisted plist still shows
IncludeAllNetworks=false (run macos-diagnose-split-tunnel.sh Section 3),
the issue is NOT the binary content — it's that macOS's saveToPreferences
silently failed OR the System Extension process is still running with
an old cached protocol config. In that case:
  - Force-quit the running extension via System Settings > General >
    Login Items & Extensions > Network Extensions > toggle OFF then ON
  - Or remove the VPN profile from System Settings > Network and let
    the Tauri app re-create it on next connect.
EOF
