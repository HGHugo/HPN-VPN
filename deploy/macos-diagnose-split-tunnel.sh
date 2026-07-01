#!/usr/bin/env bash
# =============================================================================
# HPN VPN — Split-tunnel diagnostic dump for macOS
# =============================================================================
#
# Run BEFORE clicking Connect, AGAIN while Connected. Paste the full
# stdout in the GitLab issue / chat so the maintainer can localise the
# residual leak.
#
# Asks for your sudo password ONCE (to read the root-only NetworkExtension
# plist). No state is modified — only reads.
# =============================================================================

set -u

EXT_PATH="/Applications/HPN VPN.app/Contents/Library/SystemExtensions/io.hpn.vpn.macos.packet-tunnel.systemextension"
SUBSYSTEM="io.hpn.vpn.macos.packet-tunnel"

hr() { printf '\n==[ %s ]======================================================\n' "$1"; }

hr "0. HOST INFO"
sw_vers
uname -a
date

hr "1. SYSTEM EXTENSION — installed .systemextension bundle"
if [ -d "$EXT_PATH" ]; then
    echo "Bundle path: $EXT_PATH"
    # codesign -d --verbose=1 omits CDHash; we need verbose=4 for that.
    codesign -d --verbose=4 "$EXT_PATH" 2>&1 \
        | grep -E 'CDHash|Identifier=|TeamIdentifier|Authority=Developer ID Application|Timestamp=' || true
    /usr/libexec/PlistBuddy -c 'Print :CFBundleVersion' \
        "$EXT_PATH/Contents/Info.plist" 2>/dev/null | sed 's/^/CFBundleVersion: /'
    /usr/libexec/PlistBuddy -c 'Print :CFBundleShortVersionString' \
        "$EXT_PATH/Contents/Info.plist" 2>/dev/null | sed 's/^/CFBundleShortVersionString: /'
    echo
    echo "Notarisation status (Tahoe requires stapled ticket on the extension):"
    xcrun stapler validate "$EXT_PATH" 2>&1 | tail -5
else
    echo "MISSING — '$EXT_PATH' does not exist."
    echo "The .pkg was never installed OR the bundle filename is wrong."
fi

hr "2. SYSTEM EXTENSION — what macOS believes is activated"
echo "(Look for [activated enabled] vs [terminated waiting to uninstall on reboot])"
systemextensionsctl list 2>&1 | grep -E 'hpn|Identifier|^---|enabled state' || true
echo
SYSEXT_RAW=$(systemextensionsctl list 2>&1 | grep hpn || true)
if echo "$SYSEXT_RAW" | grep -q 'terminated waiting to uninstall on reboot'; then
    echo "*** REBOOT REQUIRED ***"
    echo "An older HPN extension is in 'terminated waiting to uninstall on reboot'"
    echo "state. macOS does NOT swap the running binary until reboot, so the OLD"
    echo "code path is still serving your VPN connections — even though the new"
    echo "bundle is registered as activated. After 'sudo shutdown -r now' and a"
    echo "reconnect, re-run this script. Section 8 should then contain the"
    echo "'Skipping LAN-bypass exclude' log line if the iteration-3 fix is in"
    echo "effect."
fi
# Sanity: is there a process actually running for our extension?
if pgrep -f 'io.hpn.vpn.macos.packet-tunnel' >/dev/null 2>&1; then
    echo
    echo "Running PID(s) for our extension:"
    pgrep -lf 'io.hpn.vpn.macos.packet-tunnel' | sed 's/^/   /'
fi

hr "3. NETworkExtension persisted protocol settings"
echo "(Need sudo to read /Library/Preferences/com.apple.networkextension.plist)"
echo
# Convert binary plist to XML so we can grep with context. Then extract
# the io.hpn-related blocks with 30-line surrounding context — that
# window is large enough to catch the IncludeAllNetworks / EnforceRoutes
# / ExcludeLocalNetworks values that live a few lines after the
# Identifier key.
echo "--- HPN configuration blocks (30 lines of context around each io.hpn match) ---"
sudo plutil -convert xml1 -o - /Library/Preferences/com.apple.networkextension.plist 2>/dev/null \
    | grep -B 2 -A 30 'io\.hpn' \
    | head -300
echo
echo "--- The three flags that matter — ALL configs (HPN + any other VPN) ---"
sudo plutil -convert xml1 -o - /Library/Preferences/com.apple.networkextension.plist 2>/dev/null \
    | awk '
        /<key>IncludeAllNetworks<\/key>|<key>EnforceRoutes<\/key>|<key>ExcludeLocalNetworks<\/key>/ {
            key=$0; getline val; printf "%-60s => %s\n", key, val
        }
    ' | sed -E 's/^[[:space:]]+//'
echo
echo "  NB: NETworkExtension persists MULTIPLE VPN configs in this plist"
echo "      (each VPN profile = one set of these three flags). To know which"
echo "      set is HPN's, decode the providerConfiguration -> identifier"
echo "      string in the same object. WireGuard clients almost always store"
echo "      the three flags as false, so seeing a 'all-false' set does NOT"
echo "      prove HPN is misconfigured. The authoritative check is whether"
echo "      curl -4 ifconfig.me returns the VPN server's IP (see section 4)."
echo
echo "--- Definitive HPN protocol dump (raw NSKeyedArchiver blob with HPN markers) ---"
# Find the NEVPNTunnelProtocolPlugin block whose serverAddress / providerBundleIdentifier
# is io.hpn.vpn.macos.packet-tunnel — that's the HPN protocol object. Print a
# generous context window so the values for the three flags appear after the
# HPN identifier marker.
sudo plutil -convert xml1 -o - /Library/Preferences/com.apple.networkextension.plist 2>/dev/null \
    | awk '
        /<string>io\.hpn\.vpn\.macos\.packet-tunnel<\/string>/ {hit=NR; next}
        hit && NR <= hit + 80 {print}
        hit && NR > hit + 80 {hit=0}
    ' | head -100

hr "4. ROUTING TABLE — IPv4 defaults"
netstat -rn -f inet | awk '/^default|Destination/{print}' | head -20
echo
echo "(Apple Community 256152228: 'UGScIg' instead of 'UGScg' on the en0"
echo " default == Tahoe OS bug. Workaround: sudo route delete -net default"
echo " && sudo route add default <gateway>)"

hr "5. ROUTING TABLE — IPv6 defaults"
netstat -rn -f inet6 | awk '/^default|Destination/{print}' | head -20

hr "6. utun interfaces (which one is HPN's tunnel?)"
ifconfig | awk '/^utun[0-9]+:/{flag=1; iface=$1; print iface} flag && /inet /{print "   "$0; flag=0}'

hr "7. tcpdump SMOKE TEST (only run while VPN is connected)"
echo "If you have a connected VPN, find the utun number from section 6,"
echo "then in another Terminal run:"
echo "   sudo tcpdump -nn -i utunN -c 10"
echo "and open a browser. If tcpdump shows 0 packets after 10s of browsing,"
echo "the kernel is not routing app traffic to utun (PBR not engaged)."

hr "8. Recent packet-tunnel logs (last 15 min, info level)"
log show --last 15m --info --predicate "subsystem == \"$SUBSYSTEM\"" 2>&1 \
    | grep -vE 'No matching messages|^Filtering|^Timestamp' \
    | tail -120 || echo "(no log lines in last 15 min — has Connect been clicked?)"

hr "9. nesessionmanager / neagent / sysextd recent activity"
log show --last 5m --info --predicate \
    'process == "nesessionmanager" OR process == "neagent" OR process == "sysextd"' 2>&1 \
    | grep -iE 'hpn|io\.hpn\.vpn|VPNConfig|tunnel started|tunnel stopped|extension' \
    | tail -60

hr "10. VPN configuration as macOS sees it"
networksetup -listallnetworkservices 2>&1 | grep -i hpn || echo "(no HPN network service registered)"
scutil --nc list | grep -i hpn || echo "(scutil --nc list: no HPN entry)"

hr "DONE"
echo
echo "Paste the entire output above (from '0. HOST INFO' to here) in the chat."
echo
echo "Quick eyeball summary you can read before pasting:"
echo "  - Section 1: 'CDHash=<...>' must EXIST"
echo "  - Section 2: ONLY ONE '[activated enabled]' line, NO 'terminated' line"
echo "  - Section 3: 'IncludeAllNetworks' value must be present and == 1"
echo "  - Section 4: en0 default MUST show 'UGScg', not 'UGScIg'"
echo "  - Section 8: must contain 'buildNetworkSettings' and"
echo "    'Applying NEPacketTunnelNetworkSettings' lines when you click Connect"
