import Foundation
import NetworkExtension
import Security
import os.log

private let logger = Logger(subsystem: "io.hpn.vpn.macos.packet-tunnel", category: "PacketTunnel")

// MARK: - Keychain access (must mirror VPNManager.swift in the host app)
//
// The extension reads the VPN password and the rekey HMAC key directly from
// the shared Keychain (`keychain-access-groups` entitlement). The host app
// is the only writer; the extension never persists anything itself.
//
// CRITICAL: this string MUST exactly match the runtime value of an
// entitled `keychain-access-groups` entry on the EXTENSION binary
// (NOT the source-plist string with the `$(AppIdentifierPrefix)`
// placeholder, but the post-codesign expanded form
// `<TEAM_ID>.io.hpn.vpn`). Passing the unprefixed logical name
// `"io.hpn.vpn"` makes Security.framework return
// `errSecMissingEntitlement` (-34018), `loadMasterHmacKey()` returns
// nil, the audit-H15 envelope cannot be verified, and `startTunnel`
// fails with "Provider config not found" — masking the real keychain
// failure under a misleading file-not-found error. See the matching
// constant in `VPNManager.swift::keychainAccessGroup` for the full
// rationale; the two literals MUST stay byte-identical.
private let keychainAccessGroup = "6Y986MRM6T.io.hpn.vpn"
private let keychainServicePrefix = "io.hpn.vpn.profile."

// Audit H15: master HMAC key for the provider-config envelope. MUST
// match the values used by `VPNManager.swift` in the host app.
private let keychainHmacService = "io.hpn.vpn.rekey-hmac"
private let keychainHmacAccount = "key"
private let keychainHmacExpectedLen = 32

private func loadPasswordFromKeychain(profileId: String) -> String? {
    // `kSecUseDataProtectionKeychain = true` is MANDATORY here. The
    // host app is unsandboxed (it MUST be — see
    // `entitlements.plist` for the rationale), so without this flag
    // it writes to the file-based keychain
    // (`~/Library/Keychains/login.keychain-db`). The extension is
    // sandboxed and defaults to the data protection keychain; the
    // two backends do not share items, and the cross-context
    // mismatch surfaces as `errSecItemNotFound` here even though the
    // item exists in the host's keychain. Forcing data-protection
    // keychain on BOTH sides resolves the mismatch and is the
    // backend that actually respects `keychain-access-groups`.
    // See `VPNManager.swift::keychainBaseQuery` for the canonical
    // explanation. Field-confirmed on Tahoe 26.4 (May 2026).
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainServicePrefix + profileId,
        kSecAttrAccount as String: "password",
        kSecAttrAccessGroup as String: keychainAccessGroup,
        kSecAttrSynchronizable as String: false,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnData as String: kCFBooleanTrue as Any,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data else {
        if status != errSecItemNotFound {
            logger.error("Keychain lookup failed (OSStatus \(status, privacy: .public))")
        }
        return nil
    }
    return String(data: data, encoding: .utf8)
}

/// Audit H15: read the 32-byte master HMAC key from the App Group
/// shared Keychain. The host app creates this entry on first connect
/// (see `keychain.rs::ensure_master_hmac_key`); the extension only
/// reads it. Returns nil when the entry is missing — the caller is
/// expected to surface the resulting error so the user can re-trigger
/// the host app's connect flow once.
private func loadMasterHmacKey() -> Data? {
    // See `loadPasswordFromKeychain` above for the rationale on
    // `kSecUseDataProtectionKeychain`. Same constraints apply here.
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: keychainHmacService,
        kSecAttrAccount as String: keychainHmacAccount,
        kSecAttrAccessGroup as String: keychainAccessGroup,
        kSecAttrSynchronizable as String: false,
        kSecUseDataProtectionKeychain as String: true,
        kSecReturnData as String: kCFBooleanTrue as Any,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data else {
        if status != errSecItemNotFound {
            logger.error("Master HMAC Keychain lookup failed (OSStatus \(status, privacy: .public))")
        }
        return nil
    }
    guard data.count == keychainHmacExpectedLen else {
        logger.error("Master HMAC key has wrong length (\(data.count) vs expected \(keychainHmacExpectedLen))")
        return nil
    }
    return data
}

// MARK: - Rust FFI

@_silgen_name("hpn_tunnel_start")
private func hpn_tunnel_start(_ configJson: UnsafePointer<CChar>?, _ configLen: Int32) -> Int32

// Audit H15: verify the on-disk HMAC envelope and copy the inner JSON
// to a Swift-owned buffer. The Swift side then performs the
// credential injection (password from Keychain) before calling
// `hpn_tunnel_start` with the post-injection JSON. Splitting the
// flow this way keeps the password entirely on the Swift side — Rust
// never touches it, matching the post-CRED-1 architecture.
@_silgen_name("hpn_envelope_unwrap_to_buf")
private func hpn_envelope_unwrap_to_buf(
    _ envelopeBuf: UnsafePointer<CChar>?,
    _ envelopeLen: Int32,
    _ hmacKeyBuf: UnsafePointer<UInt8>?,
    _ hmacKeyLen: Int32,
    _ outBuf: UnsafeMutablePointer<CChar>?,
    _ outBufLen: Int32
) -> Int32

@_silgen_name("hpn_tunnel_stop")
private func hpn_tunnel_stop() -> Int32

@_silgen_name("hpn_tunnel_get_settings_json")
private func hpn_tunnel_get_settings_json(_ outBuf: UnsafeMutablePointer<CChar>?, _ outBufLen: Int32) -> Int32

@_silgen_name("hpn_tunnel_write_packets")
private func hpn_tunnel_write_packets(_ buf: UnsafePointer<UInt8>?, _ len: Int32) -> Int32

@_silgen_name("hpn_tunnel_read_packets")
private func hpn_tunnel_read_packets(_ buf: UnsafeMutablePointer<UInt8>?, _ bufLen: Int32) -> Int32

@_silgen_name("hpn_tunnel_get_stats_json")
private func hpn_tunnel_get_stats_json(_ outBuf: UnsafeMutablePointer<CChar>?, _ outBufLen: Int32) -> Int32

@_silgen_name("hpn_tunnel_force_rekey")
private func hpn_tunnel_force_rekey() -> Int32

@_silgen_name("hpn_tunnel_on_sleep")
private func hpn_tunnel_on_sleep() -> Int32

@_silgen_name("hpn_tunnel_on_wake")
private func hpn_tunnel_on_wake() -> Int32

// MARK: - Network config from Rust

private struct TunnelNetworkConfig: Decodable {
    let remote_address: String
    let mtu: UInt16
    let ipv4_address: String
    let ipv4_netmask: String
    let ipv6_address: String?
    let ipv6_prefix_length: UInt8?
    let dns_servers: [String]
    let split_routes: [String]?
    let full_tunnel: Bool
    let allow_lan: Bool
}

// MARK: - Provider

class PacketTunnelProvider: NEPacketTunnelProvider {

    private var packetPumpRunning = false
    private var statsCallsLogged = 0

    override func startTunnel(options: [String: NSObject]?, completionHandler: @escaping (Error?) -> Void) {
        logger.info("startTunnel called")

        guard let configData = loadProviderConfig() else {
            // Diagnostic-friendly wording: the previous "Provider config
            // not found" string was a pre-H15 catch-all that masked at
            // least three distinct conditions (file truly absent, file
            // corrupted, Keychain-bridge failure). On Tahoe the only
            // remaining path is `providerConfiguration["config_json_v1"]`,
            // so this can only fire when the host did not stage the
            // payload before calling `install_and_start_vpn`.
            logger.error("loadProviderConfig returned nil — providerConfiguration[config_json_v1] missing")
            completionHandler(NSError(domain: "io.hpn.vpn", code: 1,
                userInfo: [NSLocalizedDescriptionKey:
                    "VPN provider configuration is missing. Please disconnect and reconnect from the HPN VPN app."]))
            return
        }

        // Call Rust to do the PQ handshake. `loadProviderConfig` returned
        // the raw JSON the host staged in `providerConfiguration` — the
        // legacy audit-H15 envelope + Keychain-password injection path is
        // no longer reached on Tahoe Developer ID builds (the root system
        // extension cannot share a Keychain with the user-context host;
        // see `loadProviderConfig` doc comment for the full rationale).
        let startResult = configData.withUnsafeBytes { rawBuf -> Int32 in
            guard let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: CChar.self) else { return -1 }
            return hpn_tunnel_start(ptr, Int32(rawBuf.count))
        }

        guard startResult == 0 else {
            logger.error("hpn_tunnel_start failed: \(startResult)")
            completionHandler(NSError(domain: "io.hpn.vpn", code: Int(startResult),
                userInfo: [NSLocalizedDescriptionKey: "Tunnel engine failed (code \(startResult))"]))
            return
        }

        // Get network settings from Rust (produced after handshake)
        guard let networkConfig = loadNetworkSettingsFromRust() else {
            completionHandler(NSError(domain: "io.hpn.vpn", code: 3,
                userInfo: [NSLocalizedDescriptionKey: "Failed to get network settings from engine"]))
            return
        }

        // Apply Apple network settings
        logger.info("Network config: remote=\(networkConfig.remote_address) ip=\(networkConfig.ipv4_address) mask=\(networkConfig.ipv4_netmask) mtu=\(networkConfig.mtu) dns=\(networkConfig.dns_servers)")
        let neSettings = buildNetworkSettings(from: networkConfig)
        logger.info("Applying NEPacketTunnelNetworkSettings: remote=\(neSettings.tunnelRemoteAddress)")
        setTunnelNetworkSettings(neSettings) { [weak self] error in
            if let error {
                logger.error("setTunnelNetworkSettings failed: \(error.localizedDescription)")
                completionHandler(error)
                return
            }
            logger.info("Tunnel settings applied, starting packet pump")
            self?.startPacketPump()
            completionHandler(nil)
        }
    }

    override func stopTunnel(with reason: NEProviderStopReason, completionHandler: @escaping () -> Void) {
        logger.info("stopTunnel reason: \(String(describing: reason))")
        packetPumpRunning = false
        _ = hpn_tunnel_stop()
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        if let json = try? JSONSerialization.jsonObject(with: messageData) as? [String: Any],
           let cmd = json["cmd"] as? String {
            switch cmd {
            case "rekey":
                logger.info("Force rekey requested via app message")
                _ = hpn_tunnel_force_rekey()
                completionHandler?(Data("{\"ok\":true}".utf8))
            case "stats":
                // Stats IPC channel host↔extension. The host polls
                // this every ~1 s from the React UI so the
                // RX/TX/RTT/transfer-rate widgets stay live.
                //
                // Architecture: the legacy file-based stats sink
                // (extension writes `tunnel-stats.json` to the App
                // Group container, host reads it) is unusable on
                // Tahoe because the extension runs as root and its
                // `containerURL(...)` resolves under
                // `/var/root/Library/...` while the host's
                // resolves under `/Users/<admin>/Library/...` — the
                // two don't share a path. Same root-cause as
                // provider-config IPC; same fix:
                // NETunnelProviderSession.sendProviderMessage is the
                // Apple-supported XPC channel for this hop.
                //
                // Buffer size: 4 KiB is well above the typical
                // 200-300 byte stats JSON payload (tx + rx + rtt_us
                // + session_key) and matches the host-side bound in
                // `VPNManager.swift::hpn_vpn_manager_get_stats`.
                var buf = [CChar](repeating: 0, count: 4096)
                let len = hpn_tunnel_get_stats_json(&buf, Int32(buf.count))
                // DIAGNOSTIC: log first 5 calls then go silent. The
                // host side caches at 500 ms TTL so this fires at
                // most ~2/sec; 5 lines (~2.5 s) is enough to confirm
                // the IPC handshake without drowning the log.
                if statsCallsLogged < 5 {
                    logger.info("stats IPC: hpn_tunnel_get_stats_json returned \(len, privacy: .public) bytes")
                    statsCallsLogged += 1
                }
                if len > 0 {
                    completionHandler?(Data(bytes: buf, count: Int(len)))
                } else {
                    completionHandler?(nil)
                }
            default:
                completionHandler?(nil)
            }
        } else {
            completionHandler?(nil)
        }
    }

    // MARK: - Power management
    //
    // macOS notifies the Packet Tunnel Extension when the host is about
    // to sleep and when it wakes back up. Without a wake hook, the
    // tunnel relies on the passive keepalive loop to notice that the
    // UDP socket was reclaimed by the kernel during deep sleep — that
    // takes 3 × keepalive_interval (≈ 90 s with defaults) before the
    // user sees a reconnect. We forward both edges to Rust so the
    // engine can rebind the socket and kick a rekey the moment we come
    // back online.

    override func sleep(completionHandler: @escaping () -> Void) {
        logger.info("sleep() — notifying Rust tunnel engine")
        // `hpn_tunnel_on_sleep` is non-blocking and just logs; no need
        // to await anything before telling the system we're ready to
        // suspend.
        _ = hpn_tunnel_on_sleep()
        completionHandler()
    }

    override func wake() {
        logger.info("wake() — notifying Rust tunnel engine to rebind + rekey")
        // `hpn_tunnel_on_wake` will block_on `connection.rebind()` on
        // the tunnel's tokio runtime (fast: one bind() syscall + two
        // atomic pointer swaps). Return value is logged but not
        // surfaced — a failure here is not actionable from Swift; the
        // keepalive loop will still eventually detect the stall and
        // reconnect.
        let rc = hpn_tunnel_on_wake()
        if rc != 0 {
            logger.error("hpn_tunnel_on_wake returned \(rc, privacy: .public) — keepalive will retry")
        }
    }

    // MARK: - Config loading

    private func loadProviderConfig() -> Data? {
        // Read the raw JSON config from
        // `NETunnelProviderProtocol.providerConfiguration["config_json_v1"]`.
        // This is the host's primary delivery channel — see
        // `VPNManager.swift::pendingProviderConfig` for the rationale
        // on why providerConfiguration replaces the legacy
        // file-in-App-Group-container handoff on macOS Tahoe Developer
        // ID System Extensions. The credentials (username + password)
        // are inlined in this JSON; the host's `commands.rs::connect`
        // builds them directly into the dict, so the extension does
        // NOT need to query Keychain at start time. (It can't anyway
        // — the System Extension runs as root and has no access to
        // the user's data-protection keychain on Tahoe; field-
        // confirmed May 2026.)
        if let proto = self.protocolConfiguration as? NETunnelProviderProtocol,
           let providerConfig = proto.providerConfiguration,
           let jsonBytes = providerConfig["config_json_v1"] as? Data {
            logger.info("Provider config loaded from NETunnelProviderProtocol.providerConfiguration (\(jsonBytes.count, privacy: .public) bytes raw JSON)")
            return jsonBytes
        }

        logger.error("providerConfiguration[config_json_v1] missing — refusing legacy file fallback")
        return nil
    }

    /// Legacy Keychain bridge retained only for downgrade diagnostics.
    /// The Tahoe Developer-ID path does not call this: credentials arrive
    /// inline through providerConfiguration because the root system extension
    /// cannot read the host user's data-protection Keychain reliably.
    private func injectKeychainCredentials(into raw: Data) -> Data? {
        guard let object = try? JSONSerialization.jsonObject(with: raw, options: []),
              var dict = object as? [String: Any] else {
            return nil
        }

        // The host app emits ONE of the following shapes:
        //   1. `credentials_in_keychain = true` + top-level `username` +
        //      `keychain_profile_id` → look up the password in Keychain
        //      and rewrite as a `credentials` object.
        //   2. `credentials = { username, password }` → legacy inline
        //      mode; do nothing.
        //   3. `credentials = null` → profile does not require auth.
        let inKeychain = dict["credentials_in_keychain"] as? Bool ?? false
        guard inKeychain else { return nil }

        guard let username = dict["username"] as? String,
              let profileId = dict["keychain_profile_id"] as? String else {
            logger.error("credentials_in_keychain set but username/keychain_profile_id missing")
            return nil
        }

        guard let password = loadPasswordFromKeychain(profileId: profileId) else {
            logger.error("password not found in shared Keychain")
            // Surface a missing-credential error explicitly by returning
            // the JSON with credentials = null; the Rust handshake then
            // rejects it as "auth required but no creds".
            dict["credentials"] = NSNull()
            dict.removeValue(forKey: "credentials_in_keychain")
            dict.removeValue(forKey: "keychain_profile_id")
            dict.removeValue(forKey: "username")
            return try? JSONSerialization.data(withJSONObject: dict, options: [])
        }

        dict["credentials"] = [
            "username": username,
            "password": password,
        ]
        // Strip the bridging fields so they never appear in any debug
        // dump of the JSON we pass to Rust.
        dict.removeValue(forKey: "credentials_in_keychain")
        dict.removeValue(forKey: "keychain_profile_id")
        dict.removeValue(forKey: "username")
        return try? JSONSerialization.data(withJSONObject: dict, options: [])
    }

    private func loadNetworkSettingsFromRust() -> TunnelNetworkConfig? {
        var buf = [CChar](repeating: 0, count: 4096)
        let len = hpn_tunnel_get_settings_json(&buf, Int32(buf.count))
        guard len > 0 else { return nil }
        let data = Data(bytes: buf, count: Int(len))
        return try? JSONDecoder().decode(TunnelNetworkConfig.self, from: data)
    }

    // MARK: - Network settings

    private func buildNetworkSettings(from config: TunnelNetworkConfig) -> NEPacketTunnelNetworkSettings {
        let settings = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: config.remote_address)

        let ipv4 = NEIPv4Settings(addresses: [config.ipv4_address], subnetMasks: [config.ipv4_netmask])
        // Both routing modes (full_tunnel and bypass) catch every IPv4 packet
        // first with a default-route INCLUDE; only the EXCLUDE list differs.
        //
        // - full_tunnel: route everything through the VPN. The exclude list is
        //   either empty (kill-switch-everything) or the well-known RFC1918
        //   ranges when `allow_lan` is on, so the user can still reach the
        //   printer / NAS / router while connected.
        // - !full_tunnel (bypass mode): the React UI labels this "Exclude
        //   Routes" — everything goes through the VPN EXCEPT the CIDRs the
        //   user listed. The previous build inverted this contract and
        //   shipped the CIDR list as `includedRoutes` (so only the listed
        //   subnets were tunnelled and the rest leaked in clear, including
        //   DNS / IPv4 web / IPv6). Fixed here.
        //
        // Helpers below validate each CIDR via `routesFromCidrs`; entries
        // that fail to parse are dropped with a logged warning instead of
        // silently falling back to /32 (the old behaviour, which could
        // expose a much larger range than the operator intended).
        //
        // `includedRoutes` MUST contain ONLY the default route — no more-
        // specific overlapping entries.
        //
        // Apple Developer Forums thread 750173 documents that adding a
        // more-specific route that overlaps the default route causes
        // `NEPacketTunnelProvider.packetFlow.readPackets` to silently
        // stop firing — i.e. apps' packets are dropped before the
        // extension ever sees them. The repro from that thread (DTS
        // engineer Quinn confirming the question, never refuting the
        // observation):
        //
        //   [default]                                  → no packets
        //   [default, 192.168.0.103/24]                → no packets
        //   [default, 192.168.0.103/30]                → packets visible
        //
        // The /24 case is the one that lines up with how we used to add
        // the tunnel's own subnet to `includedRoutes` as a "longest-
        // prefix-match anchor" (commit 86bbc36). That belt-and-suspenders
        // attempt was itself the bug: it made TX stop entirely. Reverted
        // here. Apple installs the tunnel's own `/N` route IMPLICITLY
        // when the `NEIPv4Settings(addresses:subnetMasks:)` pair is set,
        // so no explicit declaration is needed.
        //
        // The TUNNEL-SUBNET COLLISION GUARD documented at b3911e7 is
        // still required: any RFC1918 EXCLUDE entry that contains the
        // tunnel's own CIDR is dropped from `excludedRoutes` so the
        // kill-switch flags (see VPNManager.swift) cannot blackhole the
        // tunnel gateway. The carve-out lives in
        // `localIPv4Routes(skippingCoversOf:)` and
        // `routesFromCidrs(_:skippingCoversOf:)` below — those helpers
        // are correct; only the includedRoutes addition was wrong.
        ipv4.includedRoutes = [NEIPv4Route.default()]
        let tunnelCidr = Self.parseHostCidr(address: config.ipv4_address, mask: config.ipv4_netmask)
        if tunnelCidr == nil {
            // ipv4_address / ipv4_netmask did not parse. Should never
            // happen — the Rust side built these from a verified
            // TunnelInfo. We still proceed with the default-route-only
            // include; the carve-out logic below just no-ops (every
            // RFC1918 supernet is kept, including any that might have
            // covered the tunnel CIDR). Bandwidth still flows.
            logger.error("buildNetworkSettings: failed to parse tunnel CIDR from \(config.ipv4_address, privacy: .public) / \(config.ipv4_netmask, privacy: .public); LAN-exclude carve-out disabled for this session")
        }

        var ipv4Excludes: [NEIPv4Route] = []
        if config.full_tunnel {
            if config.allow_lan {
                ipv4Excludes.append(contentsOf: Self.localIPv4Routes(skippingCoversOf: tunnelCidr))
            }
        } else if let routes = config.split_routes, !routes.isEmpty {
            ipv4Excludes.append(contentsOf: Self.routesFromCidrs(routes, skippingCoversOf: tunnelCidr))
            if config.allow_lan {
                ipv4Excludes.append(contentsOf: Self.localIPv4Routes(skippingCoversOf: tunnelCidr))
            }
        } else if config.allow_lan {
            // Bypass mode with no user CIDRs is degenerate, but still
            // honour allow_lan rather than silently routing the LAN.
            ipv4Excludes.append(contentsOf: Self.localIPv4Routes(skippingCoversOf: tunnelCidr))
        }
        if !ipv4Excludes.isEmpty {
            ipv4.excludedRoutes = ipv4Excludes
        }
        settings.ipv4Settings = ipv4

        // IPv6 handling.
        //
        // Two failure modes were possible in the previous code:
        //
        //   1. Bypass mode + server lease without IPv6 → `ipv6Settings` left
        //      `nil` → macOS falls back to the host's native IPv6 stack for
        //      every IPv6 destination. On any IPv6-enabled LAN that is a
        //      real dual-stack leak (curl -6 ifconfig.me returns the user's
        //      ISP address while curl -4 returns the VPN address).
        //   2. Full tunnel + no lease → same leak.
        //
        // Both are closed here: we always install an `NEIPv6Settings` even
        // when the lease only contains IPv4. When no IPv6 prefix is leased
        // we use the IPv6 loopback (`::1`) as a placeholder address so
        // macOS lets us declare a default `includedRoutes`. Without an IPv6
        // exit route the result is that IPv6 traffic gets pulled into the
        // tunnel and then dropped by the Rust side (no v6 tunnel route to
        // forward to) — effectively a v6 black-hole, which is the correct
        // fail-closed behaviour while there is no `split_routes_v6` in the
        // schema.
        let ipv6Settings: NEIPv6Settings
        if let ipv6Addr = config.ipv6_address, let prefix = config.ipv6_prefix_length {
            ipv6Settings = NEIPv6Settings(addresses: [ipv6Addr], networkPrefixLengths: [NSNumber(value: prefix)])
        } else {
            // Loopback placeholder: macOS will accept the `NEIPv6Settings`
            // declaration without trying to route ::1 over the wire, and
            // we still get `includedRoutes = [default]` to catch every
            // outbound v6 packet.
            ipv6Settings = NEIPv6Settings(addresses: ["::1"], networkPrefixLengths: [NSNumber(value: 128)])
        }
        ipv6Settings.includedRoutes = [NEIPv6Route.default()]
        if config.allow_lan {
            ipv6Settings.excludedRoutes = [
                NEIPv6Route(destinationAddress: "fe80::", networkPrefixLength: 10),
                NEIPv6Route(destinationAddress: "fc00::", networkPrefixLength: 7),
            ]
        }
        settings.ipv6Settings = ipv6Settings

        if !config.dns_servers.isEmpty {
            let dns = NEDNSSettings(servers: config.dns_servers)
            dns.matchDomains = [""]
            settings.dnsSettings = dns
        }

        settings.mtu = NSNumber(value: config.mtu)
        return settings
    }

    // MARK: - Packet pump

    private var statsTimer: DispatchSourceTimer?

    private func startPacketPump() {
        packetPumpRunning = true
        readFromTUN()
        readFromRust()
        startStatsWriter()
    }

    private func startStatsWriter() {
        let timer = DispatchSource.makeTimerSource(queue: DispatchQueue.global(qos: .utility))
        timer.schedule(deadline: .now() + 1, repeating: 2.0)
        timer.setEventHandler { [weak self] in
            guard let self, self.packetPumpRunning else { return }

            // Rekey requests now arrive through
            // `NETunnelProviderSession.sendProviderMessage` (handled by
            // `handleAppMessage` at the top of this class). We no
            // longer poll a `rekey-signal` file in the container —
            // that path was microseconds-vs-seconds slower, and
            // coupled the extension to a file the main app may not
            // have the privileges to write under App Sandbox.

            var buf = [CChar](repeating: 0, count: 1024)
            let len = hpn_tunnel_get_stats_json(&buf, Int32(buf.count))
            guard len > 0 else { return }
            let data = Data(bytes: buf, count: Int(len))

            // Write to app group container for the app to read
            if let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: "group.io.hpn.vpn") {
                try? data.write(to: containerURL.appendingPathComponent("tunnel-stats.json"), options: .atomic)
            }
            // Also write to app support fallback
            if let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
                let dir = appSupport.appendingPathComponent("hpn-vpn", isDirectory: true)
                try? data.write(to: dir.appendingPathComponent("tunnel-stats.json"), options: .atomic)
            }
        }
        timer.resume()
        statsTimer = timer
    }

    /// TUN -> Rust (app traffic to encrypt and send to server)
    private func readFromTUN() {
        packetFlow.readPackets { [weak self] packets, protocols in
            guard let self, self.packetPumpRunning else { return }
            for packet in packets {
                packet.withUnsafeBytes { rawBuf in
                    guard let ptr = rawBuf.baseAddress?.assumingMemoryBound(to: UInt8.self) else { return }
                    _ = hpn_tunnel_write_packets(ptr, Int32(rawBuf.count))
                }
            }
            self.readFromTUN()
        }
    }

    /// Rust -> TUN (decrypted server traffic to inject into apps).
    /// The Rust side uses a condvar (5ms timeout) instead of busy-polling,
    /// so we don't need Thread.sleep here.
    private func readFromRust() {
        DispatchQueue.global(qos: .userInteractive).async { [weak self] in
            var buf = [UInt8](repeating: 0, count: 65536)
            while let self, self.packetPumpRunning {
                // hpn_tunnel_read_packets blocks up to 5ms via condvar if no packet.
                let len = hpn_tunnel_read_packets(&buf, Int32(buf.count))
                if len > 0 {
                    let data = Data(bytes: buf, count: Int(len))
                    let proto: NSNumber = (buf[0] >> 4 == 6) ? NSNumber(value: AF_INET6) : NSNumber(value: AF_INET)
                    self.packetFlow.writePackets([data], withProtocols: [proto])
                } else if len < 0 {
                    break // Channel disconnected.
                }
            }
        }
    }

    /// Build a dotted-quad netmask string from a CIDR prefix length.
    /// Handles the two Swift-trap edges of `UInt32.max >> 32` (UB in
    /// Swift, traps the process) — both prefix=0 and prefix=32 are
    /// special-cased before the shift. Out-of-range inputs (negative
    /// or >32) clamp to /32 rather than crash.
    private static func prefixToMask(_ prefix: Int) -> String {
        let mask: UInt32
        if prefix <= 0 {
            mask = 0
        } else if prefix >= 32 {
            mask = UInt32.max
        } else {
            mask = ~(UInt32.max >> prefix)
        }
        return "\(mask >> 24 & 0xFF).\(mask >> 16 & 0xFF).\(mask >> 8 & 0xFF).\(mask & 0xFF)"
    }

    /// IPv4 CIDR in canonical form: `(networkAddress, prefixLength)`.
    /// Network address is masked, i.e. the host bits are zeroed.
    fileprivate struct IPv4Cidr: Equatable {
        let network: UInt32   // Already masked to `prefix` bits.
        let prefix: UInt8     // 0...32

        /// Dotted-quad form of `network`. Useful as `destinationAddress`
        /// for NEIPv4Route — Apple does not mask host bits for the
        /// caller, so we feed it the canonical form ourselves.
        var networkString: String {
            return "\(network >> 24 & 0xFF).\(network >> 16 & 0xFF).\(network >> 8 & 0xFF).\(network & 0xFF)"
        }

        /// Does this CIDR contain the entirety of `other`? True iff
        /// `self.prefix <= other.prefix` AND the leading `self.prefix`
        /// bits of `other.network` equal `self.network`.
        func contains(_ other: IPv4Cidr) -> Bool {
            guard self.prefix <= other.prefix else { return false }
            if self.prefix == 0 { return true }
            let shift = UInt32(32 - self.prefix)
            return (other.network >> shift) == (self.network >> shift)
        }
    }

    /// Parse a dotted-quad string into `UInt32` (big-endian / network order).
    /// Returns `nil` on any malformed octet or wrong octet count.
    fileprivate static func parseIPv4(_ s: String) -> UInt32? {
        let parts = s.split(separator: ".", omittingEmptySubsequences: false)
        guard parts.count == 4 else { return nil }
        var addr: UInt32 = 0
        for p in parts {
            guard let octet = UInt8(String(p)) else { return nil }
            addr = (addr << 8) | UInt32(octet)
        }
        return addr
    }

    /// Convert a dotted-quad netmask (e.g. "255.255.255.0") to the
    /// equivalent CIDR prefix length. Returns `nil` for non-contiguous
    /// masks (e.g. "255.0.255.0") and other malformed input.
    fileprivate static func maskToPrefix(_ mask: String) -> UInt8? {
        guard let bits = parseIPv4(mask) else { return nil }
        if bits == 0 { return 0 }
        // Contiguous-mask check: ~bits + 1 must be a power of two (or 0)
        // because a valid CIDR netmask is N leading 1-bits followed by
        // (32-N) trailing 0-bits — i.e. `~bits` is M trailing 1-bits
        // (M = 32-N), and `x & (x+1) == 0` iff x is one-less-than-a-
        // power-of-two.
        let inverted = ~bits
        if inverted != 0 && (inverted & (inverted &+ 1)) != 0 {
            return nil
        }
        // Count leading 1-bits.
        var prefix: UInt8 = 0
        var remaining = bits
        while (remaining & 0x80000000) != 0 {
            prefix += 1
            remaining <<= 1
        }
        return prefix
    }

    /// Build the 32-bit netmask matching a CIDR prefix length, with
    /// the same edge-case handling as `prefixToMask`. Lives separately
    /// because the bit-pattern (not the dotted-quad) is what
    /// `IPv4Cidr` arithmetic needs.
    fileprivate static func maskBits(forPrefix prefix: UInt8) -> UInt32 {
        if prefix == 0 { return 0 }
        if prefix >= 32 { return UInt32.max }
        return ~(UInt32.max >> prefix)
    }

    /// Build an `IPv4Cidr` from a host address + dotted-quad netmask.
    /// Used for the tunnel's own subnet (config.ipv4_address +
    /// config.ipv4_netmask from the server lease) and to canonicalise
    /// `address/prefix` user input. Returns `nil` on any parse failure.
    fileprivate static func parseHostCidr(address: String, mask: String) -> IPv4Cidr? {
        guard let host = parseIPv4(address), let prefix = maskToPrefix(mask) else {
            return nil
        }
        return IPv4Cidr(network: host & maskBits(forPrefix: prefix), prefix: prefix)
    }

    /// Build an `IPv4Cidr` from a `dest/prefix` string.
    fileprivate static func parseCidrString(_ cidr: String) -> IPv4Cidr? {
        let parts = cidr.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count == 2,
              let prefix = Int(parts[1]),
              prefix >= 0, prefix <= 32,
              let host = parseIPv4(String(parts[0])) else {
            return nil
        }
        let prefixU8 = UInt8(prefix)
        return IPv4Cidr(network: host & maskBits(forPrefix: prefixU8), prefix: prefixU8)
    }

    /// RFC1918 (10/8, 172.16/12, 192.168/16) plus IPv4 link-local
    /// (169.254/16) — the standard "keep the user reachable to printer /
    /// NAS / router / captive-portal probe" exclusion list used when
    /// `allow_lan` is on. Mirrors the historical full_tunnel-mode exclude
    /// list verbatim so the bypass and full-tunnel exclude semantics stay
    /// aligned.
    ///
    /// CGNAT (100.64/10) is NOT excluded by default: mobile-hotspot users
    /// behind CGN can still reach their hotspot LAN through the tunnel,
    /// which is the safer behaviour (the upstream CGN block is not their
    /// "local network" in the security sense). If a deployment needs
    /// CGNAT reachable bypass-style, the user should add `100.64.0.0/10`
    /// to the `split_routes` field explicitly.
    ///
    /// `skippingCoversOf` is the tunnel's own CIDR (e.g. 10.99.0.0/24
    /// from the server lease). Any RFC1918 entry that COVERS that CIDR
    /// is dropped from the exclude list — installing it would blackhole
    /// the tunnel gateway under `enforceRoutes=true`. Sacrificed coverage
    /// is logged so the operator can see the carve-out fired.
    private static func localIPv4Routes(skippingCoversOf tunnelCidr: IPv4Cidr?) -> [NEIPv4Route] {
        let entries: [(addr: String, mask: String, prefix: UInt8)] = [
            ("10.0.0.0",    "255.0.0.0",   8),
            ("172.16.0.0",  "255.240.0.0", 12),
            ("192.168.0.0", "255.255.0.0", 16),
            ("169.254.0.0", "255.255.0.0", 16),
        ]
        var out: [NEIPv4Route] = []
        out.reserveCapacity(entries.count)
        for entry in entries {
            if let tunnel = tunnelCidr,
               let supernet = parseHostCidr(address: entry.addr, mask: entry.mask),
               supernet.contains(tunnel) {
                logger.notice("Skipping LAN-bypass exclude \(entry.addr, privacy: .public)/\(entry.prefix, privacy: .public): covers the tunnel subnet \(tunnel.networkString, privacy: .public)/\(tunnel.prefix, privacy: .public); leaving that supernet routed through the VPN to keep the tunnel gateway reachable")
                continue
            }
            out.append(NEIPv4Route(destinationAddress: entry.addr, subnetMask: entry.mask))
        }
        return out
    }

    /// Parse a list of `dest/prefix` CIDR strings into `NEIPv4Route` excludes.
    ///
    /// Entries that fail to parse cleanly (missing prefix, invalid IP, prefix
    /// out of range) are SKIPPED with a logged warning rather than silently
    /// downgraded to /32. The previous code path quietly used /32 for any
    /// malformed entry, which could mask "I typed 10.0.0.0 instead of
    /// 10.0.0.0/8" by routing only the network address through the bypass —
    /// surprising the operator and leaving the rest of the intended subnet
    /// in clear.
    ///
    /// `skippingCoversOf` is the tunnel's own CIDR. Any user-supplied
    /// entry that covers it is dropped with a `.notice` log so a typo
    /// like "10.0.0.0/8" against a 10.99.0.0/24 tunnel pool cannot
    /// blackhole the tunnel under `enforceRoutes=true`.
    private static func routesFromCidrs(_ cidrs: [String], skippingCoversOf tunnelCidr: IPv4Cidr?) -> [NEIPv4Route] {
        var out: [NEIPv4Route] = []
        out.reserveCapacity(cidrs.count)
        for cidr in cidrs {
            let trimmed = cidr.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }
            let parts = trimmed.split(separator: "/", omittingEmptySubsequences: false)
            // `/0` would exclude EVERY destination from the tunnel,
            // effectively turning bypass mode into "disconnect for IPv4".
            // Almost certainly a typo for /24 or /32, so refuse rather than
            // silently producing a broken VPN.
            guard parts.count == 2,
                  let prefix = Int(parts[1]),
                  prefix >= 1, prefix <= 32 else {
                logger.warning("Dropping split-tunnel CIDR \(trimmed, privacy: .public): expected dest/prefix with 1 <= prefix <= 32")
                continue
            }
            let dest = String(parts[0])
            // NEIPv4Route does not validate the destination string, so a
            // typo like "10.0.0/8" (3 octets) or "999.999.999.999/8" (out-
            // of-range octets) would otherwise reach networkd, which then
            // silently drops the route — leaving the operator believing
            // the subnet bypasses the VPN while it does not. Parse each
            // octet as a `UInt8` to reject these explicitly.
            let octets = dest.split(separator: ".", omittingEmptySubsequences: false)
            guard octets.count == 4 else {
                logger.warning("Dropping split-tunnel CIDR \(trimmed, privacy: .public): destination is not a dotted-quad IPv4 address")
                continue
            }
            let allOctetsValid = octets.allSatisfy { UInt8(String($0)) != nil }
            guard allOctetsValid else {
                logger.warning("Dropping split-tunnel CIDR \(trimmed, privacy: .public): destination has out-of-range octets")
                continue
            }
            // Tunnel-collision guard. Compute the canonical CIDR of the
            // user's entry and refuse it if it would cover the tunnel's
            // own subnet (per `enforceRoutes=true` blackhole semantics).
            if let tunnel = tunnelCidr,
               let userCidr = parseCidrString(trimmed),
               userCidr.contains(tunnel) {
                logger.notice("Dropping split-tunnel CIDR \(trimmed, privacy: .public): covers the tunnel subnet \(tunnel.networkString, privacy: .public)/\(tunnel.prefix, privacy: .public); would blackhole the VPN gateway")
                continue
            }
            let mask = Self.prefixToMask(prefix)
            out.append(NEIPv4Route(destinationAddress: dest, subnetMask: mask))
        }
        return out
    }

    // Note: the former `checkRekeySignal()` file-poll helper was
    // removed — rekey now travels through
    // `handleAppMessage(_:completionHandler:)` above, which calls
    // `hpn_tunnel_force_rekey()` directly on receipt of
    // `{"cmd":"rekey"}`.
}
