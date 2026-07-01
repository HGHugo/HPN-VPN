import Foundation
import NetworkExtension
import Security
import SystemExtensions

private let appGroupId = "group.io.hpn.vpn"
private let extensionBundleId = "io.hpn.vpn.macos.packet-tunnel"
private let bgQueue = DispatchQueue(label: "io.hpn.vpn.manager", qos: .userInitiated)

// MARK: - System Extension activation
//
// Apple deprecated the legacy `.appex` ("App Extension") packaging for
// Network Extensions on macOS Developer-ID distributions in 2023.
// The Packet Tunnel Provider must now be packaged as a `.systemextension`
// bundle and activated explicitly via `OSSystemExtensionRequest` before
// `NETunnelProviderManager` can find it.
//
// Activation flow:
//   1. App calls `hpn_vpn_manager_install_and_start`.
//   2. `ensureSystemExtensionActivated()` runs first. It is idempotent —
//      if the extension is already activated and current, it returns
//      immediately. Otherwise it submits an activationRequest to
//      OSSystemExtensionManager.
//   3. macOS displays the system prompt and (on first install) opens
//      System Settings → Privacy & Security so the user can click Allow.
//   4. The delegate callbacks update a shared status flag.
//   5. We wait up to `systemExtensionApprovalTimeout` for the user to
//      approve. If the wait expires, we return error -16 to surface a
//      clear "approval needed" error in the UI.
//
// Idempotency on subsequent launches: OSSystemExtensionManager remembers
// the user's approval. On a clean re-launch with the same extension
// version, the activation request resolves with `.completed` in
// milliseconds without re-prompting the user. If the user revoked the
// extension in System Settings, they get re-prompted.

/// Maximum time to wait for the user to click Allow in System Settings.
/// Long enough to give a real human the time to find the prompt; short
/// enough that a forgotten dialog does not hang the connect flow forever.
private let systemExtensionApprovalTimeout: TimeInterval = 60.0

/// Cached status of the most recent activation attempt. Read by both
/// `ensureSystemExtensionActivated` (synchronous-via-semaphore) and the
/// test FFI `hpn_vpn_manager_systemextension_status`.
private var sysextStatus: SystemExtensionStatus = .unknown
private let sysextStatusLock = NSLock()

private enum SystemExtensionStatus: Int32 {
    case unknown = 0
    case activated = 1            // request resolved with .completed
    case willActivateOnReboot = 2 // request resolved with .willActivateOnReboot
    case userApprovalRequired = 3 // requestNeedsUserApproval fired
    case failed = 4               // didFailWithError fired
}

private func setSysextStatus(_ status: SystemExtensionStatus) {
    sysextStatusLock.lock()
    sysextStatus = status
    sysextStatusLock.unlock()
}

private func getSysextStatus() -> SystemExtensionStatus {
    sysextStatusLock.lock()
    defer { sysextStatusLock.unlock() }
    return sysextStatus
}

/// Delegate that drives the OSSystemExtensionRequest lifecycle.
///
/// Held by reference for the duration of the request so the delegate
/// methods are reachable when OSSystemExtensionManager invokes them.
/// `submitRequest` does NOT retain the delegate, so a local variable
/// would be deallocated before the callbacks fire.
private final class SysextDelegate: NSObject, OSSystemExtensionRequestDelegate {

    /// Semaphore the caller waits on. We signal it on every terminal
    /// state (success, failure, or user-approval-required) so the
    /// caller can decide what to do.
    let signal: DispatchSemaphore

    init(signal: DispatchSemaphore) {
        self.signal = signal
    }

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties)
                 -> OSSystemExtensionRequest.ReplacementAction {
        // Always allow upgrades. macOS asks us this whenever a new build
        // bundles a different version of the extension; saying `.replace`
        // is the only sane answer for a real-world VPN client.
        NSLog("HPN sysext: replacing existing %@ (%@) with %@ (%@)",
              existing.bundleIdentifier, existing.bundleVersion,
              ext.bundleIdentifier, ext.bundleVersion)
        return .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        // The system has displayed the approval prompt and opened
        // System Settings → Privacy & Security. We surface the state
        // to the caller so the UI can render a "Please approve in
        // System Settings" message; the caller's wait will keep
        // running until the user clicks Allow (or the timeout fires).
        NSLog("HPN sysext: user approval required — System Settings opened")
        setSysextStatus(.userApprovalRequired)
        // Note: we do NOT signal the semaphore here. The caller waits
        // for the actual approval / failure decision, not for the
        // prompt to appear.
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        switch result {
        case .completed:
            NSLog("HPN sysext: activation completed")
            setSysextStatus(.activated)
        case .willCompleteAfterReboot:
            NSLog("HPN sysext: activation will complete after reboot")
            setSysextStatus(.willActivateOnReboot)
        @unknown default:
            NSLog("HPN sysext: didFinishWithResult unknown rawValue=%d", result.rawValue)
            setSysextStatus(.failed)
        }
        signal.signal()
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        let nsErr = error as NSError
        NSLog("HPN sysext: activation failed: %@ (domain=%@ code=%d)",
              nsErr.localizedDescription, nsErr.domain, nsErr.code)
        setSysextStatus(.failed)
        signal.signal()
    }
}

/// Strong reference to the most recent delegate so it is not
/// deallocated while the OSSystemExtensionManager request is in flight.
private var sysextDelegate: SysextDelegate?

/// Ensure the Packet Tunnel System Extension is activated.
///
/// Returns 0 on success (already activated, or just got activated).
/// Returns -15 on activation failure, -16 on approval timeout, -17
/// on unrecoverable user denial. These map to user-visible error
/// messages in the Tauri layer (see `native_vpn.rs`).
private func ensureSystemExtensionActivated() -> Int32 {
    // Reset cached status so a previous failed attempt does not bleed
    // into this one.
    setSysextStatus(.unknown)

    let signal = DispatchSemaphore(value: 0)
    let delegate = SysextDelegate(signal: signal)
    sysextDelegate = delegate  // keep alive for the duration of the request

    let request = OSSystemExtensionRequest.activationRequest(
        forExtensionWithIdentifier: extensionBundleId,
        queue: .main
    )
    request.delegate = delegate
    OSSystemExtensionManager.shared.submitRequest(request)

    NSLog("HPN sysext: submitted activation request for %@", extensionBundleId)

    // Wait for either:
    //   - didFinishWithResult / didFailWithError (signal fired by delegate)
    //   - timeout (user did not approve in time)
    let waitResult = signal.wait(timeout: .now() + systemExtensionApprovalTimeout)

    sysextDelegate = nil  // allow ARC to drop the delegate now

    if waitResult == .timedOut {
        let cur = getSysextStatus()
        NSLog("HPN sysext: timed out (status=%d)", cur.rawValue)
        // If the system showed the prompt but the user never clicked
        // Allow, the cached status will be `.userApprovalRequired`.
        // We surface a distinct error code so the UI can show
        // "Please approve in System Settings" instead of a generic
        // "activation failed".
        return cur == .userApprovalRequired ? -16 : -15
    }

    switch getSysextStatus() {
    case .activated:
        return 0
    case .willActivateOnReboot:
        // The user approved but a reboot is required (rare — happens
        // when an older version is currently in-use by another
        // process). Surface as -17 so the UI can prompt to reboot.
        NSLog("HPN sysext: reboot required to finish activation")
        return -17
    case .failed, .userApprovalRequired, .unknown:
        return -15
    }
}

/// FFI: ask the System Extension framework for the current activation
/// status of the Packet Tunnel extension.
///
/// Returns one of the [`SystemExtensionStatus`] raw values (0-4).
/// Used by the UI to decide whether to show "Click here to approve"
/// when the user is stuck in the approval-required state.
@_cdecl("hpn_vpn_manager_systemextension_status")
public func hpnVpnManagerSystemextensionStatus() -> Int32 {
    return getSysextStatus().rawValue
}

// MARK: - Keychain bridge
//
// VPN credentials are stored in the shared Keychain so that both the
// containing app and the Packet Tunnel Extension can read them via the
// `keychain-access-groups` entitlement. The app NEVER writes the password
// to disk (the previous design serialised it into `provider-config.json`,
// which is the vulnerability this bridge fixes).
//
// Items are SecClassGenericPassword keyed by:
//   - service: `io.hpn.vpn.profile.<profile_id>` for per-profile passwords
//   - service: `io.hpn.vpn.rekey-hmac`           for the rekey signal HMAC key
//   - account: `password` or `key` respectively
//
// Accessibility: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
// (the tunnel may have to start up after a reboot before the user logs in
// interactively, but never on a different device — Keychain syncing must be
// disabled to keep credentials off iCloud Keychain).

/// Keychain access group name USED AT RUNTIME by `kSecAttrAccessGroup`.
///
/// CRITICAL: this string MUST exactly match one of the entitled groups
/// on the running binary, AS SEEN BY `codesign -d --entitlements -`.
/// The runtime value is the codesign-time value with $(AppIdentifierPrefix)
/// already expanded — i.e. `<TEAM_ID>.io.hpn.vpn`. There is NO further
/// runtime substitution: passing `"io.hpn.vpn"` (the unprefixed logical
/// name) makes Security.framework reject every operation with
/// `errSecMissingEntitlement` (-34018) because none of the three
/// entitled groups
///     1. `<TEAM_ID>.io.hpn.vpn`             (from keychain-access-groups)
///     2. `<TEAM_ID>.io.hpn.vpn.macos`       (implicit from application-identifier)
///     3. `group.io.hpn.vpn`                 (implicit from application-groups, macOS-only)
/// match it. The host app then cascades into a "Keychain write failed"
/// connect error AND a silent fallback to the legacy unsigned
/// provider-config envelope; the extension cascades into
/// "Provider config not found" because it cannot read the master HMAC
/// key to verify the envelope.
///
/// We hard-code the team identifier instead of substituting at runtime
/// (via SecCodeCopySigningInformation) because:
///   1. The team ID is already hard-coded in `deploy/macos-release.sh`
///      (TEAM_ID), in `application-identifier` entitlement values, and
///      in the App ID portal entries. One more constant changes the
///      attack surface zero.
///   2. A runtime-discovered team ID would silently switch keychain
///      groups across a team-rotation event — far harder to diagnose
///      than a single source-code grep.
///   3. The Packet Tunnel Extension MUST use the EXACT same constant
///      (see `PacketTunnelProvider.swift`); having both files reference
///      the same literal makes the cross-file invariant trivially
///      auditable.
private let keychainAccessGroup = "6Y986MRM6T.io.hpn.vpn"

private let keychainServicePrefix = "io.hpn.vpn.profile."
private let keychainHmacService = "io.hpn.vpn.rekey-hmac"
private let keychainAccountPassword = "password"
private let keychainAccountKey = "key"

/// Build the base query dict shared by every Keychain operation.
///
/// CRITICAL: `kSecUseDataProtectionKeychain = true` is MANDATORY when
/// the host app is unsandboxed (which it MUST be on Developer ID
/// distribution, see entitlements.plist for why). Without this flag,
/// macOS picks the keychain backend based on sandbox state:
///   - unsandboxed processes default to the FILE-BASED keychain
///     (`~/Library/Keychains/login.keychain-db`)
///   - sandboxed processes (incl. our Packet Tunnel System Extension)
///     default to the DATA PROTECTION KEYCHAIN
///
/// The two backends DO NOT share items. So an unsandboxed host writing
/// `io.hpn.vpn.rekey-hmac` lands in login.keychain-db; the sandboxed
/// extension reading the same query (same service, account,
/// access-group) hits the data protection keychain and gets
/// `errSecItemNotFound` even though the item exists in the OTHER
/// keychain. The mismatch is invisible until tunnel start, when the
/// extension fails to verify the audit-H15 envelope and aborts with
/// "master HMAC key is missing from Keychain".
///
/// Forcing data-protection keychain on BOTH sides puts host and
/// extension on the same backend. The data-protection keychain is also
/// the backend that respects `keychain-access-groups` for cross-team-
/// id-shared items, which is the entire reason we have this entitlement.
/// Field-confirmed on macOS Tahoe 26.4 (May 2026).
private func keychainBaseQuery(service: String, account: String) -> [String: Any] {
    return [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrService as String: service,
        kSecAttrAccount as String: account,
        kSecAttrAccessGroup as String: keychainAccessGroup,
        kSecAttrSynchronizable as String: false,
        kSecUseDataProtectionKeychain as String: true,
    ]
}

/// Resolve a profile-id to its Keychain service name.
private func keychainServiceFor(profileId: String) -> String {
    return keychainServicePrefix + profileId
}

/// Upper bound on `profile_id` length across the FFI surface.
///
/// The Tauri side generates profile IDs as UUID v4 strings (36 chars).
/// A 256-byte ceiling is several times larger than any legitimate
/// value but small enough that a hostile caller cannot trick us into
/// a multi-MiB allocation. Audit H13 (FFI bounds).
private let maxProfileIdBytes = 256

/// Add or update the VPN password for `profile_id` in the shared Keychain.
///
/// Returns 0 on success, OSStatus on Keychain failure, -1 on argument
/// validation failure.
@_cdecl("hpn_keychain_set_password")
public func hpnKeychainSetPassword(
    _ profileIdPtr: UnsafePointer<CChar>?,
    _ profileIdLen: Int,
    _ passwordPtr: UnsafePointer<UInt8>?,
    _ passwordLen: Int
) -> Int32 {
    guard let profileIdPtr, profileIdLen > 0, profileIdLen <= maxProfileIdBytes,
          let passwordPtr, passwordLen > 0,
          passwordLen <= 4096 else {
        return -1
    }
    let profileIdData = Data(bytes: profileIdPtr, count: profileIdLen)
    guard let profileId = String(data: profileIdData, encoding: .utf8),
          !profileId.isEmpty else {
        return -1
    }
    let passwordData = Data(bytes: passwordPtr, count: passwordLen)
    let service = keychainServiceFor(profileId: profileId)

    // Try to update first (no permission prompt if it already exists).
    let updateQuery = keychainBaseQuery(service: service, account: keychainAccountPassword)
    let updateAttrs: [String: Any] = [
        kSecValueData as String: passwordData,
        kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
    ]
    let updateStatus = SecItemUpdate(updateQuery as CFDictionary, updateAttrs as CFDictionary)
    if updateStatus == errSecSuccess { return 0 }

    // Not found → add a fresh item.
    if updateStatus == errSecItemNotFound {
        var addAttrs = updateQuery
        addAttrs[kSecValueData as String] = passwordData
        addAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let addStatus = SecItemAdd(addAttrs as CFDictionary, nil)
        return Int32(addStatus)
    }

    return Int32(updateStatus)
}

/// Delete the VPN password for `profile_id` from the shared Keychain.
///
/// Absent items return 0 (already gone is success).
@_cdecl("hpn_keychain_delete_password")
public func hpnKeychainDeletePassword(
    _ profileIdPtr: UnsafePointer<CChar>?,
    _ profileIdLen: Int
) -> Int32 {
    guard let profileIdPtr, profileIdLen > 0, profileIdLen <= maxProfileIdBytes else {
        return -1
    }
    let profileIdData = Data(bytes: profileIdPtr, count: profileIdLen)
    guard let profileId = String(data: profileIdData, encoding: .utf8),
          !profileId.isEmpty else {
        return -1
    }
    let service = keychainServiceFor(profileId: profileId)
    let query = keychainBaseQuery(service: service, account: keychainAccountPassword)
    let status = SecItemDelete(query as CFDictionary)
    if status == errSecSuccess || status == errSecItemNotFound {
        return 0
    }
    return Int32(status)
}

/// Delete every Keychain item owned by the app's access group.
///
/// Used defensively on startup after a crash and on full disconnect to
/// ensure no stale credentials remain.
@_cdecl("hpn_keychain_purge_all")
public func hpnKeychainPurgeAll() -> Int32 {
    let query: [String: Any] = [
        kSecClass as String: kSecClassGenericPassword,
        kSecAttrAccessGroup as String: keychainAccessGroup,
        kSecUseDataProtectionKeychain as String: true,
    ]
    let status = SecItemDelete(query as CFDictionary)
    if status == errSecSuccess || status == errSecItemNotFound {
        return 0
    }
    return Int32(status)
}

/// Ensure the rekey-signal HMAC key exists, creating it with 32 random bytes
/// from `SecRandomCopyBytes` on first call. Idempotent.
@_cdecl("hpn_keychain_ensure_rekey_hmac_key")
public func hpnKeychainEnsureRekeyHmacKey() -> Int32 {
    let probeQuery: [String: Any] = keychainBaseQuery(
        service: keychainHmacService,
        account: keychainAccountKey
    ).merging([
        kSecReturnData as String: kCFBooleanFalse as Any,
        kSecMatchLimit as String: kSecMatchLimitOne,
    ]) { _, new in new }
    let probeStatus = SecItemCopyMatching(probeQuery as CFDictionary, nil)
    if probeStatus == errSecSuccess { return 0 }
    if probeStatus != errSecItemNotFound { return Int32(probeStatus) }

    var keyBytes = Data(count: 32)
    let rngStatus = keyBytes.withUnsafeMutableBytes { (buf: UnsafeMutableRawBufferPointer) -> OSStatus in
        guard let base = buf.baseAddress else { return errSecParam }
        return SecRandomCopyBytes(kSecRandomDefault, 32, base)
    }
    if rngStatus != errSecSuccess { return Int32(rngStatus) }

    var addAttrs = keychainBaseQuery(
        service: keychainHmacService,
        account: keychainAccountKey
    )
    addAttrs[kSecValueData as String] = keyBytes
    addAttrs[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
    let addStatus = SecItemAdd(addAttrs as CFDictionary, nil)
    if addStatus == errSecSuccess || addStatus == errSecDuplicateItem {
        return 0
    }
    return Int32(addStatus)
}

/// Read the rekey HMAC key into a caller-supplied buffer.
///
/// Returns the number of bytes written on success (>0), 0 if the item
/// doesn't exist or the buffer is too small, negative for argument errors.
@_cdecl("hpn_keychain_get_rekey_hmac_key")
public func hpnKeychainGetRekeyHmacKey(
    _ outBuf: UnsafeMutablePointer<UInt8>?,
    _ outBufLen: Int
) -> Int32 {
    // The rekey HMAC key is exactly 32 bytes (see
    // `hpn_keychain_ensure_rekey_hmac_key`). 4 KiB is several orders
    // of magnitude above any legitimate caller — any larger value is
    // a hostile or buggy caller, refuse it before we touch
    // `memcpy`. Audit H13 (FFI bounds).
    guard let outBuf, outBufLen > 0, outBufLen <= 4096 else { return -1 }
    var query = keychainBaseQuery(service: keychainHmacService, account: keychainAccountKey)
    query[kSecReturnData as String] = kCFBooleanTrue as Any
    query[kSecMatchLimit as String] = kSecMatchLimitOne
    var item: CFTypeRef?
    let status = SecItemCopyMatching(query as CFDictionary, &item)
    guard status == errSecSuccess, let data = item as? Data else { return 0 }
    if data.count > outBufLen { return 0 }
    data.withUnsafeBytes { src in
        if let base = src.baseAddress {
            memcpy(outBuf, base, data.count)
        }
    }
    return Int32(data.count)
}

/// Maximum size of the provider-config JSON we will accept across the
/// FFI boundary. The legitimate payload is a few hundred bytes (client
/// config + endpoint + flags + optional `keychain_profile_id`). 1 MiB
/// is several orders of magnitude above that ceiling so we reject any
/// caller that asks us to allocate more — both as a defence against a
/// malformed Rust call (`config_len = Int.max`) and as a sanity check
/// against an OOM-DoS path. Audit H13 (FFI bounds).
private let maxProviderConfigBytes = 1_048_576

/// Stashed provider-config bytes from the most recent
/// `hpn_vpn_manager_save_config` call. Read back by
/// `hpn_vpn_manager_install_and_start` to populate
/// `NETunnelProviderProtocol.providerConfiguration` — the
/// Apple-recommended IPC channel between a host app and a Packet
/// Tunnel SYSTEM EXTENSION (as opposed to the legacy `.appex`
/// in-session App Extension model).
///
/// CRITICAL: file-based IPC via the App Group container
/// (`FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`)
/// DOES NOT WORK reliably for `.systemextension` providers on
/// macOS Tahoe. Empirically (May 2026 field investigation):
///   1. The host app runs in the user's session (uid 501, admin).
///      `containerURL` returns
///      `/Users/admin/Library/Group Containers/group.io.hpn.vpn/`.
///   2. The system extension is launched as a daemon by sysextd
///      (uid 0, root). Even with the matching `application-groups`
///      entitlement, `containerURL` returns either nil or a path
///      under `/var/root/Library/...` that does NOT exist and is
///      not the one the host writes to.
///   3. As a result, file-based handoff produces a "Provider
///      config not found" failure on every connect attempt, with
///      no visible error path: the file exists on disk in the
///      user's container, the extension sees its own (different)
///      container empty, the host's clear_provider_config() then
///      wipes the host-side file ~1.5 s later when the connect
///      times out.
///
/// `protocolConfiguration.providerConfiguration` (an NSDictionary
/// of plist-codable types) bypasses the filesystem entirely. Apple
/// delivers it through the same XPC channel that wires the
/// extension's startTunnel callback, so it is guaranteed to reach
/// the extension regardless of user-context divergence. This is
/// the pattern used by Radio Silence, Little Snitch, NextDNS, and
/// every other shipping Developer-ID Network Extension on Tahoe.
///
/// The file-based path is intentionally removed: the provider config can
/// contain credentials, and duplicating it into App Group / Application
/// Support files widens the forensic and backup surface. The authoritative
/// handoff is the `providerConfiguration` dict assembled in
/// `hpn_vpn_manager_install_and_start`.
private var pendingProviderConfig: Data?
private let pendingProviderConfigLock = NSLock()

private func setPendingProviderConfig(_ data: Data?) {
    pendingProviderConfigLock.lock()
    pendingProviderConfig = data
    pendingProviderConfigLock.unlock()
}

private func takePendingProviderConfig() -> Data? {
    pendingProviderConfigLock.lock()
    defer { pendingProviderConfigLock.unlock() }
    let result = pendingProviderConfig
    pendingProviderConfig = nil
    return result
}

private func removeLegacyProviderConfigFiles() {
    if let containerURL = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupId) {
        try? FileManager.default.removeItem(at: containerURL.appendingPathComponent("provider-config.json"))
    }
    if let appSupport = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first {
        try? FileManager.default.removeItem(
            at: appSupport.appendingPathComponent("hpn-vpn", isDirectory: true)
                .appendingPathComponent("provider-config.json")
        )
    }
}

@_cdecl("hpn_vpn_manager_save_config")
public func hpnVpnManagerSaveConfig(_ configJson: UnsafePointer<CChar>?, _ configLen: Int) -> Int32 {
    // Validate the length BEFORE constructing `Data`. `Data(bytes:count:)`
    // would otherwise allocate up to `Int.max` bytes on a hostile caller
    // (Rust side validation is the front line, but we should not trust
    // the FFI boundary either). Reject:
    //   - null pointer
    //   - zero / negative length
    //   - length > 1 MiB (clearly not a real provider config)
    guard let configJson else { return -1 }
    guard configLen > 0 && configLen <= maxProviderConfigBytes else { return -1 }
    let data = Data(bytes: configJson, count: configLen)

    // Primary handoff: stash for the next `install_and_start` call so
    // it can populate `proto.providerConfiguration`. This is the path
    // the extension actually reads from on Tahoe Developer ID builds.
    setPendingProviderConfig(data)
    removeLegacyProviderConfigFiles()
    NSLog("HPN: provider config stashed for providerConfiguration IPC (%d bytes raw JSON)", data.count)
    return 0
}

@_cdecl("hpn_vpn_manager_clear_provider_config")
public func hpnVpnManagerClearProviderConfig() -> Int32 {
    setPendingProviderConfig(nil)
    removeLegacyProviderConfigFiles()

    let semaphore = DispatchSemaphore(value: 0)
    var resultCode: Int32 = -32

    bgQueue.async {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error {
                NSLog("HPN: provider config clear loadAll failed: %@", error.localizedDescription)
                resultCode = -30; semaphore.signal(); return
            }
            guard let manager = managers?.first,
                  let proto = manager.protocolConfiguration as? NETunnelProviderProtocol else {
                resultCode = 0; semaphore.signal(); return
            }

            proto.providerConfiguration = [:]
            manager.protocolConfiguration = proto
            manager.saveToPreferences { error in
                if let error {
                    NSLog("HPN: provider config clear save failed: %@", error.localizedDescription)
                    resultCode = -31
                } else {
                    resultCode = 0
                }
                semaphore.signal()
            }
        }
    }

    if semaphore.wait(timeout: .now() + 10) == .timedOut {
        return -32
    }
    return resultCode
}

/// Install + start the VPN profile through `NETunnelProviderManager`.
///
/// Parameters:
/// - `fullTunnel`: `1` to route every destination through the VPN
///   (the default). `0` means the caller configured split-tunnel, in
///   which case `includeAllNetworks` is explicitly DISABLED — otherwise
///   Apple's flag would override the split routing and silently force
///   everything through the tunnel anyway.
/// - `allowLan`: `1` to keep local-network addresses reachable while
///   the VPN is up. Mirrors the profile's `allow_lan` flag so the
///   network-extension-level kill switch and the in-extension
///   `buildNetworkSettings` agree.
///
/// Return codes:
///   0   success
///  -10  loadAll failed
///  -11  save failed (usually user denied the permission prompt)
///  -12  reload-after-save failed
///  -13  startVPNTunnel failed
///  -14  host macOS too old (< 14.0) for the kill switch flags — caller
///       should surface a clear error instead of silently running
///       without network extension kill switch
@_cdecl("hpn_vpn_manager_install_and_start")
public func hpnVpnManagerInstallAndStart(_ fullTunnel: Int32, _ allowLan: Int32) -> Int32 {
    // Apple's `includeAllNetworks` / `excludeLocalNetworks` properties
    // require macOS 14. On older hosts we have NO fallback inside this
    // binary (the legacy PF-based path is dead code). Rather than ship
    // an appli-cation that claims to have a kill switch and quietly
    // delivers none, refuse to start — the caller gets -14 and surfaces
    // it in the UI.
    guard #available(macOS 14.0, *) else {
        NSLog("HPN: macOS 14 required for network-extension kill switch; refusing to start")
        return -14
    }

    // Make sure the Packet Tunnel System Extension is activated
    // BEFORE asking NETunnelProviderManager to start the tunnel.
    // Without this, `startVPNTunnel` fails with NEVPNErrorConfigurationInvalid
    // because the extension bundle ID does not resolve to a registered
    // provider. Idempotent: returns 0 immediately if the user already
    // approved on a previous launch.
    let sysextResult = ensureSystemExtensionActivated()
    if sysextResult != 0 {
        NSLog("HPN: System Extension activation failed (code %d); aborting connect", sysextResult)
        return sysextResult
    }

    let semaphore = DispatchSemaphore(value: 0)
    var resultCode: Int32 = -1

    bgQueue.async {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if let error {
                NSLog("HPN: loadAll failed: %@", error.localizedDescription)
                resultCode = -10; semaphore.signal(); return
            }
            let manager = managers?.first ?? NETunnelProviderManager()
            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = extensionBundleId
            proto.serverAddress = "HPN VPN"
            // Authoritative provider-config handoff. See the
            // `pendingProviderConfig` doc comment above for why
            // `protocolConfiguration.providerConfiguration` is the
            // ONLY reliable cross-context IPC for Tahoe Developer-ID
            // System Extensions.
            //
            // Key naming: `config_json_v1` carries RAW JSON (not the
            // audit-H15 HMAC envelope). Rationale documented in
            // `native_vpn.rs::save_provider_config`: the envelope was
            // designed for the legacy file-based handoff and is not
            // verifiable on the providerConfiguration channel because
            // the extension running as root cannot share a Keychain
            // entry with the host running as the user. The XPC
            // channel itself is the trust boundary.
            //
            // The `_v1` suffix lets the extension version-gate the
            // payload format if/when we change the schema (e.g. add
            // a future structured-credentials envelope that does NOT
            // require shared Keychain access).
            if let configBytes = takePendingProviderConfig() {
                proto.providerConfiguration = ["config_json_v1": configBytes]
                NSLog("HPN: passing provider config via NETunnelProviderProtocol.providerConfiguration (%d bytes raw JSON)", configBytes.count)
            } else {
                // Should never happen — the React UI ALWAYS calls
                // `save_provider_config` immediately before the
                // connect command's tail invokes install_and_start.
                // If we reach here, the connect flow skipped the
                // save (bug) or save failed silently. Return a
                // distinct error code so the UI can surface
                // "configuration was not saved before connect" instead
                // of a generic "VPN start failed".
                NSLog("HPN: ERROR — pendingProviderConfig is nil at install_and_start time. Refusing to start tunnel.")
                proto.providerConfiguration = [:]
                resultCode = -18; semaphore.signal(); return
            }

            // ALL `proto` PROPERTIES MUST BE SET BEFORE
            // `manager.protocolConfiguration = proto` BELOW.
            //
            // Routing-policy flags (LEAK-FIX May 2026 — two-iteration
            // history below; OPERATIONS.md "Split-tunnel kill switch
            // contract" carries the user-facing version).
            //
            // FINAL contract (this iteration, after Apple-Forum-750173
            // regression):
            //
            //   ALWAYS:
            //     proto.includeAllNetworks   = true
            //     proto.enforceRoutes        = false   (Apple ignores it
            //                                          when includeAllNetworks
            //                                          is true)
            //     proto.excludeLocalNetworks = (allow_lan != 0)
            //
            // Apple's documented split-tunnel-with-kill-switch pattern,
            // used by Mullvad and Tailscale in their lockdown modes.
            // Reference: "Routing your VPN network traffic", the
            // "Exclude Specific Traffic from VPN" section, which
            // explicitly shows includeAllNetworks=true combined with
            // excludeLocalNetworks=true and per-protocol excludes.
            //
            // Why NOT the includeAllNetworks=false + enforceRoutes=true
            // route from the previous iteration (b3911e7):
            //
            //   * enforceRoutes=true "supersedes the system routing
            //     table and scoping operations by apps". That guarantee
            //     is what we wanted as the bypass-mode kill switch.
            //   * BUT in practice it superseded the kernel's implicit
            //     /N interface route for the TUN's own subnet too.
            //     With server default pool 10.99.0.0/24 and the RFC1918
            //     LAN-bypass exclude 10.0.0.0/8 both in scope, the /8
            //     blackholed the tunnel gateway. Symptom: rx=0,
            //     curl ifconfig.me → ISP public IP.
            //   * Mitigation in 86bbc36 added the tunnel /24 to
            //     `includedRoutes` as a longest-prefix-match anchor.
            //     This triggered an UNRELATED Apple bug documented in
            //     Developer Forum thread 750173: when includedRoutes
            //     contains the default route AND a more-specific
            //     overlapping route, packetFlow.readPackets stops
            //     firing entirely — apps' packets are silently dropped
            //     before the extension can see them. The DTS engineer
            //     in that thread never refuted the repro; the bug is
            //     real and a year old as of this iteration.
            //
            // Switching to includeAllNetworks=true sidesteps both
            // issues at once:
            //
            //   - The strict-enforce-with-overlap bug doesn't apply
            //     because enforceRoutes=true is no longer set.
            //   - The LAN supernet exclude is still honoured (Apple
            //     docs: "excludedRoutes is the IPv4 network traffic
            //     that the system routes to the primary physical
            //     interface, not the TUN interface", and is honoured
            //     regardless of includeAllNetworks).
            //   - The TUN's own /N interface route is auto-installed
            //     and is NOT overridden by excludedRoutes any more,
            //     because the system uses standard kernel longest-
            //     prefix-match instead of the strict-supersede scope.
            //   - We additionally drop any RFC1918 exclude entry that
            //     covers the tunnel CIDR (see PacketTunnelProvider
            //     .swift::localIPv4Routes(skippingCoversOf:)), so even
            //     if Apple's behaviour drifts the tunnel cannot be
            //     blackholed.
            //
            // Tradeoff: includeAllNetworks=true also pulls "designated
            // system services" (DHCP, captive portal, mDNS, Apple
            // Watch companion, VoLTE) through the tunnel scope. For a
            // privacy VPN that is the correct fail-closed posture.
            //
            // excludeLocalNetworks semantics (Apple docs):
            //   "A Boolean value that indicates whether the system
            //    excludes all traffic destined for local networks
            //    from the tunnel."
            //   true  → LAN traffic BYPASSES the tunnel (physical)
            //   false → LAN traffic stays IN the tunnel
            //
            // The very first iteration of this file inverted that
            // mapping (`allowLan == 0`); the second iteration
            // (b3911e7) flipped it to the documented form (`allowLan
            // != 0`); this iteration keeps that correction.
            //
            // `fullTunnel` is no longer materially different from
            // `bypass` at this layer: both modes use the same flags
            // here, and the actual route lists (which destinations
            // tunnel vs. bypass) are decided in
            // PacketTunnelProvider.swift::buildNetworkSettings via
            // NEIPv{4,6}Settings.{included,excluded}Routes. The
            // parameter is preserved in the FFI so the Tauri side
            // can still distinguish for telemetry / future logic.
            _ = (fullTunnel != 0) // kept for FFI parity; currently unused at this layer
            proto.includeAllNetworks = true
            proto.enforceRoutes = false
            proto.excludeLocalNetworks = (allowLan != 0)

            // NEVPNProtocol adopts NSCopying. Apple's NEVPNManager
            // .protocolConfiguration setter takes a COPY of the
            // protocol object at assignment time — verified against
            // the WireGuard-Apple, Mullvad, and Apple-sample-code
            // canonical patterns, all of which set every property on
            // the protocol BEFORE assigning to manager. The previous
            // ordering in this file set
            //   manager.protocolConfiguration = proto       (line A)
            //   proto.includeAllNetworks = true             (line B)
            //   manager.saveToPreferences { ... }           (line C)
            // and line B's mutation was silently discarded — line A's
            // copy was already frozen, and line C serialised the
            // frozen copy to /Library/Preferences/com.apple
            // .networkextension.plist. End-user symptom: the plist
            // kept the values from the very first ever connect
            // (iteration-1 defaults, all three flags false) and every
            // subsequent VPNManager.swift change appeared inert at
            // the OS layer. Fix: assign AFTER all properties are set.
            // Field-tester repro is documented in the chat log for
            // this commit.
            manager.protocolConfiguration = proto
            manager.localizedDescription = "HPN VPN"
            manager.isEnabled = true

            manager.saveToPreferences { error in
                if let error {
                    NSLog("HPN: save failed: %@", error.localizedDescription)
                    resultCode = -11; semaphore.signal(); return
                }
                manager.loadFromPreferences { error in
                    if let error {
                        NSLog("HPN: reload failed: %@", error.localizedDescription)
                        resultCode = -12; semaphore.signal(); return
                    }
                    do {
                        try manager.connection.startVPNTunnel()
                        resultCode = 0
                    } catch {
                        NSLog("HPN: start failed: %@", error.localizedDescription)
                        resultCode = -13
                    }
                    semaphore.signal()
                }
            }
        }
    }

    _ = semaphore.wait(timeout: .now() + 10)
    return resultCode
}

@_cdecl("hpn_vpn_manager_stop")
public func hpnVpnManagerStop() -> Int32 {
    let semaphore = DispatchSemaphore(value: 0)
    var resultCode: Int32 = -1

    bgQueue.async {
        NETunnelProviderManager.loadAllFromPreferences { managers, _ in
            guard let manager = managers?.first else { resultCode = -20; semaphore.signal(); return }
            manager.connection.stopVPNTunnel()
            resultCode = 0; semaphore.signal()
        }
    }

    _ = semaphore.wait(timeout: .now() + 10)
    return resultCode
}

@_cdecl("hpn_vpn_manager_get_status")
public func hpnVpnManagerGetStatus() -> Int32 {
    let semaphore = DispatchSemaphore(value: 0)
    var resultCode: Int32 = -1

    bgQueue.async {
        NETunnelProviderManager.loadAllFromPreferences { managers, _ in
            guard let manager = managers?.first else { resultCode = -1; semaphore.signal(); return }
            switch manager.connection.status {
            case .invalid:       resultCode = -1
            case .disconnected:  resultCode = 0
            case .connecting:    resultCode = 1
            case .connected:     resultCode = 2
            case .disconnecting: resultCode = 3
            case .reasserting:   resultCode = 4
            @unknown default:    resultCode = -1
            }
            semaphore.signal()
        }
    }

    _ = semaphore.wait(timeout: .now() + 5)
    return resultCode
}

/// Retrieve the latest tunnel stats from the running Packet Tunnel
/// extension via `NETunnelProviderSession.sendProviderMessage`.
///
/// Why XPC instead of a file on disk:
///   The extension runs as root and its
///   `FileManager.containerURL(forSecurityApplicationGroupIdentifier:)`
///   resolves under `/var/root/Library/...` (root's home), while the
///   host's resolves under `/Users/<admin>/Library/...` (the user's
///   home). The two paths don't intersect, so a file-based hand-off
///   from extension to host fails silently in both directions on
///   Tahoe Developer ID. Same root cause as the provider-config IPC
///   bug we fixed for the host→extension direction; this is the
///   reverse direction, fixed the same way.
///
/// Wire format: extension's `handleAppMessage` receives
/// `{"cmd":"stats"}` and replies with the raw stats JSON the Rust
/// engine produces (tx, rx, rtt_us, session_key). 4 KiB is well above
/// the typical 200-300 byte payload but small enough that a hostile
/// or buggy extension cannot trick us into a multi-MiB allocation.
///
/// Return semantics:
///   > 0  : number of bytes written to outBuf
///   = 0  : extension responded with no data (yet) — caller should
///          try again later
///   -1   : argument validation failed (null buffer, bad length)
///   -2   : no NETunnelProviderManager / no session (tunnel not running)
///   -3   : sendProviderMessage threw (extension stuck, etc.)
///   -4   : 2-second timeout waiting for response (extension hung;
///          the React UI polls every ~1 s so a stuck extension would
///          otherwise queue requests indefinitely)
/// Heap-allocated container for the async stats result.
///
/// CRITICAL: `hpn_vpn_manager_get_stats` is a synchronous FFI that
/// internally dispatches an asynchronous XPC roundtrip to the
/// extension and waits on a 250 ms timeout. When the timeout fires
/// we MUST be able to return immediately from the FFI without ever
/// touching the caller's `outBuf` again — because the caller (Rust)
/// will drop the `Vec<u8>` whose data pointer was passed in `outBuf`
/// the moment the FFI returns, and any later write to that pointer
/// is a use-after-free that crashes the host process with
/// `BUG IN CLIENT OF LIBMALLOC: memory corruption of free block`
/// the next time the offending workqueue thread exits and tries to
/// touch its autorelease pool.
///
/// Fix: the dispatch closure ONLY mutates this Box (a reference
/// type, retained by ARC for as long as the closure is alive) and
/// signals the semaphore. The FFI body does the `memcpy(outBuf, …)`
/// SYNCHRONOUSLY after `semaphore.wait` succeeds — i.e. only when
/// we know the closure has finished. On timeout we return `-4`
/// without ever touching `outBuf`, and the still-running closure
/// can write to its Box safely (the Box is heap-allocated and
/// retained by the closure itself; nothing else cares).
private final class StatsResult {
    var data: Data?
    /// Set by the failure-path branches (loadAll error,
    /// no-manager, sendProviderMessage threw). 0 means "OK, see
    /// `data` for payload (which may itself be nil = no response)".
    var ffiCode: Int32 = 0
}

@_cdecl("hpn_vpn_manager_get_stats")
public func hpnVpnManagerGetStats(_ outBuf: UnsafeMutablePointer<UInt8>?, _ outBufLen: Int) -> Int32 {
    guard let outBuf, outBufLen > 0, outBufLen <= 4096 else { return -1 }

    let semaphore = DispatchSemaphore(value: 0)
    let result = StatsResult()

    bgQueue.async {
        NETunnelProviderManager.loadAllFromPreferences { managers, error in
            if error != nil {
                result.ffiCode = -2; semaphore.signal(); return
            }
            guard let manager = managers?.first,
                  let session = manager.connection as? NETunnelProviderSession else {
                result.ffiCode = -2; semaphore.signal(); return
            }

            let message = Data("{\"cmd\":\"stats\"}".utf8)
            do {
                try session.sendProviderMessage(message) { responseData in
                    // ARC-safe: the closure captures `result` and
                    // `semaphore` (both reference types). NEITHER
                    // `outBuf` nor any caller-side stack object is
                    // touched here. If the parent FFI has already
                    // returned via timeout, this branch still runs
                    // safely — `result` remains alive because the
                    // closure retains it.
                    result.data = responseData
                    semaphore.signal()
                }
            } catch {
                result.ffiCode = -3
                semaphore.signal()
            }
        }
    }

    // 1 s ceiling. The previous 250 ms was tuned for a world where
    // this FFI ran on the React-facing Tauri command thread, where
    // any longer wait would freeze the UI. As of build 9 (May
    // 2026) we run the FFI from a DEDICATED background thread
    // (`main.rs::setup` spawns `hpn-stats-poller`) and the React
    // UI reads from a process-wide cache via
    // `native_vpn::read_stats_cache`. Blocking the poller thread
    // for up to 1 s every second is fine — it bounds the FFI call
    // rate to 1 Hz and gives `loadAllFromPreferences` (which can
    // take 100-300 ms on Tahoe under load) plenty of headroom.
    //
    // Don't go above 1 s without rethinking the poller's loop
    // cadence; the current `sleep(1s)` between calls assumes the
    // FFI completes in less than 1 s.
    if semaphore.wait(timeout: .now() + 1.0) == .timedOut {
        return -4
    }

    // Closure has signalled; SYNCHRONOUS copy into outBuf is safe
    // because we still own the Rust-side buffer (the Rust caller
    // hasn't returned yet — it's inside this FFI call).
    if result.ffiCode != 0 {
        return result.ffiCode
    }
    guard let data = result.data, !data.isEmpty else {
        return 0
    }
    let copyLen = min(data.count, outBufLen)
    data.withUnsafeBytes { srcBuf in
        if let src = srcBuf.baseAddress {
            memcpy(outBuf, src, copyLen)
        }
    }
    return Int32(copyLen)
}

@_cdecl("hpn_vpn_manager_force_rekey")
public func hpnVpnManagerForceRekey() -> Int32 {
    let semaphore = DispatchSemaphore(value: 0)
    var resultCode: Int32 = -1

    bgQueue.async {
        NETunnelProviderManager.loadAllFromPreferences { managers, _ in
            guard let manager = managers?.first,
                  let session = manager.connection as? NETunnelProviderSession else {
                resultCode = -20; semaphore.signal(); return
            }

            let message = Data("{\"cmd\":\"rekey\"}".utf8)
            do {
                try session.sendProviderMessage(message) { _ in
                    resultCode = 0
                    semaphore.signal()
                }
            } catch {
                NSLog("HPN: sendProviderMessage failed: %@", error.localizedDescription)
                resultCode = -21
                semaphore.signal()
            }
        }
    }

    _ = semaphore.wait(timeout: .now() + 10)
    return resultCode
}
