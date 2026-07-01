// HPN VPN — Packet Tunnel System Extension entry point.
//
// System Extensions on macOS are full executables (not App Extension
// bundles), so the linker requires a `main()` symbol. The Apple
// pattern for a Network Extension System Extension is to call
// `NEProvider.startSystemExtensionMode()` from `main`, which boots
// the XPC service the NEAgent (in the user's session) connects to
// when `NETunnelProviderManager.startVPNTunnel()` is invoked.
//
// `dispatchMain()` then parks the process indefinitely on the main
// queue, which is required because `startSystemExtensionMode()` only
// installs the XPC handler — without a runloop the process exits and
// macOS reports the extension as crashed.
//
// The actual VPN logic lives in `PacketTunnelProvider.swift`. macOS
// instantiates the principal class declared in `Info.plist`'s
// `NSExtension.NSExtensionPrincipalClass` (`PacketTunnelProvider`)
// for each tunnel session.

import Foundation
import NetworkExtension
import os.log

private let bootLogger = Logger(
    subsystem: "io.hpn.vpn.macos.packet-tunnel",
    category: "boot"
)

bootLogger.info("Packet Tunnel System Extension boot — starting NEProvider XPC service")

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

// Park on the main queue. Without this, the process exits as soon as
// `startSystemExtensionMode()` returns, and macOS reports
// OSSystemExtensionErrorExtensionTerminated to the host app's
// `requestNeedsUserApproval` callback, which the user sees as
// "system extension stopped working".
dispatchMain()
