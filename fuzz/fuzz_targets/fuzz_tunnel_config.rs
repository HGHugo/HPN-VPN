#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the TunnelConfig decoder
    // This parses network configuration from server responses (untrusted input)
    let _ = hpn_core::protocol::TunnelConfig::from_bytes(data);
});
