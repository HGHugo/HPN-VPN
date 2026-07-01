#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the handshake response message parser
    // This parses server responses received by clients
    let _ = hpn_core::protocol::HandshakeResponse::from_bytes(data);
});
