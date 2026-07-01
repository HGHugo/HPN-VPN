#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the handshake init message parser
    // This parses client-initiated handshake messages from untrusted sources
    let _ = hpn_core::protocol::HandshakeInit::from_bytes(data);
});
