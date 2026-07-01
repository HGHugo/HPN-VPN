#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the RekeyMessage decoder
    // This parses rekey requests which contain public keys (untrusted input)
    let _ = hpn_core::protocol::RekeyMessage::from_bytes(data);
});
