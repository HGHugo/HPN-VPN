#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the RekeyResponse decoder
    // This parses rekey responses with ciphertexts and signatures (untrusted input)
    let _ = hpn_core::protocol::RekeyResponse::from_bytes(data);
});
