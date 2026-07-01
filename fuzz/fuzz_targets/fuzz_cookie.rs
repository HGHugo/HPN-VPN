#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the CookieRequest and CookieReply decoders
    // These parse anti-DoS challenge/response messages (untrusted input)
    let _ = hpn_core::protocol::CookieRequest::from_bytes(data);
    let _ = hpn_core::protocol::CookieReply::from_bytes(data);
});
