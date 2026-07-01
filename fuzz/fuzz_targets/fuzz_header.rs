#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the packet header decoder
    // This is a critical parsing function that handles untrusted network input
    let _ = hpn_core::protocol::PacketHeader::decode(data);
});
