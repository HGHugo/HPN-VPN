#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the KeepaliveMessage and KeepaliveReplyMessage decoders
    // These parse keepalive packets from the network (untrusted input)
    let _ = hpn_core::protocol::KeepaliveMessage::from_bytes(data);
    let _ = hpn_core::protocol::KeepaliveReplyMessage::from_bytes(data);
});
