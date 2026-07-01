#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Fuzz the control message parser
    // Control messages handle session management (close, rebind, error)
    let _ = hpn_core::protocol::ControlMessage::from_bytes(data);
});
