#![no_main]
//! Fuzz the LUKS1 partition-header parser over arbitrary bytes.
//! Invariant: `Luks1Header::parse` must never panic on any input.

use libfuzzer_sys::fuzz_target;
use luks::Luks1Header;

fuzz_target!(|data: &[u8]| {
    if let Ok(hdr) = Luks1Header::parse(data) {
        let _ = hdr.active_keyslots().count();
        let _ = hdr.payload_byte_offset();
        for slot in &hdr.keyslots {
            let _ = slot.is_active();
            let _ = slot.is_disabled();
        }
    }
});
