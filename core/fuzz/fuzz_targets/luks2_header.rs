#![no_main]
//! Fuzz the LUKS2 binary-header + JSON-metadata parser over arbitrary bytes.
//! Invariant: `Luks2Header::parse` must never panic — a crafted `hdr_size`,
//! truncated JSON area, or malformed keyslot/segment/digest must yield an error,
//! never a crash.

use libfuzzer_sys::fuzz_target;
use luks::Luks2Header;

fuzz_target!(|data: &[u8]| {
    if let Ok(hdr) = Luks2Header::parse(data) {
        let _ = hdr.crypt_segment();
    }
});
