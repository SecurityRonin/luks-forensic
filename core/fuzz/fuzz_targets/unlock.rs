#![no_main]
//! Fuzz the full unlock pipeline (`LuksVolume::unlock_with_passphrase`) over
//! arbitrary bytes with a fixed passphrase. Invariant: never panic. Almost every
//! input is rejected at header/version detection; the value is that any input
//! reaching the keyslot, AF-merge, and master-key-digest stages exits through a
//! typed error rather than a crash.

use libfuzzer_sys::fuzz_target;
use luks::LuksVolume;
use std::io::Cursor;

fuzz_target!(|data: &[u8]| {
    if let Ok(mut vol) = LuksVolume::unlock_with_passphrase(Cursor::new(data), b"luks-TEST") {
        let mut buf = [0u8; 512];
        let _ = vol.read_at(0, &mut buf);
    }
});
