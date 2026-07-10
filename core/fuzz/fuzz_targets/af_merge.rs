#![no_main]
//! Fuzz the anti-forensic (AF) merge over arbitrary key material.
//! Invariant: `af::merge` must never panic — a `block_size`/`stripes` that
//! overrun the supplied material must be handled by the bounds-checked `.get()`
//! reads, never by an out-of-bounds slice.
//!
//! `block_size` and `stripes` are drawn from the first bytes and bounded small so
//! the fuzzer explores the merge logic (diffuse, XOR-fold, short final chunk)
//! quickly instead of grinding a huge O(stripes) hash loop.

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.len() < 3 {
        return;
    }
    let hash_spec = match data[0] % 4 {
        0 => "sha1",
        1 => "sha256",
        2 => "sha512",
        _ => "unsupported-hash",
    };
    let block_size = usize::from(data[1]); // 0..=255
    let stripes = usize::from(data[2]); // 0..=255
    let material = &data[3..];
    let _ = luks::af_merge(hash_spec, material, block_size, stripes);
});
