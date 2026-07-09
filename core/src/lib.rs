//! # luks-core — pure-Rust LUKS reader and decryptor
//!
//! Parse a LUKS container's on-disk header, recover the master key from a
//! passphrase, and decrypt the payload. Panic-free and `forbid(unsafe)`: every
//! integer is read bounds-checked, every crypto primitive is an audited
//! RustCrypto crate.
//!
//! ```no_run
//! use std::fs::File;
//! let mut vol = luks::LuksVolume::unlock1_with_passphrase(
//!     File::open("container.luks")?,
//!     b"passphrase",
//! )?;
//! let mut first = [0u8; 512];
//! vol.read_at(0, &mut first)?;
//! # Ok::<(), Box<dyn std::error::Error>>(())
//! ```
//!
//! Correctness is validated against `cryptsetup` on real containers (Tier-2);
//! see `docs/validation.md`.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

mod af;
mod bytes;
mod crypto;
mod error;
mod header;
mod volume;

pub use error::{LuksError, Result};
pub use header::{Keyslot, Luks1Header};
pub use volume::{DecryptedPayload, LuksVolume};
