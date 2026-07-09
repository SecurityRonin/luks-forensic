//! Error type for LUKS parsing and unlocking.

use std::io;

/// Result alias for `luks-core`.
pub type Result<T> = std::result::Result<T, LuksError>;

/// A LUKS parse or unlock failure. Every variant names the offending value so an
/// investigator can act on it (never a bare "invalid").
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum LuksError {
    /// The `LUKS\xba\xbe` magic is absent — not a LUKS container.
    #[error("not a LUKS container: magic is {found:02x?}, expected 4c554b53babe")]
    NotLuks {
        /// The first six bytes actually found.
        found: [u8; 6],
    },

    /// The header version is neither 1 nor 2.
    #[error("unsupported LUKS version {version} (only 1 and 2 are supported)")]
    UnsupportedVersion {
        /// The version field value.
        version: u16,
    },

    /// The cipher/mode/hash combination has no validated decrypt path.
    #[error("unsupported {what}: {value:?}")]
    Unsupported {
        /// Which axis is unsupported (cipher, mode, hash).
        what: &'static str,
        /// The offending value verbatim.
        value: String,
    },

    /// The header is structurally malformed (a field runs past the buffer).
    #[error("malformed LUKS header: {what} (need {need} bytes, have {got})")]
    MalformedHeader {
        /// What was being read.
        what: &'static str,
        /// Bytes needed.
        need: usize,
        /// Bytes available.
        got: usize,
    },

    /// No keyslot could be unlocked with the supplied passphrase, or the derived
    /// master key failed the mk-digest check (wrong passphrase).
    #[error("authentication failed: no keyslot matched the passphrase")]
    AuthenticationFailed,

    /// The container carries no active (enabled) keyslot.
    #[error("no active keyslot in the LUKS header")]
    NoActiveKeyslot,

    /// An I/O error reading the container.
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
}
