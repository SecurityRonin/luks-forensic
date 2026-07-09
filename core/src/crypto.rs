//! Key derivation (PBKDF2-HMAC) and AES-XTS-plain64 sector decryption.
//!
//! Every primitive is an audited RustCrypto crate — never hand-rolled. Only the
//! validated LUKS cipher (`aes` / `xts-plain64`, 256- or 512-bit key) is wired;
//! anything else is refused with a named error rather than silently mis-decrypted.

use aes::cipher::KeyInit;
use aes::{Aes128, Aes256};
use xts_mode::{get_tweak_default, Xts128};

use crate::error::{LuksError, Result};

/// The LUKS encryption sector size (bytes).
const SECTOR_SIZE: usize = 512;

/// Derive `key_len` bytes with PBKDF2-HMAC-`hash_spec`.
///
/// # Errors
/// [`LuksError::Unsupported`] for a hash spec with no implementation.
pub fn derive_key(
    hash_spec: &str,
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    key_len: usize,
) -> Result<Vec<u8>> {
    let mut out = vec![0u8; key_len];
    let iters = iterations.max(1);
    match hash_spec {
        "sha1" => pbkdf2::pbkdf2_hmac::<sha1::Sha1>(password, salt, iters, &mut out),
        "sha256" => pbkdf2::pbkdf2_hmac::<sha2::Sha256>(password, salt, iters, &mut out),
        "sha512" => pbkdf2::pbkdf2_hmac::<sha2::Sha512>(password, salt, iters, &mut out),
        other => {
            return Err(LuksError::Unsupported {
                what: "hash",
                value: other.to_string(),
            })
        }
    }
    Ok(out)
}

/// Decrypt `buffer` in place as AES-XTS-plain64 512-byte sectors, keyed by `key`
/// (32 bytes → AES-128-XTS, 64 bytes → AES-256-XTS), with the XTS data-unit
/// tweak = `first_sector + sector_index` (little-endian, i.e. plain64).
///
/// # Errors
/// [`LuksError::Unsupported`] if `cipher_mode` is not `xts-plain64` or `key` is
/// not a 32- or 64-byte XTS key.
pub fn xts_decrypt(
    cipher_mode: &str,
    key: &[u8],
    buffer: &mut [u8],
    first_sector: u128,
) -> Result<()> {
    if cipher_mode != "xts-plain64" {
        return Err(LuksError::Unsupported {
            what: "cipher mode",
            value: cipher_mode.to_string(),
        });
    }
    match key.len() {
        32 => {
            let (k1, k2) = key.split_at(16);
            let xts = Xts128::<Aes128>::new(Aes128::new(k1.into()), Aes128::new(k2.into()));
            xts.decrypt_area(buffer, SECTOR_SIZE, first_sector, get_tweak_default);
        }
        64 => {
            let (k1, k2) = key.split_at(32);
            let xts = Xts128::<Aes256>::new(Aes256::new(k1.into()), Aes256::new(k2.into()));
            xts.decrypt_area(buffer, SECTOR_SIZE, first_sector, get_tweak_default);
        }
        n => {
            return Err(LuksError::Unsupported {
                what: "xts key size",
                value: format!("{n} bytes"),
            })
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn derive_key_matches_known_pbkdf2_sha256() {
        // RFC-style check via an independent value: PBKDF2-HMAC-SHA256("password",
        // "salt", 1, 32) — computed with Python hashlib.pbkdf2_hmac.
        let k = derive_key("sha256", b"password", b"salt", 1, 32).unwrap();
        assert_eq!(
            hex(&k),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn xts_roundtrip_256() {
        use aes::cipher::KeyInit;
        use xts_mode::Xts128;
        let key = [0x24u8; 64];
        let mut buf = vec![0u8; 1024];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x3c;
        }
        let plain = buf.clone();
        // encrypt with the same primitive, then decrypt via our function
        let (k1, k2) = key.split_at(32);
        let xts = Xts128::<Aes256>::new(Aes256::new(k1.into()), Aes256::new(k2.into()));
        xts.encrypt_area(&mut buf, 512, 5, get_tweak_default);
        xts_decrypt("xts-plain64", &key, &mut buf, 5).unwrap();
        assert_eq!(buf, plain);
    }

    #[test]
    fn xts_rejects_bad_mode_and_keysize() {
        let mut buf = [0u8; 512];
        assert!(matches!(
            xts_decrypt("cbc-essiv", &[0u8; 64], &mut buf, 0),
            Err(LuksError::Unsupported {
                what: "cipher mode",
                ..
            })
        ));
        assert!(matches!(
            xts_decrypt("xts-plain64", &[0u8; 48], &mut buf, 0),
            Err(LuksError::Unsupported {
                what: "xts key size",
                ..
            })
        ));
    }

    #[test]
    fn derive_key_rejects_unknown_hash() {
        assert!(matches!(
            derive_key("md5", b"x", b"y", 1, 16),
            Err(LuksError::Unsupported { what: "hash", .. })
        ));
    }

    fn hex(b: &[u8]) -> String {
        use std::fmt::Write;
        b.iter().fold(String::new(), |mut s, x| {
            let _ = write!(s, "{x:02x}");
            s
        })
    }
}
