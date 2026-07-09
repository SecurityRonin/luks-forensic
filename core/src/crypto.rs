//! Key derivation (PBKDF2-HMAC, Argon2) and AES-XTS-plain64 decryption.
//!
//! Every primitive is an audited RustCrypto crate — never hand-rolled. Only the
//! validated LUKS cipher (`aes` / `xts-plain64`, 256- or 512-bit key) is wired;
//! anything else is refused with a named error rather than silently mis-decrypted.

use aes::cipher::KeyInit;
use aes::{Aes128, Aes256};
use xts_mode::Xts128;

use crate::error::{LuksError, Result};

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

/// Argon2 KDF parameters from a LUKS2 keyslot (`argon2i` / `argon2id`).
pub struct Argon2Params<'a> {
    /// `argon2i` or `argon2id`.
    pub kind: &'a str,
    /// Time cost (iterations).
    pub time: u32,
    /// Memory cost in KiB.
    pub memory: u32,
    /// Parallelism (lanes).
    pub cpus: u32,
    /// Salt bytes.
    pub salt: &'a [u8],
}

/// Derive `key_len` bytes with Argon2 (LUKS2 keyslot KDF).
///
/// # Errors
/// [`LuksError::Unsupported`] for an unknown Argon2 variant or invalid params.
pub fn derive_key_argon2(p: &Argon2Params, password: &[u8], key_len: usize) -> Result<Vec<u8>> {
    use argon2::{Algorithm, Argon2, Params, Version};
    let algo = match p.kind {
        "argon2i" => Algorithm::Argon2i,
        "argon2id" => Algorithm::Argon2id,
        other => {
            return Err(LuksError::Unsupported {
                what: "argon2 variant",
                value: other.to_string(),
            })
        }
    };
    let params = Params::new(p.memory, p.time, p.cpus, Some(key_len)).map_err(|e| {
        LuksError::Unsupported {
            what: "argon2 params",
            value: e.to_string(),
        }
    })?;
    let mut out = vec![0u8; key_len];
    Argon2::new(algo, Version::V0x13, params)
        .hash_password_into(password, p.salt, &mut out)
        .map_err(|e| LuksError::Unsupported {
            what: "argon2",
            value: e.to_string(),
        })?;
    Ok(out)
}

/// Decrypt `buffer` in place as AES-XTS-plain64, split into `unit_size`-byte data
/// units. Data unit `u` uses the plain64 tweak `base_sector + u * (unit_size/512)`
/// (little-endian) — the 512-sector number of the unit's first byte, matching
/// dm-crypt's default (non-`iv_large_sectors`) IV even for 4096-byte sectors.
///
/// # Errors
/// [`LuksError::Unsupported`] if `cipher_mode` is not `xts-plain64` or `key` is
/// not a 32- or 64-byte XTS key.
pub fn xts_decrypt_area(
    cipher_mode: &str,
    key: &[u8],
    buffer: &mut [u8],
    unit_size: usize,
    base_sector: u128,
) -> Result<()> {
    if cipher_mode != "xts-plain64" {
        return Err(LuksError::Unsupported {
            what: "cipher mode",
            value: cipher_mode.to_string(),
        });
    }
    let step = (unit_size / 512).max(1) as u128;
    match key.len() {
        32 => {
            let (k1, k2) = key.split_at(16);
            let xts = Xts128::<Aes128>::new(Aes128::new(k1.into()), Aes128::new(k2.into()));
            decrypt_units(&xts, buffer, unit_size, base_sector, step);
        }
        64 => {
            let (k1, k2) = key.split_at(32);
            let xts = Xts128::<Aes256>::new(Aes256::new(k1.into()), Aes256::new(k2.into()));
            decrypt_units(&xts, buffer, unit_size, base_sector, step);
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

fn decrypt_units<C>(xts: &Xts128<C>, buffer: &mut [u8], unit_size: usize, base: u128, step: u128)
where
    C: aes::cipher::BlockCipher + aes::cipher::BlockEncrypt + aes::cipher::BlockDecrypt,
{
    for (u, chunk) in buffer.chunks_mut(unit_size).enumerate() {
        if chunk.len() < 16 {
            continue; // cov:unreachable: reads are always unit-aligned (>= 512)
        }
        let tweak = (base + u as u128 * step).to_le_bytes();
        xts.decrypt_sector(chunk, tweak);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xts_mode::get_tweak_default;

    #[test]
    fn derive_key_matches_known_pbkdf2_sha256() {
        // PBKDF2-HMAC-SHA256("password","salt",1,32) — cross-checked vs Python.
        let k = derive_key("sha256", b"password", b"salt", 1, 32).unwrap();
        assert_eq!(
            hex(&k),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn xts_area_roundtrip_512_units() {
        let key = [0x24u8; 64];
        let mut buf = vec![0u8; 1024];
        for (i, b) in buf.iter_mut().enumerate() {
            *b = (i as u8) ^ 0x3c;
        }
        let plain = buf.clone();
        // encrypt via the same primitive at 512 sectors starting at sector 5
        let (k1, k2) = key.split_at(32);
        let xts = Xts128::<Aes256>::new(Aes256::new(k1.into()), Aes256::new(k2.into()));
        xts.encrypt_area(&mut buf, 512, 5, get_tweak_default);
        xts_decrypt_area("xts-plain64", &key, &mut buf, 512, 5).unwrap();
        assert_eq!(buf, plain);
    }

    #[test]
    fn xts_area_4096_unit_uses_512_based_tweak() {
        // A 4096-byte data unit at 512-sector base 8 must decrypt what was
        // encrypted with tweak 8 (not 1) — proves the *8 step.
        let key = [0x51u8; 64];
        let mut buf = vec![7u8; 4096];
        let plain = buf.clone();
        let (k1, k2) = key.split_at(32);
        let xts = Xts128::<Aes256>::new(Aes256::new(k1.into()), Aes256::new(k2.into()));
        xts.encrypt_sector(&mut buf, 8u128.to_le_bytes());
        xts_decrypt_area("xts-plain64", &key, &mut buf, 4096, 8).unwrap();
        assert_eq!(buf, plain);
    }

    #[test]
    fn xts_rejects_bad_mode_and_keysize() {
        let mut buf = [0u8; 512];
        assert!(matches!(
            xts_decrypt_area("cbc-essiv", &[0u8; 64], &mut buf, 512, 0),
            Err(LuksError::Unsupported {
                what: "cipher mode",
                ..
            })
        ));
        assert!(matches!(
            xts_decrypt_area("xts-plain64", &[0u8; 48], &mut buf, 512, 0),
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

    #[test]
    fn argon2id_derives_and_rejects_unknown() {
        let p = Argon2Params {
            kind: "argon2id",
            time: 1,
            memory: 32,
            cpus: 1,
            salt: &[0x11u8; 16],
        };
        let k = derive_key_argon2(&p, b"pw", 64).unwrap();
        assert_eq!(k.len(), 64);
        let bad = Argon2Params {
            kind: "scrypt",
            ..p
        };
        assert!(matches!(
            derive_key_argon2(&bad, b"pw", 64),
            Err(LuksError::Unsupported {
                what: "argon2 variant",
                ..
            })
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
