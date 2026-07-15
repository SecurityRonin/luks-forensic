//! `forensic-vfs` [`CryptoLayer`] adapter for LUKS1 / LUKS2, behind the `vfs`
//! feature.
//!
//! Wraps an encrypted LUKS volume (a parent [`ImageSource`]) and, given a
//! passphrase, presents the **decrypted** payload as a [`DynSource`] a normal
//! filesystem mounts unchanged. The decryption is luks-core's own (audited
//! RustCrypto AES-XTS + PBKDF2/Argon2 key derivation); this module only wires the
//! contract.

use std::io::{Read, Seek};
use std::sync::{Arc, Mutex, PoisonError};

use forensic_vfs::adapters::SourceCursor;
use forensic_vfs::{
    Credential, CredentialSource, CryptoLayer, CryptoScheme, DynSource, ImageSource, VfsError,
    VfsResult,
};

use crate::{DecryptedPayload, LuksError, LuksVolume};

/// LUKS header magic (`"LUKS"` + `0xBABE`).
const LUKS_MAGIC: &[u8; 6] = b"LUKS\xba\xbe";

/// A LUKS-encrypted volume presented as a [`CryptoLayer`].
pub struct LuksLayer {
    encrypted: DynSource,
    len: u64,
    scheme: CryptoScheme,
}

impl LuksLayer {
    /// Wrap an encrypted LUKS volume (the ciphertext byte source), peeking the
    /// on-disk version to report `Luks1` vs `Luks2`.
    pub fn new(encrypted: DynSource) -> Self {
        let len = encrypted.len();
        // Version = big-endian u16 at offset 6, after the 6-byte magic.
        let mut hdr = [0u8; 8];
        let scheme = match encrypted.read_at(0, &mut hdr) {
            Ok(n)
                if n >= 8
                    && hdr.starts_with(LUKS_MAGIC)
                    && u16::from_be_bytes([hdr[6], hdr[7]]) == 1 =>
            {
                CryptoScheme::Luks1
            }
            _ => CryptoScheme::Luks2,
        };
        Self {
            encrypted,
            len,
            scheme,
        }
    }
}

impl CryptoLayer for LuksLayer {
    fn scheme(&self) -> CryptoScheme {
        self.scheme
    }

    fn open(&self, creds: &dyn CredentialSource) -> VfsResult<DynSource> {
        let cands = creds.credentials_for(self.scheme, "");
        if cands.is_empty() {
            return Err(VfsError::NeedCredentials {
                scheme: "luks",
                target: String::new(),
            });
        }
        // A LUKS passphrase may arrive as a password or a keyfile's contents
        // (RecoveryKey); try each over a fresh Read+Seek view of the ciphertext.
        let mut last_err = None;
        for cred in &cands {
            let passphrase: &[u8] = match cred {
                Credential::Password(p) | Credential::RecoveryKey(p) => p.as_bytes(),
                Credential::KeyBytes(b) => b,
                _ => continue, // KeyFile / future variants: not wired here
            };
            let cursor = SourceCursor::new(Arc::clone(&self.encrypted), 0, self.len);
            match LuksVolume::unlock_with_passphrase(cursor, passphrase) {
                Ok(payload) => return Ok(Arc::new(LuksSource::new(payload))),
                Err(e) => last_err = Some(e),
            }
        }
        Err(last_err.as_ref().map_or(
            VfsError::NeedCredentials {
                scheme: "luks",
                target: String::new(),
            },
            map_luks_err,
        ))
    }
}

/// Translate a luks-core error into the VFS error type (a wrong passphrase / bad
/// header is a loud [`VfsError::Decode`]).
fn map_luks_err(e: &LuksError) -> VfsError {
    VfsError::Decode {
        layer: "luks",
        offset: 0,
        detail: e.to_string(),
        bytes: forensic_vfs::SmallHex::new(&[]),
    }
}

/// A decrypted LUKS payload presented as a read-only [`ImageSource`]. Reads
/// serialize through a poison-recovering `Mutex` (the reader advances a cursor).
struct LuksSource<R: Read + Seek> {
    inner: Mutex<DecryptedPayload<R>>,
    len: u64,
}

impl<R: Read + Seek> LuksSource<R> {
    fn new(payload: DecryptedPayload<R>) -> Self {
        let len = payload.payload_size();
        Self {
            inner: Mutex::new(payload),
            len,
        }
    }
}

impl<R: Read + Seek + Send> ImageSource for LuksSource<R> {
    fn len(&self) -> u64 {
        self.len
    }

    fn read_at(&self, offset: u64, buf: &mut [u8]) -> VfsResult<usize> {
        let avail = self.len.saturating_sub(offset);
        if avail == 0 {
            return Ok(0);
        }
        let want = (buf.len() as u64).min(avail) as usize;
        let Some(dst) = buf.get_mut(..want) else {
            return Ok(0); // cov:unreachable: want <= buf.len() by the min above
        };
        let mut guard = self.inner.lock().unwrap_or_else(PoisonError::into_inner);
        guard.read_at(offset, dst).map_err(|e| map_luks_err(&e))?;
        Ok(want)
    }
}

#[cfg(test)]
mod tests {
    use super::LuksLayer;
    use forensic_vfs::adapters::FileSource;
    use forensic_vfs::{Credential, CredentialSource, CryptoLayer, CryptoScheme, DynSource};
    use sha2::{Digest, Sha256};
    use std::sync::Arc;

    struct FixedCreds(Vec<Credential>);
    impl CredentialSource for FixedCreds {
        fn credentials_for(&self, _scheme: CryptoScheme, _target: &str) -> Vec<Credential> {
            self.0.clone()
        }
    }

    /// A real LUKS1 aes-xts-plain64 container (passphrase `luks-TEST`), minted on
    /// an Ubuntu VM with `cryptsetup` 2.7.0 and staged to /tmp (env
    /// `LUKS_XTS_ORACLE`, default path). Ground truth from `cryptsetup` itself
    /// (Tier-1): the decrypted payload holds distinct per-sector plaintext (data
    /// sector N filled with byte N), whose SHA-256s are asserted below. Skips if
    /// absent.
    fn encrypted() -> Option<DynSource> {
        let path = std::env::var("LUKS_XTS_ORACLE")
            .unwrap_or_else(|_| "/tmp/luks1_xts_oracle.img".to_string());
        let src = FileSource::open(&path).ok()?;
        Some(Arc::new(src))
    }

    fn sha256_hex(data: &[u8]) -> String {
        use std::fmt::Write;
        Sha256::digest(data).iter().fold(String::new(), |mut s, b| {
            let _ = write!(s, "{b:02x}");
            s
        })
    }

    #[test]
    fn luks_cryptolayer_decrypts_aes_xts() {
        let Some(enc) = encrypted() else {
            eprintln!("skip: no LUKS image (set LUKS_XTS_ORACLE)");
            return;
        };
        let layer = LuksLayer::new(enc);
        assert_eq!(layer.scheme(), CryptoScheme::Luks1);

        let creds = FixedCreds(vec![Credential::Password("luks-TEST".to_string())]);
        let dec: DynSource = layer.open(&creds).expect("unlock luks aes-xts");

        // cryptsetup oracle: distinct per-sector plaintext (data sector N = byte N).
        // Matching sectors 0/1/8/15 proves correct XTS per-sector tweak AND the
        // payload-offset alignment (identical plaintext would not).
        for (sec, expected) in [
            (
                0u64,
                "076a27c79e5ace2a3d47f9dd2e83e4ff6ea8872b3c2218f66c92b89b55f36560",
            ),
            (
                1,
                "6caf38d537984e261527b8caef5f990fb91415a1db917198821a79ed28997973",
            ),
            (
                8,
                "7debd4d73a98c0df9eb7b083fd21033d7bd0907b3947f22338d8c82154face23",
            ),
            (
                15,
                "941657fde04ff270f8ae019ede5287c71d887758641536ab0eb87a0d434526bd",
            ),
        ] {
            let mut buf = [0u8; 512];
            assert_eq!(
                dec.read_at(sec * 512, &mut buf).expect("read decrypted"),
                512
            );
            assert_eq!(
                sha256_hex(&buf),
                expected,
                "sector {sec} vs cryptsetup oracle"
            );
        }

        // No credentials offered → NeedCredentials, never a guess or panic.
        assert!(layer.open(&FixedCreds(vec![])).is_err());
    }
}
