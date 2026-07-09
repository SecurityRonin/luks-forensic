//! Public API: parse a LUKS1 or LUKS2 container and unlock it from a passphrase.
//!
//! [`LuksVolume::unlock_with_passphrase`] auto-detects the version. Both run the
//! same shape — parse the header, try each keyslot (KDF → decrypt AF material →
//! AF-merge → master key), verify the master key against the digest, and return a
//! [`DecryptedPayload`] that decrypts the data segment on demand.

use std::io::{Read, Seek, SeekFrom};

use crate::af;
use crate::crypto::{derive_key, derive_key_argon2, xts_decrypt_area, Argon2Params};
use crate::error::{LuksError, Result};
use crate::header::{Luks1Header, LUKS1_PHDR_LEN, MK_DIGEST_LEN, SECTOR};
use crate::header2::{Luks2Header, Luks2Kdf, LUKS2_BIN_HDR_LEN};

/// Namespace for opening a LUKS volume. State lives in [`DecryptedPayload`].
pub struct LuksVolume;

/// The cipher/version facts of an unlocked volume.
#[derive(Debug, Clone)]
pub struct VolumeInfo {
    /// LUKS version (1 or 2).
    pub version: u16,
    /// Cipher name, e.g. `aes`.
    pub cipher_name: String,
    /// Cipher mode fed to the sector cipher, e.g. `xts-plain64`.
    pub cipher_mode: String,
    /// Master-key length in bytes.
    pub key_bytes: u32,
    /// Encryption sector size in bytes (512 or 4096).
    pub sector_size: usize,
}

/// Split a LUKS2 `encryption` string (`aes-xts-plain64`) into (name, mode). For a
/// LUKS1 header the mode is already separate, so `cipher_mode_of` is the identity.
fn split_encryption(enc: &str) -> (String, String) {
    match enc.split_once('-') {
        Some((name, mode)) => (name.to_string(), mode.to_string()),
        None => (enc.to_string(), String::new()),
    }
}

impl LuksVolume {
    /// Unlock a LUKS1 or LUKS2 container, auto-detecting the version from the
    /// header.
    ///
    /// # Errors
    /// See [`Self::unlock1_with_passphrase`] / [`Self::unlock2_with_passphrase`].
    pub fn unlock_with_passphrase<R: Read + Seek>(
        mut reader: R,
        passphrase: &[u8],
    ) -> Result<DecryptedPayload<R>> {
        let mut ver = [0u8; 8];
        reader.seek(SeekFrom::Start(0))?;
        read_fill(&mut reader, &mut ver)?;
        reader.seek(SeekFrom::Start(0))?;
        match crate::bytes::be_u16(&ver, 6) {
            1 => Self::unlock1_with_passphrase(reader, passphrase),
            2 => Self::unlock2_with_passphrase(reader, passphrase),
            other => {
                if ver.starts_with(&crate::header::LUKS_MAGIC) {
                    Err(LuksError::UnsupportedVersion { version: other })
                } else {
                    Err(LuksError::NotLuks {
                        found: crate::bytes::bytes_n::<6>(&ver, 0),
                    })
                }
            }
        }
    }

    /// Unlock a LUKS1 container from `reader` with `passphrase`.
    ///
    /// # Errors
    /// Header-parse errors, [`LuksError::NoActiveKeyslot`], or
    /// [`LuksError::AuthenticationFailed`] on a wrong passphrase.
    pub fn unlock1_with_passphrase<R: Read + Seek>(
        mut reader: R,
        passphrase: &[u8],
    ) -> Result<DecryptedPayload<R>> {
        let mut hdr_buf = vec![0u8; LUKS1_PHDR_LEN];
        reader.seek(SeekFrom::Start(0))?;
        read_fill(&mut reader, &mut hdr_buf)?;
        let header = Luks1Header::parse(&hdr_buf)?;
        if header.active_keyslots().next().is_none() {
            return Err(LuksError::NoActiveKeyslot);
        }
        let key_bytes = header.key_bytes as usize;
        let master_key = recover_master_key1(&mut reader, &header, passphrase, key_bytes)?;
        let total_size = reader.seek(SeekFrom::End(0))?;
        Ok(DecryptedPayload {
            reader,
            master_key,
            cipher_mode: header.cipher_mode.clone(),
            payload_offset: header.payload_byte_offset(),
            sector_size: SECTOR as usize,
            iv_tweak: 0,
            total_size,
            position: 0,
            info: VolumeInfo {
                version: 1,
                cipher_name: header.cipher_name.clone(),
                cipher_mode: header.cipher_mode.clone(),
                key_bytes: header.key_bytes,
                sector_size: SECTOR as usize,
            },
        })
    }

    /// Unlock a LUKS2 container from `reader` with `passphrase`.
    ///
    /// # Errors
    /// Header/JSON-parse errors, [`LuksError::NoActiveKeyslot`] if there is no
    /// crypt segment or keyslot, or [`LuksError::AuthenticationFailed`].
    pub fn unlock2_with_passphrase<R: Read + Seek>(
        mut reader: R,
        passphrase: &[u8],
    ) -> Result<DecryptedPayload<R>> {
        // Read the binary header to learn hdr_size, then the whole header+JSON.
        let mut bin = vec![0u8; LUKS2_BIN_HDR_LEN];
        reader.seek(SeekFrom::Start(0))?;
        read_fill(&mut reader, &mut bin)?;
        let hdr_size = crate::bytes::be_u64(&bin, 8).max(LUKS2_BIN_HDR_LEN as u64) as usize;
        let mut full = vec![0u8; hdr_size];
        reader.seek(SeekFrom::Start(0))?;
        read_available(&mut reader, &mut full)?;
        let header = Luks2Header::parse(&full)?;

        let segment = header
            .crypt_segment()
            .cloned()
            .ok_or(LuksError::NoActiveKeyslot)?;
        if header.keyslots.is_empty() {
            return Err(LuksError::NoActiveKeyslot);
        }

        let master_key = recover_master_key2(&mut reader, &header, passphrase)?;
        let total_size = reader.seek(SeekFrom::End(0))?;
        let (cipher_name, cipher_mode) = split_encryption(&segment.encryption);
        let key_bytes = master_key.len() as u32;
        Ok(DecryptedPayload {
            reader,
            master_key,
            cipher_mode: cipher_mode.clone(),
            payload_offset: segment.offset,
            sector_size: segment.sector_size.max(512),
            iv_tweak: segment.iv_tweak,
            total_size,
            position: 0,
            info: VolumeInfo {
                version: 2,
                cipher_name,
                cipher_mode,
                key_bytes,
                sector_size: segment.sector_size.max(512),
            },
        })
    }
}

/// LUKS1: try each active keyslot until one yields a master key whose digest
/// matches.
fn recover_master_key1<R: Read + Seek>(
    reader: &mut R,
    header: &Luks1Header,
    passphrase: &[u8],
    key_bytes: usize,
) -> Result<Vec<u8>> {
    for slot in header.active_keyslots() {
        let slot_key = derive_key(
            &header.hash_spec,
            passphrase,
            &slot.salt,
            slot.iterations,
            key_bytes,
        )?;
        let material_len = af::material_len(key_bytes, slot.stripes as usize);
        let mut material = vec![0u8; material_len];
        reader.seek(SeekFrom::Start(
            u64::from(slot.key_material_offset) * SECTOR,
        ))?;
        if read_available(reader, &mut material)? < material_len {
            continue;
        }
        xts_decrypt_area(&header.cipher_mode, &slot_key, &mut material, 512, 0)?;
        let candidate = af::merge(
            &header.hash_spec,
            &material,
            key_bytes,
            slot.stripes as usize,
        )?;
        let digest = derive_key(
            &header.hash_spec,
            &candidate,
            &header.mk_digest_salt,
            header.mk_digest_iter,
            MK_DIGEST_LEN,
        )?;
        if digest == header.mk_digest {
            return Ok(candidate);
        }
    }
    Err(LuksError::AuthenticationFailed)
}

/// LUKS2: try each keyslot (Argon2 or PBKDF2 KDF) and verify against a digest
/// that references it.
fn recover_master_key2<R: Read + Seek>(
    reader: &mut R,
    header: &Luks2Header,
    passphrase: &[u8],
) -> Result<Vec<u8>> {
    for slot in &header.keyslots {
        let slot_key = match &slot.kdf {
            Luks2Kdf::Argon2 {
                kind,
                time,
                memory,
                cpus,
                salt,
            } => derive_key_argon2(
                &Argon2Params {
                    kind,
                    time: *time,
                    memory: *memory,
                    cpus: *cpus,
                    salt,
                },
                passphrase,
                slot.key_size,
            )?,
            Luks2Kdf::Pbkdf2 {
                hash,
                iterations,
                salt,
            } => derive_key(hash, passphrase, salt, *iterations, slot.key_size)?,
        };

        let (_, area_mode) = split_encryption(&slot.area_encryption);
        let material_len = af::material_len(slot.key_size, slot.af_stripes as usize);
        let mut material = vec![0u8; material_len];
        reader.seek(SeekFrom::Start(slot.area_offset))?;
        if read_available(reader, &mut material)? < material_len {
            continue;
        }
        xts_decrypt_area(&area_mode, &slot_key, &mut material, 512, 0)?;
        let candidate = af::merge(
            &slot.af_hash,
            &material,
            slot.key_size,
            slot.af_stripes as usize,
        )?;

        for dig in &header.digests {
            if dig.kind == "pbkdf2" && dig.keyslots.iter().any(|k| k == &slot.id) {
                let d = derive_key(
                    &dig.hash,
                    &candidate,
                    &dig.salt,
                    dig.iterations,
                    dig.digest.len(),
                )?;
                if d == dig.digest {
                    return Ok(candidate);
                }
            }
        }
    }
    Err(LuksError::AuthenticationFailed)
}

/// A plaintext view of an unlocked LUKS payload.
pub struct DecryptedPayload<R> {
    reader: R,
    master_key: Vec<u8>,
    cipher_mode: String,
    payload_offset: u64,
    sector_size: usize,
    iv_tweak: u128,
    total_size: u64,
    position: u64,
    info: VolumeInfo,
}

impl<R: Read + Seek> DecryptedPayload<R> {
    /// Cipher/version facts of the volume.
    #[must_use]
    pub fn info(&self) -> &VolumeInfo {
        &self.info
    }

    /// The recovered master key (sensitive).
    #[must_use]
    pub fn master_key(&self) -> &[u8] {
        &self.master_key
    }

    /// Size of the encrypted payload in bytes.
    #[must_use]
    pub fn payload_size(&self) -> u64 {
        self.total_size.saturating_sub(self.payload_offset)
    }

    /// Read decrypted payload bytes at payload-relative `offset` into `buf`,
    /// filling it completely (bytes past the end read back as zero).
    ///
    /// # Errors
    /// Propagates I/O errors and any cipher error.
    pub fn read_at(&mut self, offset: u64, buf: &mut [u8]) -> Result<()> {
        let ss = self.sector_size as u64;
        let step = (self.sector_size / 512).max(1) as u128;
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let unit = pos / ss;
            let within = (pos % ss) as usize;
            let physical = self.payload_offset + unit * ss;

            let mut ct = vec![0u8; self.sector_size];
            self.reader.seek(SeekFrom::Start(physical))?;
            read_available(&mut self.reader, &mut ct)?;
            let tweak = self.iv_tweak + u128::from(unit) * step;
            xts_decrypt_area(
                &self.cipher_mode,
                &self.master_key,
                &mut ct,
                self.sector_size,
                tweak,
            )?;

            let take = (self.sector_size - within).min(buf.len() - done);
            buf[done..done + take].copy_from_slice(&ct[within..within + take]);
            done += take;
        }
        Ok(())
    }
}

impl<R: Read + Seek> Read for DecryptedPayload<R> {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let size = self.payload_size();
        if self.position >= size {
            return Ok(0);
        }
        let n = (buf.len() as u64).min(size - self.position) as usize;
        self.read_at(self.position, &mut buf[..n])
            .map_err(|e| std::io::Error::other(e.to_string()))?;
        self.position += n as u64;
        Ok(n)
    }
}

impl<R: Read + Seek> Seek for DecryptedPayload<R> {
    fn seek(&mut self, pos: SeekFrom) -> std::io::Result<u64> {
        let size = self.payload_size();
        let new = match pos {
            SeekFrom::Start(o) => i128::from(o),
            SeekFrom::End(o) => i128::from(size) + i128::from(o),
            SeekFrom::Current(o) => i128::from(self.position) + i128::from(o),
        };
        if new < 0 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "seek before start",
            ));
        }
        self.position = new as u64;
        Ok(self.position)
    }
}

/// Read exactly `buf.len()` bytes, erroring on premature EOF.
fn read_fill<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    reader.read_exact(buf)?;
    Ok(())
}

/// Read up to `buf.len()` bytes, zero-filling the remainder on EOF. Returns the
/// number of real bytes read.
fn read_available<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<usize> {
    let mut filled = 0;
    while filled < buf.len() {
        match reader.read(&mut buf[filled..]) {
            Ok(0) => break,
            Ok(n) => filled += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::Interrupted => {}
            Err(e) => return Err(e.into()),
        }
    }
    for b in &mut buf[filled..] {
        *b = 0;
    }
    Ok(filled)
}
