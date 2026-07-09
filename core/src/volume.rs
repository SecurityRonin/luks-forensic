//! Public API: parse a LUKS1 container and unlock it from a passphrase.
//!
//! [`LuksVolume::unlock1_with_passphrase`] runs the full LUKS1 chain — parse the
//! `phdr`, try each active keyslot (PBKDF2 → decrypt AF material → AF-merge →
//! master key), verify the master key against the `mk-digest`, and return a
//! [`DecryptedPayload`] that decrypts the data area on demand.

use std::io::{Read, Seek, SeekFrom};

use crate::af;
use crate::crypto::{derive_key, xts_decrypt};
use crate::error::{LuksError, Result};
use crate::header::{Luks1Header, MK_DIGEST_LEN, SECTOR};

/// Namespace for opening a LUKS volume. State lives in [`DecryptedPayload`].
pub struct LuksVolume;

impl LuksVolume {
    /// Unlock a LUKS1 container from `reader` with `passphrase`.
    ///
    /// # Errors
    /// [`LuksError::NotLuks`]/`UnsupportedVersion`/`MalformedHeader` from header
    /// parsing, [`LuksError::NoActiveKeyslot`] if no keyslot is enabled,
    /// [`LuksError::AuthenticationFailed`] if no keyslot matches the passphrase,
    /// or [`LuksError::Unsupported`] for an unimplemented cipher/hash.
    pub fn unlock1_with_passphrase<R: Read + Seek>(
        mut reader: R,
        passphrase: &[u8],
    ) -> Result<DecryptedPayload<R>> {
        let mut hdr_buf = vec![0u8; crate::header::LUKS1_PHDR_LEN];
        reader.seek(SeekFrom::Start(0))?;
        read_fill(&mut reader, &mut hdr_buf)?;
        let header = Luks1Header::parse(&hdr_buf)?;

        if header.active_keyslots().next().is_none() {
            return Err(LuksError::NoActiveKeyslot);
        }

        let key_bytes = header.key_bytes as usize;
        let master_key = Self::recover_master_key(&mut reader, &header, passphrase, key_bytes)?;

        let total_size = reader.seek(SeekFrom::End(0))?;
        Ok(DecryptedPayload {
            reader,
            master_key,
            cipher_mode: header.cipher_mode.clone(),
            payload_offset: header.payload_byte_offset(),
            total_size,
            position: 0,
            header,
        })
    }

    /// Try each active keyslot until one yields a master key whose digest matches.
    fn recover_master_key<R: Read + Seek>(
        reader: &mut R,
        header: &Luks1Header,
        passphrase: &[u8],
        key_bytes: usize,
    ) -> Result<Vec<u8>> {
        for slot in header.active_keyslots() {
            // 1. PBKDF2 the passphrase with the keyslot salt -> keyslot key.
            let slot_key = derive_key(
                &header.hash_spec,
                passphrase,
                &slot.salt,
                slot.iterations,
                key_bytes,
            )?;

            // 2. Read and decrypt the anti-forensic key material.
            let material_len = af::material_len(key_bytes, slot.stripes as usize);
            let mut material = vec![0u8; material_len];
            reader.seek(SeekFrom::Start(
                u64::from(slot.key_material_offset) * SECTOR,
            ))?;
            if read_available(reader, &mut material)? < material_len {
                continue; // truncated keyslot region — try the next slot
            }
            xts_decrypt(&header.cipher_mode, &slot_key, &mut material, 0)?;

            // 3. AF-merge -> candidate master key, then verify against mk-digest.
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
}

/// A plaintext view of an unlocked LUKS payload.
pub struct DecryptedPayload<R> {
    reader: R,
    master_key: Vec<u8>,
    cipher_mode: String,
    payload_offset: u64,
    total_size: u64,
    position: u64,
    header: Luks1Header,
}

impl<R: Read + Seek> DecryptedPayload<R> {
    /// The parsed LUKS header.
    #[must_use]
    pub fn header(&self) -> &Luks1Header {
        &self.header
    }

    /// The recovered master key (sensitive).
    #[must_use]
    pub fn master_key(&self) -> &[u8] {
        &self.master_key
    }

    /// Size of the encrypted payload in bytes (container size minus the header/
    /// keyslot area before the payload).
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
        let sector_size = SECTOR as usize;
        let mut done = 0usize;
        while done < buf.len() {
            let pos = offset + done as u64;
            let sector = pos / SECTOR;
            let within = (pos % SECTOR) as usize;
            let physical = self.payload_offset + sector * SECTOR;

            let mut ct = vec![0u8; sector_size];
            self.reader.seek(SeekFrom::Start(physical))?;
            read_available(&mut self.reader, &mut ct)?;
            xts_decrypt(
                &self.cipher_mode,
                &self.master_key,
                &mut ct,
                u128::from(sector),
            )?;

            let take = (sector_size - within).min(buf.len() - done);
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
