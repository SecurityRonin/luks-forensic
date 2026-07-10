# Changelog

All notable changes to this project are documented here. The format is based on
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project
adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0]

### Added

- `luks-core`: from-scratch, pure-Rust LUKS reader and decryptor.
  - **LUKS1** partition-header (`phdr`) parsing: cipher, hash spec, master-key
    digest, payload offset, and the eight keyslots.
  - **LUKS2** binary-header + JSON-metadata parsing: keyslots (with KDF
    parameters), data segments, and digests.
  - Passphrase unlock via `LuksVolume::unlock_with_passphrase` (auto-detects the
    version), plus `unlock1_with_passphrase` / `unlock2_with_passphrase`:
    PBKDF2/Argon2 keyslot derivation → keyslot key-material decrypt → AF-merge
    (anti-forensic split) → master key → master-key-digest verification.
  - Sector decryption for `aes-xts-plain64` (AES-128/256-XTS), honouring the
    LUKS2 512/4096-byte sector size and the `plain64` tweak.
  - `LuksVolume::read_at` exposes a decrypted `Read + Seek` payload view.
  - Tier-2 validated against `cryptsetup` 2.7.0 on self-minted LUKS1 and LUKS2
    containers — decrypted sectors match byte-for-byte.
- `luks-forensic`: anomaly auditor emitting `LUKS-*` findings over a parsed LUKS1
  header (weak cipher mode, weak KDF hash, low PBKDF2 iterations, keyslot
  inventory). Findings are observations, never verdicts.
