# luks-forensic

A from-scratch, pure-Rust **LUKS (Linux Unified Key Setup) reader and
decryptor** — unlock a container from its passphrase and read the plaintext,
plus an anomaly auditor over the cipher, KDF, and keyslot metadata.

!!! info "Scope"
    This build parses **LUKS1** partition headers and **LUKS2** binary-header +
    JSON metadata, and unlocks both from a passphrase over the `aes-xts-plain64`
    cipher (AES-128/256-XTS) — the `cryptsetup` default. LUKS1 keyslots derive
    with **PBKDF2**; LUKS2 keyslots derive with **PBKDF2 or Argon2i/Argon2id**.
    Each is validated against `cryptsetup` on real containers. See
    [Format Research](RESEARCH.md) and [Validation](validation.md).

## What it does

LUKS encrypts a block device behind a **master key**, itself wrapped in one of up
to eight **keyslots**. Each keyslot stretches a passphrase through a KDF (PBKDF2
or Argon2) to a keyslot key, decrypts the anti-forensically split key material,
and merges it back to the master key — checked against the header's master-key
digest. `luks-core`:

- parses the LUKS1 `phdr` (cipher, hash spec, payload offset, keyslots) and the
  LUKS2 binary header + JSON metadata (keyslots, KDF parameters, segments,
  digests),
- derives the keyslot key with PBKDF2-HMAC or Argon2, decrypts the keyslot
  key-material (`aes-xts-plain64`), runs the AF-merge (anti-forensic splitter),
  and verifies the recovered master key against the digest,
- decrypts payload sectors with AES-XTS, honouring the LUKS2 512/4096-byte sector
  size and the `plain64` tweak, and
- exposes a plaintext `Read + Seek` view (`read_at`).

`luks-forensic` grades a parsed LUKS1 header into severity-scored observations
(weak cipher mode, weak KDF hash, low PBKDF2 iterations, keyslot inventory).

## The two-crate split

| Crate | Role | Depends on | Emits |
|---|---|---|---|
| `luks-core` | reader / decryptor | `aes`, `xts-mode`, `pbkdf2`, `argon2`, `sha1`, `sha2`, `hmac`, `serde_json`, `base64`, `thiserror` | plaintext view + typed metadata |
| `luks-forensic` | anomaly analyzer | `luks-core` | graded findings |

## Trust but verify

Every cryptographic primitive is an audited RustCrypto crate (`pbkdf2`, `argon2`,
`aes`, `xts-mode`, `hmac`, `sha1`, `sha2`); the only bespoke routine is the LUKS
anti-forensic merge, validated **only** against the independent `cryptsetup`
oracle on real containers — never a self-authored round-trip. Panic-free,
bounds-checked parsing; `unwrap`/`expect` denied in production code
(`#![forbid(unsafe_code)]`); the header parsers, AF-merge, and full unlock
pipeline are fuzzed.

[Privacy Policy](https://securityronin.github.io/luks-forensic/privacy/) · [Terms of Service](https://securityronin.github.io/luks-forensic/terms/) · © 2026 Security Ronin Ltd
