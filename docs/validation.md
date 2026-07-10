# Validation

Correctness is proven against an **independent third-party oracle** —
`cryptsetup` 2.7.0, the reference LUKS implementation — never against a
self-authored round-trip (which would only prove self-consistency, the LZNT1
trap). LUKS decryption produces a value an independent oracle can check
byte-for-byte, so an oracle is mandatory, and we have one for both format
versions.

These are **Tier-2** oracles: we minted the containers on an Ubuntu 24.04 guest
with `cryptsetup luksFormat`, but the ground-truth plaintext is derived
*independently* by `cryptsetup` opening the same image with the same passphrase.
The scenario is ours; the answer key is not. Both images are env-gated and not
committed; the tests skip cleanly when the env var is unset.

## Tier-2 — LUKS1 `luks1.img` vs `cryptsetup`

- **Artifact**: `luks1.img`, 32 MiB, md5 `409f986e0bf5013a9c93661fe3c39589`.
- **Header**: cipher `aes` / `xts-plain64`, master-key **512 bits** (AES-256-XTS),
  hash `sha256`, MK iterations 1000 (forced low for a fast oracle), payload offset
  **4096 sectors** (2 MiB), UUID `b22690e1-a392-4ecc-83b1-c1cf21200116`.
- **Passphrase**: `luks-TEST`.
- **Unlock chain**: `PBKDF2-HMAC-sha256(passphrase, keyslot.salt,
  keyslot.iterations)` → keyslot key → AES-XTS decrypt of the keyslot key material
  → **AF-merge** (anti-forensic, sha256, 4000 stripes) → master key → verify
  `PBKDF2(master, mk-digest-salt, mk-digest-iter) == mk-digest` → decrypt payload
  sectors `aes-xts-plain64` (tweak = payload-relative sector number).

The env-gated test `core/tests/oracle_luks1.rs` (`LUKS1_ORACLE`) unlocks the image
and asserts these decrypted-sector SHA-256 digests against the `cryptsetup`
mapper output:

| Payload LBA | SHA-256 |
|---|---|
| 0 | `c9d8e3352f9f790d8b0be13cb1c18ed7963009888be04acc065ee5efbd934076` |
| 1 | `cb287e82f2af042cd65f1e72f3e4738a0a6dba5d9941b0dfd476fd5c8ea27cb0` |
| 2 | `492524d6fe4f2fe9309718c3d531078342c32bde0da7dd9d111bd17812f3cbe9` |
| 16 | `037f30c89ab88aa9d58417d2d95adb10b22f8691a17f7db71169ad3194ace706` |
| 100 | `d3c7f1b00475d01452cdbfcb4d9666dddecb3c633e67206016be05980293b57c` |
| 199 | `3e9dc47b357b72b7256d9fc953ee61be87d391ce34b6d3932ac5421294a84ae2` |

```bash
LUKS1_ORACLE=/tmp/luks-oracle/luks1.img \
  cargo test -p luks-core --test oracle_luks1 -- --nocapture
```

A passing run is the end-to-end proof of the whole LUKS1 chain: a wrong keyslot
KDF, AF-merge, or master key fails the mk-digest check and never reaches a
matching plaintext.

## Tier-2 — LUKS2 `luks2.img` vs `cryptsetup`

- **Artifact**: `luks2.img`, 48 MiB, md5 `10fdf8a4b4b5914a0e05ac5fb5c9f06d`.
- **Header**: cipher `aes-xts-plain64`, key **512 bits** (AES-256-XTS),
  **sector size 4096**, data offset 16 MiB (16777216).
- **KDF**: **Argon2id** (time 4, memory 32 KiB, cpus 1); AF `luks1` splitter with
  4000 stripes / sha256; digest `pbkdf2` sha256, 1000 iterations.
- **Passphrase**: `luks-TEST`.
- **KEY XTS insight**: the 4096-byte data units use the 512-based `plain64`
  tweak = `block * 8` (the dm-crypt default, no `iv_large_sectors`), so a
  512-byte read at LBA *n* decrypts within the 4096-byte data unit at the correct
  offset.

The env-gated test `core/tests/oracle_luks2.rs` (`LUKS2_ORACLE`) unlocks the image
through the unified `unlock_with_passphrase` entry point (which auto-detects
version 2) and asserts these decrypted-sector SHA-256 digests, in 512-byte units,
against `cryptsetup`:

| Payload LBA (512 B) | SHA-256 |
|---|---|
| 0 | `205671f7bc4ba5c0589baa514222f66e6e2c62e464f7ed0a00f7f451439c4bac` |
| 1 | `091344e5c2087f37fad9fc83b68167ae7136cb88f97310393c2289f40079ce5a` |
| 2 | `510bc5bda3f1659b0fc8a7235ec927025d4363c823964acaa1c6795f9186080c` |
| 16 | `3d4ac612bd846109b5e6c7ebd664e3a2f29883b1b9a87fff39643aee2efdb36e` |
| 100 | `0dd58d3c600646aa31968daa1a4231d7b1067ccbe94d2806d94579938271334c` |
| 199 | `dd0399377354f80af98f0c511142ad5b59b16d04754bb0c97ed0b98a2114283a` |

```bash
LUKS2_ORACLE=/tmp/luks-oracle/luks2.img \
  cargo test -p luks-core --test oracle_luks2 -- --nocapture
```

A passing run proves the LUKS2 JSON metadata parse, the **Argon2id** keyslot
derivation, the AF-merge, the digest verification, and the 4096-byte-sector XTS
read path together.

Both images were minted with `cryptsetup luksFormat` on the "Ubuntu 24.04 (with
Rosetta)" Parallels guest; provenance is recorded in
[`tests/data/README.md`](https://github.com/SecurityRonin/luks-forensic/blob/main/tests/data/README.md).

## Tier-3 — structural unit tests

LUKS1 `phdr` field parsing and keyslot active/disabled filtering, LUKS2
JSON keyslot/segment/digest parsing (PBKDF2 and Argon2 variants), and the
AF split/merge round-trip (sha1 / sha256 / sha512, full and short final chunk)
are exercised over hand-built byte buffers. These are regression scaffolding
under the Tier-2 oracles — a round-trip proves self-consistency only; the real
correctness proof for the full pipeline is the `cryptsetup` oracle.

## Fuzzing

`core/fuzz/fuzz_targets/` drives the untrusted-input parsers over arbitrary
bytes; invariant: never panic.

| Target | Surface |
|---|---|
| `luks1_header` | `Luks1Header::parse` |
| `luks2_header` | `Luks2Header::parse` (binary header + JSON area) |
| `af_merge` | the anti-forensic merge over crafted material / stripe counts |
| `unlock` | the full `LuksVolume::unlock_with_passphrase` pipeline |
