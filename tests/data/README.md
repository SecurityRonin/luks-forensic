# Test data — luks-forensic

The correctness oracles are **not committed** (32–48 MiB each) and are
**env-gated**: the tests read them in place and skip cleanly when the env var is
unset. They are minted with `cryptsetup luksFormat` on an Ubuntu 24.04 guest and
decrypted independently by `cryptsetup` (the answer key), so they are **Tier-2**
(scenario ours, oracle independent). The single fleet-wide corpus index is
`issen/docs/corpus-catalog.md`; this file is the co-located human-facing detail.

Ground truth for both is captured in `/tmp/luks-oracle/GROUND-TRUTH.md`.

#### luks1.img

- **Source**: self-minted (Tier-2). `cryptsetup luksFormat --type luks1
  --cipher aes-xts-plain64 --key-size 512 --hash sha256
  --pbkdf-force-iterations 1000`, on the Parallels "Ubuntu 24.04 (with Rosetta)"
  guest (host `/tmp` shared as `/media/psf/tmp`).
- **Identity**: LUKS1, `aes` / `xts-plain64`, master key 512 bits (AES-256-XTS),
  hash sha256, MK iterations 1000, payload offset 4096 sectors (2 MiB), UUID
  `b22690e1-a392-4ecc-83b1-c1cf21200116`.
- **Size / md5**: 32 MiB, `409f986e0bf5013a9c93661fe3c39589`.
- **Passphrase**: `luks-TEST`.
- **Oracle**: `cryptsetup` 2.7.0 (`luksOpen` → mapper) — decrypted sectors match
  byte-for-byte.
- **Consumed by**: `core/tests/oracle_luks1.rs`, env `LUKS1_ORACLE`.

#### luks2.img

- **Source**: self-minted (Tier-2). `cryptsetup luksFormat --type luks2
  --cipher aes-xts-plain64 --key-size 512 --pbkdf argon2id
  --sector-size 4096` (KDF forced to a small cost for a fast oracle).
- **Identity**: LUKS2, `aes-xts-plain64`, key 512 bits (AES-256-XTS), sector size
  4096, data offset 16 MiB, KDF Argon2id (time 4, memory 32 KiB, cpus 1), AF
  `luks1` 4000 stripes / sha256, digest pbkdf2 sha256 iter 1000. Full JSON in
  `/tmp/luks-oracle/luks2.json`.
- **Size / md5**: 48 MiB, `10fdf8a4b4b5914a0e05ac5fb5c9f06d`.
- **Passphrase**: `luks-TEST`.
- **Oracle**: `cryptsetup` 2.7.0 — decrypted sectors match byte-for-byte.
- **Consumed by**: `core/tests/oracle_luks2.rs`, env `LUKS2_ORACLE`.

## Redistribution

Both images are self-minted by Security Ronin and contain no third-party
copyrighted content; they are documented here for reproducibility rather than
committed. Re-mint with the commands above to regenerate.
