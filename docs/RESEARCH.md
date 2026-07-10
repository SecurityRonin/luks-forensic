# LUKS format research

This is the working reference the implementation is built to. It records the
authoritative sources, the on-disk layout, and the exact unlock pipeline — so the
code can be checked against the spec line by line, and so the next reader does not
have to re-derive LUKS's layout from memory.

## Authoritative sources

| Source | Used for |
|---|---|
| **LUKS1 On-Disk Format Specification** (C. Fruhwirth, v1.2.3) ([cryptsetup wiki](https://gitlab.com/cryptsetup/cryptsetup/-/wikis/LUKS-standard/on-disk-format.pdf)) | LUKS1 `phdr` layout, keyslot layout, anti-forensic split, master-key digest |
| **LUKS2 On-Disk Format Specification** ([cryptsetup/docs/on-disk-format-luks2.pdf](https://gitlab.com/cryptsetup/cryptsetup/-/blob/main/docs/on-disk-format-luks2.pdf)) | LUKS2 binary header, JSON metadata objects (keyslots/segments/digests), KDF objects |
| **cryptsetup source** (`lib/luks1/*`, `lib/luks2/*`, `lib/utils_crypt.c`) | Exact PBKDF2/Argon2 parameters, AF stripe hashing, the `plain64` IV, sector-size handling |
| **dm-crypt** kernel documentation ([Documentation/admin-guide/device-mapper/dm-crypt.rst](https://www.kernel.org/doc/html/latest/admin-guide/device-mapper/dm-crypt.html)) | `aes-xts-plain64` tweak = 512-byte sector number, `iv_large_sectors` semantics |
| **[TKS1]** — C. Fruhwirth & others, *TKS1 — an anti-forensic, two-level, and iterated key setup scheme* | The AF (anti-forensic) split/merge design and rationale |

## LUKS1 partition header (`phdr`, first 592 bytes)

All integers big-endian, per the LUKS1 spec. Layout:

```text
  0  magic[6] = "LUKS\xba\xbe"       104  payload-offset  u32 (512-byte sectors)
  6  version  u16 (= 1)              108  key-bytes       u32 (master-key length)
  8  cipher-name[32]  (e.g. "aes")   112  mk-digest[20]
 40  cipher-mode[32]  ("xts-plain64")132  mk-digest-salt[32]
 72  hash-spec[32]    ("sha256")     164  mk-digest-iter  u32
                                     168  uuid[40]
208  8 × keyslot (48 bytes each)
```

### Keyslot (48 bytes, at `208 + i × 48`)

```text
  0  active  u32   0x00AC71F3 = enabled · 0x0000DEAD = disabled
  4  iterations  u32   (PBKDF2 iterations for this slot)
  8  salt[32]
 40  key-material-offset  u32  (512-byte sectors)
 44  stripes  u32   (anti-forensic stripe count, typically 4000)
```

String fields are fixed-width, NUL-padded, and read as C strings (the parser
stops at the first NUL). A slot whose `active` marker is neither `0x00AC71F3` nor
`0x0000DEAD` is corrupt/unknown — treated as inactive.

## LUKS2 header (binary header + JSON metadata)

LUKS2 keeps a small **binary header** followed by a **JSON metadata area** (and a
second, redundant copy). The binary header carries the same `LUKS\xba\xbe` magic,
`version = 2` at offset 6, and a 64-bit **header size** at offset 8 (big-endian)
that bounds the JSON area. The JSON area is a single UTF-8 JSON object,
NUL-terminated within its region:

```jsonc
{
  "keyslots": { "0": { "type": "luks2", "key_size": 64,
                       "kdf":  { "type": "argon2id", "time": 4, "memory": 32,
                                 "cpus": 1, "salt": "<base64>" },
                       "af":   { "type": "luks1", "stripes": 4000, "hash": "sha256" },
                       "area": { "offset": "32768", "size": "258048",
                                 "encryption": "aes-xts-plain64", "key_size": 64 } } },
  "segments": { "0": { "type": "crypt", "offset": "16777216",
                       "encryption": "aes-xts-plain64", "sector_size": 4096 } },
  "digests":  { "0": { "type": "pbkdf2", "hash": "sha256", "iterations": 1000,
                       "salt": "<base64>", "digest": "<base64>",
                       "keyslots": ["0"], "segments": ["0"] } }
}
```

Numeric fields may be encoded as JSON strings or numbers — LUKS2 uses strings for
byte offsets/sizes; the parser accepts either. Salts and digests are base64.
The keyslot `area.offset`/`area.size` locate the AF key material; the segment
`offset` locates the encrypted payload and its `sector_size` (512 or 4096) selects
the XTS data-unit size.

## Passphrase → keyslot key → master key

The passphrase unlocks *a keyslot*, not the volume directly:

1. **Keyslot key** — stretch the passphrase with the keyslot's KDF over its salt:
   - **LUKS1**: `PBKDF2-HMAC-<hash>(passphrase, keyslot.salt, keyslot.iterations)`,
     output length = `key-bytes`.
   - **LUKS2**: **PBKDF2** *or* **Argon2i/Argon2id** with the JSON `kdf` object's
     `time` (iterations), `memory` (KiB), and `cpus` (parallelism); output length
     = the keyslot `key_size`.
2. **AF key material** — read the keyslot's anti-forensic area (LUKS1:
   `key-material-offset × 512`, `key-bytes × stripes` bytes; LUKS2: `area.offset`,
   `area.size`) and **AES decrypt** it with the keyslot key under the keyslot
   cipher (`aes-xts-plain64`, tweak = area-relative sector number).
3. **AF-merge** — collapse the `stripes`-way anti-forensic split back to the
   master key (below).
4. **Digest check** — verify the recovered master key against the header's
   master-key digest: LUKS1 `PBKDF2(master, mk-digest-salt, mk-digest-iter)` must
   equal `mk-digest`; LUKS2 the matching `digests` object (`pbkdf2` over the
   master key). A mismatch ⇒ wrong passphrase (`AuthenticationFailed`), tried
   keyslot by keyslot.

## Anti-forensic (AF) split and merge

LUKS stores the master key inflated to `key-bytes × stripes` bytes so that
wiping any part destroys it (the TKS1 anti-forensic property). **Merge** (decrypt
direction) reduces the material back to a `block_size`-byte key:

```text
acc = 0
for i in 0 .. stripes-1:
    acc ^= material[i × block_size .. (i+1) × block_size]
    acc  = diffuse_<hash>(acc)        # H over the running accumulator
acc ^= material[(stripes-1) × block_size ..]   # final (possibly short) chunk
```

`diffuse_<hash>` hashes the accumulator in `digest_size` blocks with a big-endian
block counter prepended, so the diffusion covers the whole `block_size` regardless
of the hash's native digest length. Supported hashes: **sha1 / sha256 / sha512**
(an unknown `hash_spec` is a loud `Unsupported` error, never a silent default).
Every read into `material` is bounds-checked with `.get()`, so a `stripes` /
`block_size` that overruns the supplied material yields a short/zero contribution
rather than a panic — this is the `af_merge` fuzz target's invariant.

## Sector decryption — `aes-xts-plain64`

LUKS's default (and this build's) cipher is AES-XTS with the `plain64` IV. Each
data unit is decrypted by XTS keyed off the master key's two halves (data key +
tweak key), with the **tweak = the 512-byte sector number**:

```text
plain = XTS-AES-DEC(data_key, tweak_key, tweak = LE128(sector_number), unit)
```

- **LUKS1** always uses 512-byte data units; the tweak is the payload-relative
  512-byte sector number.
- **LUKS2** may set `sector_size = 4096`. With the dm-crypt default (no
  `iv_large_sectors`), the `plain64` tweak is still expressed in **512-byte
  units** — the tweak for the 4096-byte unit starting at block *b* is `b × 8`.
  A 512-byte `read_at` therefore decrypts the enclosing 4096-byte unit and slices
  the requested sub-range. Confirmed against the `cryptsetup` oracle (see
  [Validation](validation.md)).

`plain64` is the 64-bit little-endian sector number in the low 8 bytes, zero-padded
to the 16-byte XTS tweak. XTS is provided by the `xts-mode` crate (0.5.x — cipher
0.4 / aes 0.8).

## Out of scope in this build

Cipher modes other than `aes-xts-plain64` (e.g. `cbc-essiv`, `cbc-plain`), the
LUKS2 token/keyring objects, re-encryption metadata, and detached-header layouts.
The parsers still surface the cipher/mode/hash they find; an unsupported
combination is a loud `Unsupported` error naming the offending value.
