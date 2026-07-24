# luks-forensic — Design & Scope

*A library, not a product. This document records what the two crates are for, who
links them, what is in and out of scope, how they are structured, and how
correctness is proven. Every current-state claim is grounded in a same-session
read of the workspace (`Cargo.toml`, `core/src/`, `forensic/src/`, `docs/`) on
2026-07-24; the load-bearing decisions live as ADRs under
[`docs/decisions/`](decisions/).*

## Purpose

Unlock a LUKS container from its passphrase and read the plaintext, in pure Rust,
with no `cryptsetup` C dependency, no `dm-crypt`, no mounting, and no root — and,
separately, audit a container's metadata for weak parameters. The reader parses
the on-disk header, derives the master key through PBKDF2 or Argon2, and decrypts
sectors with AES-XTS; the analyzer grades the cipher, KDF, and keyslot parameters
a header exposes without any passphrase.

## Who links it

These are libraries linked by other code, not a binary an examiner runs:

- **Rust / DFIR tooling** that needs to decrypt a LUKS volume programmatically
  without shelling out to `cryptsetup` — links `luks-core`.
- **The fleet VFS stack** — via the optional `vfs` feature, `luks-core` presents
  a decrypted LUKS payload as a `forensic-vfs` `EncryptionLayer` so an enclosing
  filesystem mounts the plaintext unchanged (ADR 0004).
- **Orchestration / triage layers** that aggregate `forensicnomicon::report`
  findings — link `luks-forensic` for LUKS metadata anomalies.

## What it does

- **`luks-core`** (reader/decryptor): auto-detects LUKS1 vs LUKS2; parses the
  LUKS1 `phdr` (big-endian, 592-byte header + 8 keyslots) and the LUKS2 binary
  header + JSON metadata (keyslots / segments / digests); derives the keyslot key
  (PBKDF2 for LUKS1; PBKDF2 or Argon2i/Argon2id for LUKS2), AES-XTS-decrypts the
  anti-forensic key material, runs the TKS1 AF-merge, verifies the master-key
  digest, and decrypts payload sectors over `aes-xts-plain64`. Exposes a plaintext
  `Read + Seek` view and typed header metadata.
- **`luks-forensic`** (analyzer): audits a **LUKS1 header** (`audit1` /
  `audit1_findings` over `Luks1Header`; no LUKS2 audit is built yet) and emits
  severity-graded findings —
  `LUKS-WEAK-CIPHER-MODE` (CBC/ECB), `LUKS-WEAK-KDF-HASH` (SHA-1),
  `LUKS-LOW-KDF-ITERATIONS` (brute-forceable iteration count),
  `LUKS-KEYSLOT-INVENTORY` (active-keyslot count). Findings are observations,
  never verdicts.

## Artifact family

LUKS1 partition headers and LUKS2 binary-header + JSON containers, over the
`aes-xts-plain64` cipher (AES-128/256-XTS) — the `cryptsetup` default. LUKS1
keyslots derive with PBKDF2; LUKS2 with PBKDF2 or Argon2i/Argon2id. The AF split
uses the LUKS1/TKS1 splitter (sha1/sha256/sha512). See
[`RESEARCH.md`](RESEARCH.md) for the authoritative spec sources and on-disk
layout the implementation is built to.

## Scope and non-goals

**In scope:** LUKS1 + LUKS2 parse and passphrase unlock over `aes-xts-plain64`
(512- and 4096-byte sectors); PBKDF2 and Argon2 keyslot derivation; the
metadata anomaly audit over **LUKS1 headers only** (the analyzer takes
`Luks1Header`; a LUKS2 header audit is not yet built).

**Out of scope (recognized, then refused loudly — ADR 0006):** cipher modes other
than `aes-xts-plain64` (`cbc-essiv`, `cbc-plain`, …), the LUKS2 token/keyring
objects, re-encryption metadata, and detached-header layouts. An unsupported
cipher/mode/hash is surfaced and returned as `LuksError::Unsupported` naming the
offending value verbatim — never silently mis-decrypted.

**Deliberately not built:** no CLI, GUI, or MCP front end; no key brute-forcing;
no mounting (that is `4n6mount` over the `vfs` adapter); no re-encryption or
write path — the crate reads and decrypts, it never modifies a container.

## Structure

One workspace, two crates (ADR 0001): `luks-core` (package name; `[lib] name =
"luks"` because the bare `luks` name is taken on crates.io — ADR 0002) and
`luks-forensic` (analyzer, depends down on the reader). Every cryptographic
primitive is an audited RustCrypto crate; the only bespoke routine is the AF-merge
(ADR 0005). `forbid(unsafe)`, `unwrap`/`expect` denied in production, bounded
readers, and per-structure fuzz targets (ADR 0003). Published-library MSRV floor
1.81, distinct from the 1.96 dev pin (ADR 0008).

## Validation approach

Correctness is proven against an independent `cryptsetup` 2.7.0 oracle (Tier-2):
decrypted sectors match `cryptsetup`'s mapper output byte-for-byte across LUKS1
and LUKS2, through env-gated tests (`core/tests/oracle_luks1.rs`,
`oracle_luks2.rs`) that skip cleanly when the images are absent (ADR 0007).
Structural / round-trip unit tests are regression scaffolding beneath the oracle;
the header parsers, AF-merge, and full unlock pipeline are fuzzed. Details in
[`validation.md`](validation.md).
