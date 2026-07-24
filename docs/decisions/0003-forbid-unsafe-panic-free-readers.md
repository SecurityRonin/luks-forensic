# 3. `forbid(unsafe)` and panic-free bounded readers

Date: 2026-07-24
Status: Accepted

## Context

`luks-core` parses untrusted, attacker-controllable LUKS containers — a lying
header size, an over-large `stripes` count, or a truncated keyslot must never
crash or read out of bounds. The fleet Paranoid Gatekeeper standard
(`ronin-issen/CLAUDE.md`) mandates: never panic, never read OOB, never trust a
length field. Unlike the mmap-backed readers in the fleet (`ewf`,
`memory-forensic`, which downgrade to `unsafe_code = "deny"` + bounded allow),
this crate does purely in-memory, positioned reads and needs no `unsafe` at all.

## Decision

- **`unsafe_code = "forbid"`** workspace-wide (root `Cargo.toml`
  `[workspace.lints.rust]`; `#![forbid(unsafe_code)]` in both `lib.rs`). Because
  there is no mmap, this is a full `forbid`, not `deny` + a per-site allow — the
  crate earns the badge honestly.
- **`unwrap_used` / `expect_used` = `deny`** in production
  (`[workspace.lints.clippy]`); tests opt out via `clippy.toml`
  (`allow-unwrap-in-tests`) rather than scattering `#[allow]`.
- **Bounded big-endian readers** (`core/src/bytes.rs`): `be_u16/u32/u64` and
  `bytes_n` return 0 / zero-filled out of range via `data.get(off..off+N)`, so a
  truncated or lying header degrades gracefully. The AF-merge bounds-checks every
  read into the key material for the same reason (`core/src/af.rs`).
- **Fuzzing** — one target per parsed structure plus the full pipeline
  (`core/fuzz/fuzz_targets/`: `luks1_header`, `luks2_header`, `af_merge`,
  `unlock`); invariant: never panic.

## Consequences

A crafted container can produce a wrong-passphrase error or a short/zero field,
never a panic or memory-safety fault. The static posture (`forbid` + panic
lints) makes panics unreachable by construction; the fuzz targets test that
empirically over untrusted input.

**Known divergence:** the bounded readers are hand-rolled in `core/src/bytes.rs`
rather than routed through the fleet's shared `safe-read` crate, which the
constitution names as the single audited implementation ("NEVER hand-roll a
per-crate `bytes.rs`"). The original rationale for the local copy is not
recovered from history; migrating `bytes.rs` to `safe-read` is the compliant
follow-up.
