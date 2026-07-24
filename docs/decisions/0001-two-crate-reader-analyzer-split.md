# 1. Two-crate reader/analyzer split (luks-core + luks-forensic)

Date: 2026-07-24
Status: Accepted

## Context

The repo does two distinct jobs: it *reads and decrypts* a LUKS container
(parse the header, derive the master key, decrypt the payload) and it *audits*
the container's metadata for weak parameters. These have different audiences —
a downstream Rust tool wanting only the decryptor should not have to compile the
finding model, and the analyzer must depend on the reader, not the reverse.

The SecurityRonin fleet standard (`ronin-issen/CLAUDE.md` → "Crate-structure
standard — reader/analyzer split (core/ + forensic/)") prescribes exactly this
shape: one workspace repo named `<x>-forensic` with a `core/` reader crate and a
`forensic/` analyzer crate.

## Decision

Structure the repo as one Cargo workspace, `luks-forensic`, with two members
(root `Cargo.toml`: `members = ["core", "forensic"]`):

- **`core/` → `luks-core`** — the reader/decryptor. Exposes `LuksVolume`, a
  plaintext `Read + Seek` view (`DecryptedPayload`), and typed header metadata
  (`Luks1Header`, `Luks2Header`, keyslots/segments/digests). No findings
  (`core/src/lib.rs`).
- **`forensic/` → `luks-forensic`** — the anomaly analyzer. Keeps its own typed
  `AnomalyKind` and converts to `forensicnomicon::report::Finding` via
  `impl Observation`, depending down on `luks-core` (`forensic/Cargo.toml`:
  `luks = { workspace = true }`; `forensic/src/lib.rs`).

The analyzer consumes the reader's public `luks::Luks1Header` type — its
`audit1` / `audit1_findings` entry points take a `Luks1Header`, so the audit
currently covers **LUKS1 headers only** (no LUKS2 audit is built yet). That type
exposes everything the current cipher/KDF/keyslot audit needs, so `luks-forensic`
builds on `luks-core` rather than re-parsing the raw header.

## Consequences

A consumer that only needs decryption depends on `luks-core` alone. The finding
model stays out of the reader's dependency tree. The dependency arrow is fixed
(analyzer → reader); should a future audit need to see raw byte layout, slack, or
malformed fields that the reader normalizes away, the fleet standard permits
`luks-forensic` to drop to lower-level parsing — that would be a follow-on
decision, not a break of this one.
