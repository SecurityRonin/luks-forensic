# 8. Low published-library MSRV floor (1.81), distinct from the dev toolchain pin

Date: 2026-07-24
Status: Accepted

## Context

The fleet MSRV policy (`CLAUDE.core.md` → "Rust MSRV & Toolchain Policy";
`CLAUDE.personal.md` fleet specifics) separates the *dev toolchain* (a single
pinned current stable, in `rust-toolchain.toml`) from the *declared MSRV*
(`rust-version`, a downstream-facing promise). `luks-core` and `luks-forensic`
are **published libraries**, so a third party may pin against them; their MSRV
should stay low and CI-verified, not track the drifting dev pin.

## Decision

- Develop on the pinned stable — `rust-toolchain.toml` `channel = "1.96.0"`.
- Declare a low library MSRV — `rust-version = "1.81"` in
  `[workspace.package]` (root `Cargo.toml`), inherited by both members.

The floor is deliberately below the dev pin so the crates stay broadly
publishable; it is raised only when a dependency genuinely needs newer Rust,
never merely to match the toolchain.

## Consequences

Downstream consumers on toolchains as old as 1.81 can build `luks-core`, at the
cost of forgoing newer-Rust features workspace-wide. Raising this floor later
narrows the crates.io audience and is treated as a near-breaking change.

**Unrecovered rationale:** why the floor is exactly **1.81** — rather than the
fleet's usual `1.75`/`1.80` library floor — is not recorded in available history;
it is most likely dictated by a transitive dependency's own MSRV (e.g. within the
`argon2` / `xts-mode` / `base64` graph). *Rationale reconstructed from structure;
original intent for the specific 1.81 value not recovered in available history.*
