# 5. Audited RustCrypto for every primitive; the AF-merge is the sole bespoke code

Date: 2026-07-24
Status: Accepted

## Context

The global discipline (`CLAUDE.core.md` → "Never hand-roll a cryptographic
primitive") is absolute: KDFs, ciphers, and hashes are solved problems; a
hand-derived key-schedule or round function is wrong, unaudited, and usually
side-channel-unsafe. LUKS unlock needs PBKDF2, Argon2i/Argon2id, AES-XTS, and
HMAC/SHA. The one part with *no* mature ecosystem crate is LUKS's anti-forensic
(TKS1) split/merge — a format-specific diffusion codec.

## Decision

- **Every cryptographic primitive is an audited RustCrypto crate**, never
  hand-rolled (`core/src/crypto.rs`; root `Cargo.toml` `[workspace.dependencies]`):
  `pbkdf2`, `argon2`, `aes`, `xts-mode`, `hmac`, `sha1`, `sha2`.
- **The only bespoke routine is the LUKS anti-forensic merge** (`core/src/af.rs`,
  `af::merge`) — the TKS1 splitter, for which no ecosystem implementation exists.
  Its generic `diffuse::<D>` (`fn diffuse<D: Digest>`, `core/src/af.rs`) still
  delegates the underlying hashing to `sha1`/`sha2`; only the stripe-diffusion
  structure is ours (documented in `docs/RESEARCH.md`, built to the TKS1 paper +
  cryptsetup source).
- The bespoke AF-merge is validated **only against the independent `cryptsetup`
  oracle on real containers**, never a self-authored round-trip (see ADR 0007).

## Consequences

The attack surface for cryptographic error is confined to one small, spec-driven,
oracle-validated routine; everything else rides on maintained, audited crates.
This is the sanctioned exception to "prefer our own crates" — for crypto, the
mature ecosystem crate always wins — and the sanctioned case for rolling our own:
a format-specific codec with no ecosystem equivalent, held to an independent-oracle
validation bar rather than a self-consistent round-trip (the LZNT1 trap).
