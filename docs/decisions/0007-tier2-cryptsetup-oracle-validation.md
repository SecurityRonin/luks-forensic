# 7. Tier-2 `cryptsetup` oracle as the mandatory validation gate

Date: 2026-07-24
Status: Accepted

## Context

LUKS decryption produces a value an independent party can check byte-for-byte, so
it sits squarely in the "LZNT1 trap" zone (`CLAUDE.core.md` → Evidence-Based
Rigor): a self-authored encrypt→decrypt round-trip passes while both directions
share the same bug. A codec that emits data and can be cross-checked by an
independent oracle *must* be validated by that oracle, not by self-consistency.
`cryptsetup` is the reference LUKS implementation and serves as that oracle.

## Decision

Prove correctness against **`cryptsetup` 2.7.0** opening the same container with
the same passphrase, and assert decrypted-sector SHA-256 digests match
byte-for-byte (`docs/validation.md`; `core/tests/oracle_luks1.rs`,
`core/tests/oracle_luks2.rs`). These are **Tier-2** oracles: the containers were
minted by us with `cryptsetup luksFormat`, but the ground-truth plaintext is
derived independently by `cryptsetup` — the scenario is ours, the answer key is
not. Oracle images are env-gated (`LUKS1_ORACLE`, `LUKS2_ORACLE`) and not
committed; tests skip cleanly when the env var is unset. Tier-3 structural /
round-trip unit tests exist only as regression scaffolding *under* the Tier-2
oracles.

## Consequences

A wrong keyslot KDF, AF-merge, digest check, or XTS tweak fails the oracle
comparison rather than passing a self-referential test — the full LUKS1 and
LUKS2 chains (including LUKS2's Argon2id derivation and 4096-byte-sector XTS
read path) are end-to-end validated. Because the oracle images are env-gated and
uncommitted, CI correctness runs require the operator to supply them; the
committed unit tests remain the always-on regression backstop.
