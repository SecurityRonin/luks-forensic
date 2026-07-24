# 6. Scope: `aes-xts-plain64` only; unsupported combinations refused loudly

Date: 2026-07-24
Status: Accepted

## Context

LUKS permits many cipher/mode/hash combinations (`cbc-essiv`, `cbc-plain`, …),
but `aes-xts-plain64` is the `cryptsetup` default and the overwhelming
real-world case. Implementing every mode up front is unbounded work; silently
mis-decrypting an unsupported mode would fabricate plaintext — the worst
failure class for a forensic tool (`CLAUDE.core.md` → Fail-loud / Show the
unrecognized value; Secure-by-Design).

## Decision

Support only **`aes-xts-plain64`** (AES-128/256-XTS), with LUKS1 keyslots deriving
via PBKDF2 and LUKS2 via PBKDF2 or Argon2i/Argon2id (`docs/RESEARCH.md`
"Out of scope"; README "Scope"). Any other cipher, mode, or hash is **recognized
and refused with a named error carrying the offending value verbatim** —
`LuksError::Unsupported { what, value }` (`core/src/crypto.rs`, e.g. the
`derive_key` hash match arm returns `Unsupported { what: "hash", value: other }`).
The parsers still surface the cipher/mode/hash they found; an unsupported
combination is never decrypted by construction.

## Consequences

An examiner meeting an out-of-scope container gets a loud, diagnosable error
naming exactly what was unsupported — not a plausible-but-wrong plaintext.
Adding a mode later is an additive change (a new match arm + oracle vector) that
does not weaken this guarantee. The narrowed scope is honest and stated in the
README and RESEARCH doc rather than implied.
