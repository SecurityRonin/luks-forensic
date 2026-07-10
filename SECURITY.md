# Security Policy

`luks-forensic` is designed to parse **untrusted LUKS (Linux Unified Key Setup)
containers** — including images acquired from compromised or actively hostile
systems. Hostile input is the expected case, not an edge case. Robustness against
crafted LUKS1 partition headers and LUKS2 binary-header + JSON metadata is a core
design goal, and we take reports of crashes, hangs, or memory-safety issues
seriously.

The security posture below is the standard the crates are built and held to.

## Supported versions

| Version | Supported |
|---|---|
| 0.1.x   | ✅ — current development line |
| < 0.1   | ❌ — pre-release, unsupported |

## Reporting a vulnerability

**Do not open a public GitHub issue for a security vulnerability.**

Report privately, by either:

- **GitHub Security Advisories** — open a private advisory on the
  [`luks-forensic` repository](https://github.com/SecurityRonin/luks-forensic/security/advisories/new), or
- **Email** — [albert@securityronin.com](mailto:albert@securityronin.com).

Please include:

- the affected version and target triple,
- a minimal reproducing LUKS container or byte buffer (a fuzz corpus entry is ideal),
- the observed behaviour (panic, hang, excessive allocation, mis-parse) and the
  expected behaviour.

We aim to acknowledge a report within a few business days and to coordinate
disclosure once a fix is available.

## Security posture

`luks-forensic` is hardened against adversarial input by construction:

- **`#![forbid(unsafe_code)]`** across the whole workspace — no `unsafe`, anywhere.
- **No panics on malicious input** — every length and offset is validated against
  both the structure's declared size and the actual buffer; integers are read
  through bounds-checked helpers that yield 0 out of range rather than panic.
- **Bounded reads** — keyslots, the LUKS2 `hdr_size`/JSON area, and the
  anti-forensic key material are length-checked before use, so a crafted length
  field cannot drive an out-of-bounds read or an allocation bomb.
- **Never hand-rolled crypto** — PBKDF2, Argon2, AES, XTS, and the hashes are all
  audited RustCrypto crates; the only bespoke routine is the AF-merge (LUKS
  anti-forensic splitter), validated against `cryptsetup` on real containers.
- **Pure auditor** — `luks-forensic` is a side-effect-free function of an
  already-decoded header: no I/O, no allocation surprises.

Continuous fuzzing with [`cargo-fuzz`](https://github.com/rust-fuzz/cargo-fuzz)
backs this hardening: one target per parsed structure (`luks1_header`,
`luks2_header`, `af_merge`) plus a full-pipeline `unlock` target; each target's
invariant is "must not panic," and any panic found is fixed and pinned as a
regression test.
