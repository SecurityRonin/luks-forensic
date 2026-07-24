# 4. forensic-vfs EncryptionLayer adapter behind an optional `vfs` feature

Date: 2026-07-24
Status: Accepted

## Context

The fleet VFS abstraction (`ronin-issen/CLAUDE.md` → "VFS & Universal Container
Abstraction") composes a whole stack — e.g. `E01 → GPT → BitLocker → NTFS` — as
one `ImageSource` a filesystem reads unchanged. A LUKS volume is a crypto layer
in that stack: given a passphrase, its *decrypted* payload should present as an
`ImageSource` so the enclosing filesystem mounts the plaintext with no LUKS
knowledge. `forensic-vfs` defines an `EncryptionLayer` contract for exactly this.

But most consumers of `luks-core` want only the standalone decryptor, and pulling
`forensic-vfs` into every dependency tree would bloat them for a capability they
do not use.

## Decision

Provide a `forensic-vfs` `EncryptionLayer` adapter (`core/src/vfs.rs`,
`LuksLayer`) **behind an optional, default-off `vfs` Cargo feature**
(`core/Cargo.toml`: `vfs = ["dep:forensic-vfs"]`, `forensic-vfs = { version =
"0.7", optional = true }`). The adapter wraps an encrypted parent `DynSource`,
peeks the on-disk version to report `Luks1`/`Luks2`, and exposes the decrypted
payload as a `DynSource`. The decryption stays luks-core's own audited
RustCrypto (AES-XTS + PBKDF2/Argon2); the feature only wires the contract.

## Consequences

Standalone consumers get a lean `luks-core` with no `forensic-vfs` dependency;
fleet composition turns on `vfs` and drops LUKS into a layered stack. The adapter
tracks the `forensic-vfs` API: the git history shows migrations across
`forensic-vfs` 0.1→0.7 and the `CryptoLayer`→`EncryptionLayer` rename
(commits `9dd8bfc`, `f87c6f6`, `4b01b59`), a maintenance cost this decision
accepts in exchange for reusing the shared contract rather than inventing a
LUKS-specific one. (The `core/Cargo.toml` comment already cites "ADR 0004" for
this feature.)
