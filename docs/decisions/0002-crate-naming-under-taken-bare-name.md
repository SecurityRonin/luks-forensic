# 2. Crate naming under a taken bare `luks` name

Date: 2026-07-24
Status: Accepted

## Context

The natural import path for the reader is `luks::…`. But the bare crate name
`luks` is already published on crates.io by an unrelated third party (verified
2026-07-24 via the crates.io API: crate `luks`, created 2026-02-14, 766
downloads, multiple versions) — so `luks-core` cannot claim the bare name as its
*package* name.

The fleet naming grammar (`ronin-issen/CLAUDE.md` → "Crate naming grammar" /
"Crate-structure standard") covers this: when the bare `<x>` name is taken by a
third party we can co-exist with, publish `<x>-core` with `[lib] name = "<x>"`
so consumers still write `use <x>::…`.

## Decision

- Publish the reader as package **`luks-core`** with **`[lib] name = "luks"`**
  (`core/Cargo.toml`), so downstream code writes `use luks::LuksVolume`.
- Reference it inside the workspace as
  `luks = { version = "0.1", path = "core", package = "luks-core" }`
  (root `Cargo.toml` `[workspace.dependencies]`).
- Name the analyzer **`luks-forensic`** — the Pattern A single-format
  `<x>-core` + `<x>-forensic` pair.

## Consequences

The published package names are unambiguous on crates.io (`luks-core`,
`luks-forensic`) and never collide with the third-party `luks` crate, while the
import path stays the clean `luks::`. The two names are settled before the crate
gained dependents, so no post-72h rename orphan is at risk. A consumer that also
depends on the third-party `luks` crate would face a name clash on the import
path — an accepted, low-probability cost given the fleet convention favors import
brevity.
