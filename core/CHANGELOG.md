# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.8](https://github.com/SecurityRonin/luks-forensic/compare/luks-core-v0.1.7...luks-core-v0.1.8) - 2026-08-07

### Fixed

- *(crypto)* GREEN - bound the master-key length before allocating or calibrating
- *(luks2)* GREEN - bound a LUKS2 unlock in aggregate, closing #10
- *(security)* bound an unlock in aggregate, not just per derivation ([#10](https://github.com/SecurityRonin/luks-forensic/pull/10))

## [0.1.7](https://github.com/SecurityRonin/luks-forensic/compare/luks-core-v0.1.6...luks-core-v0.1.7) - 2026-08-05

### Fixed

- *(af)* GREEN - bound the anti-forensic stripe count
- *(crypto)* bound the Argon2 costs the LUKS2 keyslot chooses
- *(crypto)* GREEN - bound key derivation by wall clock, refuse over budget

## [0.1.5](https://github.com/SecurityRonin/luks-forensic/compare/luks-core-v0.1.4...luks-core-v0.1.5) - 2026-07-19

### Fixed

- *(deps)* bump forensic-vfs 0.4 -> 0.5
