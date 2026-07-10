//! # luks-forensic — LUKS metadata anomaly auditor
//!
//! Emits severity-graded [`forensicnomicon::report::Finding`]s over the cipher,
//! KDF, and keyslot parameters a LUKS header exposes *without* any passphrase.
//! Findings are observations, never verdicts — the examiner draws conclusions.
//!
//! - `LUKS-WEAK-CIPHER-MODE` — CBC/ECB is weaker than XTS (Low).
//! - `LUKS-WEAK-KDF-HASH` — a SHA-1 KDF/AF hash (Low).
//! - `LUKS-LOW-KDF-ITERATIONS` — a keyslot with a brute-forceable iteration count (Medium).
//! - `LUKS-KEYSLOT-INVENTORY` — the active-keyslot count (Info).

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use forensicnomicon::report::{Category, Evidence, Finding, Observation, Severity, Source};
use luks::Luks1Header;

/// The producing analyzer name embedded in emitted findings' `Source`.
pub const ANALYZER: &str = "luks-forensic";

/// A classified LUKS metadata observation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AnomalyKind {
    /// The volume cipher mode is CBC/ECB (weaker than XTS).
    WeakCipherMode {
        /// The offending cipher mode.
        mode: String,
    },
    /// The KDF/anti-forensic hash is SHA-1.
    WeakKdfHash {
        /// The offending hash spec.
        hash: String,
    },
    /// A keyslot has a very low PBKDF2 iteration count.
    LowKdfIterations {
        /// Keyslot index.
        slot: usize,
        /// The iteration count.
        iterations: u32,
    },
    /// The count of active keyslots (one per header).
    KeyslotInventory {
        /// Number of active keyslots.
        active: usize,
    },
}

impl AnomalyKind {
    /// Severity — the single source of truth for this kind.
    #[must_use]
    pub fn severity(&self) -> Severity {
        match self {
            AnomalyKind::WeakCipherMode { .. } | AnomalyKind::WeakKdfHash { .. } => Severity::Low,
            AnomalyKind::LowKdfIterations { .. } => Severity::Medium,
            AnomalyKind::KeyslotInventory { .. } => Severity::Info,
        }
    }

    /// Stable, scheme-prefixed machine code (published contract).
    #[must_use]
    pub fn code(&self) -> &'static str {
        match self {
            AnomalyKind::WeakCipherMode { .. } => "LUKS-WEAK-CIPHER-MODE",
            AnomalyKind::WeakKdfHash { .. } => "LUKS-WEAK-KDF-HASH",
            AnomalyKind::LowKdfIterations { .. } => "LUKS-LOW-KDF-ITERATIONS",
            AnomalyKind::KeyslotInventory { .. } => "LUKS-KEYSLOT-INVENTORY",
        }
    }

    /// Analytical lens.
    #[must_use]
    pub fn category(&self) -> Category {
        match self {
            AnomalyKind::WeakCipherMode { .. }
            | AnomalyKind::WeakKdfHash { .. }
            | AnomalyKind::LowKdfIterations { .. } => Category::Integrity,
            AnomalyKind::KeyslotInventory { .. } => Category::Provenance,
        }
    }

    /// Human-readable note including the offending value.
    #[must_use]
    pub fn note(&self) -> String {
        match self {
            AnomalyKind::WeakCipherMode { mode } => {
                format!("cipher mode is {mode} (weaker than xts-plain64)")
            }
            AnomalyKind::WeakKdfHash { hash } => format!("KDF/AF hash is {hash}"),
            AnomalyKind::LowKdfIterations { slot, iterations } => {
                format!("keyslot {slot} has only {iterations} PBKDF2 iterations (brute-force risk)")
            }
            AnomalyKind::KeyslotInventory { active } => format!("{active} active keyslot(s) of 8"),
        }
    }

    fn evidence(&self) -> Vec<Evidence> {
        match self {
            AnomalyKind::WeakCipherMode { mode } => vec![evidence("cipher_mode", mode.clone())],
            AnomalyKind::WeakKdfHash { hash } => vec![evidence("hash_spec", hash.clone())],
            AnomalyKind::LowKdfIterations { slot, iterations } => vec![
                evidence("keyslot", slot.to_string()),
                evidence("iterations", iterations.to_string()),
            ],
            AnomalyKind::KeyslotInventory { active } => {
                vec![evidence("active_keyslots", active.to_string())]
            }
        }
    }
}

fn evidence(field: &str, value: String) -> Evidence {
    Evidence {
        field: field.to_string(),
        value,
        location: None,
    }
}

/// A LUKS forensic anomaly: an observation graded by severity, with a stable code
/// and note derived from its [`AnomalyKind`] so they cannot drift.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity, derived from `kind`.
    pub severity: Severity,
    /// Stable machine-readable code, derived from `kind`.
    pub code: &'static str,
    /// The classified anomaly.
    pub kind: AnomalyKind,
    /// Human-readable note, derived from `kind`.
    pub note: String,
}

impl Anomaly {
    /// Build an [`Anomaly`], deriving severity/code/note from `kind`.
    #[must_use]
    pub fn new(kind: AnomalyKind) -> Self {
        Anomaly {
            severity: kind.severity(),
            code: kind.code(),
            note: kind.note(),
            kind,
        }
    }
}

impl Observation for Anomaly {
    fn severity(&self) -> Option<Severity> {
        Some(self.severity)
    }
    fn code(&self) -> &'static str {
        self.code
    }
    fn note(&self) -> String {
        self.note.clone()
    }
    fn category(&self) -> Category {
        self.kind.category()
    }
    fn evidence(&self) -> Vec<Evidence> {
        self.kind.evidence()
    }
}

/// Audit a parsed LUKS1 header, returning classified anomalies. Pure.
#[must_use]
pub fn audit1(header: &Luks1Header) -> Vec<Anomaly> {
    let mut out = Vec::new();

    if header.cipher_mode.starts_with("cbc") || header.cipher_mode.starts_with("ecb") {
        out.push(Anomaly::new(AnomalyKind::WeakCipherMode {
            mode: header.cipher_mode.clone(),
        }));
    }

    if header.hash_spec == "sha1" {
        out.push(Anomaly::new(AnomalyKind::WeakKdfHash {
            hash: header.hash_spec.clone(),
        }));
    }

    for (i, slot) in header.keyslots.iter().enumerate() {
        if slot.is_active() && slot.iterations < 1000 {
            out.push(Anomaly::new(AnomalyKind::LowKdfIterations {
                slot: i,
                iterations: slot.iterations,
            }));
        }
    }

    out.push(Anomaly::new(AnomalyKind::KeyslotInventory {
        active: header.active_keyslots().count(),
    }));

    out
}

/// Audit a LUKS1 header and map each anomaly to a canonical [`Finding`], tagged
/// with the producing [`Source`] (`scope` names the evidence).
#[must_use]
pub fn audit1_findings(header: &Luks1Header, scope: impl Into<String>) -> Vec<Finding> {
    let source = Source {
        analyzer: ANALYZER.to_string(),
        scope: scope.into(),
        version: Some(env!("CARGO_PKG_VERSION").to_string()),
    };
    audit1(header)
        .into_iter()
        .map(|a| a.to_finding(source.clone()))
        .collect()
}

#[cfg(test)]
mod tests;
