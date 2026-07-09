//! # luks-forensic — LUKS metadata anomaly auditor
//!
//! Emits severity-graded observations over the cipher, KDF, and keyslot
//! parameters a LUKS header exposes *without* any passphrase. Findings are
//! observations, never verdicts — the examiner draws conclusions.

#![forbid(unsafe_code)]
#![cfg_attr(test, allow(clippy::unwrap_used, clippy::expect_used))]

use luks::Luks1Header;

/// Severity of a LUKS finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    /// Informational context.
    Info,
    /// A weak but not broken parameter.
    Low,
    /// A materially weak configuration.
    Medium,
}

/// A classified LUKS metadata observation with a stable code and note.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Anomaly {
    /// Severity.
    pub severity: Severity,
    /// Stable, scheme-prefixed machine code.
    pub code: &'static str,
    /// Human-readable note including the offending value.
    pub note: String,
}

/// Audit a parsed LUKS1 header, returning classified anomalies. Pure.
#[must_use]
pub fn audit1(header: &Luks1Header) -> Vec<Anomaly> {
    let mut out = Vec::new();

    // Cipher mode weaker than XTS.
    if header.cipher_mode.starts_with("cbc") || header.cipher_mode.starts_with("ecb") {
        out.push(Anomaly {
            severity: Severity::Low,
            code: "LUKS-WEAK-CIPHER-MODE",
            note: format!(
                "cipher mode is {} (weaker than xts-plain64)",
                header.cipher_mode
            ),
        });
    }

    // SHA-1 KDF hash.
    if header.hash_spec == "sha1" {
        out.push(Anomaly {
            severity: Severity::Low,
            code: "LUKS-WEAK-KDF-HASH",
            note: "KDF/AF hash is sha1".to_string(),
        });
    }

    // Very low PBKDF2 iteration count on any active keyslot.
    for (i, slot) in header.keyslots.iter().enumerate() {
        if slot.is_active() && slot.iterations < 1000 {
            out.push(Anomaly {
                severity: Severity::Medium,
                code: "LUKS-LOW-KDF-ITERATIONS",
                note: format!(
                    "keyslot {i} has only {} PBKDF2 iterations (brute-force risk)",
                    slot.iterations
                ),
            });
        }
    }

    // Keyslot inventory (Info).
    let active = header.active_keyslots().count();
    out.push(Anomaly {
        severity: Severity::Info,
        code: "LUKS-KEYSLOT-INVENTORY",
        note: format!("{active} active keyslot(s) of 8"),
    });

    out
}

#[cfg(test)]
mod tests;
