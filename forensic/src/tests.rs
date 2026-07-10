use super::*;
use luks::Luks1Header;

/// Build a synthetic LUKS1 header buffer with tunable cipher mode, hash, and
/// keyslot-0 iterations.
fn header_bytes(mode: &[u8], hash: &[u8], iters: u32) -> Vec<u8> {
    let mut h = vec![0u8; 592];
    h[0..6].copy_from_slice(&[b'L', b'U', b'K', b'S', 0xba, 0xbe]);
    h[6..8].copy_from_slice(&1u16.to_be_bytes());
    h[8..11].copy_from_slice(b"aes");
    h[40..40 + mode.len()].copy_from_slice(mode);
    h[72..72 + hash.len()].copy_from_slice(hash);
    h[104..108].copy_from_slice(&4096u32.to_be_bytes());
    h[108..112].copy_from_slice(&64u32.to_be_bytes());
    // keyslot 0 active
    let b = 208;
    h[b..b + 4].copy_from_slice(&0x00AC_71F3u32.to_be_bytes());
    h[b + 4..b + 8].copy_from_slice(&iters.to_be_bytes());
    h[b + 44..b + 48].copy_from_slice(&4000u32.to_be_bytes());
    h
}

#[test]
fn clean_xts_sha256_header_only_inventory() {
    let h = Luks1Header::parse(&header_bytes(b"xts-plain64", b"sha256", 50000)).unwrap();
    let a = audit1(&h);
    assert_eq!(a.len(), 1);
    assert_eq!(a[0].code, "LUKS-KEYSLOT-INVENTORY");
    assert_eq!(a[0].severity, Severity::Info);
}

#[test]
fn flags_cbc_mode_and_sha1_and_low_iterations() {
    let h = Luks1Header::parse(&header_bytes(b"cbc-essiv:sha256", b"sha1", 100)).unwrap();
    let codes: Vec<_> = audit1(&h).into_iter().map(|x| x.code).collect();
    assert!(codes.contains(&"LUKS-WEAK-CIPHER-MODE"));
    assert!(codes.contains(&"LUKS-WEAK-KDF-HASH"));
    assert!(codes.contains(&"LUKS-LOW-KDF-ITERATIONS"));
}

#[test]
fn low_iterations_is_medium() {
    let h = Luks1Header::parse(&header_bytes(b"xts-plain64", b"sha256", 999)).unwrap();
    let low = audit1(&h)
        .into_iter()
        .find(|x| x.code == "LUKS-LOW-KDF-ITERATIONS")
        .unwrap();
    assert_eq!(low.severity, Severity::Medium);
}

#[test]
fn findings_carry_source_category_and_evidence() {
    // A header triggering all four anomaly kinds → exercises every Observation arm.
    let h = Luks1Header::parse(&header_bytes(b"cbc-essiv:sha256", b"sha1", 100)).unwrap();
    let findings = audit1_findings(&h, "container.luks");
    assert_eq!(findings.len(), 4);
    for f in &findings {
        assert_eq!(f.source.analyzer, "luks-forensic");
        assert_eq!(f.source.scope, "container.luks");
        assert!(f.source.version.is_some());
    }
    let inv = findings
        .iter()
        .find(|f| f.code == "LUKS-KEYSLOT-INVENTORY")
        .unwrap();
    assert_eq!(inv.category, Category::Provenance);
    assert_eq!(inv.severity, Some(Severity::Info));
    let weak = findings
        .iter()
        .find(|f| f.code == "LUKS-WEAK-CIPHER-MODE")
        .unwrap();
    assert_eq!(weak.category, Category::Integrity);
    assert!(!weak.evidence.is_empty());
    let low = findings
        .iter()
        .find(|f| f.code == "LUKS-LOW-KDF-ITERATIONS")
        .unwrap();
    assert_eq!(low.evidence.len(), 2);
}
