//! RFC 8785 canonical JSON serialization.
//!
//! All hashing and signing in Glassbox operates on the bytes produced
//! by this module. The properties we rely on (per spec §12.10):
//!
//! - Object keys are emitted in lexicographic order of their UTF-16
//!   code units (the RFC 8785 rule).
//! - There is no insignificant whitespace.
//! - Numbers are emitted in their shortest round-trip form.
//! - The output is UTF-8 with no BOM.
//! - Null fields are emitted only when explicitly present; this crate
//!   relies on `serde(skip_serializing_if = "Option::is_none")` on
//!   optional fields so the producer side decides what to include.
//!
//! These properties are not enforced here — they are enforced by
//! `serde_jcs` 0.1, which implements RFC 8785 directly. We wrap that
//! crate to centralise the error type and to document the invariant
//! that any internal change touching this module is cryptographic.

use crate::errors::{Error, Result};

use sha2::{Digest, Sha256};

/// Produce the canonical-form bytes for any `serde::Serialize` value.
///
/// The output is deterministic across implementations of RFC 8785, so a
/// verifier in another language (or in a future Rust version with a
/// different JSON library) will produce byte-identical bytes for the
/// same logical value.
pub fn canonicalize<T: serde::Serialize>(value: &T) -> Result<Vec<u8>> {
    let s = serde_jcs::to_string(value).map_err(Error::canonical)?;
    Ok(s.into_bytes())
}

/// Convenience: canonicalize and SHA-256-hash in one call.
///
/// This is the single most-used helper in the crate; every record's
/// `this_hash` and every Merkle leaf flows through it.
pub fn canonical_hash<T: serde::Serialize>(value: &T) -> Result<[u8; 32]> {
    let bytes = canonicalize(value)?;
    Ok(sha256(&bytes))
}

/// SHA-256 of an arbitrary byte slice.
#[must_use]
pub fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    let out = h.finalize();
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&out);
    arr
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn key_order_is_deterministic_under_reorder() {
        let a = canonicalize(&json!({"a": 1, "b": 2, "c": 3})).unwrap();
        let b = canonicalize(&json!({"c": 3, "a": 1, "b": 2})).unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn whitespace_does_not_affect_canonical_form() {
        let raw1 = r#"{"x":1,"y":[1,2,3]}"#;
        let raw2 = "{ \"x\":  1 ,   \"y\" : [1, 2,3 ]  }";
        let v1: serde_json::Value = serde_json::from_str(raw1).unwrap();
        let v2: serde_json::Value = serde_json::from_str(raw2).unwrap();
        assert_eq!(canonicalize(&v1).unwrap(), canonicalize(&v2).unwrap());
    }

    #[test]
    fn nested_objects_canonicalize_recursively() {
        let v1 = json!({"outer": {"b": 1, "a": [{"y": 2, "x": 1}]}});
        let v2 = json!({"outer": {"a": [{"x": 1, "y": 2}], "b": 1}});
        assert_eq!(canonicalize(&v1).unwrap(), canonicalize(&v2).unwrap());
    }

    #[test]
    fn unicode_is_utf8_and_stable() {
        let v = json!({"name": "café", "emoji": "🔒"});
        let bytes = canonicalize(&v).unwrap();
        let s = core::str::from_utf8(&bytes).expect("valid utf-8");
        assert!(s.contains("café"));
        assert!(s.contains("🔒"));
    }

    #[test]
    fn sha256_known_vector() {
        // FIPS 180-2 standard test vector.
        let h = sha256(b"abc");
        assert_eq!(
            hex::encode(h),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn canonical_hash_matches_manual_canonicalize_then_hash() {
        let v = json!({"a": 1, "b": [2, 3]});
        let manual = sha256(&canonicalize(&v).unwrap());
        let combined = canonical_hash(&v).unwrap();
        assert_eq!(manual, combined);
    }
}
