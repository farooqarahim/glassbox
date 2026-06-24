//! How the two halves of a hybrid signature are combined for
//! verification (spec §13.3).
//!
//! v0.1 hard-coded the AND combiner. v0.2 promotes the combiner to a
//! proper enum that is parsed from the algorithm string stored in the
//! [`KeyRegistryEntry`](crate::key_registry::KeyRegistryEntry). This
//! keeps the wire-level [`Record`](crate::record::Record) structure
//! unchanged — old chains stay byte-identical — while letting different
//! tenants and different streams pick different combiner semantics.
//!
//! ## Why combiners matter
//!
//! "Hybrid" is not free. Pure-AND signatures are stronger than either
//! alone, but a real-world cryptanalytic break in one half puts every
//! such record into "cannot verify until rotated" the day it lands.
//! An OR combiner is weaker in steady state but lets a tenant keep
//! verifying their own history through an emergency-rotation window.
//! The choice is a real one and is operator-controlled; this module
//! makes it explicit on the chain rather than implicit in code.

use crate::crypto::{HybridPublicKey, HybridSignature};
use crate::errors::{Error, Result};

/// How both halves of a hybrid signature combine at verify time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureCombiner {
    /// Both halves must verify (the default and the only combiner v0.1
    /// produced). Strongest in steady state.
    And,
    /// At least one half must verify. Used only during an emergency
    /// rotation window after a real-world break of one of the schemes.
    Or,
}

impl SignatureCombiner {
    /// Parse the combiner from the suffix of a
    /// [`KeyRegistryEntry::algorithm`](crate::key_registry::KeyRegistryEntry)
    /// string. Returns `None` for unrecognised algorithms.
    ///
    /// The expected algorithm string shape is
    /// `hybrid:<classical>+<pq>/<combiner>` where `<combiner>` is one
    /// of `and` or `or` — matching the constants in
    /// [`crate`](crate::ALGORITHM_HYBRID_ED25519_MLDSA65).
    #[must_use]
    pub fn from_algorithm(s: &str) -> Option<Self> {
        let (_, combiner) = s.rsplit_once('/')?;
        match combiner {
            "and" => Some(Self::And),
            "or" => Some(Self::Or),
            _ => None,
        }
    }

    /// Verify a hybrid signature over `msg` under this combiner.
    pub fn verify(self, key: &HybridPublicKey, msg: &[u8], sig: &HybridSignature) -> Result<()> {
        match self {
            Self::And => key.verify(msg, sig),
            Self::Or => {
                // Use the AND verifier's two halves directly. The
                // `HybridPublicKey::verify` impl is the only path that
                // touches signature bytes, so we drive it twice with
                // single-half signatures synthesised from the input.
                let only_ed = HybridSignature {
                    ed25519: sig.ed25519,
                    mldsa: sig.mldsa.clone(),
                };
                let ed_ok = key.verify(msg, &only_ed).is_ok();
                if ed_ok {
                    return Ok(());
                }
                // If AND failed, at least one of the two halves was bad.
                // Try each half in isolation by intentionally corrupting
                // the other and observing which side the original side
                // came from. Because `HybridPublicKey::verify` only
                // returns `Ok` when BOTH halves verify, we cannot use it
                // alone for an OR check; instead we call the underlying
                // primitives directly. See the helper below.
                or_verify_either_half(key, msg, sig)
            }
        }
    }
}

/// OR-mode helper: verify each half independently. Either alone is
/// sufficient. Used during emergency rotations after a break.
fn or_verify_either_half(key: &HybridPublicKey, msg: &[u8], sig: &HybridSignature) -> Result<()> {
    use ed25519_dalek::{Signature as EdSig, Verifier as _, VerifyingKey as EdVk};

    if let Ok(ed_pk) = EdVk::from_bytes(&key.ed25519) {
        let ed_sig = EdSig::from_bytes(&sig.ed25519);
        if ed_pk.verify(msg, &ed_sig).is_ok() {
            return Ok(());
        }
    }

    if sig.mldsa.len() == crate::crypto::MLDSA65_SIG_LEN
        && key.mldsa.len() == crate::crypto::MLDSA65_PK_LEN
    {
        let mut pk_arr = ml_dsa::EncodedVerifyingKey::<ml_dsa::MlDsa65>::default();
        let pk_slice: &mut [u8] = &mut pk_arr;
        pk_slice.copy_from_slice(&key.mldsa);
        let ml_pk = ml_dsa::VerifyingKey::<ml_dsa::MlDsa65>::decode(&pk_arr);

        let mut sig_arr = ml_dsa::EncodedSignature::<ml_dsa::MlDsa65>::default();
        let sig_slice: &mut [u8] = &mut sig_arr;
        sig_slice.copy_from_slice(&sig.mldsa);
        if let Some(ml_sig) = ml_dsa::Signature::<ml_dsa::MlDsa65>::decode(&sig_arr) {
            if ml_pk.verify_with_context(msg, &[], &ml_sig) {
                return Ok(());
            }
        }
    }

    Err(Error::Signature(
        "neither Ed25519 nor ML-DSA-65 half verified under OR combiner".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HybridKeypair;

    #[test]
    fn parses_known_algorithm_strings() {
        assert_eq!(
            SignatureCombiner::from_algorithm(crate::ALGORITHM_HYBRID_ED25519_MLDSA65),
            Some(SignatureCombiner::And)
        );
        assert_eq!(
            SignatureCombiner::from_algorithm(crate::ALGORITHM_HYBRID_ED25519_MLDSA65_OR),
            Some(SignatureCombiner::Or)
        );
    }

    #[test]
    fn rejects_unknown_combiner() {
        assert_eq!(
            SignatureCombiner::from_algorithm("hybrid:ed25519+ml-dsa-65/xor"),
            None
        );
        assert_eq!(SignatureCombiner::from_algorithm("ed25519"), None);
    }

    #[test]
    fn and_combiner_requires_both_halves() {
        let kp = HybridKeypair::generate().unwrap();
        let pk = kp.public_key();
        let sig = kp.sign(b"x");
        SignatureCombiner::And.verify(&pk, b"x", &sig).unwrap();

        let mut bad = sig.clone();
        bad.ed25519[0] ^= 1;
        assert!(SignatureCombiner::And.verify(&pk, b"x", &bad).is_err());
    }

    #[test]
    fn or_combiner_accepts_either_half() {
        let kp = HybridKeypair::generate().unwrap();
        let pk = kp.public_key();
        let mut sig = kp.sign(b"x");
        // Break the ML-DSA half; the Ed25519 half still verifies, so OR
        // must accept.
        sig.mldsa[0] ^= 1;
        SignatureCombiner::Or.verify(&pk, b"x", &sig).unwrap();
    }

    #[test]
    fn or_combiner_rejects_when_both_halves_broken() {
        let kp = HybridKeypair::generate().unwrap();
        let pk = kp.public_key();
        let mut sig = kp.sign(b"x");
        sig.ed25519[0] ^= 1;
        sig.mldsa[0] ^= 1;
        assert!(SignatureCombiner::Or.verify(&pk, b"x", &sig).is_err());
    }
}
