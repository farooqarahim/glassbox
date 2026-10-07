//! Hybrid Ed25519 + ML-DSA-65 signing.
//!
//! Per spec §13.3, every record carries two signatures combined under
//! an AND combiner: a classical Ed25519 signature and a NIST
//! ML-DSA-65 signature. Both must verify for the record to be accepted.
//!
//! This module exposes:
//!
//! - [`HybridKeypair`] — the private/public material, with serialization
//!   in a deterministic bag-of-bytes layout (so a key file produced by
//!   one version can be read by another).
//! - [`HybridPublicKey`] — the verification-only half. Embedded in
//!   [`KeyRegistryEntry`](crate::key_registry::KeyRegistryEntry) records.
//! - [`HybridSignature`] — a record's combined signature value.
//!
//! ## Where the bytes come from
//!
//! `ed25519-dalek` requires a 32-byte secret seed; `ml-dsa` requires a
//! 32-byte ξ value plus deterministic key derivation. We sample both
//! from the system CSPRNG (`rand_core::OsRng`) on `generate()` and
//! store both raw seeds so the keypair is reproducible from its
//! on-disk form.

use ed25519_dalek::{
    SIGNATURE_LENGTH, Signature as Ed25519Signature, SigningKey as Ed25519Signing,
    VerifyingKey as Ed25519Verifying,
};
#[allow(unused_imports)]
use ed25519_dalek::{Signer, Verifier};
use ml_dsa::signature::{Keypair as _, Signer as _};
use ml_dsa::{
    B32, EncodedVerifyingKey as MlEncodedVerifying, MlDsa65, Signature as MlSignature,
    SigningKey as MlSigning, VerifyingKey as MlVerifying,
};
use rand_core::{OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::ZeroizeOnDrop;

use crate::errors::{Error, Result};

/// Length of a serialized Ed25519 public key.
pub const ED25519_PK_LEN: usize = 32;
/// Length of a serialized ML-DSA-65 public key.
pub const MLDSA65_PK_LEN: usize = 1952;
/// Length of a serialized ML-DSA-65 signature.
pub const MLDSA65_SIG_LEN: usize = 3309;
/// Length of an Ed25519 signature.
pub const ED25519_SIG_LEN: usize = SIGNATURE_LENGTH;

/// A hybrid keypair: classical Ed25519 plus post-quantum ML-DSA-65.
///
/// Drop zeroises the secret material. Clone is **deliberately not
/// implemented**; secrets should be moved, not duplicated.
#[derive(ZeroizeOnDrop)]
pub struct HybridKeypair {
    /// 32-byte seed for Ed25519. Held so that on-disk persistence of
    /// the keypair is trivially reproducible.
    ed25519_seed: [u8; 32],
    /// 32-byte ξ value for ML-DSA-65 deterministic key generation.
    mldsa_xi: [u8; 32],
}

impl HybridKeypair {
    /// Generate a fresh keypair from the system CSPRNG.
    pub fn generate() -> Result<Self> {
        let mut ed25519_seed = [0u8; 32];
        let mut mldsa_xi = [0u8; 32];
        OsRng.fill_bytes(&mut ed25519_seed);
        OsRng.fill_bytes(&mut mldsa_xi);
        Ok(Self {
            ed25519_seed,
            mldsa_xi,
        })
    }

    /// Reconstruct a keypair from its 64-byte serialized form
    /// (`ed25519_seed || mldsa_xi`).
    pub fn from_bytes(bytes: &[u8; 64]) -> Self {
        let mut ed25519_seed = [0u8; 32];
        let mut mldsa_xi = [0u8; 32];
        ed25519_seed.copy_from_slice(&bytes[..32]);
        mldsa_xi.copy_from_slice(&bytes[32..]);
        Self {
            ed25519_seed,
            mldsa_xi,
        }
    }

    /// Serialize to the 64-byte concatenation `ed25519_seed || mldsa_xi`.
    pub fn to_bytes(&self) -> [u8; 64] {
        let mut out = [0u8; 64];
        out[..32].copy_from_slice(&self.ed25519_seed);
        out[32..].copy_from_slice(&self.mldsa_xi);
        out
    }

    /// Sign a message with both halves.
    pub fn sign(&self, msg: &[u8]) -> HybridSignature {
        let ed_sk = Ed25519Signing::from_bytes(&self.ed25519_seed);
        let ed_sig: Ed25519Signature = ed_sk.sign(msg);

        let xi: B32 = self.mldsa_xi.into();
        // `from_seed` is FIPS-204 `ML-DSA.KeyGen_internal`; the `Signer`
        // impl on `SigningKey` is the *deterministic* sign variant with an
        // empty context, so a given (key, message) always yields the same
        // signature — required for a reproducible ledger.
        let ml_sk: MlSigning<MlDsa65> = MlSigning::from_seed(&xi);
        let ml_sig: MlSignature<MlDsa65> = ml_sk.sign(msg);

        let ml_sig_enc = ml_sig.encode();
        HybridSignature {
            ed25519: ed_sig.to_bytes(),
            mldsa: ml_sig_enc.to_vec(),
        }
    }

    /// Derive the public-only half of this keypair.
    pub fn public_key(&self) -> HybridPublicKey {
        let ed_sk = Ed25519Signing::from_bytes(&self.ed25519_seed);
        let ed_pk: Ed25519Verifying = ed_sk.verifying_key();

        let xi: B32 = self.mldsa_xi.into();
        let ml_sk: MlSigning<MlDsa65> = MlSigning::from_seed(&xi);
        let ml_pk: MlVerifying<MlDsa65> = ml_sk.verifying_key();

        let ml_pk_enc = ml_pk.encode();
        HybridPublicKey {
            ed25519: ed_pk.to_bytes(),
            mldsa: ml_pk_enc.to_vec(),
        }
    }
}

impl core::fmt::Debug for HybridKeypair {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HybridKeypair")
            .field("ed25519_seed", &"<redacted>")
            .field("mldsa_xi", &"<redacted>")
            .finish()
    }
}

/// The verification-only half of a hybrid keypair.
///
/// This struct is what gets embedded in
/// [`KeyRegistryEntry`](crate::key_registry::KeyRegistryEntry) records,
/// so its serialization is part of canonical form and is signed over.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridPublicKey {
    /// 32 bytes, base64-encoded in canonical form.
    #[serde(with = "crate::crypto::serde_b64_arr32")]
    pub ed25519: [u8; ED25519_PK_LEN],
    /// 1952 bytes, base64-encoded in canonical form.
    #[serde(with = "crate::crypto::serde_b64_vec")]
    pub mldsa: Vec<u8>,
}

impl HybridPublicKey {
    /// Verify a hybrid signature over `msg`. Both halves must verify.
    pub fn verify(&self, msg: &[u8], sig: &HybridSignature) -> Result<()> {
        let ed_pk = Ed25519Verifying::from_bytes(&self.ed25519).map_err(Error::crypto)?;
        let ed_sig = Ed25519Signature::from_bytes(&sig.ed25519);
        ed_pk
            .verify(msg, &ed_sig)
            .map_err(|e| Error::signature(format!("ed25519: {e}")))?;

        if self.mldsa.len() != MLDSA65_PK_LEN {
            return Err(Error::crypto(format!(
                "ml-dsa public key wrong length: {} (expected {})",
                self.mldsa.len(),
                MLDSA65_PK_LEN
            )));
        }
        let mut pk_arr = MlEncodedVerifying::<MlDsa65>::default();
        let pk_slice: &mut [u8] = &mut pk_arr;
        pk_slice.copy_from_slice(&self.mldsa);
        let ml_pk = MlVerifying::<MlDsa65>::decode(&pk_arr);

        if sig.mldsa.len() != MLDSA65_SIG_LEN {
            return Err(Error::signature(format!(
                "ml-dsa signature wrong length: {} (expected {})",
                sig.mldsa.len(),
                MLDSA65_SIG_LEN
            )));
        }
        let mut sig_arr = ml_dsa::EncodedSignature::<MlDsa65>::default();
        let sig_slice: &mut [u8] = &mut sig_arr;
        sig_slice.copy_from_slice(&sig.mldsa);
        let ml_sig = MlSignature::<MlDsa65>::decode(&sig_arr)
            .ok_or_else(|| Error::signature("ml-dsa signature failed to decode"))?;
        // Signing uses the deterministic, empty-context variant; verify
        // with the matching empty context. Returns bool, not Result.
        if !ml_pk.verify_with_context(msg, &[], &ml_sig) {
            return Err(Error::signature("ml-dsa-65: signature did not verify"));
        }

        Ok(())
    }

    /// Stable bag-of-bytes serialization: `ed25519_pk || mldsa_pk`.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(ED25519_PK_LEN + self.mldsa.len());
        out.extend_from_slice(&self.ed25519);
        out.extend_from_slice(&self.mldsa);
        out
    }
}

/// A combined hybrid signature.
///
/// The wire form is two byte fields, each base64-encoded in canonical
/// form so the canonical hash is deterministic.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HybridSignature {
    /// Ed25519 signature, exactly 64 bytes.
    #[serde(with = "crate::crypto::serde_b64_arr64")]
    pub ed25519: [u8; ED25519_SIG_LEN],
    /// ML-DSA-65 signature, exactly [`MLDSA65_SIG_LEN`] bytes.
    #[serde(with = "crate::crypto::serde_b64_vec")]
    pub mldsa: Vec<u8>,
}

/// Reuse for any 32-byte array field that should serialize as base64.
pub(crate) mod serde_b64_arr32 {
    use base64ct::{Base64, Encoding};
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub(crate) fn serialize<S: Serializer>(v: &[u8; 32], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&Base64::encode_string(v))
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 32], D::Error> {
        let s = String::deserialize(de)?;
        let bytes = Base64::decode_vec(&s).map_err(D::Error::custom)?;
        let arr: [u8; 32] = bytes.try_into().map_err(|v: Vec<u8>| {
            D::Error::custom(format!("expected 32 bytes, got {}", v.len()))
        })?;
        Ok(arr)
    }
}

/// Reuse for any 64-byte array field that should serialize as base64.
pub(crate) mod serde_b64_arr64 {
    use base64ct::{Base64, Encoding};
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub(crate) fn serialize<S: Serializer>(v: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&Base64::encode_string(v))
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let s = String::deserialize(de)?;
        let bytes = Base64::decode_vec(&s).map_err(D::Error::custom)?;
        let arr: [u8; 64] = bytes.try_into().map_err(|v: Vec<u8>| {
            D::Error::custom(format!("expected 64 bytes, got {}", v.len()))
        })?;
        Ok(arr)
    }
}

/// Reuse for variable-length byte arrays in canonical form.
pub(crate) mod serde_b64_vec {
    use base64ct::{Base64, Encoding};
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    pub(crate) fn serialize<S: Serializer>(v: &Vec<u8>, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&Base64::encode_string(v))
    }
    pub(crate) fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        Base64::decode_vec(&s).map_err(D::Error::custom)
    }
}

/// Public alias of the crate-private `serde_b64_vec` for downstream crates and for
/// fields of types in [`crate::record`] that need the same encoding.
pub mod serde_b64_vec_pub {
    use base64ct::{Base64, Encoding};
    use serde::{Deserialize, Deserializer, Serializer, de::Error as _};

    /// Serialize a `Vec<u8>` as a base64 string in canonical form.
    pub fn serialize<S: Serializer>(v: &Vec<u8>, ser: S) -> Result<S::Ok, S::Error> {
        ser.serialize_str(&Base64::encode_string(v))
    }
    /// Deserialize a base64-encoded `Vec<u8>` from canonical form.
    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<Vec<u8>, D::Error> {
        let s = String::deserialize(de)?;
        Base64::decode_vec(&s).map_err(D::Error::custom)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_and_verify_roundtrip() {
        let kp = HybridKeypair::generate().unwrap();
        let pk = kp.public_key();
        let msg = b"glassbox: tamper-evident audit ledger";
        let sig = kp.sign(msg);
        pk.verify(msg, &sig).expect("hybrid signature verifies");
    }

    #[test]
    fn message_mutation_breaks_verify() {
        let kp = HybridKeypair::generate().unwrap();
        let pk = kp.public_key();
        let sig = kp.sign(b"original");
        assert!(pk.verify(b"original!", &sig).is_err());
    }

    #[test]
    fn signature_byte_mutation_breaks_verify() {
        let kp = HybridKeypair::generate().unwrap();
        let pk = kp.public_key();
        let mut sig = kp.sign(b"msg");
        sig.ed25519[0] ^= 0x01;
        let err = pk.verify(b"msg", &sig).unwrap_err();
        match err {
            Error::Signature(_) => {}
            other => panic!("expected signature error, got {other:?}"),
        }
    }

    #[test]
    fn mldsa_signature_byte_mutation_breaks_verify() {
        let kp = HybridKeypair::generate().unwrap();
        let pk = kp.public_key();
        let mut sig = kp.sign(b"msg");
        sig.mldsa[0] ^= 0x01;
        let err = pk.verify(b"msg", &sig).unwrap_err();
        match err {
            Error::Signature(_) => {}
            other => panic!("expected signature error, got {other:?}"),
        }
    }

    #[test]
    fn keypair_roundtrips_through_bytes() {
        let kp = HybridKeypair::generate().unwrap();
        let bytes = kp.to_bytes();
        let restored = HybridKeypair::from_bytes(&bytes);
        assert_eq!(kp.public_key(), restored.public_key());
        let sig = restored.sign(b"hello");
        kp.public_key().verify(b"hello", &sig).unwrap();
    }

    #[test]
    fn public_key_serde_roundtrip() {
        let kp = HybridKeypair::generate().unwrap();
        let pk = kp.public_key();
        let s = serde_json::to_string(&pk).unwrap();
        let restored: HybridPublicKey = serde_json::from_str(&s).unwrap();
        assert_eq!(pk, restored);
    }

    #[test]
    fn ed25519_pk_constant_matches_runtime_length() {
        let kp = HybridKeypair::generate().unwrap();
        assert_eq!(kp.public_key().ed25519.len(), ED25519_PK_LEN);
    }

    #[test]
    fn mldsa_pk_and_sig_constants_match_runtime_lengths() {
        let kp = HybridKeypair::generate().unwrap();
        let pk = kp.public_key();
        assert_eq!(pk.mldsa.len(), MLDSA65_PK_LEN);
        let sig = kp.sign(b"x");
        assert_eq!(sig.mldsa.len(), MLDSA65_SIG_LEN);
    }
}
