//! On-ledger key registry entries.
//!
//! Per spec §12.7 the key registry is itself a sequence of records on a
//! special administrative stream. Each `KeyRegistryEntry` declares a
//! key's identifier, algorithm, public material, validity window, and
//! status.
//!
//! In v0.1 the administrative-stream isolation is logical only: the
//! verifier accepts `RecordBody::KeyRegistry` entries on the same chain
//! as `Interaction` records, and the storage layer is told to surface
//! them when resolving a `key_id`. Splitting administrative records onto
//! a separate stream is deferred to v0.2.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;

use crate::crypto::HybridPublicKey;

/// The status of a key, per spec §12.7.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum KeyStatus {
    /// Key is currently usable to sign new records.
    #[serde(rename = "active")]
    Active,
    /// Key has been rotated out; still valid for verifying old records.
    #[serde(rename = "rotated")]
    Rotated,
    /// Key has been revoked; records signed during the suspected-compromise
    /// window are flagged by the verifier.
    #[serde(rename = "revoked")]
    Revoked,
}

/// A key-registry administrative record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct KeyRegistryEntry {
    /// Caller-meaningful identifier, e.g. `tenant-acme/active-2026`.
    pub key_id: String,
    /// Algorithm string from the registry; in v0.1 always
    /// [`crate::ALGORITHM_HYBRID_ED25519_MLDSA65`].
    pub algorithm: String,
    /// The verification-only key material.
    pub public_key: HybridPublicKey,
    /// Earliest time (inclusive) the key is valid.
    #[serde(with = "time::serde::rfc3339")]
    pub valid_from: OffsetDateTime,
    /// Latest time (exclusive) the key is valid, or `None` for open-ended.
    #[serde(with = "time::serde::rfc3339::option", default)]
    pub valid_to: Option<OffsetDateTime>,
    /// Current status.
    pub status: KeyStatus,
}
