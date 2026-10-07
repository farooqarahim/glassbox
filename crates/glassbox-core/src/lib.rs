//! Glassbox cryptographic core.
//!
//! This crate is the only place in the workspace where cryptography
//! lives. Every byte that gets signed passes through this crate; see
//! the Glassbox specification (§11.1 and §13) for the contract.
//!
//! # What lives here
//!
//! - [`canonical`] — RFC 8785 canonical JSON, used as the byte-stable
//!   serialization that gets hashed and signed.
//! - [`record`] — the [`Record`] and related schema
//!   structures (content references, model and prompt fingerprints,
//!   agent trajectory linkage).
//! - [`chain`] — hash-chain linkage between records.
//! - [`crypto`] — hybrid Ed25519 + ML-DSA-65 keypair, signature, and
//!   verification.
//! - [`merkle`] — a binary SHA-256 Merkle tree and O(log N) inclusion
//!   proofs over a batch of records.
//! - [`key_registry`] — on-ledger key administration records.
//! - [`errors`] — the unified error type the rest of the workspace consumes.
//!
//! # Invariants
//!
//! The crate enforces the invariants enumerated in spec §13.11. Tests
//! exercise each one adversarially under `tests/`.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(missing_docs)]

pub mod canonical;
pub mod chain;
pub mod combiner;
pub mod crypto;
pub mod errors;
pub mod key_registry;
pub mod merkle;
pub mod nl_query;
pub mod record;

pub use combiner::SignatureCombiner;
pub use errors::{Error, Result};
pub use record::{
    ApprovalDecision, AutomationLevel, ContentRef, CorpusAnchor, CorpusRef, CrossChainProofStep,
    CrossChainRef, DecisionContext, EndOfRetentionAction, HashAlgorithm, HumanApproval, LegalHold,
    LegalHoldRelease, MerkleRootEntry, ModelFingerprint, PromptFingerprint, Record, RecordBody,
    RedactionReason, RedactionRecord, RetentionPolicy, SignedRecord, SignedTreeHead, SpanKind, Tag,
    TimestampAnchor, ToolInvocation, WitnessCountersignature,
};

/// The schema version this build of `glassbox-core` produces and accepts.
///
/// Records signed under a different schema version are still verifiable
/// because every record's `schema_version` field is itself part of
/// canonical form (see spec §12.6) — a v0.3 verifier presented with a
/// v0.1 or v0.2 record recomputes the older canonical bytes and the
/// older hash.
pub const SCHEMA_VERSION: &str = "0.6.0";

/// The canonical algorithm string for hybrid Ed25519 + ML-DSA-65 under
/// the AND combiner: both signatures must verify.
///
/// Verifiers consult the resolved [`key_registry::KeyRegistryEntry`] for
/// the algorithm string of any given record; this constant is what new
/// keys default to.
pub const ALGORITHM_HYBRID_ED25519_MLDSA65: &str = "hybrid:ed25519+ml-dsa-65/and";

/// The canonical algorithm string for hybrid Ed25519 + ML-DSA-65 under
/// the OR combiner: at least one signature must verify.
///
/// **Not** a default. This combiner exists for emergency rotation
/// scenarios in which one half of the hybrid scheme has been broken
/// in practice and a switch-over period is needed. Keys registered
/// under this string MUST also carry a `valid_to` (spec §13.3).
pub const ALGORITHM_HYBRID_ED25519_MLDSA65_OR: &str = "hybrid:ed25519+ml-dsa-65/or";

/// The genesis previous-hash value: 32 zero bytes (see spec §13.2).
pub const GENESIS_PREV_HASH: [u8; 32] = [0u8; 32];
