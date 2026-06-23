//! Chain construction and verification primitives.
//!
//! A *chain* is a sequence of [`SignedRecord`] values ordered by
//! `sequence`, on the same `stream_id`, where:
//!
//! 1. The first record has sequence 0 and `prev_hash_hex` of 64 zero
//!    hex chars (the genesis marker per spec §13.2).
//! 2. Every subsequent record's `prev_hash_hex` is the previous
//!    record's `this_hash_hex`.
//! 3. Every record's stored `this_hash_hex` matches the SHA-256 of its
//!    own canonical form.
//! 4. Every record's `signature` verifies under the registered key for
//!    its declared `key_id`.
//! 5. Every `MerkleRoot` body, when read in order, names a contiguous
//!    sequence range and a root that matches the SHA-256 Merkle root of
//!    those records' `this_hash` values.
//!
//! [`verify_chain`] checks all five invariants for a slice of records.
//! Storage backends call it; the CLI calls it via the storage backend.

use std::collections::{HashMap, HashSet};

use crate::canonical::sha256;
use crate::combiner::SignatureCombiner;
use crate::crypto::HybridPublicKey;
use crate::errors::{Error, Result};
use crate::key_registry::KeyRegistryEntry;
use crate::merkle;
use crate::record::{Record, RecordBody, SignedRecord};

/// Outcome of a verification walk.
#[derive(Clone, Debug, Default)]
pub struct VerificationReport {
    /// Number of records walked.
    pub records_walked: u64,
    /// Number of hybrid signatures verified.
    pub signatures_verified: u64,
    /// Number of Merkle roots cross-checked.
    pub merkle_roots_checked: u64,
    /// Number of tombstone records observed and validated against
    /// their targets.
    pub tombstones_observed: u64,
    /// Number of cross-chain references whose Merkle inclusion proof
    /// was validated against the embedded foreign STH (spec §29.2).
    pub cross_chain_refs_verified: u64,
    /// Sequence numbers that were marked redacted by a tombstone
    /// encountered later in the walk. Surfaced so exporters can apply
    /// per-record redaction markers without re-walking.
    pub redacted_sequences: Vec<u64>,
    /// `Some` if verification stopped early because of a discrepancy.
    pub failure: Option<VerificationFailure>,
}

impl VerificationReport {
    /// `true` if no failure was observed.
    #[must_use]
    pub fn is_ok(&self) -> bool {
        self.failure.is_none()
    }
}

/// Structured diagnostic naming the first observed invariant violation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerificationFailure {
    /// Sequence number of the offending record.
    pub sequence: u64,
    /// Human-readable reason. Maps to one of the [`Error`] variants.
    pub reason: String,
}

/// A resolved key plus the algorithm string declared for it.
#[derive(Clone, Debug)]
pub struct ResolvedKey {
    /// Verification material.
    pub public_key: HybridPublicKey,
    /// Algorithm string from the registry. Parsed by the verifier into
    /// a [`SignatureCombiner`].
    pub algorithm: String,
}

/// Trait implemented by anything that can resolve a `key_id` to a
/// [`ResolvedKey`] during verification.
///
/// The [`InMemoryKeyResolver`] implementation walks the supplied
/// records, picking up `RecordBody::KeyRegistry` entries as it goes,
/// which is what the SQLite storage backend uses.
pub trait KeyResolver {
    /// Return the resolved key registered under `key_id` at the time
    /// the record was signed, or `None` if not registered.
    fn resolve(&self, key_id: &str) -> Option<ResolvedKey>;
}

/// A trivial resolver populated from a flat list of registry entries.
#[derive(Default, Debug)]
pub struct InMemoryKeyResolver {
    keys: HashMap<String, ResolvedKey>,
}

impl InMemoryKeyResolver {
    /// Create an empty resolver.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Add or replace an entry by key_id, taken from a registry record.
    pub fn insert(&mut self, entry: &KeyRegistryEntry) {
        self.keys.insert(
            entry.key_id.clone(),
            ResolvedKey {
                public_key: entry.public_key.clone(),
                algorithm: entry.algorithm.clone(),
            },
        );
    }

    /// Add or replace by id, public key, and algorithm string directly.
    /// Useful in tests and SDKs that build resolvers from an out-of-band
    /// trust root without walking the full registry.
    pub fn insert_raw(
        &mut self,
        key_id: impl Into<String>,
        pk: HybridPublicKey,
        algorithm: impl Into<String>,
    ) {
        self.keys.insert(
            key_id.into(),
            ResolvedKey {
                public_key: pk,
                algorithm: algorithm.into(),
            },
        );
    }
}

impl KeyResolver for InMemoryKeyResolver {
    fn resolve(&self, key_id: &str) -> Option<ResolvedKey> {
        self.keys.get(key_id).cloned()
    }
}

/// Walk a chain and check every invariant. The records must be in
/// `sequence` order. KeyRegistry entries encountered during the walk
/// are added to `resolver` so that records signed under a key
/// registered earlier in the same walk verify naturally.
pub fn verify_chain(
    records: &[SignedRecord],
    resolver: &mut InMemoryKeyResolver,
) -> Result<VerificationReport> {
    let mut report = VerificationReport::default();

    let mut expected_prev = [0u8; 32];
    let mut expected_seq: u64 = 0;
    let mut accumulated: Vec<[u8; 32]> = Vec::new();
    let mut accumulated_first: Option<u64> = None;
    let mut stream_id: Option<String> = None;
    // Track records we've seen so tombstones can validate their targets.
    let mut seen_by_sequence: HashMap<u64, &SignedRecord> = HashMap::new();
    let mut redacted_sequences: HashSet<u64> = HashSet::new();

    for sr in records {
        sr.record.validate_shape()?;
        if let Some(s) = &stream_id {
            if s != &sr.record.stream_id {
                return early_fail(
                    &mut report,
                    sr.record.sequence,
                    format!(
                        "stream_id changed mid-chain: {} -> {}",
                        s, sr.record.stream_id
                    ),
                );
            }
        } else {
            stream_id = Some(sr.record.stream_id.clone());
        }

        if sr.record.sequence != expected_seq {
            return early_fail(
                &mut report,
                sr.record.sequence,
                format!(
                    "expected sequence {expected_seq}, found {}",
                    sr.record.sequence
                ),
            );
        }
        let expected_prev_hex = hex::encode(expected_prev);
        if sr.record.prev_hash_hex != expected_prev_hex {
            return early_fail(
                &mut report,
                sr.record.sequence,
                format!(
                    "prev_hash_hex {} does not match prior this_hash {}",
                    sr.record.prev_hash_hex, expected_prev_hex
                ),
            );
        }

        // recompute this_hash and compare to stored
        let bytes = sr.record.canonical_bytes()?;
        let recomputed = sha256(&bytes);
        let recomputed_hex = hex::encode(recomputed);
        if recomputed_hex != sr.this_hash_hex {
            return early_fail(
                &mut report,
                sr.record.sequence,
                format!(
                    "stored this_hash {} does not match canonical hash {recomputed_hex}",
                    sr.this_hash_hex
                ),
            );
        }

        // If this record is itself a KeyRegistry entry, register the key
        // BEFORE attempting to verify the record's signature, so a
        // genesis key-registry record can self-bootstrap.
        if let RecordBody::KeyRegistry(entry) = &sr.record.body {
            resolver.insert(entry);
        }

        // verify signature using the combiner declared by the resolved key
        let resolved = resolver.resolve(&sr.record.key_id).ok_or_else(|| {
            Error::Signature(format!(
                "key_id {} not registered at sequence {}",
                sr.record.key_id, sr.record.sequence
            ))
        })?;
        let combiner = SignatureCombiner::from_algorithm(&resolved.algorithm).ok_or_else(|| {
            Error::Signature(format!(
                "sequence {}: unknown algorithm `{}` on key `{}`",
                sr.record.sequence, resolved.algorithm, sr.record.key_id
            ))
        })?;
        combiner
            .verify(&resolved.public_key, &bytes, &sr.signature)
            .map_err(|e| match e {
                Error::Signature(msg) => {
                    Error::Signature(format!("sequence {}: {msg}", sr.record.sequence))
                }
                other => other,
            })?;
        report.signatures_verified += 1;

        // body-kind specific handling: Merkle commits close a batch;
        // tombstones validate that their target exists earlier;
        // interactions get their cross-chain refs verified.
        match &sr.record.body {
            RecordBody::MerkleRoot(entry) => {
                check_merkle_root(&mut report, sr, entry, &accumulated, accumulated_first)?;
                accumulated.clear();
                accumulated_first = None;
            }
            RecordBody::Tombstone(redaction) => {
                check_tombstone(&mut report, sr, redaction, &seen_by_sequence)?;
                redacted_sequences.insert(redaction.target_sequence);
                report.tombstones_observed += 1;
                if accumulated.is_empty() {
                    accumulated_first = Some(sr.record.sequence);
                }
                accumulated.push(recomputed);
            }
            RecordBody::Interaction(body) => {
                for cref in &body.cross_chain_refs {
                    check_cross_chain_ref(&mut report, sr, cref)?;
                    report.cross_chain_refs_verified += 1;
                }
                if accumulated.is_empty() {
                    accumulated_first = Some(sr.record.sequence);
                }
                accumulated.push(recomputed);
            }
            _ => {
                if accumulated.is_empty() {
                    accumulated_first = Some(sr.record.sequence);
                }
                accumulated.push(recomputed);
            }
        }
        seen_by_sequence.insert(sr.record.sequence, sr);

        // advance
        expected_prev = recomputed;
        expected_seq = sr
            .record
            .sequence
            .checked_add(1)
            .ok_or_else(|| Error::invalid("sequence overflow"))?;
        report.records_walked += 1;
    }

    report.redacted_sequences = {
        let mut v: Vec<u64> = redacted_sequences.into_iter().collect();
        v.sort_unstable();
        v
    };
    Ok(report)
}

fn check_cross_chain_ref(
    report: &mut VerificationReport,
    sr: &SignedRecord,
    cref: &crate::record::CrossChainRef,
) -> Result<()> {
    // The foreign STH must be internally consistent with the
    // reference (the named foreign_sequence falls within the STH's
    // claimed range).
    if cref.foreign_sequence < cref.foreign_sth.first_sequence
        || cref.foreign_sequence > cref.foreign_sth.last_sequence
    {
        return early_fail(
            report,
            sr.record.sequence,
            format!(
                "cross_chain_ref foreign_sequence {} outside foreign_sth range [{}..={}]",
                cref.foreign_sequence,
                cref.foreign_sth.first_sequence,
                cref.foreign_sth.last_sequence
            ),
        )
        .map(|_| ());
    }
    // STH identity: stream_id must match.
    if cref.foreign_sth.stream_id
        != format!("{}/{}", cref.foreign_tenant_id, cref.foreign_stream_id)
        && cref.foreign_sth.stream_id != cref.foreign_stream_id
    {
        return early_fail(
            report,
            sr.record.sequence,
            format!(
                "cross_chain_ref foreign_sth.stream_id {} does not match the ref's tenant/stream",
                cref.foreign_sth.stream_id
            ),
        )
        .map(|_| ());
    }
    // Validate the inclusion proof against the foreign root.
    let leaf: [u8; 32] = decode_hash_32(
        &cref.foreign_record_this_hash_hex,
        "foreign_record_this_hash_hex",
    )?;
    let root: [u8; 32] =
        decode_hash_32(&cref.foreign_sth.root_hash_hex, "foreign_sth.root_hash_hex")?;
    let mut steps: Vec<merkle::ProofStep> = Vec::with_capacity(cref.inclusion_proof_steps.len());
    for s in &cref.inclusion_proof_steps {
        let sibling = decode_hash_32(&s.sibling_hex, "cross_chain_ref proof step sibling_hex")?;
        steps.push(merkle::ProofStep {
            sibling,
            sibling_is_right: s.sibling_is_right,
        });
    }
    merkle::verify_proof(&leaf, &steps, &root).map_err(|e| match e {
        Error::Merkle(msg) => Error::HashMismatch {
            sequence: sr.record.sequence,
            reason: format!("cross_chain_ref inclusion proof: {msg}"),
        },
        other => other,
    })?;
    Ok(())
}

fn decode_hash_32(hex_str: &str, label: &str) -> Result<[u8; 32]> {
    let bytes =
        hex::decode(hex_str).map_err(|e| Error::invalid(format!("{label} not hex: {e}")))?;
    bytes
        .try_into()
        .map_err(|_| Error::invalid(format!("{label} is not 32 bytes")))
}

fn check_tombstone(
    report: &mut VerificationReport,
    sr: &SignedRecord,
    redaction: &crate::record::RedactionRecord,
    seen: &HashMap<u64, &SignedRecord>,
) -> Result<()> {
    if redaction.target_sequence >= sr.record.sequence {
        return early_fail(
            report,
            sr.record.sequence,
            format!(
                "tombstone target_sequence {} must point to an earlier record",
                redaction.target_sequence
            ),
        )
        .map(|_| ());
    }
    let Some(target) = seen.get(&redaction.target_sequence) else {
        return early_fail(
            report,
            sr.record.sequence,
            format!(
                "tombstone target_sequence {} not seen earlier on stream",
                redaction.target_sequence
            ),
        )
        .map(|_| ());
    };
    if target.record.record_id != redaction.target_record_id {
        return early_fail(
            report,
            sr.record.sequence,
            format!(
                "tombstone target_record_id {} does not match record at sequence {}",
                redaction.target_record_id, redaction.target_sequence
            ),
        )
        .map(|_| ());
    }
    if target.this_hash_hex != redaction.original_this_hash_hex {
        return early_fail(
            report,
            sr.record.sequence,
            format!(
                "tombstone original_this_hash_hex {} does not match target's stored this_hash {}",
                redaction.original_this_hash_hex, target.this_hash_hex
            ),
        )
        .map(|_| ());
    }
    Ok(())
}

fn check_merkle_root(
    report: &mut VerificationReport,
    sr: &SignedRecord,
    entry: &crate::record::MerkleRootEntry,
    accumulated: &[[u8; 32]],
    accumulated_first: Option<u64>,
) -> Result<()> {
    if accumulated.is_empty() {
        return early_fail(
            report,
            sr.record.sequence,
            "merkle_root record references an empty batch".to_string(),
        )
        .map(|_| ());
    }
    let first = accumulated_first.expect("non-empty accumulated implies first");
    let last = first + accumulated.len() as u64 - 1;
    if entry.first_sequence != first || entry.last_sequence != last {
        return early_fail(
            report,
            sr.record.sequence,
            format!(
                "merkle_root claims [{}..={}] but accumulated batch is [{first}..={last}]",
                entry.first_sequence, entry.last_sequence
            ),
        )
        .map(|_| ());
    }
    let computed = merkle::compute_root(accumulated)?;
    let computed_hex = hex::encode(computed);
    if computed_hex != entry.root_hash_hex {
        return early_fail(
            report,
            sr.record.sequence,
            format!(
                "merkle root {} does not match computed {computed_hex}",
                entry.root_hash_hex
            ),
        )
        .map(|_| ());
    }
    report.merkle_roots_checked += 1;
    Ok(())
}

fn early_fail(
    report: &mut VerificationReport,
    sequence: u64,
    reason: String,
) -> Result<VerificationReport> {
    report.failure = Some(VerificationFailure {
        sequence,
        reason: reason.clone(),
    });
    Err(Error::HashMismatch { sequence, reason })
}

/// Compute the [`SignedRecord`] for an unsigned [`Record`] using the
/// supplied keypair. This is where the hash and signature get joined.
pub fn sign_record(record: Record, keypair: &crate::crypto::HybridKeypair) -> Result<SignedRecord> {
    record.validate_shape()?;
    let bytes = record.canonical_bytes()?;
    let this_hash = sha256(&bytes);
    let signature = keypair.sign(&bytes);
    Ok(SignedRecord {
        record,
        this_hash_hex: hex::encode(this_hash),
        signature,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::HybridKeypair;
    use crate::key_registry::{KeyRegistryEntry, KeyStatus};
    use crate::record::{InteractionBody, MerkleRootEntry, RecordBody, make_interaction};
    use time::OffsetDateTime;
    use time::macros::datetime;

    fn now() -> OffsetDateTime {
        datetime!(2026-05-12 12:00:00 UTC)
    }

    fn make_test_chain(n: u64) -> (Vec<SignedRecord>, HybridKeypair) {
        let kp = HybridKeypair::generate().unwrap();
        let pk = kp.public_key();
        let entry = KeyRegistryEntry {
            key_id: "test-key".into(),
            algorithm: crate::ALGORITHM_HYBRID_ED25519_MLDSA65.into(),
            public_key: pk,
            valid_from: now(),
            valid_to: None,
            status: KeyStatus::Active,
        };

        // sequence 0 is the registry record itself
        let mut prev = [0u8; 32];
        let mut records = Vec::new();
        let reg_record = Record {
            record_id: ulid::Ulid::new(),
            stream_id: "acme/sys".into(),
            sequence: 0,
            occurred_at: now(),
            received_at: now(),
            schema_version: crate::SCHEMA_VERSION.into(),
            source_sdk: "test/0.1.0".into(),
            key_id: "test-key".into(),
            prev_hash_hex: hex::encode(prev),
            body: RecordBody::KeyRegistry(entry),
        };
        let sr0 = sign_record(reg_record, &kp).unwrap();
        prev = hex::decode(&sr0.this_hash_hex).unwrap().try_into().unwrap();
        records.push(sr0);

        for seq in 1..=n {
            let body = InteractionBody {
                metadata: {
                    let mut m = serde_json::Map::new();
                    m.insert("i".into(), serde_json::Value::from(seq));
                    m
                },
                ..Default::default()
            };
            let r = make_interaction(
                "acme/sys",
                seq,
                now(),
                now(),
                prev,
                "test-key",
                "test/0.1.0",
                body,
            )
            .unwrap();
            let sr = sign_record(r, &kp).unwrap();
            prev = hex::decode(&sr.this_hash_hex).unwrap().try_into().unwrap();
            records.push(sr);
        }
        (records, kp)
    }

    #[test]
    fn empty_chain_verifies_trivially() {
        let mut resolver = InMemoryKeyResolver::new();
        let report = verify_chain(&[], &mut resolver).unwrap();
        assert!(report.is_ok());
        assert_eq!(report.records_walked, 0);
    }

    #[test]
    fn happy_path_chain_verifies() {
        let (chain, _kp) = make_test_chain(5);
        let mut resolver = InMemoryKeyResolver::new();
        let report = verify_chain(&chain, &mut resolver).unwrap();
        assert!(report.is_ok());
        assert_eq!(report.records_walked, 6);
        assert_eq!(report.signatures_verified, 6);
    }

    #[test]
    fn merkle_commit_record_verifies() {
        let (mut chain, kp) = make_test_chain(3);
        // Merkle batch covers every non-MerkleRoot record up to here,
        // including the genesis KeyRegistry at sequence 0.
        let leaves: Vec<[u8; 32]> = chain
            .iter()
            .map(|sr| hex::decode(&sr.this_hash_hex).unwrap().try_into().unwrap())
            .collect();
        let root = merkle::compute_root(&leaves).unwrap();
        let prev: [u8; 32] = hex::decode(&chain.last().unwrap().this_hash_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let entry = MerkleRootEntry {
            first_sequence: 0,
            last_sequence: 3,
            root_hash_hex: hex::encode(root),
            ..Default::default()
        };
        let r = Record {
            record_id: ulid::Ulid::new(),
            stream_id: "acme/sys".into(),
            sequence: 4,
            occurred_at: now(),
            received_at: now(),
            schema_version: crate::SCHEMA_VERSION.into(),
            source_sdk: "test/0.1.0".into(),
            key_id: "test-key".into(),
            prev_hash_hex: hex::encode(prev),
            body: RecordBody::MerkleRoot(entry),
        };
        chain.push(sign_record(r, &kp).unwrap());
        let mut resolver = InMemoryKeyResolver::new();
        let report = verify_chain(&chain, &mut resolver).unwrap();
        assert!(report.is_ok());
        assert_eq!(report.merkle_roots_checked, 1);
    }

    #[test]
    fn mutated_record_body_breaks_chain() {
        let (mut chain, _kp) = make_test_chain(3);
        // tamper: replace tags on record at seq 2 but keep stored hash + sig
        if let RecordBody::Interaction(ib) = &mut chain[2].record.body {
            ib.tags.push(crate::record::Tag {
                key: "evil".into(),
                value: "yes".into(),
            });
        }
        let mut resolver = InMemoryKeyResolver::new();
        let err = verify_chain(&chain, &mut resolver).unwrap_err();
        match err {
            Error::HashMismatch { sequence, .. } => assert_eq!(sequence, 2),
            other => panic!("expected hash mismatch, got {other:?}"),
        }
    }

    #[test]
    fn deletion_breaks_chain() {
        let (mut chain, _kp) = make_test_chain(3);
        chain.remove(2); // drop sequence 2; the next record's sequence (3) won't match.
        let mut resolver = InMemoryKeyResolver::new();
        let err = verify_chain(&chain, &mut resolver).unwrap_err();
        match err {
            Error::HashMismatch { sequence, .. } => assert_eq!(sequence, 3),
            other => panic!("expected hash mismatch, got {other:?}"),
        }
    }

    #[test]
    fn reorder_breaks_chain() {
        let (mut chain, _kp) = make_test_chain(3);
        chain.swap(2, 3);
        let mut resolver = InMemoryKeyResolver::new();
        assert!(verify_chain(&chain, &mut resolver).is_err());
    }

    #[test]
    fn signature_tamper_breaks_chain() {
        let (mut chain, _kp) = make_test_chain(2);
        chain[1].signature.ed25519[0] ^= 0x01;
        let mut resolver = InMemoryKeyResolver::new();
        let err = verify_chain(&chain, &mut resolver).unwrap_err();
        match err {
            Error::Signature(_) => {}
            other => panic!("expected signature error, got {other:?}"),
        }
    }

    #[test]
    fn merkle_root_tamper_breaks_chain() {
        let (mut chain, kp) = make_test_chain(3);
        let prev: [u8; 32] = hex::decode(&chain.last().unwrap().this_hash_hex)
            .unwrap()
            .try_into()
            .unwrap();
        // pretend a different root
        let entry = MerkleRootEntry {
            first_sequence: 0,
            last_sequence: 3,
            root_hash_hex: hex::encode([0xab; 32]),
            ..Default::default()
        };
        let r = Record {
            record_id: ulid::Ulid::new(),
            stream_id: "acme/sys".into(),
            sequence: 4,
            occurred_at: now(),
            received_at: now(),
            schema_version: crate::SCHEMA_VERSION.into(),
            source_sdk: "test/0.1.0".into(),
            key_id: "test-key".into(),
            prev_hash_hex: hex::encode(prev),
            body: RecordBody::MerkleRoot(entry),
        };
        chain.push(sign_record(r, &kp).unwrap());
        let mut resolver = InMemoryKeyResolver::new();
        let err = verify_chain(&chain, &mut resolver).unwrap_err();
        match err {
            Error::HashMismatch { .. } => {}
            other => panic!("expected hash mismatch, got {other:?}"),
        }
    }

    fn append_tombstone(chain: &mut Vec<SignedRecord>, kp: &HybridKeypair, target_sequence: u64) {
        let target = chain
            .iter()
            .find(|sr| sr.record.sequence == target_sequence)
            .expect("target exists");
        let redaction = crate::record::RedactionRecord {
            target_record_id: target.record.record_id,
            target_sequence,
            original_this_hash_hex: target.this_hash_hex.clone(),
            reason: crate::record::RedactionReason::GdprErasure,
            actor_id: "compliance-officer-1".into(),
            rationale_hash_hex: None,
        };
        let last = chain.last().unwrap();
        let prev: [u8; 32] = hex::decode(&last.this_hash_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let r = Record {
            record_id: ulid::Ulid::new(),
            stream_id: last.record.stream_id.clone(),
            sequence: last.record.sequence + 1,
            occurred_at: now(),
            received_at: now(),
            schema_version: crate::SCHEMA_VERSION.into(),
            source_sdk: "test/0.1.0".into(),
            key_id: "test-key".into(),
            prev_hash_hex: hex::encode(prev),
            body: RecordBody::Tombstone(redaction),
        };
        chain.push(sign_record(r, kp).unwrap());
    }

    #[test]
    fn tombstone_verifies_and_surfaces_redaction() {
        let (mut chain, kp) = make_test_chain(3);
        append_tombstone(&mut chain, &kp, 2);
        let mut resolver = InMemoryKeyResolver::new();
        let report = verify_chain(&chain, &mut resolver).unwrap();
        assert!(report.is_ok(), "verification should succeed");
        assert_eq!(report.tombstones_observed, 1);
        assert_eq!(report.redacted_sequences, vec![2]);
    }

    #[test]
    fn tombstone_pointing_at_future_sequence_is_rejected() {
        let (mut chain, kp) = make_test_chain(3);
        // craft a tombstone whose target_sequence is its own sequence
        let last = chain.last().unwrap();
        let redaction = crate::record::RedactionRecord {
            target_record_id: ulid::Ulid::new(),
            target_sequence: last.record.sequence + 1,
            original_this_hash_hex: last.this_hash_hex.clone(),
            reason: crate::record::RedactionReason::OperatorRequest,
            actor_id: "actor".into(),
            rationale_hash_hex: None,
        };
        let prev: [u8; 32] = hex::decode(&last.this_hash_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let r = Record {
            record_id: ulid::Ulid::new(),
            stream_id: last.record.stream_id.clone(),
            sequence: last.record.sequence + 1,
            occurred_at: now(),
            received_at: now(),
            schema_version: crate::SCHEMA_VERSION.into(),
            source_sdk: "test/0.1.0".into(),
            key_id: "test-key".into(),
            prev_hash_hex: hex::encode(prev),
            body: RecordBody::Tombstone(redaction),
        };
        chain.push(sign_record(r, &kp).unwrap());
        let mut resolver = InMemoryKeyResolver::new();
        let err = verify_chain(&chain, &mut resolver).unwrap_err();
        assert!(matches!(err, Error::HashMismatch { .. }));
    }

    #[test]
    fn tombstone_with_mismatched_target_hash_is_rejected() {
        let (mut chain, kp) = make_test_chain(3);
        let target = chain
            .iter()
            .find(|sr| sr.record.sequence == 2)
            .unwrap()
            .clone();
        let redaction = crate::record::RedactionRecord {
            target_record_id: target.record.record_id,
            target_sequence: 2,
            // wrong hash
            original_this_hash_hex: hex::encode([0u8; 32]),
            reason: crate::record::RedactionReason::CourtOrder,
            actor_id: "actor".into(),
            rationale_hash_hex: None,
        };
        let last = chain.last().unwrap();
        let prev: [u8; 32] = hex::decode(&last.this_hash_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let r = Record {
            record_id: ulid::Ulid::new(),
            stream_id: last.record.stream_id.clone(),
            sequence: last.record.sequence + 1,
            occurred_at: now(),
            received_at: now(),
            schema_version: crate::SCHEMA_VERSION.into(),
            source_sdk: "test/0.1.0".into(),
            key_id: "test-key".into(),
            prev_hash_hex: hex::encode(prev),
            body: RecordBody::Tombstone(redaction),
        };
        chain.push(sign_record(r, &kp).unwrap());
        let mut resolver = InMemoryKeyResolver::new();
        let err = verify_chain(&chain, &mut resolver).unwrap_err();
        assert!(matches!(err, Error::HashMismatch { .. }));
    }

    #[test]
    fn or_combiner_verifies_under_emergency_rotation() {
        // Register a key under the OR algorithm and append a record;
        // mutate the ML-DSA half of the signature — OR still verifies.
        let kp = HybridKeypair::generate().unwrap();
        let entry = KeyRegistryEntry {
            key_id: "or-key".into(),
            algorithm: crate::ALGORITHM_HYBRID_ED25519_MLDSA65_OR.into(),
            public_key: kp.public_key(),
            valid_from: now(),
            valid_to: None,
            status: KeyStatus::Active,
        };
        let r0 = Record {
            record_id: ulid::Ulid::new(),
            stream_id: "t/s".into(),
            sequence: 0,
            occurred_at: now(),
            received_at: now(),
            schema_version: crate::SCHEMA_VERSION.into(),
            source_sdk: "test/0.1.0".into(),
            key_id: "or-key".into(),
            prev_hash_hex: hex::encode([0u8; 32]),
            body: RecordBody::KeyRegistry(entry),
        };
        let sr0 = sign_record(r0, &kp).unwrap();
        let prev: [u8; 32] = hex::decode(&sr0.this_hash_hex).unwrap().try_into().unwrap();
        let r1 = make_interaction(
            "t/s",
            1,
            now(),
            now(),
            prev,
            "or-key",
            "test/0.1.0",
            InteractionBody::default(),
        )
        .unwrap();
        let mut sr1 = sign_record(r1, &kp).unwrap();
        // Break the ML-DSA half post-hoc. Under AND this would fail;
        // under OR it must still verify because the Ed25519 half is good.
        sr1.signature.mldsa[0] ^= 1;

        let chain = vec![sr0, sr1];
        let mut resolver = InMemoryKeyResolver::new();
        let report = verify_chain(&chain, &mut resolver).unwrap();
        assert!(report.is_ok());
    }

    fn make_cross_chain_ref(
        foreign_tenant: &str,
        foreign_stream: &str,
        first_sequence: u64,
        leaves_hex: &[&str],
        target_index: usize,
    ) -> crate::record::CrossChainRef {
        let leaves: Vec<[u8; 32]> = leaves_hex
            .iter()
            .map(|h| decode_hash_32(h, "leaf").unwrap())
            .collect();
        let root = crate::merkle::compute_root(&leaves).unwrap();
        let proof = crate::merkle::build_proof(&leaves, target_index).unwrap();
        crate::record::CrossChainRef {
            foreign_tenant_id: foreign_tenant.into(),
            foreign_stream_id: foreign_stream.into(),
            foreign_sequence: first_sequence + target_index as u64,
            foreign_record_this_hash_hex: leaves_hex[target_index].into(),
            foreign_sth: crate::record::SignedTreeHead {
                stream_id: format!("{foreign_tenant}/{foreign_stream}"),
                first_sequence,
                last_sequence: first_sequence + leaves_hex.len() as u64 - 1,
                root_hash_hex: hex::encode(root),
                root_record_this_hash_hex: String::new(),
            },
            inclusion_proof_steps: proof
                .into_iter()
                .map(|s| crate::record::CrossChainProofStep {
                    sibling_hex: hex::encode(s.sibling),
                    sibling_is_right: s.sibling_is_right,
                })
                .collect(),
        }
    }

    fn fake_leaves() -> Vec<String> {
        (0u8..5)
            .map(|i| {
                let mut a = [0u8; 32];
                a[0] = i + 1;
                hex::encode(a)
            })
            .collect()
    }

    fn append_interaction_with_cross_chain(
        chain: &mut Vec<SignedRecord>,
        kp: &HybridKeypair,
        cref: crate::record::CrossChainRef,
    ) {
        let last = chain.last().unwrap();
        let prev: [u8; 32] = hex::decode(&last.this_hash_hex)
            .unwrap()
            .try_into()
            .unwrap();
        let body = crate::record::InteractionBody {
            cross_chain_refs: vec![cref],
            ..Default::default()
        };
        let r = crate::record::make_interaction(
            "acme/sys",
            last.record.sequence + 1,
            now(),
            now(),
            prev,
            "test-key",
            "test/0.4.0",
            body,
        )
        .unwrap();
        chain.push(sign_record(r, kp).unwrap());
    }

    #[test]
    fn cross_chain_ref_with_valid_proof_verifies() {
        let (mut chain, kp) = make_test_chain(2);
        let leaves: Vec<String> = fake_leaves();
        let leaves_ref: Vec<&str> = leaves.iter().map(String::as_str).collect();
        let cref = make_cross_chain_ref("vendor", "model-v1", 0, &leaves_ref, 2);
        append_interaction_with_cross_chain(&mut chain, &kp, cref);
        let mut resolver = InMemoryKeyResolver::new();
        let report = verify_chain(&chain, &mut resolver).unwrap();
        assert!(report.is_ok());
        assert_eq!(report.cross_chain_refs_verified, 1);
    }

    #[test]
    fn cross_chain_ref_with_tampered_root_is_rejected() {
        let (mut chain, kp) = make_test_chain(2);
        let leaves: Vec<String> = fake_leaves();
        let leaves_ref: Vec<&str> = leaves.iter().map(String::as_str).collect();
        let mut cref = make_cross_chain_ref("vendor", "model-v1", 0, &leaves_ref, 2);
        cref.foreign_sth.root_hash_hex = hex::encode([0u8; 32]);
        append_interaction_with_cross_chain(&mut chain, &kp, cref);
        let mut resolver = InMemoryKeyResolver::new();
        let err = verify_chain(&chain, &mut resolver).unwrap_err();
        assert!(matches!(err, Error::HashMismatch { .. }));
    }

    #[test]
    fn cross_chain_ref_with_out_of_range_sequence_is_rejected() {
        let (mut chain, kp) = make_test_chain(2);
        let leaves: Vec<String> = fake_leaves();
        let leaves_ref: Vec<&str> = leaves.iter().map(String::as_str).collect();
        let mut cref = make_cross_chain_ref("vendor", "model-v1", 0, &leaves_ref, 2);
        cref.foreign_sequence = 999; // outside [0..=4]
        append_interaction_with_cross_chain(&mut chain, &kp, cref);
        let mut resolver = InMemoryKeyResolver::new();
        let err = verify_chain(&chain, &mut resolver).unwrap_err();
        assert!(matches!(err, Error::HashMismatch { .. }));
    }
}
