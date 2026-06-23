//! Reference Glassbox witness server + publication client.
//!
//! Per spec §13.7 a witness is an independent operator that:
//!
//! 1. Receives a [`SignedTreeHead`](glassbox_core::SignedTreeHead) from
//!    a ledger operator who is publishing a fresh Merkle root.
//! 2. Validates the STH for *internal consistency* against its own
//!    prior observations of the same stream (i.e. the new root must
//!    not contradict the previous one — `last_sequence` advances, and
//!    the operator never replays a stale root).
//! 3. Counter-signs the STH with its own hybrid keypair, returning a
//!    [`WitnessCountersignature`](glassbox_core::WitnessCountersignature)
//!    that the operator records back into the ledger.
//!
//! The witness's view is stored on disk as a JSON-Lines append-only
//! file — itself an audit log, observable by other witnesses.
//!
//! This crate is **not** a network server in v0.3. The protocol is
//! file-based: the operator writes a publication request to a watch
//! directory, the witness picks it up, returns a countersignature. A
//! gRPC or HTTPS surface is straightforward to add on top of these
//! types and is on the v0.4 list.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(missing_docs)]

pub mod tsa;

use std::collections::HashMap;
use std::fs;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

use glassbox_core::SignedTreeHead;
use glassbox_core::canonical;
use glassbox_core::combiner::SignatureCombiner;
use glassbox_core::crypto::{HybridKeypair, HybridPublicKey, HybridSignature};
use glassbox_core::record::WitnessCountersignature;

/// Errors produced by the witness crate.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WitnessError {
    /// I/O failure reading or writing the witness's observation log.
    #[error("witness i/o: {0}")]
    Io(String),
    /// The submitted STH contradicts a prior observation on the same
    /// `stream_id` (the operator tried to rewind or fork). The witness
    /// MUST refuse to counter-sign in this case — that refusal is the
    /// whole point of the witness layer.
    #[error("inconsistent STH on stream `{stream_id}`: {reason}")]
    Inconsistent {
        /// Stream identifier where the contradiction was detected.
        stream_id: String,
        /// Human-readable reason.
        reason: String,
    },
    /// Malformed JSON in the observation log.
    #[error("witness storage corrupt: {0}")]
    Corrupt(String),
    /// Counter-signature failed to verify against the witness's
    /// declared public key — only surfaces in self-tests.
    #[error("witness signature verification failed: {0}")]
    Signature(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, WitnessError>;

/// A witness's observation of one STH on one stream. One line in the
/// observations file.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessObservation {
    /// The witness's identifier (matches the witness's directory name).
    pub witness_id: String,
    /// The STH the witness observed.
    pub sth: SignedTreeHead,
    /// When the witness saw it.
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
    /// The witness's counter-signature (over the canonical form of `sth`).
    pub countersignature: HybridSignature,
}

/// The reference witness server. Single-witness, file-backed,
/// suitable for a quorum-of-three local deployment or for running on
/// three independent VPS hosts under three different operators.
#[derive(Debug)]
pub struct WitnessServer {
    witness_id: String,
    keypair: HybridKeypair,
    storage: PathBuf,
}

impl WitnessServer {
    /// Create a new witness backed by `storage_dir`. The directory is
    /// created if missing.
    pub fn new(
        witness_id: impl Into<String>,
        keypair: HybridKeypair,
        storage_dir: impl AsRef<Path>,
    ) -> Result<Self> {
        let storage = storage_dir.as_ref().to_path_buf();
        fs::create_dir_all(&storage).map_err(io)?;
        Ok(Self {
            witness_id: witness_id.into(),
            keypair,
            storage,
        })
    }

    /// The witness's own public key — embedded into every counter-
    /// signature so any third party can verify without contacting the
    /// witness directly.
    pub fn public_key(&self) -> HybridPublicKey {
        self.keypair.public_key()
    }

    /// Identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.witness_id
    }

    /// Observe and counter-sign an STH. Returns the counter-signature
    /// the operator should record back into their Merkle-root entry.
    ///
    /// Refuses if the STH contradicts a prior observation on the same
    /// stream (last_sequence retreating, root forking on identical
    /// last_sequence, or operator trying to re-publish a stale root).
    pub fn observe(&mut self, sth: SignedTreeHead) -> Result<WitnessCountersignature> {
        let path = self.stream_log_path(&sth.stream_id);
        let prior = Self::load_observations(&path)?;
        check_consistency(&prior, &sth, &sth.stream_id)?;

        let canonical_sth = canonical::canonicalize(&sth)
            .map_err(|e| WitnessError::Corrupt(format!("canonicalize STH: {e}")))?;
        let signature = self.keypair.sign(&canonical_sth);
        let now = OffsetDateTime::now_utc();

        let observation = WitnessObservation {
            witness_id: self.witness_id.clone(),
            sth: sth.clone(),
            observed_at: now,
            countersignature: signature.clone(),
        };
        let mut f = fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
            .map_err(io)?;
        let line = serde_json::to_string(&observation)
            .map_err(|e| WitnessError::Corrupt(e.to_string()))?;
        writeln!(f, "{line}").map_err(io)?;

        Ok(WitnessCountersignature {
            witness_id: self.witness_id.clone(),
            witness_public_key: self.public_key(),
            signature,
            observed_at: now,
        })
    }

    /// Return every observation this witness has on the given stream,
    /// in append order. Used by `glassbox witness check` to surface
    /// the witness's view to a third-party verifier.
    pub fn observations(&self, stream_id: &str) -> Result<Vec<WitnessObservation>> {
        let path = self.stream_log_path(stream_id);
        Self::load_observations(&path)
    }

    fn stream_log_path(&self, stream_id: &str) -> PathBuf {
        // Stream IDs contain `/`; replace for a filesystem-safe name.
        let safe = stream_id.replace('/', "__");
        self.storage.join(format!("{safe}.jsonl"))
    }

    fn load_observations(path: &Path) -> Result<Vec<WitnessObservation>> {
        if !path.exists() {
            return Ok(Vec::new());
        }
        let text = fs::read_to_string(path).map_err(io)?;
        let mut out = Vec::new();
        for (lineno, line) in text.lines().enumerate() {
            if line.trim().is_empty() {
                continue;
            }
            let obs: WitnessObservation = serde_json::from_str(line)
                .map_err(|e| WitnessError::Corrupt(format!("line {lineno}: {e}")))?;
            out.push(obs);
        }
        Ok(out)
    }
}

fn io<E: std::fmt::Display>(e: E) -> WitnessError {
    WitnessError::Io(e.to_string())
}

fn check_consistency(
    prior: &[WitnessObservation],
    sth: &SignedTreeHead,
    stream_id: &str,
) -> Result<()> {
    let Some(last) = prior
        .iter()
        .rev()
        .find(|o| o.sth.stream_id == sth.stream_id)
    else {
        return Ok(()); // first observation on this stream
    };
    if sth.last_sequence < last.sth.last_sequence {
        return Err(WitnessError::Inconsistent {
            stream_id: stream_id.into(),
            reason: format!(
                "new STH last_sequence {} < prior {}",
                sth.last_sequence, last.sth.last_sequence
            ),
        });
    }
    if sth.last_sequence == last.sth.last_sequence && sth.root_hash_hex != last.sth.root_hash_hex {
        return Err(WitnessError::Inconsistent {
            stream_id: stream_id.into(),
            reason: format!(
                "fork: same last_sequence {} but two different roots ({} vs {})",
                sth.last_sequence, sth.root_hash_hex, last.sth.root_hash_hex
            ),
        });
    }
    if sth.first_sequence > sth.last_sequence {
        return Err(WitnessError::Inconsistent {
            stream_id: stream_id.into(),
            reason: "first_sequence > last_sequence".into(),
        });
    }
    Ok(())
}

/// Verify a counter-signature on a Signed Tree Head independently
/// (e.g. from a third-party verifier holding the witness's published
/// view).
pub fn verify_countersignature(sth: &SignedTreeHead, cs: &WitnessCountersignature) -> Result<()> {
    let bytes = canonical::canonicalize(sth)
        .map_err(|e| WitnessError::Signature(format!("canonicalize STH: {e}")))?;
    SignatureCombiner::And
        .verify(&cs.witness_public_key, &bytes, &cs.signature)
        .map_err(|e| WitnessError::Signature(e.to_string()))
}

/// Aggregate the counter-signatures already attached to a `MerkleRootEntry`
/// into a per-witness summary, used by reports.
#[must_use]
pub fn summarise(signatures: &[WitnessCountersignature]) -> HashMap<String, OffsetDateTime> {
    let mut out = HashMap::with_capacity(signatures.len());
    for cs in signatures {
        out.insert(cs.witness_id.clone(), cs.observed_at);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use glassbox_core::SignedTreeHead;
    use glassbox_core::crypto::HybridKeypair;

    fn sth(stream: &str, first: u64, last: u64, root: &str) -> SignedTreeHead {
        SignedTreeHead {
            stream_id: stream.into(),
            first_sequence: first,
            last_sequence: last,
            root_hash_hex: root.into(),
            root_record_this_hash_hex: format!("rec_{last}"),
        }
    }

    #[test]
    fn observe_appends_and_signs() {
        let dir = tempfile::tempdir().unwrap();
        let mut w =
            WitnessServer::new("w1", HybridKeypair::generate().unwrap(), dir.path()).unwrap();
        let h = sth("acme/sys", 0, 4, "deadbeef");
        let cs = w.observe(h.clone()).unwrap();
        verify_countersignature(&h, &cs).unwrap();
        assert_eq!(w.observations("acme/sys").unwrap().len(), 1);
    }

    #[test]
    fn rejects_rewinding_sth() {
        let dir = tempfile::tempdir().unwrap();
        let mut w =
            WitnessServer::new("w1", HybridKeypair::generate().unwrap(), dir.path()).unwrap();
        w.observe(sth("acme/sys", 0, 10, "aa")).unwrap();
        let err = w.observe(sth("acme/sys", 0, 5, "bb")).unwrap_err();
        assert!(matches!(err, WitnessError::Inconsistent { .. }));
    }

    #[test]
    fn rejects_fork_at_same_height() {
        let dir = tempfile::tempdir().unwrap();
        let mut w =
            WitnessServer::new("w1", HybridKeypair::generate().unwrap(), dir.path()).unwrap();
        w.observe(sth("acme/sys", 0, 10, "aa")).unwrap();
        let err = w.observe(sth("acme/sys", 0, 10, "bb")).unwrap_err();
        assert!(matches!(err, WitnessError::Inconsistent { .. }));
    }

    #[test]
    fn accepts_idempotent_re_publication() {
        let dir = tempfile::tempdir().unwrap();
        let mut w =
            WitnessServer::new("w1", HybridKeypair::generate().unwrap(), dir.path()).unwrap();
        w.observe(sth("acme/sys", 0, 10, "aa")).unwrap();
        // Same height, same root: not a fork. Witness accepts and adds a
        // second observation (e.g. retry after dropped network).
        w.observe(sth("acme/sys", 0, 10, "aa")).unwrap();
        assert_eq!(w.observations("acme/sys").unwrap().len(), 2);
    }

    #[test]
    fn streams_are_isolated() {
        let dir = tempfile::tempdir().unwrap();
        let mut w =
            WitnessServer::new("w1", HybridKeypair::generate().unwrap(), dir.path()).unwrap();
        w.observe(sth("a/x", 0, 5, "aa")).unwrap();
        // Different stream: independent history.
        w.observe(sth("b/y", 0, 3, "bb")).unwrap();
        // Rewind on a/x is still detected.
        let err = w.observe(sth("a/x", 0, 1, "aa")).unwrap_err();
        assert!(matches!(err, WitnessError::Inconsistent { .. }));
    }
}
