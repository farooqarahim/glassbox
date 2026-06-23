//! Annex IV export for Glassbox audit ledgers.
//!
//! Per spec §22, an Annex IV export is a zip archive containing
//!
//! - a machine-readable JSON sidecar (the same content a PDF would
//!   render, in structured form for downstream tooling),
//! - per-artifact files in an `exhibits/` subdirectory, and
//! - a `manifest.json` listing every artifact's SHA-256 hash, signed by
//!   the operator's active hybrid key.
//!
//! A regulator can verify the export end-to-end with: the manifest's
//! signature (using the operator's published `KeyRegistryEntry`), then
//! each artifact's hash against the manifest. The optional PDF +
//! PAdES signing step is deferred — spec §22.4 notes that PAdES on its
//! own is non-trivial and warrants its own engagement.
//!
//! The sidecar populates Annex IV §1–4, §7, and §9 from real ledger
//! queries. §5, §6, §8 (harmonised standards, EU declaration of
//! conformity, risk-management system) require operator-supplied
//! documents and are passed through unchanged.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(missing_docs)]

#[cfg(feature = "pdf")]
pub mod pdf;

use std::collections::{BTreeMap, BTreeSet};
use std::io::Write as _;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use glassbox_core::canonical;
use glassbox_core::crypto::{HybridKeypair, HybridSignature};
use glassbox_core::record::{InteractionBody, RecordBody, SignedRecord};

/// Errors produced by the exporter.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ExportError {
    /// I/O failure.
    #[error("export i/o: {0}")]
    Io(String),
    /// Underlying core error (canonical-form / signing).
    #[error(transparent)]
    Core(#[from] glassbox_core::Error),
    /// Storage error reading the stream.
    #[error(transparent)]
    Storage(#[from] glassbox_storage::StorageError),
    /// Stream produced no records.
    #[error("stream `{0}` is empty; nothing to export")]
    EmptyStream(String),
    /// Zip-archive serialization failed.
    #[error("zip serialization: {0}")]
    Zip(String),
}

/// Annex IV export request: who, what system, over what window.
#[derive(Clone, Debug)]
pub struct ExportRequest {
    /// Operator's display name for §1 of the export.
    pub system_name: String,
    /// Annex III category id (e.g. `5b` for credit scoring, `4` for
    /// recruitment, `5e` for clinical decision support). Free-form
    /// string; spec doesn't restrict beyond Annex III.
    pub annex_iii_category: String,
    /// Inclusive lower bound on `occurred_at` — `None` means open.
    pub period_from: Option<OffsetDateTime>,
    /// Inclusive upper bound on `occurred_at` — `None` means open.
    pub period_to: Option<OffsetDateTime>,
}

/// The Annex IV JSON sidecar. Mirrors the nine spec §22.2 sections.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AnnexIvSidecar {
    /// Format version for the sidecar itself (independent of
    /// `glassbox-core` schema version).
    pub sidecar_version: String,
    /// Stream the export covers.
    pub stream_id: String,
    /// Time the export was generated, RFC 3339.
    pub generated_at: String,
    /// §1 — general description.
    pub general_description: SectionGeneralDescription,
    /// §2 — system elements and development.
    pub system_elements: SectionSystemElements,
    /// §3 — monitoring, functioning, control (aggregate volumes etc.).
    pub monitoring: SectionMonitoring,
    /// §4 — changes to the system over the period.
    pub changes: Vec<ChangeEvent>,
    /// §5–§6, §8 — operator-supplied artefacts. Empty in v0.3.
    pub operator_supplied: SectionOperatorSupplied,
    /// §7 — performance assessment (sampled from the ledger).
    pub performance: SectionPerformance,
    /// §9 — lifecycle changes (consolidated timeline pointer).
    pub lifecycle: SectionLifecycle,
}

/// §1.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionGeneralDescription {
    /// Operator display name.
    pub system_name: String,
    /// Annex III category id.
    pub annex_iii_category: String,
    /// Period covered (RFC 3339 strings or `null`).
    pub period_from: Option<String>,
    /// Period covered (RFC 3339 strings or `null`).
    pub period_to: Option<String>,
    /// Tenant identifier extracted from `stream_id`.
    pub tenant_id: String,
    /// System identifier extracted from `stream_id`.
    pub system_id: String,
}

/// §2.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionSystemElements {
    /// Distinct `(provider, model_name, model_version)` triples observed.
    pub model_fingerprints: Vec<ModelFingerprintSummary>,
    /// Distinct prompt-template ids and their hex hashes.
    pub prompt_templates: Vec<PromptTemplateSummary>,
    /// Distinct `(corpus_id, corpus_version)` pairs referenced.
    pub corpus_versions: Vec<CorpusVersion>,
    /// SDKs that wrote records on this stream over the period.
    pub source_sdks: Vec<String>,
}

/// §3.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionMonitoring {
    /// Total record count over the period.
    pub total_records: u64,
    /// Records by `kind` (interaction / merkle_root / etc.).
    pub records_by_kind: BTreeMap<String, u64>,
    /// Interactions broken down by automation level.
    pub interactions_by_automation_level: BTreeMap<String, u64>,
    /// Approved / rejected / escalated / override counts.
    pub approval_outcomes: BTreeMap<String, u64>,
    /// Merkle roots committed.
    pub merkle_roots_committed: u64,
    /// Tombstones observed.
    pub tombstones: u64,
}

/// §4 entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChangeEvent {
    /// Sequence the change record sits at.
    pub sequence: u64,
    /// What changed.
    pub kind: String,
    /// Human-readable summary built from the record.
    pub summary: String,
    /// RFC 3339 timestamp.
    pub occurred_at: String,
}

/// §5, §6, §8 placeholder.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SectionOperatorSupplied {
    /// Harmonised standards applied.
    pub harmonised_standards: Vec<String>,
    /// EU declaration-of-conformity reference.
    pub declaration_of_conformity: Option<String>,
    /// Risk-management-system reference.
    pub risk_management_system: Option<String>,
}

/// §7.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionPerformance {
    /// Total interactions over the period.
    pub interactions: u64,
    /// Records with `approval` populated.
    pub human_oversight_records: u64,
    /// Percentage of interactions that hit a human reviewer, rounded.
    pub human_oversight_percent: u32,
    /// Decisions by automation level.
    pub decisions_by_automation: BTreeMap<String, u64>,
}

/// §9.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SectionLifecycle {
    /// Cumulative key rotations.
    pub key_rotations: u64,
    /// Cumulative retention-policy changes.
    pub retention_policy_changes: u64,
    /// Open legal holds at export time.
    pub open_legal_holds: u64,
}

/// Model triple summary.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ModelFingerprintSummary {
    /// Provider, e.g. `anthropic`.
    pub provider: String,
    /// Model name, e.g. `claude-opus-4-7`.
    pub model_name: String,
    /// Provider version identifier.
    pub model_version: String,
    /// Number of interactions referencing this triple.
    pub interactions: u64,
}

/// Prompt-template summary entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PromptTemplateSummary {
    /// Caller-meaningful identifier.
    pub template_id: String,
    /// Canonical-form hash of the template body, hex.
    pub template_hash_hex: String,
    /// Number of interactions referencing it.
    pub interactions: u64,
}

/// Corpus-version summary entry.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CorpusVersion {
    /// Corpus identifier.
    pub corpus_id: String,
    /// Corpus version string.
    pub corpus_version: String,
}

/// Manifest entry: one file in the zip, with a SHA-256 hash.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ManifestEntry {
    /// Path inside the zip archive.
    pub path: String,
    /// Hex-encoded SHA-256 of the file's content bytes.
    pub sha256_hex: String,
    /// File size in bytes.
    pub size_bytes: u64,
}

/// The signed manifest.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SignedManifest {
    /// Format version.
    pub manifest_version: String,
    /// Stream id.
    pub stream_id: String,
    /// RFC 3339 generation time.
    pub generated_at: String,
    /// Per-artifact entries.
    pub entries: Vec<ManifestEntry>,
    /// Key id used to sign.
    pub key_id: String,
    /// The hybrid signature over the *unsigned* manifest's canonical form.
    pub signature: HybridSignature,
}

/// Build the sidecar from the stream's records, restricted to the
/// optional [`ExportRequest::period_from`] / `period_to` window.
pub fn build_sidecar(
    stream_id: &str,
    records: &[SignedRecord],
    request: &ExportRequest,
) -> AnnexIvSidecar {
    let (tenant_id, system_id) = stream_id
        .split_once('/')
        .map_or((stream_id, ""), |(t, s)| (t, s));

    let in_period = |sr: &SignedRecord| -> bool {
        let t = sr.record.occurred_at;
        request.period_from.is_none_or(|from| t >= from)
            && request.period_to.is_none_or(|to| t <= to)
    };

    let mut total: u64 = 0;
    let mut by_kind: BTreeMap<String, u64> = BTreeMap::new();
    let mut model_counts: BTreeMap<(String, String, String), u64> = BTreeMap::new();
    let mut prompt_counts: BTreeMap<(String, String), u64> = BTreeMap::new();
    let mut corpus_versions: BTreeSet<(String, String)> = BTreeSet::new();
    let mut sdks: BTreeSet<String> = BTreeSet::new();
    let mut automation: BTreeMap<String, u64> = BTreeMap::new();
    let mut approvals: BTreeMap<String, u64> = BTreeMap::new();
    let mut human_oversight = 0u64;
    let mut interactions = 0u64;
    let mut roots = 0u64;
    let mut tombstones = 0u64;
    let mut changes: Vec<ChangeEvent> = Vec::new();
    let mut key_rotations = 0u64;
    let mut policy_changes = 0u64;
    let mut holds_placed = 0u64;
    let mut holds_released = 0u64;

    for sr in records.iter().filter(|sr| in_period(sr)) {
        total += 1;
        sdks.insert(sr.record.source_sdk.clone());
        let kind = body_kind_name(&sr.record.body).to_string();
        *by_kind.entry(kind.clone()).or_default() += 1;

        match &sr.record.body {
            RecordBody::Interaction(b) => {
                interactions += 1;
                summarise_interaction(
                    b,
                    &mut model_counts,
                    &mut prompt_counts,
                    &mut corpus_versions,
                    &mut automation,
                    &mut approvals,
                    &mut human_oversight,
                );
            }
            RecordBody::MerkleRoot(_) => roots += 1,
            RecordBody::Tombstone(t) => {
                tombstones += 1;
                changes.push(ChangeEvent {
                    sequence: sr.record.sequence,
                    kind: "redaction".into(),
                    summary: format!("redacted sequence {} ({:?})", t.target_sequence, t.reason),
                    occurred_at: rfc3339(sr.record.occurred_at),
                });
            }
            RecordBody::KeyRegistry(k) => {
                key_rotations += 1;
                changes.push(ChangeEvent {
                    sequence: sr.record.sequence,
                    kind: "key_rotation".into(),
                    summary: format!("registered key `{}` ({})", k.key_id, k.algorithm),
                    occurred_at: rfc3339(sr.record.occurred_at),
                });
            }
            RecordBody::CorpusAnchor(c) => {
                changes.push(ChangeEvent {
                    sequence: sr.record.sequence,
                    kind: "corpus_anchor".into(),
                    summary: format!("registered corpus `{}` v{}", c.corpus_id, c.corpus_version),
                    occurred_at: rfc3339(sr.record.occurred_at),
                });
            }
            RecordBody::RetentionPolicy(p) => {
                policy_changes += 1;
                changes.push(ChangeEvent {
                    sequence: sr.record.sequence,
                    kind: "retention_policy".into(),
                    summary: format!(
                        "policy `{}` hot={}d warm={}d cold={}d",
                        p.template_id, p.hot_days, p.warm_days, p.cold_days
                    ),
                    occurred_at: rfc3339(sr.record.occurred_at),
                });
            }
            RecordBody::LegalHold(h) => {
                holds_placed += 1;
                changes.push(ChangeEvent {
                    sequence: sr.record.sequence,
                    kind: "legal_hold".into(),
                    summary: format!(
                        "hold `{}` placed on [{}..={}]",
                        h.hold_id,
                        h.first_sequence,
                        h.last_sequence
                            .map_or_else(|| "open".to_string(), |s| s.to_string())
                    ),
                    occurred_at: rfc3339(sr.record.occurred_at),
                });
            }
            RecordBody::LegalHoldRelease(r) => {
                holds_released += 1;
                changes.push(ChangeEvent {
                    sequence: sr.record.sequence,
                    kind: "legal_hold_release".into(),
                    summary: format!("hold `{}` released", r.hold_id),
                    occurred_at: rfc3339(sr.record.occurred_at),
                });
            }
        }
    }

    AnnexIvSidecar {
        sidecar_version: "1.0.0".into(),
        stream_id: stream_id.into(),
        generated_at: rfc3339(OffsetDateTime::now_utc()),
        general_description: SectionGeneralDescription {
            system_name: request.system_name.clone(),
            annex_iii_category: request.annex_iii_category.clone(),
            period_from: request.period_from.map(rfc3339),
            period_to: request.period_to.map(rfc3339),
            tenant_id: tenant_id.into(),
            system_id: system_id.into(),
        },
        system_elements: SectionSystemElements {
            model_fingerprints: model_counts
                .into_iter()
                .map(
                    |((provider, model_name, model_version), n)| ModelFingerprintSummary {
                        provider,
                        model_name,
                        model_version,
                        interactions: n,
                    },
                )
                .collect(),
            prompt_templates: prompt_counts
                .into_iter()
                .map(
                    |((template_id, template_hash_hex), n)| PromptTemplateSummary {
                        template_id,
                        template_hash_hex,
                        interactions: n,
                    },
                )
                .collect(),
            corpus_versions: corpus_versions
                .into_iter()
                .map(|(corpus_id, corpus_version)| CorpusVersion {
                    corpus_id,
                    corpus_version,
                })
                .collect(),
            source_sdks: sdks.into_iter().collect(),
        },
        monitoring: SectionMonitoring {
            total_records: total,
            records_by_kind: by_kind,
            interactions_by_automation_level: automation.clone(),
            approval_outcomes: approvals,
            merkle_roots_committed: roots,
            tombstones,
        },
        changes,
        operator_supplied: SectionOperatorSupplied::default(),
        performance: SectionPerformance {
            interactions,
            human_oversight_records: human_oversight,
            human_oversight_percent: if interactions == 0 {
                0
            } else {
                u32::try_from((human_oversight * 100) / interactions).unwrap_or(u32::MAX)
            },
            decisions_by_automation: automation,
        },
        lifecycle: SectionLifecycle {
            key_rotations,
            retention_policy_changes: policy_changes,
            open_legal_holds: holds_placed.saturating_sub(holds_released),
        },
    }
}

fn summarise_interaction(
    b: &InteractionBody,
    models: &mut BTreeMap<(String, String, String), u64>,
    prompts: &mut BTreeMap<(String, String), u64>,
    corpora: &mut BTreeSet<(String, String)>,
    automation: &mut BTreeMap<String, u64>,
    approvals: &mut BTreeMap<String, u64>,
    human_oversight: &mut u64,
) {
    if let Some(m) = &b.model {
        let key = (
            m.provider.clone(),
            m.model_name.clone(),
            m.model_version.clone(),
        );
        *models.entry(key).or_default() += 1;
    }
    if let Some(p) = &b.prompt {
        let key = (p.template_id.clone(), p.template_hash_hex.clone());
        *prompts.entry(key).or_default() += 1;
    }
    for cr in &b.corpus_refs {
        corpora.insert((cr.corpus_id.clone(), cr.corpus_version.clone()));
    }
    if let Some(d) = &b.decision {
        if let Some(level) = &d.automation_level {
            *automation
                .entry(format!("{level:?}").to_lowercase())
                .or_default() += 1;
        }
    }
    if let Some(app) = &b.approval {
        *human_oversight += 1;
        *approvals
            .entry(format!("{:?}", app.decision).to_lowercase())
            .or_default() += 1;
    }
}

fn body_kind_name(body: &RecordBody) -> &'static str {
    match body {
        RecordBody::Interaction(_) => "interaction",
        RecordBody::KeyRegistry(_) => "key_registry",
        RecordBody::MerkleRoot(_) => "merkle_root",
        RecordBody::CorpusAnchor(_) => "corpus_anchor",
        RecordBody::Tombstone(_) => "tombstone",
        RecordBody::RetentionPolicy(_) => "retention_policy",
        RecordBody::LegalHold(_) => "legal_hold",
        RecordBody::LegalHoldRelease(_) => "legal_hold_release",
    }
}

fn rfc3339(t: OffsetDateTime) -> String {
    t.format(&Rfc3339).unwrap_or_default()
}

/// Assemble and sign the export, writing a zip archive to `out`.
///
/// The zip contains:
///
/// ```text
/// sidecar.json           — Annex IV JSON sidecar
/// stream.jsonl           — every record on the stream, JSON Lines
/// manifest.json          — signed manifest (artifacts + signature)
/// ```
pub fn write_zip(
    out: impl std::io::Write + std::io::Seek,
    stream_id: &str,
    records: &[SignedRecord],
    request: &ExportRequest,
    key_id: &str,
    keypair: &HybridKeypair,
) -> Result<(), ExportError> {
    if records.is_empty() {
        return Err(ExportError::EmptyStream(stream_id.into()));
    }
    let sidecar = build_sidecar(stream_id, records, request);
    let sidecar_bytes = serde_json::to_vec_pretty(&sidecar)
        .map_err(|e| ExportError::Zip(format!("sidecar serialize: {e}")))?;

    let mut stream_jsonl: Vec<u8> = Vec::new();
    for sr in records {
        let line =
            serde_json::to_string(sr).map_err(|e| ExportError::Zip(format!("stream line: {e}")))?;
        stream_jsonl.extend_from_slice(line.as_bytes());
        stream_jsonl.push(b'\n');
    }

    // Build unsigned manifest first; its canonical form is what we sign.
    let entries = vec![
        ManifestEntry {
            path: "sidecar.json".into(),
            sha256_hex: hex::encode(canonical::sha256(&sidecar_bytes)),
            size_bytes: sidecar_bytes.len() as u64,
        },
        ManifestEntry {
            path: "stream.jsonl".into(),
            sha256_hex: hex::encode(canonical::sha256(&stream_jsonl)),
            size_bytes: stream_jsonl.len() as u64,
        },
    ];
    let unsigned = UnsignedManifest {
        manifest_version: "1.0.0".into(),
        stream_id: stream_id.into(),
        generated_at: rfc3339(OffsetDateTime::now_utc()),
        entries: entries.clone(),
        key_id: key_id.into(),
    };
    let unsigned_bytes = canonical::canonicalize(&unsigned)?;
    let signature = keypair.sign(&unsigned_bytes);
    let signed = SignedManifest {
        manifest_version: unsigned.manifest_version,
        stream_id: unsigned.stream_id,
        generated_at: unsigned.generated_at,
        entries: unsigned.entries,
        key_id: unsigned.key_id,
        signature,
    };
    let manifest_bytes = serde_json::to_vec_pretty(&signed)
        .map_err(|e| ExportError::Zip(format!("manifest serialize: {e}")))?;

    let mut zw = zip::ZipWriter::new(out);
    let opts: zip::write::SimpleFileOptions = zip::write::SimpleFileOptions::default()
        .compression_method(zip::CompressionMethod::Deflated);
    zw.start_file("sidecar.json", opts)
        .map_err(|e| ExportError::Zip(e.to_string()))?;
    zw.write_all(&sidecar_bytes).map_err(io)?;
    zw.start_file("stream.jsonl", opts)
        .map_err(|e| ExportError::Zip(e.to_string()))?;
    zw.write_all(&stream_jsonl).map_err(io)?;
    zw.start_file("manifest.json", opts)
        .map_err(|e| ExportError::Zip(e.to_string()))?;
    zw.write_all(&manifest_bytes).map_err(io)?;
    zw.finish().map_err(|e| ExportError::Zip(e.to_string()))?;
    Ok(())
}

fn io<E: std::fmt::Display>(e: E) -> ExportError {
    ExportError::Io(e.to_string())
}

/// The unsigned manifest. The canonical form of this struct is what
/// the signing key signs over.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct UnsignedManifest {
    manifest_version: String,
    stream_id: String,
    generated_at: String,
    entries: Vec<ManifestEntry>,
    key_id: String,
}

/// Verify the manifest's signature against a hybrid public key.
///
/// Convenience helper for downstream code (e.g. a regulator-side
/// verifier that consumes the zip and checks the manifest signature
/// before trusting the per-artifact hashes).
pub fn verify_manifest(
    signed: &SignedManifest,
    public_key: &glassbox_core::crypto::HybridPublicKey,
    combiner: glassbox_core::combiner::SignatureCombiner,
) -> Result<(), ExportError> {
    let unsigned = UnsignedManifest {
        manifest_version: signed.manifest_version.clone(),
        stream_id: signed.stream_id.clone(),
        generated_at: signed.generated_at.clone(),
        entries: signed.entries.clone(),
        key_id: signed.key_id.clone(),
    };
    let bytes = canonical::canonicalize(&unsigned)?;
    combiner
        .verify(public_key, &bytes, &signed.signature)
        .map_err(|e| ExportError::Io(format!("manifest signature: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use glassbox_core::Record;
    use glassbox_core::SCHEMA_VERSION;
    use glassbox_core::chain::sign_record;
    use glassbox_core::record::{
        ApprovalDecision, AutomationLevel, DecisionContext, HumanApproval, InteractionBody,
        ModelFingerprint, RecordBody, make_interaction,
    };
    use time::OffsetDateTime;

    fn now() -> OffsetDateTime {
        OffsetDateTime::from_unix_timestamp(1_715_500_000).unwrap()
    }

    fn fake_chain() -> (Vec<SignedRecord>, glassbox_core::crypto::HybridKeypair) {
        let kp = HybridKeypair::generate().unwrap();
        let pk = kp.public_key();
        let entry = glassbox_core::key_registry::KeyRegistryEntry {
            key_id: "k".into(),
            algorithm: glassbox_core::ALGORITHM_HYBRID_ED25519_MLDSA65.into(),
            public_key: pk,
            valid_from: now(),
            valid_to: None,
            status: glassbox_core::key_registry::KeyStatus::Active,
        };
        let r0 = Record {
            record_id: ulid::Ulid::new(),
            stream_id: "acme/sys".into(),
            sequence: 0,
            occurred_at: now(),
            received_at: now(),
            schema_version: SCHEMA_VERSION.into(),
            source_sdk: "test/0.3.0".into(),
            key_id: "k".into(),
            prev_hash_hex: hex::encode([0u8; 32]),
            body: RecordBody::KeyRegistry(entry),
        };
        let sr0 = sign_record(r0, &kp).unwrap();
        let mut prev: [u8; 32] = hex::decode(&sr0.this_hash_hex).unwrap().try_into().unwrap();
        let mut chain = vec![sr0];
        for i in 1..=3 {
            let body = InteractionBody {
                model: Some(ModelFingerprint {
                    provider: "anthropic".into(),
                    model_name: "claude-opus-4-7".into(),
                    model_version: "20260119".into(),
                    sampling: None,
                }),
                approval: Some(HumanApproval {
                    approver_id: "r1".into(),
                    decision: ApprovalDecision::Approve,
                    rationale_hash_hex: None,
                    decided_at: now(),
                }),
                decision: Some(DecisionContext {
                    decision_id: format!("d{i}"),
                    subject_id: None,
                    jurisdiction: Some("DE".into()),
                    outcome: Some("approved".into()),
                    automation_level: Some(AutomationLevel::HumanInTheLoop),
                }),
                ..Default::default()
            };
            let r = make_interaction("acme/sys", i, now(), now(), prev, "k", "test/0.3.0", body)
                .unwrap();
            let sr = sign_record(r, &kp).unwrap();
            prev = hex::decode(&sr.this_hash_hex).unwrap().try_into().unwrap();
            chain.push(sr);
        }
        (chain, kp)
    }

    #[test]
    fn sidecar_summarises_interactions() {
        let (chain, _kp) = fake_chain();
        let req = ExportRequest {
            system_name: "Credit v3".into(),
            annex_iii_category: "5b".into(),
            period_from: None,
            period_to: None,
        };
        let sidecar = build_sidecar("acme/sys", &chain, &req);
        assert_eq!(sidecar.monitoring.total_records, 4);
        assert_eq!(sidecar.performance.interactions, 3);
        assert_eq!(sidecar.performance.human_oversight_records, 3);
        assert_eq!(sidecar.performance.human_oversight_percent, 100);
        assert_eq!(sidecar.system_elements.model_fingerprints.len(), 1);
        assert_eq!(sidecar.lifecycle.key_rotations, 1);
    }

    #[test]
    fn zip_roundtrip_with_signed_manifest_verifies() {
        let (chain, kp) = fake_chain();
        let req = ExportRequest {
            system_name: "Credit v3".into(),
            annex_iii_category: "5b".into(),
            period_from: None,
            period_to: None,
        };
        let mut buf = std::io::Cursor::new(Vec::new());
        write_zip(&mut buf, "acme/sys", &chain, &req, "k", &kp).unwrap();
        let zip_bytes = buf.into_inner();

        // Parse the zip and extract manifest.json.
        let mut zr = zip::ZipArchive::new(std::io::Cursor::new(zip_bytes)).unwrap();
        let mut manifest_bytes = Vec::new();
        {
            let mut entry = zr.by_name("manifest.json").unwrap();
            std::io::copy(&mut entry, &mut manifest_bytes).unwrap();
        }
        let signed: SignedManifest = serde_json::from_slice(&manifest_bytes).unwrap();
        verify_manifest(
            &signed,
            &kp.public_key(),
            glassbox_core::combiner::SignatureCombiner::And,
        )
        .unwrap();
    }
}
