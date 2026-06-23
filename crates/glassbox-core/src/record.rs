//! The Glassbox record schema.
//!
//! This module defines the [`Record`] type — the unit that gets hashed,
//! signed, and chained — and its component structures (content
//! references, model and prompt fingerprints, tags, agent-trajectory
//! linkage).
//!
//! ## Canonical form
//!
//! [`Record::canonical_bytes`] returns the bytes that flow through
//! SHA-256 to produce `this_hash` and through the signing keypair to
//! produce the signature. Signature fields are deliberately **not** part
//! of `Record` (see [`SignedRecord`]) so it is impossible to write a
//! record whose canonical form includes its own signature.
//!
//! The kind tag [`RecordKind`] discriminates payload-bearing records,
//! [`KeyRegistryEntry`](crate::key_registry::KeyRegistryEntry) records,
//! and Merkle-root commitment records, all on the same chain.

use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use ulid::Ulid;

use crate::canonical;
use crate::crypto::{HybridPublicKey, HybridSignature};
use crate::errors::{Error, Result};
use crate::key_registry::KeyRegistryEntry;

/// Hash algorithms recognised by canonical record bodies. The chain
/// hash itself is always SHA-256 (spec §13.2); this enum exists so a
/// caller can record that their content fingerprint used a different
/// algorithm (e.g. BLAKE3) and a verifier knows what to compare to.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum HashAlgorithm {
    /// SHA-256 (FIPS 180-4). The default and the only algorithm v0.1
    /// commits to producing for `this_hash` and chain linkage.
    #[serde(rename = "SHA-256")]
    Sha256,
    /// BLAKE3, accepted for caller-supplied content hashes.
    #[serde(rename = "BLAKE3")]
    Blake3,
}

impl Default for HashAlgorithm {
    fn default() -> Self {
        Self::Sha256
    }
}

/// A hash plus metadata about what the hash covers (spec §12.2).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentRef {
    /// The hash algorithm used to produce `hash_hex`.
    pub hash_algorithm: HashAlgorithm,
    /// Hex-encoded hash bytes. We deliberately use hex (not base64) here
    /// because content hashes are frequently compared by humans during
    /// audits.
    pub hash_hex: String,
    /// The length of the original content in bytes, uncompressed.
    pub byte_size: u64,
    /// Optional MIME type hint for downstream decoders.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mime_type: Option<String>,
}

/// Model identity captured per interaction (spec §12.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelFingerprint {
    /// Vendor or stack: `anthropic`, `openai`, `google`, `mistral`,
    /// `vllm-local`, etc.
    pub provider: String,
    /// Caller-meaningful model name, e.g. `claude-opus-4-7`.
    pub model_name: String,
    /// Provider-specific version identifier.
    pub model_version: String,
    /// Sampling parameters and similar reproducibility-relevant hints.
    /// Use a `serde_json::Value` so callers can carry whatever fields
    /// their provider exposes; absence is meaningful (the provider does
    /// not expose them).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sampling: Option<serde_json::Value>,
}

/// Prompt template identity (spec §12.3).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptFingerprint {
    /// Caller-meaningful identifier of the template (e.g. `credit-v3`).
    pub template_id: String,
    /// Hex-encoded SHA-256 of the canonical-form template body.
    pub template_hash_hex: String,
    /// Map of each substituted variable to the hex SHA-256 of its
    /// substituted value, so values are auditable without storing PII.
    #[serde(default, skip_serializing_if = "std::collections::BTreeMap::is_empty")]
    pub variable_hashes: std::collections::BTreeMap<String, String>,
}

/// A structured tag attached to a record for query targeting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Tag {
    /// Tag key, e.g. `decision_id`, `subject_id`, `jurisdiction`.
    pub key: String,
    /// Tag value as a string. Numeric or structured tags are out of
    /// scope in v0.1.
    pub value: String,
}

/// One tool invocation as an inline summary within an interaction
/// record (spec §12.1). Long tool calls should be linked as their own
/// child records via `parent_record_id` instead; this struct is for
/// short call summaries that don't justify a separate record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolInvocation {
    /// Caller-meaningful tool name, e.g. `search_corpus`.
    pub tool_name: String,
    /// Hex SHA-256 of the canonical-form arguments.
    pub args_hash_hex: String,
    /// Hex SHA-256 of the canonical-form result, when one was produced.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result_hash_hex: Option<String>,
    /// Wall-clock latency of the invocation in milliseconds.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub latency_ms: Option<u64>,
    /// `true` if the tool completed without error.
    pub success: bool,
}

/// The decision a human reviewer recorded at a checkpoint (spec §12.1,
/// referenced by EU AI Act Article 14).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ApprovalDecision {
    /// The reviewer approved the model output as-is.
    #[serde(rename = "approve")]
    Approve,
    /// The reviewer rejected the model output and the system did not act on it.
    #[serde(rename = "reject")]
    Reject,
    /// The reviewer escalated to a higher authority.
    #[serde(rename = "escalate")]
    Escalate,
    /// The reviewer overrode the output with their own decision.
    #[serde(rename = "override")]
    Override,
}

/// A human-in-the-loop checkpoint (spec §12.1, Article 14).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct HumanApproval {
    /// Opaque identifier for the reviewer. Real names belong in a
    /// side-table indexed by this id, not in the ledger.
    pub approver_id: String,
    /// The decision.
    pub decision: ApprovalDecision,
    /// Hex SHA-256 of the reviewer's free-form rationale, if any.
    /// The rationale itself is never stored in the ledger by default;
    /// only its hash, so the rationale can be audited under chain of
    /// custody without forcing PII into immutable storage.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale_hash_hex: Option<String>,
    /// Timestamp the human reached the decision, RFC 3339.
    #[serde(with = "time::serde::rfc3339")]
    pub decided_at: OffsetDateTime,
}

/// Business-decision metadata captured for downstream regulator queries
/// (spec §12.1, Colorado AI Act §6-1-1701, EU AI Act Annex IV §7).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecisionContext {
    /// Caller-meaningful identifier for the decision, e.g. `loan-12345`.
    /// Indexed by storage backends for per-decision regulator queries.
    pub decision_id: String,
    /// Caller-meaningful identifier for the affected subject, e.g.
    /// `applicant-67890`. **Opaque by convention** — never a raw email
    /// or government identifier.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject_id: Option<String>,
    /// Jurisdiction tag in ISO 3166-1 alpha-2 (e.g. `DE`, `US-CO`) so
    /// per-jurisdiction queries and conflict-of-law filters (§28.7) are
    /// expressible.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub jurisdiction: Option<String>,
    /// The downstream outcome the decision caused, in caller-defined
    /// terms (`approved`, `denied`, `escalated`, `flagged`, ...).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// Whether the decision was made wholly by the AI system, by a
    /// human after AI input, or by a human acting independently.
    /// Surfaces in Annex IV §3 and §5.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub automation_level: Option<AutomationLevel>,
}

/// Per-decision automation classification (spec §12.1, §21.6).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum AutomationLevel {
    /// Decision produced solely by the AI system; no human review.
    #[serde(rename = "fully_automated")]
    FullyAutomated,
    /// AI proposed; a human approved (or rejected).
    #[serde(rename = "human_in_the_loop")]
    HumanInTheLoop,
    /// AI input was advisory; a human made the actual decision.
    #[serde(rename = "advisory")]
    Advisory,
    /// Decision made by a human without AI involvement.
    #[serde(rename = "human_only")]
    HumanOnly,
}

/// A reference to a corpus that grounded one or more retrievals
/// (spec §12.5). The `CorpusAnchor` body type registers the corpus
/// identity once; interaction records reference it by `corpus_id` plus
/// the specific chunks returned for that retrieval.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusRef {
    /// The tenant-scoped corpus identifier that a prior
    /// `RecordBody::CorpusAnchor` record on this stream registered.
    pub corpus_id: String,
    /// The version label from the registered anchor (so a verifier can
    /// pin which version was actually used).
    pub corpus_version: String,
    /// Hex SHA-256 of each chunk the retrieval returned, in order.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub chunk_hashes_hex: Vec<String>,
}

/// A corpus-anchor administrative record (spec §12.5).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CorpusAnchor {
    /// Tenant-scoped identifier (e.g. `internal-policies`,
    /// `pubmed-2026q1`).
    pub corpus_id: String,
    /// Semver or date-based version string.
    pub corpus_version: String,
    /// Optional Merkle root over the corpus's chunk set, hex-encoded.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub corpus_root_hash_hex: Option<String>,
    /// Upstream source (URL, vendor, date of acquisition).
    pub corpus_provenance: String,
}

/// Why a record was redacted (spec §12.9).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RedactionReason {
    /// GDPR Article 17 right-to-erasure request.
    #[serde(rename = "gdpr_erasure")]
    GdprErasure,
    /// A legal hold was released and retention policy now requires erasure.
    #[serde(rename = "legal_hold_release")]
    LegalHoldRelease,
    /// Operator request under documented authority.
    #[serde(rename = "operator_request")]
    OperatorRequest,
    /// Court order or regulator-coerced redaction. Witness network will
    /// surface the inconsistency, per spec §23.1 A6.
    #[serde(rename = "court_order")]
    CourtOrder,
}

/// A tombstone record marking an earlier record as redacted while
/// preserving chain integrity (spec §12.9).
///
/// The target record's stored `this_hash` is *not* recomputed and its
/// signature stays valid, because canonical form only ever hashed the
/// content **reference** (a hash), never the raw content. Side-store
/// blobs indexed by the content hash can be zeroed independently.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RedactionRecord {
    /// The record being redacted. Verifier requires this record to
    /// exist earlier on the same stream.
    pub target_record_id: Ulid,
    /// Sequence number of the target. Stored redundantly so a verifier
    /// can quickly locate the target without scanning the full stream.
    pub target_sequence: u64,
    /// The target's `this_hash_hex` at the time the tombstone was
    /// written, preserved so that any later state can be compared
    /// against what was originally signed.
    pub original_this_hash_hex: String,
    /// Why the redaction was performed.
    pub reason: RedactionReason,
    /// Opaque identifier of the actor performing the redaction. Like
    /// HumanApproval.approver_id, this is **not** a raw identity.
    pub actor_id: String,
    /// Hex SHA-256 of the actor's free-form rationale, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale_hash_hex: Option<String>,
}

/// A retention policy attached to a stream (spec §20.1, §20.2).
///
/// Policies are themselves on-ledger records on the administrative
/// stream so every policy change is auditable. The most recent
/// `RetentionPolicy` record on a stream is the active policy.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    /// Caller-meaningful identifier of the policy template, e.g.
    /// `eu-ai-act-high-risk`, `hipaa`, `nyc-aedt`, `generic-3-year`.
    pub template_id: String,
    /// How long records remain on the hot tier, in days.
    pub hot_days: u32,
    /// How long records remain on the warm tier after hot, in days.
    pub warm_days: u32,
    /// How long records remain on the cold tier after warm, in days.
    pub cold_days: u32,
    /// What happens when retention ends and no legal hold is in place.
    pub end_of_retention: EndOfRetentionAction,
    /// Whether records under this policy may be redacted at all.
    /// GDPR Article 17 sometimes requires `true` even on retention-
    /// mandatory streams; legal review owns this decision.
    pub allow_redaction: bool,
    /// Free-form policy notes (e.g. references to the operator's
    /// internal SOP that codified this policy choice).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notes: Option<String>,
}

/// What the retention manager does when the cold-tier window expires.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EndOfRetentionAction {
    /// Move records to a deep-archive tier and keep them indefinitely.
    #[serde(rename = "archive_deep_cold")]
    ArchiveDeepCold,
    /// Generate a signed inclusion-proof export covering the to-be-
    /// deleted range, then delete. The proof survives deletion.
    #[serde(rename = "delete_with_proof")]
    DeleteWithProof,
    /// Hand off to a successor controller's ledger. Retains a
    /// forwarding pointer record.
    #[serde(rename = "transfer_to_successor")]
    TransferToSuccessor,
}

/// A legal hold record placed on a sequence range (spec §20.3).
///
/// While a hold is in effect, the retention manager moves data through
/// tiers but never deletes it. Hold release is a separate record.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalHold {
    /// Caller-meaningful identifier of the hold (e.g. a case number).
    pub hold_id: String,
    /// First sequence the hold covers (inclusive).
    pub first_sequence: u64,
    /// Last sequence the hold covers (inclusive), or `None` for an
    /// open-ended hold covering everything from `first_sequence` to
    /// the current tail of the stream.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_sequence: Option<u64>,
    /// Opaque identifier of the placer (a custodian, legal counsel,
    /// or court-appointed actor).
    pub placed_by: String,
    /// Hex SHA-256 of the placer's free-form justification, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale_hash_hex: Option<String>,
}

/// A legal-hold release record (spec §20.3).
///
/// References the prior [`LegalHold`] record. The verifier rejects a
/// release that does not match an earlier hold's `hold_id` on the
/// same stream.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LegalHoldRelease {
    /// The `hold_id` of the hold being released.
    pub hold_id: String,
    /// Opaque identifier of the releasing actor.
    pub released_by: String,
    /// Hex SHA-256 of the free-form release rationale, if any.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rationale_hash_hex: Option<String>,
}

/// A cross-tenant inclusion proof (spec §29.2, §29.4).
///
/// A record in tenant A's ledger may reference a record in tenant B's
/// ledger by carrying B's record_id, B's `SignedTreeHead`, and a
/// Merkle inclusion proof. A third party with B's witness view can
/// verify the cross-reference without trusting A's operator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossChainRef {
    /// Identifier of the foreign tenant. Caller-meaningful.
    pub foreign_tenant_id: String,
    /// `stream_id` on the foreign tenant.
    pub foreign_stream_id: String,
    /// Sequence of the referenced record on the foreign stream.
    pub foreign_sequence: u64,
    /// Hex SHA-256 `this_hash` of the referenced record at the time
    /// of reference.
    pub foreign_record_this_hash_hex: String,
    /// The foreign tenant's [`SignedTreeHead`] that was current when
    /// this reference was minted — what a verifier should compare the
    /// inclusion proof against.
    pub foreign_sth: SignedTreeHead,
    /// Inclusion-proof steps, base64-encoded so they survive canonical
    /// form unchanged.
    pub inclusion_proof_steps: Vec<CrossChainProofStep>,
}

/// One step in a cross-chain Merkle inclusion proof. Mirrors
/// [`crate::merkle::ProofStep`] but lives in the record schema so it
/// can be serialized.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrossChainProofStep {
    /// Hex-encoded SHA-256 of the sibling node.
    pub sibling_hex: String,
    /// `true` if the sibling is on the right of the current path node.
    pub sibling_is_right: bool,
}

/// Span kinds for agent trajectory records (spec §12.4).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SpanKind {
    /// The user's initial prompt; the root of a run.
    #[serde(rename = "user_prompt")]
    UserPrompt,
    /// A call to a model.
    #[serde(rename = "model_call")]
    ModelCall,
    /// An invocation of a tool.
    #[serde(rename = "tool_call")]
    ToolCall,
    /// A retrieval-augmented step.
    #[serde(rename = "retrieval")]
    Retrieval,
    /// Delegation to a sub-agent.
    #[serde(rename = "sub_agent")]
    SubAgent,
    /// A human-in-the-loop checkpoint.
    #[serde(rename = "human_review")]
    HumanReview,
    /// The final response shown to the user.
    #[serde(rename = "final_response")]
    FinalResponse,
}

/// Discriminator for the record-body variants this chain accepts.
///
/// All variants live on the same chain so that key rotations, Merkle
/// commits, corpus registrations, and redaction tombstones are
/// themselves visible in verification walks (spec §12.5, §12.7, §12.8,
/// §12.9).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind")]
pub enum RecordBody {
    /// A normal AI-interaction record.
    #[serde(rename = "interaction")]
    Interaction(InteractionBody),
    /// A key-registry administrative entry.
    #[serde(rename = "key_registry")]
    KeyRegistry(KeyRegistryEntry),
    /// A Merkle-root commitment over a batch.
    #[serde(rename = "merkle_root")]
    MerkleRoot(MerkleRootEntry),
    /// A retrieval-corpus anchor (spec §12.5).
    #[serde(rename = "corpus_anchor")]
    CorpusAnchor(CorpusAnchor),
    /// A redaction tombstone (spec §12.9).
    #[serde(rename = "tombstone")]
    Tombstone(RedactionRecord),
    /// A retention-policy declaration (spec §20.1).
    #[serde(rename = "retention_policy")]
    RetentionPolicy(RetentionPolicy),
    /// A legal-hold placement (spec §20.3).
    #[serde(rename = "legal_hold")]
    LegalHold(LegalHold),
    /// A legal-hold release (spec §20.3).
    #[serde(rename = "legal_hold_release")]
    LegalHoldRelease(LegalHoldRelease),
}

/// Body of an `interaction` record. Optional fields are omitted from
/// canonical form when absent, so adding fields here in a minor release
/// does not invalidate signatures over records that did not set them
/// (see spec §12.6).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct InteractionBody {
    /// Content reference for the input (typically the prompt).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<ContentRef>,
    /// Content reference for the output (typically the model response).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<ContentRef>,
    /// The model that produced the output.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<ModelFingerprint>,
    /// The prompt template applied.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prompt: Option<PromptFingerprint>,
    /// Parent record in the agent trajectory tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parent_record_id: Option<Ulid>,
    /// Root of the agent run this record belongs to. Typically the
    /// `user_prompt` span; allows the full trajectory to be fetched in
    /// one query.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_record_id: Option<Ulid>,
    /// Span kind in the trajectory tree.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_kind: Option<SpanKind>,
    /// Ordinal position among siblings under the same parent.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub span_index: Option<u32>,
    /// `Some` if this record is a retry of an earlier record (e.g.
    /// after a 429, a tool error, or a content-policy refusal).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_of: Option<Ulid>,
    /// Records whose result was used to produce this one but which
    /// are not the parent (e.g. a retrieval whose output was reused
    /// across multiple model calls).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub causal_links: Vec<Ulid>,
    /// Inline tool-call summaries. Long tool calls should be linked as
    /// their own child records and referenced via `parent_record_id`
    /// instead.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tool_calls: Vec<ToolInvocation>,
    /// References to corpus anchors that grounded this generation,
    /// plus the specific chunks returned.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub corpus_refs: Vec<CorpusRef>,
    /// Cross-tenant references for AI-supply-chain audit (spec §29.2).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cross_chain_refs: Vec<CrossChainRef>,
    /// A human-in-the-loop checkpoint, if one occurred.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub approval: Option<HumanApproval>,
    /// Business-decision metadata.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub decision: Option<DecisionContext>,
    /// Structured tags for query targeting.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<Tag>,
    /// Free-form metadata under caller control.
    #[serde(default, skip_serializing_if = "serde_json::Map::is_empty")]
    pub metadata: serde_json::Map<String, serde_json::Value>,
}

/// A trusted-timestamp anchor on a Merkle root (spec §13.5).
///
/// `kind` identifies the issuer's protocol so a verifier knows which
/// parser to apply; `token` is the issuer-returned byte blob — for
/// RFC 3161 this is a `TimeStampToken` (ContentInfo SignedData), for
/// roughtime it is the signed response.
///
/// The field is byte-stored as base64 in canonical form so the Merkle
/// root's `this_hash` covers the timestamp commitment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimestampAnchor {
    /// Anchor source: `rfc3161` or `roughtime` in v0.3.
    pub kind: String,
    /// Caller-meaningful identifier of the authority that issued this
    /// token (e.g. `freetsa.org`, `roughtime.cloudflare.com`).
    pub authority_id: String,
    /// The issuer's signed token, base64-encoded.
    #[serde(with = "crate::crypto::serde_b64_vec_pub")]
    pub token: Vec<u8>,
}

/// Witness counter-signature on a published Merkle root (spec §13.7).
///
/// Each witness in the configured set publishes its observation of the
/// ledger as a Signed Tree Head. A counter-signature stored back into
/// the chain is what gives a third party an operator-independent
/// integrity check.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WitnessCountersignature {
    /// Stable identifier of the witness operator (caller-meaningful).
    pub witness_id: String,
    /// The witness's hybrid public key the verifier should resolve
    /// against — stored in-line so a counter-signature is verifiable
    /// without contacting the witness.
    pub witness_public_key: crate::crypto::HybridPublicKey,
    /// `Ed25519 || ML-DSA-65` combined signature over the canonical
    /// form of a [`SignedTreeHead`].
    pub signature: crate::crypto::HybridSignature,
    /// RFC 3339 timestamp the witness recorded for this observation.
    #[serde(with = "time::serde::rfc3339")]
    pub observed_at: OffsetDateTime,
}

/// The structure each witness signs to attest to a Merkle root
/// (spec §13.7). Distinct from the [`MerkleRootEntry`] itself so a
/// witness can sign the *publishable summary* without seeing the full
/// chain bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedTreeHead {
    /// Stream identifier the root is over.
    pub stream_id: String,
    /// First sequence covered.
    pub first_sequence: u64,
    /// Last sequence covered.
    pub last_sequence: u64,
    /// Hex-encoded Merkle root hash.
    pub root_hash_hex: String,
    /// Hex-encoded SHA-256 of the canonical form of the
    /// `MerkleRootEntry`-bearing `Record` whose root this signs.
    /// Lets a witness commit to the exact bytes the operator stored.
    pub root_record_this_hash_hex: String,
}

/// Body of a Merkle-root commitment record (spec §12.8).
///
/// Trusted-timestamp anchors and witness counter-signatures are part of
/// the *signed* canonical form so a v0.1 verifier that doesn't know
/// about them still produces the same hash (they default to empty).
/// A v0.3 verifier additionally checks every anchor and counter-
/// signature it understands.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct MerkleRootEntry {
    /// First sequence covered by this root (inclusive).
    pub first_sequence: u64,
    /// Last sequence covered by this root (inclusive).
    pub last_sequence: u64,
    /// Hex-encoded SHA-256 Merkle root over the batch's `this_hash` values.
    pub root_hash_hex: String,
    /// Trusted-timestamp anchors (RFC 3161 / roughtime). One per
    /// authority. Empty in v0.1 chains.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timestamp_anchors: Vec<TimestampAnchor>,
    /// Witness counter-signatures collected after publication. Empty
    /// in v0.1 chains. New counter-signatures may be appended to the
    /// same Merkle-root record by an updater record (see §13.7) — in
    /// v0.3 we store the witness signatures at write time and treat
    /// late-arriving signatures as a v0.4 extension.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub witness_signatures: Vec<WitnessCountersignature>,
}

/// A record before signing.
///
/// `this_hash` is the SHA-256 of the canonical form of *this* struct
/// (which excludes the signature, by construction).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Record {
    /// Sortable 128-bit identifier.
    pub record_id: Ulid,
    /// `<tenant>/<system>` tuple.
    pub stream_id: String,
    /// Zero-indexed position within the stream.
    pub sequence: u64,
    /// Client-side event time, in RFC 3339 form.
    #[serde(with = "time::serde::rfc3339")]
    pub occurred_at: OffsetDateTime,
    /// Server-side receipt time, in RFC 3339 form.
    #[serde(with = "time::serde::rfc3339")]
    pub received_at: OffsetDateTime,
    /// Schema version this record was produced under.
    pub schema_version: String,
    /// SDK that produced this record, e.g. `glassbox-cli/0.1.0`.
    pub source_sdk: String,
    /// `key_id` from the [`KeyRegistryEntry`] that signed this record.
    pub key_id: String,
    /// Hex-encoded SHA-256 of the immediately-preceding record's
    /// canonical form (or 32 zero bytes for genesis).
    pub prev_hash_hex: String,
    /// The discriminated payload.
    pub body: RecordBody,
}

impl Record {
    /// Bytes that get hashed and signed.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>> {
        canonical::canonicalize(self)
    }

    /// SHA-256 of [`Self::canonical_bytes`].
    pub fn this_hash(&self) -> Result<[u8; 32]> {
        canonical::canonical_hash(self)
    }

    /// Hex form of [`Self::this_hash`]. Convenience for storage backends.
    pub fn this_hash_hex(&self) -> Result<String> {
        Ok(hex::encode(self.this_hash()?))
    }

    /// Validate light-weight schema invariants. Hash and signature
    /// invariants are checked by the verifier; this only catches
    /// obviously-malformed inputs at the API boundary.
    pub fn validate_shape(&self) -> Result<()> {
        if !self.stream_id.contains('/') {
            return Err(Error::invalid(
                "stream_id must be `<tenant>/<system>` (one slash)",
            ));
        }
        if self.prev_hash_hex.len() != 64 {
            return Err(Error::invalid(format!(
                "prev_hash_hex must be 64 hex chars, got {}",
                self.prev_hash_hex.len()
            )));
        }
        hex::decode(&self.prev_hash_hex).map_err(Error::invalid)?;
        if self.key_id.is_empty() {
            return Err(Error::invalid("key_id is required"));
        }
        if self.schema_version.is_empty() {
            return Err(Error::invalid("schema_version is required"));
        }
        if self.source_sdk.is_empty() {
            return Err(Error::invalid("source_sdk is required"));
        }
        Ok(())
    }
}

/// A record together with its hybrid signature and pre-computed
/// `this_hash`. Storage backends persist this struct.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRecord {
    /// The unsigned record.
    pub record: Record,
    /// Hex-encoded SHA-256 of [`Record::canonical_bytes`].
    pub this_hash_hex: String,
    /// The hybrid signature over [`Record::canonical_bytes`].
    pub signature: HybridSignature,
}

impl SignedRecord {
    /// Verify this record's signature under the supplied public key,
    /// assuming the default AND combiner (the only combiner v0.1 and
    /// new v0.2 records use). Equivalent to
    /// [`Self::verify_signature_with`] with
    /// [`SignatureCombiner::And`](crate::combiner::SignatureCombiner::And).
    pub fn verify_signature(&self, key: &HybridPublicKey) -> Result<()> {
        self.verify_signature_with(key, crate::combiner::SignatureCombiner::And)
    }

    /// Verify this record's signature under the supplied public key
    /// and combiner. Storage backends use this path with the combiner
    /// parsed from the resolved key-registry entry.
    pub fn verify_signature_with(
        &self,
        key: &HybridPublicKey,
        combiner: crate::combiner::SignatureCombiner,
    ) -> Result<()> {
        let bytes = self.record.canonical_bytes()?;
        let computed = canonical::sha256(&bytes);
        let expected_hex = hex::encode(computed);
        if expected_hex != self.this_hash_hex {
            return Err(Error::HashMismatch {
                sequence: self.record.sequence,
                reason: format!(
                    "stored this_hash {} does not match canonical hash {expected_hex}",
                    self.this_hash_hex
                ),
            });
        }
        combiner.verify(key, &bytes, &self.signature)
    }
}

/// Convenience constructor for a payload-bearing record. The caller
/// supplies the previous record's `this_hash` (or genesis zeroes for
/// sequence 0) and the active `key_id`; the server fills in
/// `received_at` and the body fills in `occurred_at`.
#[allow(clippy::too_many_arguments)]
pub fn make_interaction(
    stream_id: impl Into<String>,
    sequence: u64,
    occurred_at: OffsetDateTime,
    received_at: OffsetDateTime,
    prev_hash: [u8; 32],
    key_id: impl Into<String>,
    source_sdk: impl Into<String>,
    body: InteractionBody,
) -> Result<Record> {
    let record = Record {
        record_id: Ulid::new(),
        stream_id: stream_id.into(),
        sequence,
        occurred_at,
        received_at,
        schema_version: crate::SCHEMA_VERSION.to_string(),
        source_sdk: source_sdk.into(),
        key_id: key_id.into(),
        prev_hash_hex: hex::encode(prev_hash),
        body: RecordBody::Interaction(body),
    };
    record.validate_shape()?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    fn now() -> OffsetDateTime {
        datetime!(2026-05-12 12:00:00 UTC)
    }

    #[test]
    fn interaction_canonical_form_is_stable_under_metadata_reorder() {
        let mut a_meta = serde_json::Map::new();
        a_meta.insert("z".into(), serde_json::Value::from(1));
        a_meta.insert("a".into(), serde_json::Value::from(2));
        let mut b_meta = serde_json::Map::new();
        b_meta.insert("a".into(), serde_json::Value::from(2));
        b_meta.insert("z".into(), serde_json::Value::from(1));

        let body_a = InteractionBody {
            metadata: a_meta,
            ..Default::default()
        };
        let body_b = InteractionBody {
            metadata: b_meta,
            ..Default::default()
        };

        let r_a = make_interaction(
            "acme/sys",
            0,
            now(),
            now(),
            crate::GENESIS_PREV_HASH,
            "key-1",
            "test/0.1.0",
            body_a,
        )
        .unwrap();
        let mut r_b = r_a.clone();
        r_b.body = RecordBody::Interaction(body_b);

        // record_id differs; force-equal both for canonical comparison
        let mut r_a2 = r_a.clone();
        let mut r_b2 = r_b.clone();
        r_a2.record_id = Ulid::nil();
        r_b2.record_id = Ulid::nil();
        assert_eq!(
            r_a2.canonical_bytes().unwrap(),
            r_b2.canonical_bytes().unwrap()
        );
    }

    #[test]
    fn validate_shape_rejects_missing_stream_id_slash() {
        let mut r = make_interaction(
            "acme/sys",
            0,
            now(),
            now(),
            crate::GENESIS_PREV_HASH,
            "k",
            "t",
            InteractionBody::default(),
        )
        .unwrap();
        r.stream_id = "no-slash".into();
        assert!(matches!(r.validate_shape(), Err(Error::Invalid(_))));
    }

    #[test]
    fn validate_shape_rejects_bad_prev_hash() {
        let mut r = make_interaction(
            "acme/sys",
            0,
            now(),
            now(),
            crate::GENESIS_PREV_HASH,
            "k",
            "t",
            InteractionBody::default(),
        )
        .unwrap();
        r.prev_hash_hex = "deadbeef".into();
        assert!(matches!(r.validate_shape(), Err(Error::Invalid(_))));
    }

    #[test]
    fn signed_record_verifies_with_correct_key() {
        let kp = crate::crypto::HybridKeypair::generate().unwrap();
        let pk = kp.public_key();
        let r = make_interaction(
            "acme/sys",
            0,
            now(),
            now(),
            crate::GENESIS_PREV_HASH,
            "k",
            "t",
            InteractionBody::default(),
        )
        .unwrap();
        let bytes = r.canonical_bytes().unwrap();
        let this_hash = canonical::sha256(&bytes);
        let signature = kp.sign(&bytes);
        let sr = SignedRecord {
            record: r,
            this_hash_hex: hex::encode(this_hash),
            signature,
        };
        sr.verify_signature(&pk).expect("verifies");
    }

    #[test]
    fn signed_record_rejects_mutated_body() {
        let kp = crate::crypto::HybridKeypair::generate().unwrap();
        let pk = kp.public_key();
        let mut r = make_interaction(
            "acme/sys",
            0,
            now(),
            now(),
            crate::GENESIS_PREV_HASH,
            "k",
            "t",
            InteractionBody::default(),
        )
        .unwrap();
        let bytes = r.canonical_bytes().unwrap();
        let signature = kp.sign(&bytes);
        let this_hash = canonical::sha256(&bytes);
        // mutate the body after signing
        if let RecordBody::Interaction(ref mut ib) = r.body {
            ib.tags.push(Tag {
                key: "x".into(),
                value: "y".into(),
            });
        }
        let sr = SignedRecord {
            record: r,
            this_hash_hex: hex::encode(this_hash),
            signature,
        };
        let err = sr.verify_signature(&pk).unwrap_err();
        match err {
            Error::HashMismatch { .. } => {}
            other => panic!("expected hash mismatch, got {other:?}"),
        }
    }
}
