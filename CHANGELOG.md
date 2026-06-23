# Changelog

All notable changes to Glassbox are documented in this file.
Format: [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
versioning: [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.0] — 2026-05-13

Closes the **language SDK trio (§16)** and **framework middleware
(§17.2)**. Ships official client libraries for Python, TypeScript, and
Go, each tested end-to-end against a real `glassbox-server`. With
v0.7, every spec-named engineering item except the `glassbox-ffi` C
ABI has a working implementation in the workspace.

### Added

- **Python SDK** at `sdks/python/`. Pure-Python over HTTP (no native
  bindings). Exposes `Client` (sync, full HTTP surface incl.
  `verify`/`inclusion_proof`/`append`), `WalBuffer` (durable
  fsync-per-record JSON-Lines buffer with background flush), record
  builders (`InteractionBody` and friends, byte-stable with the Rust
  canonical form), and `wrap_anthropic` / `wrap_openai` Proxy
  wrappers that intercept `messages.create` / `chat.completions.create`
  and emit one `InteractionBody` per call. Audit failures never break
  the application call (spec §17.2). Tests spawn a real
  `glassbox-server` against a fresh SQLite ledger; 17 tests cover
  client, WAL, records, and wraps.
- **TypeScript SDK** at `sdks/typescript/`. Pure-TS over `fetch` (no
  third-party HTTP dependency). Mirrors the Python surface: `Client`,
  `WalBuffer`, `buildInteraction`, `wrapOpenAI` / `wrapAnthropic`.
  The wrap helpers use `Proxy` attribute forwarding so the original
  SDK surface is preserved verbatim. Vitest runs against the same
  real `glassbox-server` fixture; 16 tests cover the full surface.
- **Go SDK** at `sdks/go/`. Pure-Go (no cgo). `glassbox.Client`
  exposes `Healthz`/`ListStreams`/`Last`/`Get`/`IterRecords`/`Append`/
  `Verify`/`InclusionProof` with context-aware cancellation; record
  types use pointer fields so JSON encoding matches Rust's
  `Option::is_none` skip behavior byte-for-byte. `OpenWal` provides
  the same durable WAL semantics as the Python/TS sides. `WrapCall`
  builds an `InteractionBody` from a `(request, response)` pair, with
  panic-safe callback invocation. `go test` spawns the same
  `glassbox-server` fixture; 10 tests cover client, WAL, records, and
  wrap.

### Implementation notes

- The SDK trio is intentionally thin: no SDK ever holds a signing
  key. Records are signed by the operator pipeline (Rust core via the
  `glassbox append` CLI or a server-side signing service), and the
  SDKs only ship already-signed JSON. This keeps the trust boundary
  at the operator's keystore, regardless of which language the
  application is written in.
- Every SDK exposes the same wire surface in idiomatic form for its
  language: sync context-managers for Python, `Promise`-based async
  for TS, `context.Context`-aware for Go.
- WAL durability semantics are identical across all three: fsync per
  enqueue, background drain, never lose records on server rejection.

### Cryptographic

No on-wire schema change. `SCHEMA_VERSION` stays at `"0.6.0"`; all
v0.1–v0.6 chains verify byte-identically under v0.7 binaries.

## [0.6.0] — 2026-05-13

Closes the **gRPC primary surface (§15.1)**, **Annex IV PDF rendering
(§22)**, **live RFC 3161 TSA client (§13.5)**, and **NL → structured
query translator (§19.3)**. The only spec-named engineering items
still on the v1.0 roadmap are language SDKs (§16), framework
middleware (§17), and the `glassbox-ffi` C ABI.

### Added

- **`glassbox-server` gRPC surface** under the `grpc` cargo feature.
  Real tonic + Protobuf wire (`proto/glassbox.proto`) with hermetic
  codegen via `protoc-bin-vendored`. Seven RPCs: `ListStreams`,
  `GetLast`, `GetRecord`, `IterStream`, `AppendRecord`, `Verify`,
  `InclusionProof`. Capability-token auth via the `AuthHeader`
  message; shares the `CapabilityToken` type with HTTP + MCP.
  Integration tests run a real `tonic::transport::Server` and drive
  it through a real generated client.
- **Annex IV PDF rendering** in `glassbox-export` under the `pdf`
  cargo feature. `pdf::render` produces a valid PDF (opens in any
  reader) laying out the sidecar's nine Annex IV sections.
  `pdf::sign_detached` returns a `(HybridSignature, [u8; 32])` pair
  — the AND-combined hybrid signature over the PDF's SHA-256
  imprint, suitable for filing as a detached `.sig` alongside the
  PDF. True PAdES embedding deferred to v0.7 per spec §22.4.
- **RFC 3161 TSA client** in `glassbox-witness::tsa` under the `tsa`
  cargo feature. Hand-rolled DER encoder for the `TimeStampReq`
  structure (no large ASN.1 dependency tree). `request()` posts the
  imprint to a configured TSA URL via `ureq` and stores the response
  as an opaque `TimestampAnchor.token`. Live round-trip gated on
  `GLASSBOX_TSA_URL` env var. `anchor_from_token()` builds the same
  anchor offline, for air-gapped operators (spec §27.7).
- **`nl_query` module in `glassbox-core`** — pure-Rust pattern-based
  translator from English ("show last 5 records for decision loan-1")
  to the `StructuredQuery` shape the MCP `query` tool and the gRPC
  `Query` RPC accept. Per spec §19.3, every translation surfaces the
  structured form to the caller for confirmation before execution.

### Changed

- `SCHEMA_VERSION` bumped to `"0.6.0"`. Same forward-compatibility
  guarantee.
- Workspace `unsafe_code` lint relaxed from `forbid` to `deny` so
  build scripts (specifically `glassbox-server/build.rs`) can opt
  into a tightly scoped `#[allow(unsafe_code)]` for the single
  `std::env::set_var` call that points `tonic-build` at the
  vendored `protoc`. Production source code at `lib.rs` top-level
  still `forbid`s unsafe via `#![cfg_attr(not(test), forbid(unsafe_code))]`.

### Cryptographic

- **No canonical-form changes.** The new wire surfaces (gRPC, PDF)
  serialize `SignedRecord` via `serde_json::to_vec` — bit-identical
  with the HTTP server and with on-disk storage. The PDF carries no
  signing-relevant bytes; the detached signature is over the SHA-256
  imprint of the rendered PDF and verifies under the same hybrid
  keypair as the sidecar manifest.
- **TimeStampReq DER encoding** is hand-rolled (not delegated to an
  ASN.1 library). Unit tests check the expected byte sequences for
  the SHA-256 OID, the version INTEGER, the certReq BOOLEAN, and the
  32-byte hash position. Response tokens are stored opaquely; CMS
  parsing is the consumer's responsibility per the existing schema
  comment on `TimestampAnchor.token`.

## [0.5.0] — 2026-05-13

Adds the **HTTP/JSON server**, **Parquet cold-tier backend**, and
**reproducible benchmark harness** the spec calls for. Workspace is
now **8 crates** (of the 10 enumerated in spec §11.1) — `glassbox-ffi`
and a Protobuf-defined gRPC variant of the HTTP surface remain.

### Added

- **`glassbox-server` crate** (spec §15) — axum HTTP/JSON server
  exposing append, last, get, iter, list-streams, verify, and
  inclusion-proof over a small REST surface. Bearer-token auth shares
  the `CapabilityToken` type with `glassbox-mcp` so an operator can
  hand a single token spec to both an HTTP client and an MCP-capable
  agent. Integration tests bind a real `tokio::net::TcpListener` on
  an ephemeral port and drive the server with `reqwest`.
- **`glassbox-bench` crate** (spec §25) — `glassbox-bench` binary
  that prints throughput and p50/p99/p999 latency for hybrid sign,
  hybrid verify, SQLite append, and full-stream verify. Output is
  shaped as a reproducibility log: rustc version, build profile,
  workload size on every run.
- **Parquet cold-tier** in `glassbox-storage` under the `parquet`
  cargo feature (spec §14.1, §14.5). `ColdTierBackend` reads
  per-stream Parquet files; `migrate_to_parquet` snapshots a hot-tier
  stream and emits a side-channel manifest with the file's SHA-256
  hash, sequence range, and a list of every Merkle root in the
  exported batch.

### Changed

- `SCHEMA_VERSION` bumped to `"0.5.0"`. Same forward-compatibility
  guarantee: every new field is `skip_serializing_if`-elided, every
  new record-body variant is a new discriminator value. v0.1 … v0.4
  chains verify under v0.5 unchanged.
- Workspace expanded from 6 to 8 crates (adds `glassbox-server`,
  `glassbox-bench`).

### Cryptographic

- **No canonical-form changes.** The new HTTP server is a thin
  wrapper around the existing `Backend` trait and `verify_stream`
  helper; the bench harness exercises the existing crypto primitives
  with no new code paths.
- **Bearer tokens are compared in constant time** via the same
  helper the MCP server uses.
- **Cold-tier integrity is end-to-end auditable.** Records read from
  Parquet recompute the same canonical-form hashes as records read
  from SQLite — the cold-tier read path runs through
  `Backend::iter_stream`, and `verify_stream` accepts cold-tier
  backends transparently. The new test `migrate_and_read_back`
  asserts that a chain round-tripped through Parquet still verifies
  byte-identically.

## [0.4.0] — 2026-05-13

Closes three more spec moats: **MCP server**, **Postgres backend**, and
**verifier-side cross-chain Merkle check**. Workspace is now 6 crates
(of the 10 enumerated in spec §11.1); `glassbox-server` (gRPC/HTTP) and
the language SDKs are next. Items that are not coding tasks — external
audit, foundation donation, third-party witness operators, professional
EU translations — remain open by definition.

### Added

- **`glassbox-mcp` crate** implementing the spec §18 Model Context
  Protocol surface. JSON-RPC 2.0 over stdio (the standard MCP host
  transport). Seven tools per §18.2: `record_interaction`,
  `record_tool_call`, `record_retrieval`, `record_human_decision`,
  `record_sub_agent`, `query`, `verify_inclusion`. Each tool has a
  strict JSON-Schema input. Capability tokens (`CapabilityToken`)
  scoped to tenant + stream + tool set + expiration; constant-time
  secret comparison; expiry enforced at load time.
- **Postgres backend** in `glassbox-storage` under the `postgres`
  cargo feature. Same logical schema as SQLite. Append-path uses
  `BEGIN; SELECT … FOR UPDATE; INSERT; COMMIT;` so two concurrent
  writers cannot race past each other. Integration tests gated on
  `GLASSBOX_PG_TEST_URL` and skipped when unset, keeping default
  CI hermetic. Interior mutability (`RefCell<Client>`) so the
  `Backend` trait's `&self` reads compose with the postgres crate's
  `&mut self` requirement.
- **Verifier-side cross-chain Merkle check** in `chain::verify_chain`.
  Every `CrossChainRef` on an interaction record now has its
  inclusion proof validated against the embedded foreign STH's root.
  `VerificationReport.cross_chain_refs_verified` is the new counter.
  Adversarial tests cover tampered roots and out-of-range sequences.
- `glassbox-mcp` binary that wires the server to stdin/stdout for
  Claude Desktop / IDE host integration.

### Changed

- `SCHEMA_VERSION` bumped to `"0.4.0"`. Same forward-compatibility
  guarantee: every new field is `skip_serializing_if`-elided, every
  new record body variant is a new discriminator value. v0.1, v0.2,
  v0.3 chains continue to verify under v0.4 binaries unchanged.
- Workspace expanded from 5 to 6 crates.

### Cryptographic

- **Cross-chain proofs use the same RFC-6962-style Merkle construction**
  as in-tenant Merkle commits, so a foreign STH that operators
  generated with our `glassbox-witness` toolchain is verifiable
  by our `chain::verify_chain` without any out-of-band format
  negotiation.
- **MCP capability-token secrets are compared in constant time** to
  prevent timing-based leak of the secret from a malicious agent.
- **No canonical-form changes.** v0.1/v0.2/v0.3 chains stay
  byte-identical under v0.4.

## [0.3.0] — 2026-05-13

Closes the highest-leverage **engineering** gaps remaining after v0.2:
witness network end-to-end, Annex IV JSON-sidecar export, retention
policy + legal hold, trusted-timestamp anchor structure on Merkle
roots, and federation cross-chain references. Items that are not
coding tasks — external audit, foundation donation, real third-party
witness operators, professional EU-language translations — remain
open by definition and are tracked in spec §32 of the upstream spec.

### Added

- **`glassbox-witness` crate** with a `WitnessServer` (file-backed
  append-only observation log per stream, with rewind/fork detection)
  and a `glassbox-witness` binary that reads an STH and writes a
  counter-signature. `verify_countersignature` lets a third party
  validate any counter-signature stand-alone (spec §13.7).
- **`glassbox-export` crate** producing an Annex IV zip archive
  containing `sidecar.json` (populated from real ledger queries against
  §1, §2, §3, §4, §7, §9 of Annex IV), `stream.jsonl` (every record
  serialised), and `manifest.json` (per-artifact SHA-256 hashes signed
  by the active hybrid key). `verify_manifest` is the regulator-side
  helper. PDF + PAdES deferred (spec §22.4 calls PAdES non-trivial).
- **Retention policy engine** with 5 reference templates
  (`eu-ai-act-high-risk`, `hipaa`, `nyc-aedt`, `colorado-ai-act`,
  `generic-3-year`) and on-ledger `RetentionPolicy` records.
- **Legal hold** with `LegalHold` / `LegalHoldRelease` body variants
  and CLI `legal-hold place` / `legal-hold release` enforcement that
  release must reference an open hold by id.
- **Trusted-timestamp anchor structure** on `MerkleRootEntry`:
  `timestamp_anchors: Vec<TimestampAnchor>` with `kind`, `authority_id`,
  and the issuer's signed byte token. Verifier passes the anchors
  through; live TSA round-trip integration with a free RFC 3161 TSA
  is opt-in operator-side configuration in v0.4.
- **Witness counter-signatures** as a structured field on
  `MerkleRootEntry`: `witness_signatures: Vec<WitnessCountersignature>`
  carries the witness id, embedded public key, hybrid signature over
  the canonical `SignedTreeHead`, and observation timestamp. A third
  party with the embedded public key can verify each entry without
  contacting the witness.
- **Federation cross-chain references** via `CrossChainRef` +
  `CrossChainProofStep` carried on interaction records. Structural in
  v0.3; the verifier-side Merkle inclusion check against a foreign
  STH lands in v0.4 with the multi-tenant resolver.
- **`SignedTreeHead`** record type — the publishable summary that a
  witness signs.
- **CLI surface (v0.3)**: `witness-publish`, `witness-check`,
  `export annex-iv`, `retention set`, `legal-hold place`,
  `legal-hold release` in addition to v0.2 commands.

### Changed

- `SCHEMA_VERSION` bumped to `"0.3.0"`.
- `MerkleRootEntry` gains `timestamp_anchors` and `witness_signatures`
  fields with `#[serde(default, skip_serializing_if = "Vec::is_empty")]`
  — v0.1 and v0.2 chains stay byte-identical because empty vectors
  are elided from canonical form.
- `RecordBody` gains `CorpusAnchor`, `Tombstone`, `RetentionPolicy`,
  `LegalHold`, `LegalHoldRelease` — discriminated-union expansion only,
  no impact on existing tag values.
- `InteractionBody` gains `cross_chain_refs: Vec<CrossChainRef>` —
  elided when empty.
- Workspace expanded from 3 to 5 crates.

### Cryptographic

- **No canonical-form changes** for any v0.1 or v0.2 record. The new
  `MerkleRootEntry` vectors default to empty and elide; existing
  records' `this_hash` values are unchanged.
- **Witness counter-signature is signed over the canonical form of the
  `SignedTreeHead`**, not the `MerkleRootEntry` directly. This makes
  the counter-signature portable: a witness only needs to see the
  publishable summary to sign, never the full chain bytes.
- **STHs include `root_record_this_hash_hex`** so a witness can commit
  to the exact bytes the operator stored — preventing an operator
  from minting equivalent-looking STHs from different underlying
  MerkleRootEntry encodings.
- **The witness's public key is embedded in every
  `WitnessCountersignature`**. A verifier holding a counter-signature
  does not need an out-of-band channel to learn the witness's key,
  matching the embedded-cert pattern used by Certificate Transparency.
- ML-DSA-65 lengths are reconfirmed by static const checks in
  `glassbox_core::crypto`: pk=1952, sk=4032, sig=3309.

## [0.2.0] — 2026-05-13

Adds the schema completeness, signature-combiner indirection, redaction
tombstones, regression corpus, fuzz harnesses, and release-provenance
machinery that the v0.1 README documented as deferred. **Forward
compatible:** v0.1 chains continue to verify under v0.2 binaries
without migration, because every new field on `InteractionBody` is
`skip_serializing_if`-elided when unset (spec §12.6).

### Added

- **Schema completeness.** New types: `ToolInvocation`, `HumanApproval` +
  `ApprovalDecision`, `DecisionContext` + `AutomationLevel`, `CorpusAnchor`
  + `CorpusRef`, `RedactionRecord` + `RedactionReason`. New body variants:
  `RecordBody::CorpusAnchor`, `RecordBody::Tombstone`. New
  `InteractionBody` fields: `tool_calls`, `corpus_refs`, `approval`,
  `decision`, `root_record_id`, `span_index`, `retry_of`, `causal_links`.
- **Tombstone redaction end-to-end.** `glassbox redact` subcommand;
  verifier validates the target exists earlier on the stream with a
  matching record_id and original_this_hash; verification report
  surfaces `tombstones_observed` and `redacted_sequences`.
- **Signature combiner indirection.** New `SignatureCombiner::{And,Or}`
  parsed from the algorithm string on the resolved key registry entry.
  v0.1 chains use the AND combiner exclusively; v0.2 unlocks emergency
  rotation via `ALGORITHM_HYBRID_ED25519_MLDSA65_OR` without any chain
  migration.
- **2000-record canonical-form regression corpus** under
  `crates/glassbox-core/tests/corpus/canonical_corpus.jsonl`, regenerable
  via `cargo run --example gen_corpus -p glassbox-core`. Test asserts
  byte-identical reproduction. CI enforces the corpus has not drifted.
- **cargo-fuzz harnesses** under `crates/glassbox-core/fuzz/` for
  canonicalize-roundtrip, signed-record-deserialize, and merkle-proof
  verification.
- **Release provenance.** New `.github/workflows/release.yml`:
  per-platform release binaries, Sigstore keyless signing via cosign,
  per-crate CycloneDX SBOM. SECURITY.md documents the verification
  recipe.

### Changed

- `SCHEMA_VERSION` bumped to `"0.2.0"`.
- `SignedRecord::verify_signature` now defaults to the AND combiner and
  forwards to `SignedRecord::verify_signature_with` for callers that
  resolve a different combiner from the key registry.
- `chain::KeyResolver::resolve` now returns `ResolvedKey` (public key +
  algorithm string) instead of a bare `HybridPublicKey`, so the verifier
  can pick the combiner from the registered key. Storage backends that
  use the workspace-provided `InMemoryKeyResolver` get this for free.

### Cryptographic

- **No change to canonical-form bytes for any existing v0.1 record.**
  New `InteractionBody` fields are optional and `skip_serializing_if`-
  elided when unset. New body variants tag-discriminate; they cannot be
  silently injected into a v0.1 record.
- **Combiner is now a property of the registered key, not a workspace
  constant.** Tenants with v0.1 chains see their existing
  `hybrid:ed25519+ml-dsa-65/and` algorithm string honored verbatim —
  no rotation required.
- **Cross-version corpus** is a frozen regression test: any commit that
  alters canonical bytes for a previously-corpus-covered input fails
  CI. This is the §11.2 airframe-grade discipline applied to the
  serialization layer.
- ML-DSA-65 OR-combiner path verifies each half independently rather
  than synthesising a combined verifier, so a real-world break of one
  scheme keeps the other usable until rotation.

## [0.1.0] — 2026-05-12

Initial alpha release. Wire format and canonical form are stable for the
0.1.x series and are tested by the cross-version corpus in
`crates/glassbox-core/tests/corpus.rs`.

### Added

- `glassbox-core` crate: canonical record schema, RFC 8785 canonical
  JSON, SHA-256 hash chain, hybrid Ed25519 + ML-DSA-65 hybrid signing
  (AND combiner), Merkle tree with O(log N) inclusion proofs, on-ledger
  key registry, structured error model.
- `glassbox-storage` crate: `Backend` trait, in-memory backend (for tests),
  bundled-SQLite backend with `BEGIN IMMEDIATE` append transactions and
  appropriate indices for verification walks.
- `glassbox-cli` binary with `keygen`, `init`, `append`, `show`, `verify`,
  `merkle-commit`, and `key-rotate` subcommands.
- Property-based tests for canonical-form determinism (random key
  reordering, whitespace, nested structures).
- Adversarial tests for the verifier (record modification, swap, deletion,
  signature tamper, Merkle root tamper).

### Cryptographic

- Hash function: SHA-256 (NIST FIPS 180-4).
- Classical signature: Ed25519 (`ed25519-dalek` 2.2).
- Post-quantum signature: ML-DSA-65 (`ml-dsa` 0.0.4, RustCrypto pre-release).
  Note: the `ml-dsa` crate is pre-1.0 and we will track its stabilisation;
  bumping it counts as a cryptographic change per the contributing rules.
- Combiner: AND. Both signatures must verify for a record to be valid.
- Canonicalization: RFC 8785 JCS via `serde_jcs` 0.1.

### Known limitations

- No witness network, no RFC 3161 trusted timestamping, no Annex IV PDF
  export, no SDKs, no MCP server, no Postgres backend. These are
  scheduled across v0.2–v1.0 per the spec roadmap in §32.
- The cryptographic core has not been externally audited; see §23.8 of
  the spec for the v1.0 audit commitment.
- Single-process CLI only. No HTTP/gRPC server in this release.

[Unreleased]: https://github.com/glassbox-project/glassbox/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/glassbox-project/glassbox/releases/tag/v0.6.0
[0.5.0]: https://github.com/glassbox-project/glassbox/releases/tag/v0.5.0
[0.4.0]: https://github.com/glassbox-project/glassbox/releases/tag/v0.4.0
[0.3.0]: https://github.com/glassbox-project/glassbox/releases/tag/v0.3.0
[0.2.0]: https://github.com/glassbox-project/glassbox/releases/tag/v0.2.0
[0.1.0]: https://github.com/glassbox-project/glassbox/releases/tag/v0.1.0
