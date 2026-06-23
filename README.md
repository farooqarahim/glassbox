# Glassbox

> **Tamper-evident audit ledger for AI systems.**

[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85+-orange.svg)](rust-toolchain.toml)
[![Status](https://img.shields.io/badge/status-v0.6--alpha-yellow.svg)](#status)

Glassbox is an open-source, framework-agnostic audit ledger that sits between
application code and any LLM and writes every interaction to a hash-chained,
signed, append-only log. Each entry carries content hashes of inputs and
outputs, model fingerprints, prompt-template fingerprints, tool invocations,
retrieval-context provenance, human-approver identities, and arbitrary caller
metadata — enough that a regulator can reconstruct exactly what the system
did, when, under what version, and under what oversight.

The log is designed for 10-year retention with eventual automatic tiering
from hot storage (Postgres) to cold storage (S3-compatible Parquet), and
ships with a verification CLI that walks the chain, validates signatures,
and proves no entry was altered, removed, or backdated.

---

## What v0.7 actually ships

Builds on v0.6 with the **language SDK trio (spec §16)** and
**framework middleware (spec §17.2)**:

- **Python SDK** (`sdks/python/`) — pure-Python over `httpx`. `Client`
  + `WalBuffer` + record builders + `wrap_anthropic` / `wrap_openai`
  Proxy wrappers. 17 tests against a real `glassbox-server`.
- **TypeScript SDK** (`sdks/typescript/`) — pure-TS over `fetch`. Same
  surface as Python, idiomatic `Promise`-based async, vitest harness
  spawning the real server. 16 tests.
- **Go SDK** (`sdks/go/`) — pure-Go (no cgo). `context.Context`-aware
  client, the same fsync-per-record WAL, `WrapCall` for tracing model
  invocations. 10 `go test` tests against the real server.

All three SDKs share one invariant: **no SDK ever holds a signing
key.** Records are signed by the operator pipeline; SDKs only ship
already-signed JSON. The trust boundary stays at the operator's
keystore regardless of which language your application is written in.

The only spec-named engineering item still on the v1.0 roadmap is the
`glassbox-ffi` C ABI.

## What v0.6 actually ships

Builds on v0.5 with the four engineering blocks the v0.5 self-grade
called out:

- **gRPC server (spec §15.1 primary)** under the `grpc` feature on
  `glassbox-server`. Real tonic + Protobuf wire from
  `proto/glassbox.proto`, hermetic codegen via `protoc-bin-vendored`,
  seven RPCs (ListStreams, GetLast, GetRecord, IterStream,
  AppendRecord, Verify, InclusionProof). Capability-token auth shared
  with the HTTP and MCP surfaces.
- **Annex IV PDF (spec §22)** under the `pdf` feature on
  `glassbox-export`. Real PDF rendering via `pdf-writer`,
  detached hybrid signature over the PDF's SHA-256 imprint. PAdES
  embedding deferred to v0.7.
- **RFC 3161 TSA client (spec §13.5)** in `glassbox-witness::tsa`
  under the `tsa` feature. Hand-rolled DER encoder for
  `TimeStampReq`; ureq-based POST to a configurable TSA URL. Live
  round-trip gated on `GLASSBOX_TSA_URL`.
- **NL → structured query translator (spec §19.3)** in
  `glassbox-core::nl_query`. Pure-Rust pattern-based; output is the
  same `StructuredQuery` shape MCP and the gRPC `Query` RPC accept.

## What v0.5 actually ships

Builds on v0.4 with the three engineering blocks the v0.4 self-grade
flagged next:

- **`glassbox-server` crate + binary** (spec §15.1 compatibility
  surface) — axum HTTP/JSON server with bearer-token auth sharing
  the `CapabilityToken` type with the MCP server. Routes: append,
  last, get, iter_stream, list_streams, verify, inclusion_proof.
  Integration tests run against a real `tokio::net::TcpListener`.
- **Parquet cold-tier** (spec §14.1, §14.5) under the `parquet`
  cargo feature on `glassbox-storage`. `ColdTierBackend` for reads;
  `migrate_to_parquet` snapshots a hot-tier stream and emits a
  side-channel manifest with the file SHA-256 + Merkle roots.
- **`glassbox-bench` crate + binary** (spec §25) — reproducible
  benchmark harness that prints p50/p99/p999 latency and throughput
  for the four workloads the spec calls out (hybrid sign, hybrid
  verify, SQLite append, full-stream verify).

## What v0.4 actually ships

Builds on v0.3 with three more spec moats:

- **`glassbox-mcp` crate + binary** (spec §18) — full Model Context
  Protocol server speaking JSON-RPC 2.0 on stdio (the host transport
  used by Claude Desktop and IDE integrations). All seven tools from
  §18.2 with strict JSON-Schema input. Capability tokens scoped to
  tenant + stream + tool set + expiration, with constant-time secret
  comparison.
- **Postgres backend** (spec §14.3) under the `postgres` cargo
  feature on `glassbox-storage`. Same logical schema as SQLite,
  append-path serialised by `SELECT … FOR UPDATE`. Integration tests
  gated on `GLASSBOX_PG_TEST_URL` so default CI stays hermetic.
- **Verifier-side cross-chain Merkle check** (spec §29.2, finishing
  the federation work that v0.3 made structural). `chain::verify_chain`
  now validates every `CrossChainRef`'s inclusion proof against the
  embedded foreign STH.

## What v0.3 actually ships

Builds on v0.2 with the spec moats:

- **Witness network** (spec §13.7, §29.6) — `glassbox-witness` crate
  with a file-backed reference server that detects rewinds and forks
  on every observed `SignedTreeHead`. `glassbox witness-publish` and
  `glassbox witness-check` integrate it into the operator flow.
  Witness counter-signatures embed the witness public key so any third
  party can verify a counter-signature stand-alone.
- **Annex IV JSON-sidecar export** (spec §22) — `glassbox-export`
  crate and `glassbox export annex-iv` CLI subcommand. Produces a zip
  with a sidecar populated from real ledger queries against §1, §2,
  §3, §4, §7, §9, plus every record as `stream.jsonl`, plus a
  signed `manifest.json` with per-artifact SHA-256 hashes. PDF +
  PAdES is deferred to v0.4 — see CHANGELOG.
- **Retention policy engine** (spec §20) with 5 reference templates
  (`eu-ai-act-high-risk`, `hipaa`, `nyc-aedt`, `colorado-ai-act`,
  `generic-3-year`). Each policy is itself an on-ledger record so
  every change is auditable.
- **Legal hold** (spec §20.3) with `legal-hold place` /
  `legal-hold release` CLI subcommands. Release is rejected if no
  matching hold is open.
- **Trusted-timestamp anchor structure** (spec §13.5) on
  `MerkleRootEntry`. RFC 3161 / roughtime issuer tokens flow through
  the schema; live TSA wiring is opt-in operator config.
- **Federation cross-chain references** (spec §29) — `CrossChainRef`
  type on interaction records carries a foreign STH plus an inclusion
  proof. Verifier-side Merkle check against the foreign STH lands in
  v0.4.

## What v0.2 actually ships

This release is the **cryptographic primitive plus complete schema and
release provenance** described in `spec/glassbox-spec-v2.md` §§9.1–9.2.
Specifically:

- **Full record schema** (spec §12) — content hashes, model and prompt
  fingerprints, tool-call inline summaries, retrieval-corpus references,
  human-approval and business-decision metadata, agent-trajectory linkage
  (`parent_record_id`, `root_record_id`, `span_index`, `retry_of`,
  `causal_links`), tags, free-form metadata.
- **Five `RecordBody` variants on one chain**: `interaction`,
  `key_registry`, `merkle_root`, `corpus_anchor`, `tombstone`.
- **RFC 8785 canonical JSON** for byte-stable hashing and signing, with a
  frozen 2000-record cross-version regression corpus under
  `crates/glassbox-core/tests/corpus/`. CI enforces no drift.
- **SHA-256 hash chain** — every record links to the previous one's hash.
- **Hybrid Ed25519 + ML-DSA-65 signing** combined under a registry-
  resolved **signature combiner**. AND (default, both halves required) and
  OR (emergency-rotation, either half sufficient) are both shipped.
- **Merkle tree + inclusion proofs** — RFC 6962-style with O(log N)
  third-party-verifiable proofs.
- **Key registry** as on-ledger administrative records per spec §12.7.
- **Tombstone redaction** per spec §12.9 — `glassbox redact` appends a
  signed tombstone, verifier validates the target exists earlier with a
  matching record_id and `original_this_hash`, verification report
  surfaces `redacted_sequences` for exporters.
- **SQLite storage backend** with a `Backend` trait abstraction so
  Postgres / object-store backends can drop in later.
- **`glassbox` CLI** with `keygen`, `init`, `append`, `show`, `verify`,
  `merkle-commit`, `key-rotate`, `redact`, and `streams` subcommands.
- **Adversarial tests** for body mutation, reorder, deletion, signature
  tamper, Merkle-root tamper, tombstone-target-mismatch,
  tombstone-pointing-at-future-sequence, and OR-combiner
  emergency-rotation flows.
- **cargo-fuzz harnesses** under `crates/glassbox-core/fuzz/` for
  canonical-form roundtrip, signed-record deserialize, and Merkle proof
  verification. Nightly-only; documented in `fuzz/README.md`.
- **Release provenance**: per-platform release binaries with Sigstore
  keyless signing via cosign + per-crate CycloneDX SBOM, wired in
  `.github/workflows/release.yml`. Verification recipe in
  [SECURITY.md](SECURITY.md).

### Explicitly **not** in v0.2

Deferred to v0.3 / v1.0; the architecture leaves each as a non-breaking
addition rather than a rewrite:

- Postgres / cold-tier Parquet backends (`Backend` trait is stable).
- The 7-tool MCP server surface (spec §18).
- Annex IV PDF + machine-readable sidecar export (spec §22).
- Witness network publication and counter-signature workflow (spec §13.7,
  §29) — until this lands, tamper-evidence against the operator
  themselves depends on a verifier holding their own signing-key trust
  root.
- RFC 3161 trusted timestamping (spec §13.5).
- Python / TypeScript / Go SDKs and framework middleware (spec §16, §17).
- Natural-language query layer (spec §19.3).
- Multi-tenant gRPC/HTTP server (spec §15) — the CLI is still the only
  frontend.
- External cryptographic audit (spec §23.8) — a v1.0 GA prerequisite that
  cannot be satisfied by code alone.

---

## Status

`v0.2-alpha`. The wire format, canonical form, and hash construction are
stable for the v0.2 series and are tested by the 2000-record cross-version
regression corpus; any drift fails CI. v0.1 chains continue to verify
under v0.2 binaries without migration.

The cryptographic core has **not** been externally audited. Do not use
Glassbox in production for regulatory artifacts until v1.0 GA, which
includes the external audit committed to in spec §23.8.

---

## Install

Build from source — releases will be published once the wire format
stabilises in v0.2.

```sh
git clone https://github.com/glassbox-project/glassbox
cd glassbox
cargo install --path crates/glassbox-cli
```

You now have a `glassbox` binary on your path.

---

## Quickstart

```sh
# Generate a hybrid keypair (Ed25519 + ML-DSA-65) and a fresh ledger.
glassbox keygen --out tenant.key
glassbox init --ledger ledger.db --tenant acme --system credit-scoring-v3 \
    --key tenant.key

# Append a record. The body is canonical JSON describing one interaction.
cat > interaction.json <<'EOF'
{
  "input":  { "hash_algorithm": "SHA-256", "hash_hex": "abcd...", "byte_size": 1234 },
  "output": { "hash_algorithm": "SHA-256", "hash_hex": "ef01...", "byte_size": 256 },
  "model":  {
    "provider": "anthropic",
    "model_name": "claude-opus-4-7",
    "model_version": "20260119",
    "sampling": { "temperature": 0.2, "max_tokens": 1024 }
  },
  "tags": [{"key": "decision_id", "value": "loan-12345"}]
}
EOF

glassbox append --ledger ledger.db --stream acme/credit-scoring-v3 \
    --key tenant.key --body interaction.json

# Periodically commit a Merkle root over the recent batch.
glassbox merkle-commit --ledger ledger.db --stream acme/credit-scoring-v3 \
    --key tenant.key

# Walk the chain, validate every signature, every hash link, every root.
glassbox verify --ledger ledger.db --stream acme/credit-scoring-v3

# Show a specific record by sequence number.
glassbox show --ledger ledger.db --stream acme/credit-scoring-v3 --sequence 0
```

`verify` exits 0 only if every signature, every hash link, and every
Merkle root in the stream check out. Any mismatch produces a structured
diagnostic naming the first record where the invariant breaks.

---

## Threat model

See spec `§23` for the full enumeration. In v0.1 the system detects:

- Any modification, reordering, or silent deletion of records by an
  adversary with full storage access (mathematical detection — a single
  hash mismatch is dispositive).
- Forgery attempts against either the classical or post-quantum half of
  the hybrid signature.

The witness network — which gives self-hosted Glassbox tamper-evidence
against the operator themselves — is **deferred to v0.2**. Until then,
v0.1 is honest about being verifiable only by parties who trust the
operator's signing key but not their database. This is the same property
as Sigstore Rekor before the gossip protocol matured, and it is still
substantially stronger than mutable-database audit logs.

---

## Architecture

```
glassbox/
├── crates/
│   ├── glassbox-core/        # canonical form, hash chain, hybrid signing, Merkle tree
│   ├── glassbox-storage/     # Backend trait + SQLite + in-memory implementations
│   └── glassbox-cli/         # the `glassbox` binary
├── spec/                     # links into ../spec/ (the upstream spec lives at workspace root)
└── tests/                    # cross-crate integration tests
```

`glassbox-core` is the only crate where cryptography lives. Per spec
§11.2, changes to its public API require two reviewers and trigger a
CVE-style notification even for refactors. The crate forbids `unsafe`
and `missing_docs` at the workspace level.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). All contributions are accepted
under the Apache 2.0 license with a Developer Certificate of Origin sign-off
(per spec §30.3 — no CLA).

Security issues: **do not file public issues.** See [SECURITY.md](SECURITY.md).

---

## License

Apache License 2.0. See [LICENSE](LICENSE) and [NOTICE](NOTICE).
