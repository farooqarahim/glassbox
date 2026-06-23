//! Axum route handlers.

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode, header};
use serde::{Deserialize, Serialize};
use serde_json::json;

use glassbox_core::record::SignedRecord;
use glassbox_storage::Backend;

use crate::state::AppState;

/// `GET /healthz` — unauthenticated liveness probe.
pub(crate) async fn healthz() -> &'static str {
    "ok\n"
}

/// `GET /v1/streams`
pub(crate) async fn list_streams(
    headers: HeaderMap,
    State(state): State<AppState>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_bearer(&headers, &state)?;
    let streams = state
        .with_backend(|b| b.list_streams())
        .map_err(AppError::storage)?;
    Ok(Json(json!({ "streams": streams })))
}

/// `POST /v1/streams/:stream/append`
pub(crate) async fn append(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(stream): Path<String>,
    Json(record): Json<SignedRecord>,
) -> Result<Json<serde_json::Value>, AppError> {
    check_bearer(&headers, &state)?;
    check_stream(&stream, &state)?;
    if record.record.stream_id != stream {
        return Err(AppError::bad_request(format!(
            "body's stream_id {} does not match path `{stream}`",
            record.record.stream_id
        )));
    }
    state
        .with_backend(|b| b.append(record.clone()))
        .map_err(AppError::storage)?;
    Ok(Json(json!({
        "sequence": record.record.sequence,
        "this_hash_hex": record.this_hash_hex,
        "record_id": record.record.record_id.to_string()
    })))
}

/// `GET /v1/streams/:stream/last`
pub(crate) async fn last(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(stream): Path<String>,
) -> Result<Json<Option<SignedRecord>>, AppError> {
    check_bearer(&headers, &state)?;
    check_stream(&stream, &state)?;
    let last = state
        .with_backend(|b| b.last(&stream))
        .map_err(AppError::storage)?;
    Ok(Json(last))
}

/// `GET /v1/streams/:stream/records/:sequence`
pub(crate) async fn get_record(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path((stream, sequence)): Path<(String, u64)>,
) -> Result<Json<SignedRecord>, AppError> {
    check_bearer(&headers, &state)?;
    check_stream(&stream, &state)?;
    let sr = state
        .with_backend(|b| b.get(&stream, sequence))
        .map_err(AppError::storage)?
        .ok_or_else(|| AppError::not_found(format!("no record at sequence {sequence}")))?;
    Ok(Json(sr))
}

/// `GET /v1/streams/:stream/records`
pub(crate) async fn iter_stream(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(stream): Path<String>,
) -> Result<Json<Vec<SignedRecord>>, AppError> {
    check_bearer(&headers, &state)?;
    check_stream(&stream, &state)?;
    let chain = state
        .with_backend(|b| b.iter_stream(&stream))
        .map_err(AppError::storage)?;
    Ok(Json(chain))
}

/// `POST /v1/streams/:stream/verify`
pub(crate) async fn verify(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(stream): Path<String>,
) -> Result<Json<VerifyResponse>, AppError> {
    check_bearer(&headers, &state)?;
    check_stream(&stream, &state)?;
    let report = state
        .with_backend(|b| glassbox_storage::verify_stream(b, &stream))
        .map_err(|e| match e {
            glassbox_storage::StorageError::Core(core_err) => AppError::verification(format!(
                "verification failed on stream {stream}: {core_err}"
            )),
            other => AppError::storage(other),
        })?;
    let failure = report.failure.as_ref().map(|f| VerifyFailure {
        sequence: f.sequence,
        reason: f.reason.clone(),
    });
    Ok(Json(VerifyResponse {
        ok: report.is_ok(),
        records_walked: report.records_walked,
        signatures_verified: report.signatures_verified,
        merkle_roots_checked: report.merkle_roots_checked,
        tombstones_observed: report.tombstones_observed,
        cross_chain_refs_verified: report.cross_chain_refs_verified,
        redacted_sequences: report.redacted_sequences,
        failure,
    }))
}

/// `POST /v1/streams/:stream/inclusion-proof`
pub(crate) async fn inclusion_proof(
    headers: HeaderMap,
    State(state): State<AppState>,
    Path(stream): Path<String>,
    Json(req): Json<InclusionProofRequest>,
) -> Result<Json<InclusionProofResponse>, AppError> {
    check_bearer(&headers, &state)?;
    check_stream(&stream, &state)?;
    let chain = state
        .with_backend(|b| b.iter_stream(&stream))
        .map_err(AppError::storage)?;
    let leaves: Vec<[u8; 32]> = chain
        .iter()
        .filter(|sr| {
            !matches!(
                sr.record.body,
                glassbox_core::record::RecordBody::MerkleRoot(_)
            )
        })
        .map(|sr| {
            hex::decode(&sr.this_hash_hex)
                .map_err(|e| AppError::internal(format!("stored this_hash bad hex: {e}")))?
                .try_into()
                .map_err(|_| AppError::internal("stored this_hash not 32 bytes"))
        })
        .collect::<Result<_, _>>()?;
    let target_idx = chain
        .iter()
        .filter(|sr| {
            !matches!(
                sr.record.body,
                glassbox_core::record::RecordBody::MerkleRoot(_)
            )
        })
        .position(|sr| sr.record.sequence == req.sequence)
        .ok_or_else(|| AppError::not_found(format!("sequence {} not in stream", req.sequence)))?;
    let root = glassbox_core::merkle::compute_root(&leaves)
        .map_err(|e| AppError::internal(e.to_string()))?;
    let proof = glassbox_core::merkle::build_proof(&leaves, target_idx)
        .map_err(|e| AppError::internal(e.to_string()))?;
    let leaf = leaves[target_idx];
    Ok(Json(InclusionProofResponse {
        leaf_hex: hex::encode(leaf),
        root_hex: hex::encode(root),
        steps: proof
            .iter()
            .map(|s| ProofStep {
                sibling_hex: hex::encode(s.sibling),
                sibling_is_right: s.sibling_is_right,
            })
            .collect(),
    }))
}

#[derive(Debug, Deserialize)]
pub(crate) struct InclusionProofRequest {
    sequence: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct InclusionProofResponse {
    leaf_hex: String,
    root_hex: String,
    steps: Vec<ProofStep>,
}

#[derive(Debug, Serialize)]
pub(crate) struct ProofStep {
    sibling_hex: String,
    sibling_is_right: bool,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyResponse {
    ok: bool,
    records_walked: u64,
    signatures_verified: u64,
    merkle_roots_checked: u64,
    tombstones_observed: u64,
    cross_chain_refs_verified: u64,
    redacted_sequences: Vec<u64>,
    failure: Option<VerifyFailure>,
}

#[derive(Debug, Serialize)]
pub(crate) struct VerifyFailure {
    sequence: u64,
    reason: String,
}

// --- auth + error mapping ---

fn check_bearer(headers: &HeaderMap, state: &AppState) -> Result<(), AppError> {
    let raw = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| AppError::unauthorized("missing Authorization header"))?;
    let presented = raw
        .strip_prefix("Bearer ")
        .ok_or_else(|| AppError::unauthorized("Authorization must be Bearer"))?;
    state
        .token()
        .check_secret(presented)
        .map_err(|e| AppError::forbidden(e.to_string()))
}

fn check_stream(requested: &str, state: &AppState) -> Result<(), AppError> {
    state
        .token()
        .check_stream(requested)
        .map_err(|e| AppError::forbidden(e.to_string()))
}

#[derive(Debug)]
pub(crate) struct AppError {
    status: StatusCode,
    message: String,
}

impl AppError {
    fn unauthorized(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNAUTHORIZED,
            message: msg.into(),
        }
    }
    fn forbidden(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::FORBIDDEN,
            message: msg.into(),
        }
    }
    fn bad_request(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::BAD_REQUEST,
            message: msg.into(),
        }
    }
    fn not_found(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::NOT_FOUND,
            message: msg.into(),
        }
    }
    fn verification(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::UNPROCESSABLE_ENTITY,
            message: msg.into(),
        }
    }
    fn internal(msg: impl Into<String>) -> Self {
        Self {
            status: StatusCode::INTERNAL_SERVER_ERROR,
            message: msg.into(),
        }
    }
    fn storage(e: glassbox_storage::StorageError) -> Self {
        let status = match e {
            glassbox_storage::StorageError::Invariant(_) => StatusCode::CONFLICT,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };
        Self {
            status,
            message: e.to_string(),
        }
    }
}

impl axum::response::IntoResponse for AppError {
    fn into_response(self) -> axum::response::Response {
        (self.status, Json(json!({ "error": self.message }))).into_response()
    }
}
