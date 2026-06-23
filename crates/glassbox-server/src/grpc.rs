//! gRPC service implementation (spec §15.1 primary surface).
//!
//! Generated from `proto/glassbox.proto` by `build.rs` at compile
//! time. The service delegates to the same [`AppState`] the HTTP
//! handlers use, so HTTP and gRPC share auth, storage, and the
//! capability-token scope.

use glassbox_core::record::SignedRecord;
use glassbox_storage::Backend;
use tonic::{Request, Response, Status};

use crate::state::AppState;

#[allow(missing_docs, clippy::all, clippy::pedantic, unreachable_pub)]
mod proto {
    tonic::include_proto!("glassbox.v1");
}

pub use proto::ledger_client;
pub use proto::ledger_server;
pub use proto::ledger_server::{Ledger, LedgerServer};
pub use proto::{
    AppendRecordRequest, AppendRecordResponse, AuthHeader, GetLastRequest, GetLastResponse,
    GetRecordRequest, GetRecordResponse, InclusionProofRequest, InclusionProofResponse,
    IterStreamRequest, IterStreamResponse, ListStreamsRequest, ListStreamsResponse, ProofStep,
    VerifyRequest, VerifyResponse,
};

/// The Ledger gRPC service backed by an [`AppState`].
pub struct LedgerService {
    state: AppState,
}

impl LedgerService {
    /// Construct.
    #[must_use]
    pub fn new(state: AppState) -> Self {
        Self { state }
    }

    fn check(&self, auth: Option<&AuthHeader>, stream: &str) -> Result<(), Status> {
        let token = auth.ok_or_else(|| Status::unauthenticated("missing auth"))?;
        self.state
            .token()
            .check_secret(&token.token)
            .map_err(|e| Status::permission_denied(e.to_string()))?;
        self.state
            .token()
            .check_stream(stream)
            .map_err(|e| Status::permission_denied(e.to_string()))
    }
}

fn storage_status(e: glassbox_storage::StorageError) -> Status {
    use glassbox_storage::StorageError;
    match e {
        StorageError::Invariant(msg) => Status::failed_precondition(msg),
        _ => Status::internal(e.to_string()),
    }
}

#[tonic::async_trait]
impl Ledger for LedgerService {
    async fn list_streams(
        &self,
        req: Request<ListStreamsRequest>,
    ) -> Result<Response<ListStreamsResponse>, Status> {
        let r = req.into_inner();
        // For list-streams the token is scoped to one stream; we
        // surface only that stream so the scope is honoured.
        let token = r
            .auth
            .as_ref()
            .ok_or_else(|| Status::unauthenticated("missing auth"))?;
        self.state
            .token()
            .check_secret(&token.token)
            .map_err(|e| Status::permission_denied(e.to_string()))?;
        let scope_stream = self.state.token().scope.stream_id.clone();
        let streams = self
            .state
            .with_backend(|b| b.list_streams())
            .map_err(storage_status)?
            .into_iter()
            .filter(|s| *s == scope_stream)
            .collect();
        Ok(Response::new(ListStreamsResponse { streams }))
    }

    async fn get_last(
        &self,
        req: Request<GetLastRequest>,
    ) -> Result<Response<GetLastResponse>, Status> {
        let r = req.into_inner();
        self.check(r.auth.as_ref(), &r.stream_id)?;
        let last = self
            .state
            .with_backend(|b| b.last(&r.stream_id))
            .map_err(storage_status)?;
        match last {
            None => Ok(Response::new(GetLastResponse {
                present: false,
                signed_record_json: Vec::new(),
            })),
            Some(sr) => {
                let json = serde_json::to_vec(&sr).map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(GetLastResponse {
                    present: true,
                    signed_record_json: json,
                }))
            }
        }
    }

    async fn get_record(
        &self,
        req: Request<GetRecordRequest>,
    ) -> Result<Response<GetRecordResponse>, Status> {
        let r = req.into_inner();
        self.check(r.auth.as_ref(), &r.stream_id)?;
        let got = self
            .state
            .with_backend(|b| b.get(&r.stream_id, r.sequence))
            .map_err(storage_status)?;
        match got {
            None => Ok(Response::new(GetRecordResponse {
                present: false,
                signed_record_json: Vec::new(),
            })),
            Some(sr) => {
                let json = serde_json::to_vec(&sr).map_err(|e| Status::internal(e.to_string()))?;
                Ok(Response::new(GetRecordResponse {
                    present: true,
                    signed_record_json: json,
                }))
            }
        }
    }

    async fn iter_stream(
        &self,
        req: Request<IterStreamRequest>,
    ) -> Result<Response<IterStreamResponse>, Status> {
        let r = req.into_inner();
        self.check(r.auth.as_ref(), &r.stream_id)?;
        let chain = self
            .state
            .with_backend(|b| b.iter_stream(&r.stream_id))
            .map_err(storage_status)?;
        let mut signed_record_json = Vec::with_capacity(chain.len());
        for sr in chain {
            signed_record_json
                .push(serde_json::to_vec(&sr).map_err(|e| Status::internal(e.to_string()))?);
        }
        Ok(Response::new(IterStreamResponse { signed_record_json }))
    }

    async fn append_record(
        &self,
        req: Request<AppendRecordRequest>,
    ) -> Result<Response<AppendRecordResponse>, Status> {
        let r = req.into_inner();
        self.check(r.auth.as_ref(), &r.stream_id)?;
        let sr: SignedRecord = serde_json::from_slice(&r.signed_record_json)
            .map_err(|e| Status::invalid_argument(format!("bad signed_record_json: {e}")))?;
        if sr.record.stream_id != r.stream_id {
            return Err(Status::invalid_argument(format!(
                "body stream_id {} != request stream_id {}",
                sr.record.stream_id, r.stream_id
            )));
        }
        let resp = AppendRecordResponse {
            sequence: sr.record.sequence,
            this_hash_hex: sr.this_hash_hex.clone(),
            record_id: sr.record.record_id.to_string(),
        };
        self.state
            .with_backend(|b| b.append(sr))
            .map_err(storage_status)?;
        Ok(Response::new(resp))
    }

    async fn verify(
        &self,
        req: Request<VerifyRequest>,
    ) -> Result<Response<VerifyResponse>, Status> {
        let r = req.into_inner();
        self.check(r.auth.as_ref(), &r.stream_id)?;
        let report = self
            .state
            .with_backend(|b| glassbox_storage::verify_stream(b, &r.stream_id))
            .map_err(|e| match e {
                glassbox_storage::StorageError::Core(core_err) => {
                    Status::failed_precondition(format!("verification failed: {core_err}"))
                }
                other => storage_status(other),
            })?;
        let (failure_reason, failure_sequence) = match &report.failure {
            Some(f) => (f.reason.clone(), f.sequence),
            None => (String::new(), 0),
        };
        Ok(Response::new(VerifyResponse {
            ok: report.is_ok(),
            records_walked: report.records_walked,
            signatures_verified: report.signatures_verified,
            merkle_roots_checked: report.merkle_roots_checked,
            tombstones_observed: report.tombstones_observed,
            cross_chain_refs_verified: report.cross_chain_refs_verified,
            redacted_sequences: report.redacted_sequences,
            failure_reason,
            failure_sequence,
        }))
    }

    async fn inclusion_proof(
        &self,
        req: Request<InclusionProofRequest>,
    ) -> Result<Response<InclusionProofResponse>, Status> {
        let r = req.into_inner();
        self.check(r.auth.as_ref(), &r.stream_id)?;
        let chain = self
            .state
            .with_backend(|b| b.iter_stream(&r.stream_id))
            .map_err(storage_status)?;
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
                    .map_err(|e| Status::internal(format!("stored this_hash bad hex: {e}")))?
                    .try_into()
                    .map_err(|_| Status::internal("stored this_hash not 32 bytes"))
            })
            .collect::<Result<_, _>>()?;
        let idx = chain
            .iter()
            .filter(|sr| {
                !matches!(
                    sr.record.body,
                    glassbox_core::record::RecordBody::MerkleRoot(_)
                )
            })
            .position(|sr| sr.record.sequence == r.sequence)
            .ok_or_else(|| Status::not_found(format!("sequence {} not in stream", r.sequence)))?;
        let root = glassbox_core::merkle::compute_root(&leaves)
            .map_err(|e| Status::internal(e.to_string()))?;
        let proof = glassbox_core::merkle::build_proof(&leaves, idx)
            .map_err(|e| Status::internal(e.to_string()))?;
        Ok(Response::new(InclusionProofResponse {
            leaf_hex: hex::encode(leaves[idx]),
            root_hex: hex::encode(root),
            steps: proof
                .into_iter()
                .map(|s| ProofStep {
                    sibling_hex: hex::encode(s.sibling),
                    sibling_is_right: s.sibling_is_right,
                })
                .collect(),
        }))
    }
}
