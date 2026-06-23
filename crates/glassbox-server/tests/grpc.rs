//! gRPC integration test: bind a tonic server on an ephemeral port,
//! make real RPCs through a tonic client, assert the chain
//! invariants flow through the wire.

#![cfg(feature = "grpc")]

use std::net::SocketAddr;
use std::time::Duration;

use glassbox_core::SCHEMA_VERSION;
use glassbox_core::chain::sign_record;
use glassbox_core::crypto::HybridKeypair;
use glassbox_core::key_registry::{KeyRegistryEntry, KeyStatus};
use glassbox_core::record::{Record, RecordBody};
use glassbox_mcp::{CapabilityToken, TokenScope};
use glassbox_server::AppState;
use glassbox_server::grpc::ledger_server::LedgerServer;
use glassbox_server::grpc::{
    AuthHeader, InclusionProofRequest, IterStreamRequest, LedgerService, ListStreamsRequest,
    VerifyRequest,
};
use tempfile::TempDir;
use time::{Duration as TDuration, OffsetDateTime};
use tokio::net::TcpListener;
use tonic::transport::Server;
use ulid::Ulid;

struct Fixture {
    _dir: TempDir,
    addr: SocketAddr,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for Fixture {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

async fn spawn(stream: &str) -> Fixture {
    let dir = tempfile::tempdir().unwrap();
    let ledger = dir.path().join("ledger.db");
    let kp = HybridKeypair::generate().unwrap();

    {
        let mut backend = glassbox_storage::sqlite::SqliteBackend::open(&ledger).unwrap();
        let entry = KeyRegistryEntry {
            key_id: "k".into(),
            algorithm: glassbox_core::ALGORITHM_HYBRID_ED25519_MLDSA65.into(),
            public_key: kp.public_key(),
            valid_from: OffsetDateTime::now_utc(),
            valid_to: None,
            status: KeyStatus::Active,
        };
        let r0 = Record {
            record_id: Ulid::new(),
            stream_id: stream.into(),
            sequence: 0,
            occurred_at: OffsetDateTime::now_utc(),
            received_at: OffsetDateTime::now_utc(),
            schema_version: SCHEMA_VERSION.into(),
            source_sdk: "test/0.6.0".into(),
            key_id: "k".into(),
            prev_hash_hex: hex::encode([0u8; 32]),
            body: RecordBody::KeyRegistry(entry),
        };
        let sr0 = sign_record(r0, &kp).unwrap();
        glassbox_storage::Backend::append(&mut backend, sr0).unwrap();
    }

    let token = CapabilityToken {
        token_id: "t1".into(),
        scope: TokenScope {
            tenant_id: stream.split('/').next().unwrap_or("").into(),
            stream_id: stream.into(),
            allowed_tools: vec![],
            expires_at: OffsetDateTime::now_utc() + TDuration::hours(1),
        },
        secret: "sssh".into(),
    };
    let state = AppState::new(ledger, HybridKeypair::generate().unwrap(), token).unwrap();

    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .await
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let stream_io = tokio_stream::wrappers::TcpListenerStream::new(listener);
    let service = LedgerService::new(state);

    let handle = tokio::spawn(async move {
        Server::builder()
            .add_service(LedgerServer::new(service))
            .serve_with_incoming(stream_io)
            .await
            .ok();
    });
    tokio::time::sleep(Duration::from_millis(80)).await;
    Fixture {
        _dir: dir,
        addr,
        handle,
    }
}

fn auth() -> AuthHeader {
    AuthHeader {
        token: "sssh".into(),
    }
}

#[tokio::test]
async fn list_streams_returns_scoped_stream() {
    let f = spawn("acme/sys").await;
    let mut client =
        glassbox_server::grpc::ledger_client::LedgerClient::connect(format!("http://{}", f.addr))
            .await
            .unwrap();
    let resp = client
        .list_streams(ListStreamsRequest { auth: Some(auth()) })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.streams, vec!["acme/sys".to_string()]);
}

#[tokio::test]
async fn iter_stream_returns_genesis_record() {
    let f = spawn("acme/sys").await;
    let mut client =
        glassbox_server::grpc::ledger_client::LedgerClient::connect(format!("http://{}", f.addr))
            .await
            .unwrap();
    let resp = client
        .iter_stream(IterStreamRequest {
            auth: Some(auth()),
            stream_id: "acme/sys".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.signed_record_json.len(), 1);
}

#[tokio::test]
async fn verify_returns_ok_on_genesis_only_chain() {
    let f = spawn("acme/sys").await;
    let mut client =
        glassbox_server::grpc::ledger_client::LedgerClient::connect(format!("http://{}", f.addr))
            .await
            .unwrap();
    let resp = client
        .verify(VerifyRequest {
            auth: Some(auth()),
            stream_id: "acme/sys".into(),
        })
        .await
        .unwrap()
        .into_inner();
    assert!(resp.ok);
    assert_eq!(resp.records_walked, 1);
}

#[tokio::test]
async fn inclusion_proof_for_genesis_returns_root() {
    let f = spawn("acme/sys").await;
    let mut client =
        glassbox_server::grpc::ledger_client::LedgerClient::connect(format!("http://{}", f.addr))
            .await
            .unwrap();
    let resp = client
        .inclusion_proof(InclusionProofRequest {
            auth: Some(auth()),
            stream_id: "acme/sys".into(),
            sequence: 0,
        })
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.leaf_hex.len(), 64);
    assert_eq!(resp.root_hex.len(), 64);
    assert!(resp.steps.is_empty());
}

#[tokio::test]
async fn missing_auth_returns_unauthenticated() {
    let f = spawn("acme/sys").await;
    let mut client =
        glassbox_server::grpc::ledger_client::LedgerClient::connect(format!("http://{}", f.addr))
            .await
            .unwrap();
    let err = client
        .list_streams(ListStreamsRequest { auth: None })
        .await
        .unwrap_err();
    assert_eq!(err.code(), tonic::Code::Unauthenticated);
}
