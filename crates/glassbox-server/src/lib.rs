//! HTTP/JSON server exposing the Glassbox ledger.
//!
//! Per spec §15.1, the project's primary wire protocol is gRPC and
//! HTTP/JSON is the compatibility surface. v0.5 ships HTTP/JSON only
//! — every endpoint declared in §15.2 (Append, Verify, Query, Export,
//! Inclusion Proof, Streams) is reachable here. gRPC + the matching
//! Protobuf service definition land in v0.6.
//!
//! ## Routes
//!
//! | Method | Path | Operation |
//! |--------|------|-----------|
//! | `GET`  | `/healthz` | unauthenticated liveness probe |
//! | `GET`  | `/v1/streams` | list every stream stored on this server |
//! | `POST` | `/v1/streams/{stream}/append` | append a `SignedRecord` |
//! | `GET`  | `/v1/streams/{stream}/last` | fetch the most recent record |
//! | `GET`  | `/v1/streams/{stream}/records/{sequence}` | fetch by sequence |
//! | `GET`  | `/v1/streams/{stream}/records` | iterate the stream |
//! | `POST` | `/v1/streams/{stream}/verify` | walk the chain and return a `VerificationReport` |
//! | `POST` | `/v1/streams/{stream}/inclusion-proof` | build an O(log N) inclusion proof |
//!
//! ## Authentication
//!
//! Every authenticated route requires an `Authorization: Bearer <secret>`
//! header. The secret is matched in constant time against the
//! [`CapabilityToken`] loaded at server start. The same token type
//! the MCP server uses (see spec §18.3) — a Glassbox operator hands
//! one token to MCP-capable agents and the matching token to HTTP
//! clients, so the scope is consistent.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(missing_docs)]

#[cfg(feature = "grpc")]
pub mod grpc;
mod handlers;
mod state;

pub use state::{AppState, ServerError};

use std::net::SocketAddr;

use axum::Router;
use axum::routing::{get, post};

pub use glassbox_mcp::CapabilityToken;

/// Build the [`axum::Router`] that backs the server.
///
/// Exposed so integration tests can call the server in-process via
/// `tower::ServiceExt::oneshot` without binding to a real socket.
#[must_use]
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(handlers::healthz))
        .route("/v1/streams", get(handlers::list_streams))
        .route("/v1/streams/{stream}/append", post(handlers::append))
        .route("/v1/streams/{stream}/last", get(handlers::last))
        .route(
            "/v1/streams/{stream}/records/{sequence}",
            get(handlers::get_record),
        )
        .route("/v1/streams/{stream}/records", get(handlers::iter_stream))
        .route("/v1/streams/{stream}/verify", post(handlers::verify))
        .route(
            "/v1/streams/{stream}/inclusion-proof",
            post(handlers::inclusion_proof),
        )
        .with_state(state)
}

/// Bind and serve until the listener is shut down. Used by the binary.
///
/// Returns once the listener stops accepting (e.g. ctrl-C, or after
/// the `tokio::signal::ctrl_c` handler closes it). For graceful
/// shutdown patterns see the `glassbox-server` binary.
pub async fn serve(state: AppState, addr: SocketAddr) -> Result<(), ServerError> {
    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .map_err(|e| ServerError::Io(e.to_string()))?;
    let router = router(state);
    axum::serve(listener, router.into_make_service())
        .await
        .map_err(|e| ServerError::Io(e.to_string()))
}
