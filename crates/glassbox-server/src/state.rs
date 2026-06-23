//! Shared server state.

use std::path::PathBuf;
use std::sync::Mutex;

use thiserror::Error;

use glassbox_core::crypto::HybridKeypair;
use glassbox_mcp::CapabilityToken;
use glassbox_storage::sqlite::SqliteBackend;

/// Shared application state. Mutex around the backend because SQLite
/// connections are not `Sync`. For high throughput, replace with a
/// connection pool — outside v0.5 scope.
#[derive(Clone)]
pub struct AppState {
    inner: std::sync::Arc<Inner>,
}

struct Inner {
    backend: Mutex<SqliteBackend>,
    /// Signing keypair used by the server when it needs to mint
    /// records (e.g. inclusion-proof manifests). Append RPCs accept
    /// already-signed records from the client.
    #[allow(dead_code)]
    keypair: HybridKeypair,
    /// The capability token whose `secret` clients must present in
    /// the `Authorization: Bearer …` header.
    token: CapabilityToken,
}

impl AppState {
    /// Construct a new app state from a SQLite ledger path, a signing
    /// keypair, and a capability token.
    pub fn new(
        ledger: PathBuf,
        keypair: HybridKeypair,
        token: CapabilityToken,
    ) -> Result<Self, ServerError> {
        let backend = SqliteBackend::open(&ledger)
            .map_err(|e| ServerError::Io(format!("open {}: {e}", ledger.display())))?;
        Ok(Self {
            inner: std::sync::Arc::new(Inner {
                backend: Mutex::new(backend),
                keypair,
                token,
            }),
        })
    }

    /// Run a closure with locked backend access.
    pub fn with_backend<R, F: FnOnce(&mut SqliteBackend) -> R>(&self, f: F) -> R {
        let mut g = self.inner.backend.lock().expect("backend mutex poisoned");
        f(&mut g)
    }

    /// Reference to the capability token (for auth checks).
    #[must_use]
    pub fn token(&self) -> &CapabilityToken {
        &self.inner.token
    }
}

/// Errors produced by the server.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ServerError {
    /// I/O failure binding the socket or talking to the listener.
    #[error("server i/o: {0}")]
    Io(String),
}
