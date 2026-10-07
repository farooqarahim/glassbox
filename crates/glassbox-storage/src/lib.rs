//! Pluggable storage backends for the Glassbox ledger.
//!
//! This crate defines the [`Backend`] trait that abstracts the storage
//! layer, plus two reference implementations:
//!
//! - [`mem::InMemoryBackend`] — used by tests and as the documented
//!   reference for trait semantics.
//! - [`sqlite::SqliteBackend`] — single-node production backend backed
//!   by bundled-libsqlite via [`rusqlite`].
//!
//! Postgres, Parquet/object-store, and any other backend listed in
//! spec §11.1 implements [`Backend`] without changes to `glassbox-core`.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(missing_docs)]

pub mod mem;
#[cfg(feature = "parquet")]
pub mod parquet;
#[cfg(feature = "postgres")]
pub mod postgres;
pub mod sqlite;

use thiserror::Error;

use glassbox_core::chain::{InMemoryKeyResolver, VerificationReport, verify_chain};
use glassbox_core::record::SignedRecord;

/// Errors produced by storage backends.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StorageError {
    /// Underlying I/O failure from the database driver.
    #[error("backend i/o error: {0}")]
    Io(String),

    /// The append violated chain invariants enforced by the backend
    /// (e.g. wrong sequence number, wrong stream).
    #[error("invariant violation: {0}")]
    Invariant(String),

    /// Forwarded core error (canonical form, signature, hash).
    #[error(transparent)]
    Core(#[from] glassbox_core::Error),

    /// Serialization to/from the on-disk JSON representation failed.
    #[error("serialization error: {0}")]
    Serde(String),
}

/// Convenience alias.
pub type Result<T> = std::result::Result<T, StorageError>;

/// Common operations every storage backend must support.
///
/// Implementations are expected to enforce, on append, the local
/// invariants that do not require resolving the active key:
/// monotonic sequence within stream, matching `prev_hash_hex`, and
/// matching `stream_id` against the stream key. Signature checking
/// during a write is **not** required (the producer signed; the chain
/// itself is verified end-to-end via [`verify_stream`]).
pub trait Backend {
    /// Append a signed record to the named stream. The backend MUST
    /// fsync (or equivalent durability) before returning `Ok`.
    fn append(&mut self, record: SignedRecord) -> Result<()>;

    /// Return the most recently appended record for a stream, or `None`
    /// if the stream is empty.
    fn last(&self, stream_id: &str) -> Result<Option<SignedRecord>>;

    /// Return the record at the given sequence on the named stream.
    fn get(&self, stream_id: &str, sequence: u64) -> Result<Option<SignedRecord>>;

    /// Iterate every record on the stream in sequence order.
    fn iter_stream(&self, stream_id: &str) -> Result<Vec<SignedRecord>>;

    /// List every stream the backend knows about.
    fn list_streams(&self) -> Result<Vec<String>>;
}

/// Walk a stream and verify every invariant. Wraps
/// [`glassbox_core::chain::verify_chain`] for caller ergonomics.
pub fn verify_stream<B: Backend + ?Sized>(
    backend: &B,
    stream_id: &str,
) -> Result<VerificationReport> {
    let chain = backend.iter_stream(stream_id)?;
    let mut resolver = InMemoryKeyResolver::new();
    let report = verify_chain(&chain, &mut resolver)?;
    Ok(report)
}
