//! The unified error type for the core crate.
//!
//! Errors are designed to be cheap to construct and to carry enough
//! structured context that callers (the storage and CLI crates) can map
//! them to user-facing diagnostics without re-parsing strings.

use thiserror::Error;

/// Convenience alias for `Result<T, Error>`.
pub type Result<T> = core::result::Result<T, Error>;

/// All errors produced by `glassbox-core`.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum Error {
    /// Canonical JSON serialization failed.
    #[error("canonical-form serialization failed: {0}")]
    Canonical(String),

    /// JSON parsing or shape error.
    #[error("schema error: {0}")]
    Schema(String),

    /// A signature failed to verify under the registered key.
    #[error("signature verification failed: {0}")]
    Signature(String),

    /// A hash mismatch broke a chain invariant. The `sequence` field
    /// names the first record where the mismatch was observed.
    #[error("hash mismatch at sequence {sequence}: {reason}")]
    HashMismatch {
        /// Sequence number of the offending record.
        sequence: u64,
        /// Human-readable reason.
        reason: String,
    },

    /// A Merkle inclusion proof did not verify.
    #[error("merkle proof verification failed: {0}")]
    Merkle(String),

    /// Internal cryptographic error (RNG failure, malformed key material).
    #[error("crypto error: {0}")]
    Crypto(String),

    /// Invalid input from a caller (e.g. a malformed key, a stream ID
    /// with disallowed characters).
    #[error("invalid input: {0}")]
    Invalid(String),
}

impl Error {
    pub(crate) fn canonical(e: impl core::fmt::Display) -> Self {
        Self::Canonical(e.to_string())
    }
    pub(crate) fn crypto(e: impl core::fmt::Display) -> Self {
        Self::Crypto(e.to_string())
    }
    pub(crate) fn signature(e: impl core::fmt::Display) -> Self {
        Self::Signature(e.to_string())
    }
    pub(crate) fn invalid(e: impl core::fmt::Display) -> Self {
        Self::Invalid(e.to_string())
    }
}
