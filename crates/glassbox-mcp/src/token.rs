//! Capability tokens for MCP authentication (spec §18.3).
//!
//! A capability token is a small JSON document signed by the operator
//! key that issued it. It declares a scope (tenant, stream, allowed
//! tool set, expiration). In v0.4 the token is loaded from a file at
//! server startup; the server enforces that every JSON-RPC request
//! carries an `auth_token` matching the loaded token, and that the
//! requested tool is in the scope's allowed list.
//!
//! Token issuance is itself an on-ledger record in the spec's full
//! design (§18.3 "Token issuance is logged into the administrative
//! stream"); v0.4 ships the verification half and leaves issuance as
//! a v0.5 operator-tooling item.

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};
use thiserror::Error;
use time::OffsetDateTime;

/// What a token may do.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct TokenScope {
    /// Tenant identifier the token is scoped to.
    pub tenant_id: String,
    /// `<tenant>/<system>` stream identifier the token may write to.
    pub stream_id: String,
    /// Allowed tool names. An empty list means "all tools" — operators
    /// SHOULD enumerate explicitly.
    pub allowed_tools: Vec<String>,
    /// Hard expiration. Tokens past this time MUST be rejected.
    #[serde(with = "time::serde::rfc3339")]
    pub expires_at: OffsetDateTime,
}

/// A capability token. v0.4 stores it as a plain JSON file at server
/// startup; the file path is what the operator hands to the agent.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct CapabilityToken {
    /// Opaque caller-meaningful identifier of the token (for logs).
    pub token_id: String,
    /// The token's scope.
    pub scope: TokenScope,
    /// Opaque secret the agent presents on every request. Must match
    /// the value the server loaded. Comparison is constant-time at the
    /// server side.
    pub secret: String,
}

/// Errors during token loading or validation.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TokenError {
    /// I/O failure reading the token file.
    #[error("token i/o: {0}")]
    Io(String),
    /// JSON parse error.
    #[error("malformed token: {0}")]
    Malformed(String),
    /// The token's `expires_at` is in the past at load time.
    #[error("token expired at {0}")]
    Expired(String),
    /// The presented secret does not match the loaded token.
    #[error("invalid auth_token")]
    InvalidSecret,
    /// The requested tool is not in the token's allowed list.
    #[error("tool `{0}` not permitted by token scope")]
    ToolForbidden(String),
    /// The token's stream_id does not match the requested stream.
    #[error("stream `{requested}` not permitted by token scoped to `{permitted}`")]
    StreamForbidden {
        /// Stream the request named.
        requested: String,
        /// Stream the token grants access to.
        permitted: String,
    },
}

impl CapabilityToken {
    /// Load a token from a JSON file and fail fast if it is already
    /// expired.
    pub fn load(path: &Path) -> Result<Self, TokenError> {
        let text = fs::read_to_string(path).map_err(|e| TokenError::Io(e.to_string()))?;
        let token: Self =
            serde_json::from_str(&text).map_err(|e| TokenError::Malformed(e.to_string()))?;
        if token.scope.expires_at < OffsetDateTime::now_utc() {
            return Err(TokenError::Expired(token.scope.expires_at.to_string()));
        }
        Ok(token)
    }

    /// Validate that `presented` is the token's secret. Constant-time
    /// comparison.
    pub fn check_secret(&self, presented: &str) -> Result<(), TokenError> {
        if constant_time_eq(self.secret.as_bytes(), presented.as_bytes()) {
            Ok(())
        } else {
            Err(TokenError::InvalidSecret)
        }
    }

    /// Validate that `tool` is permitted by the scope. An empty
    /// `allowed_tools` list means "all tools".
    pub fn check_tool(&self, tool: &str) -> Result<(), TokenError> {
        if self.scope.allowed_tools.is_empty() || self.scope.allowed_tools.iter().any(|t| t == tool)
        {
            Ok(())
        } else {
            Err(TokenError::ToolForbidden(tool.into()))
        }
    }

    /// Validate that `stream` matches the scoped stream exactly.
    pub fn check_stream(&self, stream: &str) -> Result<(), TokenError> {
        if self.scope.stream_id == stream {
            Ok(())
        } else {
            Err(TokenError::StreamForbidden {
                requested: stream.into(),
                permitted: self.scope.stream_id.clone(),
            })
        }
    }
}

/// Compare two byte slices in constant time. Returns false for
/// different-length inputs.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::Duration;

    fn token(allowed: Vec<&str>, expires_in: Duration) -> CapabilityToken {
        CapabilityToken {
            token_id: "t1".into(),
            scope: TokenScope {
                tenant_id: "acme".into(),
                stream_id: "acme/credit".into(),
                allowed_tools: allowed.into_iter().map(String::from).collect(),
                expires_at: OffsetDateTime::now_utc() + expires_in,
            },
            secret: "sssh".into(),
        }
    }

    #[test]
    fn allowed_tool_passes() {
        let t = token(vec!["record_interaction"], Duration::hours(1));
        t.check_tool("record_interaction").unwrap();
    }

    #[test]
    fn empty_allowed_list_means_all() {
        let t = token(vec![], Duration::hours(1));
        t.check_tool("query").unwrap();
        t.check_tool("verify_inclusion").unwrap();
    }

    #[test]
    fn unlisted_tool_rejected() {
        let t = token(vec!["record_interaction"], Duration::hours(1));
        assert!(matches!(
            t.check_tool("query"),
            Err(TokenError::ToolForbidden(_))
        ));
    }

    #[test]
    fn secret_mismatch_rejected() {
        let t = token(vec![], Duration::hours(1));
        assert!(matches!(
            t.check_secret("wrong"),
            Err(TokenError::InvalidSecret)
        ));
        t.check_secret("sssh").unwrap();
    }

    #[test]
    fn stream_mismatch_rejected() {
        let t = token(vec![], Duration::hours(1));
        assert!(matches!(
            t.check_stream("other/stream"),
            Err(TokenError::StreamForbidden { .. })
        ));
        t.check_stream("acme/credit").unwrap();
    }

    #[test]
    fn expired_token_rejected_on_load() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t.json");
        let t = token(vec![], Duration::seconds(-1));
        fs::write(&p, serde_json::to_string(&t).unwrap()).unwrap();
        assert!(matches!(
            CapabilityToken::load(&p),
            Err(TokenError::Expired(_))
        ));
    }
}
