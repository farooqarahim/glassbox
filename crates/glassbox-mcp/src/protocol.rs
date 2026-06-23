//! JSON-RPC 2.0 wire types for MCP.
//!
//! MCP uses a small subset of JSON-RPC: method calls with structured
//! params, results, and error objects. Notifications carry no `id`.
//! Field naming follows the MCP spec, not Rust idioms.

use serde::{Deserialize, Serialize};

/// JSON-RPC 2.0 request or notification on the wire.
#[derive(Clone, Debug, Deserialize)]
pub(crate) struct JsonRpcRequest {
    pub(crate) jsonrpc: String,
    pub(crate) method: String,
    #[serde(default)]
    pub(crate) params: serde_json::Value,
    /// Notifications omit `id`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) id: Option<serde_json::Value>,
}

/// Successful response.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct JsonRpcResult {
    pub(crate) jsonrpc: &'static str,
    pub(crate) id: serde_json::Value,
    pub(crate) result: serde_json::Value,
}

/// Error response.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct JsonRpcErrorResponse {
    pub(crate) jsonrpc: &'static str,
    pub(crate) id: serde_json::Value,
    pub(crate) error: JsonRpcError,
}

/// Error object body.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct JsonRpcError {
    pub(crate) code: i64,
    pub(crate) message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub(crate) data: Option<serde_json::Value>,
}

/// MCP-spec error codes per the spec's JSON-RPC mapping.
pub(crate) mod codes {
    /// JSON-RPC parse error.
    pub(crate) const PARSE_ERROR: i64 = -32700;
    /// JSON-RPC invalid request.
    pub(crate) const INVALID_REQUEST: i64 = -32600;
    /// JSON-RPC method not found.
    pub(crate) const METHOD_NOT_FOUND: i64 = -32601;
    /// JSON-RPC invalid params.
    pub(crate) const INVALID_PARAMS: i64 = -32602;
    /// JSON-RPC internal error.
    #[allow(dead_code)]
    pub(crate) const INTERNAL_ERROR: i64 = -32603;
    /// MCP application error: forbidden by scope.
    pub(crate) const FORBIDDEN: i64 = -32000;
    /// MCP application error: storage failure. Reserved for use by
    /// future MCP tool wrappers that need to differentiate storage
    /// failures from generic internal errors.
    #[allow(dead_code)]
    pub(crate) const STORAGE: i64 = -32001;
}
