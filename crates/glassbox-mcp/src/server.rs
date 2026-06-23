//! MCP server core. Reads JSON-RPC requests on a `BufRead`, writes
//! responses on a `Write`. The `glassbox-mcp` binary wires this to
//! stdin/stdout; tests wire it to in-memory buffers.

use std::io::{BufRead, Write};
use std::path::PathBuf;

use serde::{Deserialize, Serialize};
use serde_json::json;
use thiserror::Error;
use time::OffsetDateTime;
use ulid::Ulid;

use glassbox_core::SCHEMA_VERSION;
use glassbox_core::chain::sign_record;
use glassbox_core::crypto::HybridKeypair;
use glassbox_core::key_registry::KeyStatus;
use glassbox_core::record::{
    ApprovalDecision, ContentRef, CorpusRef, HashAlgorithm, HumanApproval, InteractionBody,
    ModelFingerprint, Record, RecordBody, SpanKind, ToolInvocation,
};
use glassbox_storage::Backend;
use glassbox_storage::sqlite::SqliteBackend;

use crate::protocol::{JsonRpcError, JsonRpcErrorResponse, JsonRpcRequest, JsonRpcResult, codes};
use crate::token::{CapabilityToken, TokenError};

/// Errors at the server layer (not over the wire — those are mapped to
/// JSON-RPC errors).
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum McpError {
    /// I/O on the transport.
    #[error("transport i/o: {0}")]
    Io(String),
    /// Storage error.
    #[error(transparent)]
    Storage(#[from] glassbox_storage::StorageError),
    /// Core error.
    #[error(transparent)]
    Core(#[from] glassbox_core::Error),
}

/// Server configuration.
#[derive(Clone, Debug)]
pub struct ServerConfig {
    /// SQLite ledger path.
    pub ledger: PathBuf,
    /// Stream the server records into.
    pub stream_id: String,
    /// `key_id` to record under. The active key on the stream.
    pub key_id: String,
    /// Loaded capability token.
    pub token: CapabilityToken,
}

/// MCP server.
pub struct McpServer {
    backend: SqliteBackend,
    keypair: HybridKeypair,
    config: ServerConfig,
    initialized: bool,
}

impl McpServer {
    /// Create a server from on-disk ledger + signing keypair + config.
    pub fn new(keypair: HybridKeypair, config: ServerConfig) -> Result<Self, McpError> {
        let backend = SqliteBackend::open(&config.ledger)?;
        let chain = backend.iter_stream(&config.stream_id)?;
        if chain.is_empty() {
            return Err(McpError::Io(format!(
                "stream `{}` is empty; initialise it before starting the MCP server",
                config.stream_id
            )));
        }
        let mut active = false;
        for sr in &chain {
            if let RecordBody::KeyRegistry(entry) = &sr.record.body {
                if entry.key_id == config.key_id && matches!(entry.status, KeyStatus::Active) {
                    active = true;
                }
            }
        }
        if !active {
            return Err(McpError::Io(format!(
                "key_id `{}` is not active on `{}`",
                config.key_id, config.stream_id
            )));
        }
        Ok(Self {
            backend,
            keypair,
            config,
            initialized: false,
        })
    }

    /// Run the server loop until the input is exhausted.
    pub fn run<R: BufRead, W: Write>(
        &mut self,
        mut input: R,
        mut output: W,
    ) -> Result<(), McpError> {
        let mut line = String::new();
        loop {
            line.clear();
            let n = input.read_line(&mut line).map_err(io)?;
            if n == 0 {
                return Ok(());
            }
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let response = self.handle_line(trimmed);
            if let Some(resp) = response {
                writeln!(output, "{resp}").map_err(io)?;
                output.flush().map_err(io)?;
            }
        }
    }

    fn handle_line(&mut self, line: &str) -> Option<String> {
        let request: JsonRpcRequest = match serde_json::from_str(line) {
            Ok(r) => r,
            Err(e) => {
                return Some(error_response(
                    json!(null),
                    codes::PARSE_ERROR,
                    format!("parse: {e}"),
                ));
            }
        };
        if request.jsonrpc != "2.0" {
            return Some(error_response(
                request.id.unwrap_or(json!(null)),
                codes::INVALID_REQUEST,
                "jsonrpc must be \"2.0\"".into(),
            ));
        }
        if request.id.is_none() {
            self.handle_notification(&request);
            return None;
        }
        let id = request.id.clone().expect("checked above");
        let result = match request.method.as_str() {
            "initialize" => Ok(self.handle_initialize()),
            "tools/list" => Ok(self.handle_tools_list()),
            "tools/call" => self.handle_tools_call(&request.params),
            other => Err(JsonRpcError {
                code: codes::METHOD_NOT_FOUND,
                message: format!("method `{other}` not found"),
                data: None,
            }),
        };
        Some(match result {
            Ok(value) => serde_json::to_string(&JsonRpcResult {
                jsonrpc: "2.0",
                id,
                result: value,
            })
            .expect("serialize result"),
            Err(error) => serde_json::to_string(&JsonRpcErrorResponse {
                jsonrpc: "2.0",
                id,
                error,
            })
            .expect("serialize error"),
        })
    }

    fn handle_notification(&mut self, request: &JsonRpcRequest) {
        if request.method == "notifications/initialized" {
            self.initialized = true;
        }
    }

    #[allow(clippy::unused_self)]
    fn handle_initialize(&mut self) -> serde_json::Value {
        json!({
            "protocolVersion": "2024-11-05",
            "serverInfo": {
                "name": "glassbox-mcp",
                "version": env!("CARGO_PKG_VERSION"),
            },
            "capabilities": {
                "tools": { "listChanged": false }
            }
        })
    }

    #[allow(clippy::unused_self)]
    fn handle_tools_list(&self) -> serde_json::Value {
        json!({ "tools": tool_descriptors() })
    }

    fn handle_tools_call(
        &mut self,
        params: &serde_json::Value,
    ) -> Result<serde_json::Value, JsonRpcError> {
        let call: CallParams =
            serde_json::from_value(params.clone()).map_err(|e| JsonRpcError {
                code: codes::INVALID_PARAMS,
                message: format!("params: {e}"),
                data: None,
            })?;
        if let Err(e) = self.config.token.check_secret(&call.arguments.auth_token) {
            return Err(map_token_err(&e));
        }
        if let Err(e) = self.config.token.check_tool(&call.name) {
            return Err(map_token_err(&e));
        }
        if let Err(e) = self.config.token.check_stream(&self.config.stream_id) {
            return Err(map_token_err(&e));
        }
        let outcome = match call.name.as_str() {
            "record_interaction" => self.tool_record_interaction(call.arguments),
            "record_tool_call" => self.tool_record_tool_call(call.arguments),
            "record_retrieval" => self.tool_record_retrieval(call.arguments),
            "record_human_decision" => self.tool_record_human_decision(call.arguments),
            "record_sub_agent" => self.tool_record_sub_agent(call.arguments),
            "query" => self.tool_query(call.arguments),
            "verify_inclusion" => self.tool_verify_inclusion(call.arguments),
            other => Err(format!("unknown tool `{other}`")),
        };
        match outcome {
            Ok(text) => Ok(json!({
                "content": [{ "type": "text", "text": text }],
                "isError": false
            })),
            Err(msg) => Ok(json!({
                "content": [{ "type": "text", "text": msg }],
                "isError": true
            })),
        }
    }

    fn append(&mut self, body: RecordBody, sdk: &str) -> Result<(Ulid, u64, String), String> {
        let chain = self
            .backend
            .iter_stream(&self.config.stream_id)
            .map_err(|e| e.to_string())?;
        let last = chain.last().expect("non-empty stream invariant");
        let prev: [u8; 32] = hex::decode(&last.this_hash_hex)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "stored this_hash_hex was not 32 bytes".to_string())?;
        let seq = last.record.sequence + 1;
        let r = Record {
            record_id: Ulid::new(),
            stream_id: self.config.stream_id.clone(),
            sequence: seq,
            occurred_at: OffsetDateTime::now_utc(),
            received_at: OffsetDateTime::now_utc(),
            schema_version: SCHEMA_VERSION.into(),
            source_sdk: sdk.into(),
            key_id: self.config.key_id.clone(),
            prev_hash_hex: hex::encode(prev),
            body,
        };
        let sr = sign_record(r, &self.keypair).map_err(|e| e.to_string())?;
        let id = sr.record.record_id;
        let hash = sr.this_hash_hex.clone();
        self.backend.append(sr).map_err(|e| e.to_string())?;
        Ok((id, seq, hash))
    }

    fn tool_record_interaction(&mut self, args: ToolArgs) -> Result<String, String> {
        let body = InteractionBody {
            input: args.input.map(ContentRefArgs::into_content_ref),
            output: args.output.map(ContentRefArgs::into_content_ref),
            model: args.model.map(ModelArgs::into_model),
            decision: args.decision.map(|d| glassbox_core::DecisionContext {
                decision_id: d.decision_id,
                subject_id: d.subject_id,
                jurisdiction: d.jurisdiction,
                outcome: d.outcome,
                automation_level: None,
            }),
            parent_record_id: args.parent_record_id,
            span_kind: Some(SpanKind::ModelCall),
            ..Default::default()
        };
        let (id, seq, hash) = self.append(RecordBody::Interaction(body), "glassbox-mcp/0.4.0")?;
        Ok(format!(
            "recorded interaction record_id={id} sequence={seq} this_hash={hash}"
        ))
    }

    fn tool_record_tool_call(&mut self, args: ToolArgs) -> Result<String, String> {
        let tool = args.tool.ok_or("missing `tool`")?;
        let body = InteractionBody {
            tool_calls: vec![ToolInvocation {
                tool_name: tool.name,
                args_hash_hex: tool.args_hash_hex,
                result_hash_hex: tool.result_hash_hex,
                latency_ms: tool.latency_ms,
                success: tool.success.unwrap_or(true),
            }],
            parent_record_id: args.parent_record_id,
            span_kind: Some(SpanKind::ToolCall),
            ..Default::default()
        };
        let (id, seq, hash) = self.append(RecordBody::Interaction(body), "glassbox-mcp/0.4.0")?;
        Ok(format!(
            "recorded tool_call record_id={id} sequence={seq} this_hash={hash}"
        ))
    }

    fn tool_record_retrieval(&mut self, args: ToolArgs) -> Result<String, String> {
        let retrieval = args.retrieval.ok_or("missing `retrieval`")?;
        let body = InteractionBody {
            corpus_refs: vec![CorpusRef {
                corpus_id: retrieval.corpus_id,
                corpus_version: retrieval.corpus_version,
                chunk_hashes_hex: retrieval.chunk_hashes_hex,
            }],
            parent_record_id: args.parent_record_id,
            span_kind: Some(SpanKind::Retrieval),
            ..Default::default()
        };
        let (id, seq, hash) = self.append(RecordBody::Interaction(body), "glassbox-mcp/0.4.0")?;
        Ok(format!(
            "recorded retrieval record_id={id} sequence={seq} this_hash={hash}"
        ))
    }

    fn tool_record_human_decision(&mut self, args: ToolArgs) -> Result<String, String> {
        let h = args.human.ok_or("missing `human`")?;
        let decision = match h.decision.as_str() {
            "approve" => ApprovalDecision::Approve,
            "reject" => ApprovalDecision::Reject,
            "escalate" => ApprovalDecision::Escalate,
            "override" => ApprovalDecision::Override,
            other => return Err(format!("unknown human decision `{other}`")),
        };
        let body = InteractionBody {
            approval: Some(HumanApproval {
                approver_id: h.approver_id,
                decision,
                rationale_hash_hex: h.rationale_hash_hex,
                decided_at: OffsetDateTime::now_utc(),
            }),
            parent_record_id: args.parent_record_id,
            span_kind: Some(SpanKind::HumanReview),
            ..Default::default()
        };
        let (id, seq, hash) = self.append(RecordBody::Interaction(body), "glassbox-mcp/0.4.0")?;
        Ok(format!(
            "recorded human_decision record_id={id} sequence={seq} this_hash={hash}"
        ))
    }

    fn tool_record_sub_agent(&mut self, args: ToolArgs) -> Result<String, String> {
        let sub = args.sub_agent.ok_or("missing `sub_agent`")?;
        let mut meta = serde_json::Map::new();
        meta.insert(
            "sub_agent_id".into(),
            serde_json::Value::String(sub.sub_agent_id.clone()),
        );
        if let Some(reason) = sub.reason.clone() {
            meta.insert("reason".into(), serde_json::Value::String(reason));
        }
        let body = InteractionBody {
            parent_record_id: args.parent_record_id,
            span_kind: Some(SpanKind::SubAgent),
            metadata: meta,
            ..Default::default()
        };
        let (id, seq, hash) = self.append(RecordBody::Interaction(body), "glassbox-mcp/0.4.0")?;
        Ok(format!(
            "recorded sub_agent record_id={id} sequence={seq} this_hash={hash}"
        ))
    }

    fn tool_query(&self, args: ToolArgs) -> Result<String, String> {
        let q = args.query.ok_or("missing `query`")?;
        let chain = self
            .backend
            .iter_stream(&self.config.stream_id)
            .map_err(|e| e.to_string())?;
        let mut matches: Vec<serde_json::Value> = Vec::new();
        for sr in chain {
            let mut ok = true;
            if let Some(seq) = q.sequence {
                if sr.record.sequence != seq {
                    ok = false;
                }
            }
            if let Some(decision_id) = q.decision_id.as_deref() {
                let hit = if let RecordBody::Interaction(b) = &sr.record.body {
                    b.decision
                        .as_ref()
                        .is_some_and(|d| d.decision_id == decision_id)
                } else {
                    false
                };
                if !hit {
                    ok = false;
                }
            }
            if let Some(subject_id) = q.subject_id.as_deref() {
                let hit = if let RecordBody::Interaction(b) = &sr.record.body {
                    b.decision
                        .as_ref()
                        .and_then(|d| d.subject_id.as_deref())
                        .is_some_and(|s| s == subject_id)
                } else {
                    false
                };
                if !hit {
                    ok = false;
                }
            }
            if ok {
                matches.push(serde_json::to_value(&sr).map_err(|e| e.to_string())?);
            }
            if matches.len() >= q.limit.unwrap_or(50) {
                break;
            }
        }
        Ok(serde_json::Value::Array(matches).to_string())
    }

    fn tool_verify_inclusion(&self, args: ToolArgs) -> Result<String, String> {
        let v = args.verify.ok_or("missing `verify`")?;
        let chain = self
            .backend
            .iter_stream(&self.config.stream_id)
            .map_err(|e| e.to_string())?;
        let target = chain
            .iter()
            .find(|sr| sr.record.sequence == v.sequence)
            .ok_or_else(|| format!("no record at sequence {}", v.sequence))?;
        let leaf: [u8; 32] = hex::decode(&target.this_hash_hex)
            .map_err(|e| e.to_string())?
            .try_into()
            .map_err(|_| "stored this_hash not 32 bytes".to_string())?;
        let leaves: Vec<[u8; 32]> = chain
            .iter()
            .filter(|sr| !matches!(sr.record.body, RecordBody::MerkleRoot(_)))
            .map(|sr| {
                hex::decode(&sr.this_hash_hex)
                    .map_err(|e| e.to_string())?
                    .try_into()
                    .map_err(|_| "stored this_hash not 32 bytes".to_string())
            })
            .collect::<Result<_, _>>()?;
        let target_idx = chain
            .iter()
            .filter(|sr| !matches!(sr.record.body, RecordBody::MerkleRoot(_)))
            .position(|sr| sr.record.sequence == v.sequence)
            .ok_or_else(|| format!("sequence {} not in batch", v.sequence))?;
        let root = glassbox_core::merkle::compute_root(&leaves).map_err(|e| e.to_string())?;
        let proof =
            glassbox_core::merkle::build_proof(&leaves, target_idx).map_err(|e| e.to_string())?;
        let json = json!({
            "leaf_hex": hex::encode(leaf),
            "root_hex": hex::encode(root),
            "steps": proof
                .iter()
                .map(|s| json!({
                    "sibling_hex": hex::encode(s.sibling),
                    "sibling_is_right": s.sibling_is_right
                }))
                .collect::<Vec<_>>()
        });
        Ok(json.to_string())
    }
}

fn io<E: std::fmt::Display>(e: E) -> McpError {
    McpError::Io(e.to_string())
}

fn map_token_err(e: &TokenError) -> JsonRpcError {
    JsonRpcError {
        code: codes::FORBIDDEN,
        message: e.to_string(),
        data: None,
    }
}

fn error_response(id: serde_json::Value, code: i64, message: String) -> String {
    serde_json::to_string(&JsonRpcErrorResponse {
        jsonrpc: "2.0",
        id,
        error: JsonRpcError {
            code,
            message,
            data: None,
        },
    })
    .expect("serialize")
}

fn tool_descriptors() -> Vec<serde_json::Value> {
    let auth = json!({
        "auth_token": { "type": "string", "description": "Capability-token secret." }
    });
    vec![
        json!({
            "name": "record_interaction",
            "description": "Record a single model interaction. Spec section 18.2.",
            "inputSchema": {
                "type": "object",
                "required": ["auth_token"],
                "properties": {
                    "auth_token": auth["auth_token"],
                    "input": content_ref_schema(),
                    "output": content_ref_schema(),
                    "model": model_schema(),
                    "decision": decision_schema(),
                    "parent_record_id": ulid_schema(),
                }
            }
        }),
        json!({
            "name": "record_tool_call",
            "description": "Record one tool invocation as a child of the active interaction.",
            "inputSchema": {
                "type": "object",
                "required": ["auth_token", "tool"],
                "properties": {
                    "auth_token": auth["auth_token"],
                    "parent_record_id": ulid_schema(),
                    "tool": tool_invocation_schema(),
                }
            }
        }),
        json!({
            "name": "record_retrieval",
            "description": "Record a retrieval-augmented-generation step.",
            "inputSchema": {
                "type": "object",
                "required": ["auth_token", "retrieval"],
                "properties": {
                    "auth_token": auth["auth_token"],
                    "parent_record_id": ulid_schema(),
                    "retrieval": retrieval_schema(),
                }
            }
        }),
        json!({
            "name": "record_human_decision",
            "description": "Record a human-in-the-loop checkpoint.",
            "inputSchema": {
                "type": "object",
                "required": ["auth_token", "human"],
                "properties": {
                    "auth_token": auth["auth_token"],
                    "parent_record_id": ulid_schema(),
                    "human": human_schema(),
                }
            }
        }),
        json!({
            "name": "record_sub_agent",
            "description": "Record a delegation to a sub-agent.",
            "inputSchema": {
                "type": "object",
                "required": ["auth_token", "sub_agent"],
                "properties": {
                    "auth_token": auth["auth_token"],
                    "parent_record_id": ulid_schema(),
                    "sub_agent": sub_agent_schema(),
                }
            }
        }),
        json!({
            "name": "query",
            "description": "Read-only query over the stream.",
            "inputSchema": {
                "type": "object",
                "required": ["auth_token", "query"],
                "properties": {
                    "auth_token": auth["auth_token"],
                    "query": query_schema(),
                }
            }
        }),
        json!({
            "name": "verify_inclusion",
            "description": "Generate a Merkle inclusion proof for a sequence.",
            "inputSchema": {
                "type": "object",
                "required": ["auth_token", "verify"],
                "properties": {
                    "auth_token": auth["auth_token"],
                    "verify": json!({
                        "type": "object",
                        "required": ["sequence"],
                        "properties": {
                            "sequence": { "type": "integer", "minimum": 0 }
                        }
                    })
                }
            }
        }),
    ]
}

fn content_ref_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["hash_hex", "byte_size"],
        "properties": {
            "hash_algorithm": { "type": "string", "enum": ["SHA-256", "BLAKE3"] },
            "hash_hex": { "type": "string" },
            "byte_size": { "type": "integer", "minimum": 0 },
            "mime_type": { "type": "string" }
        }
    })
}

fn model_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["provider", "model_name", "model_version"],
        "properties": {
            "provider": { "type": "string" },
            "model_name": { "type": "string" },
            "model_version": { "type": "string" }
        }
    })
}

fn decision_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["decision_id"],
        "properties": {
            "decision_id": { "type": "string" },
            "subject_id": { "type": "string" },
            "jurisdiction": { "type": "string" },
            "outcome": { "type": "string" }
        }
    })
}

fn tool_invocation_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["name", "args_hash_hex"],
        "properties": {
            "name": { "type": "string" },
            "args_hash_hex": { "type": "string" },
            "result_hash_hex": { "type": "string" },
            "latency_ms": { "type": "integer", "minimum": 0 },
            "success": { "type": "boolean" }
        }
    })
}

fn retrieval_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["corpus_id", "corpus_version"],
        "properties": {
            "corpus_id": { "type": "string" },
            "corpus_version": { "type": "string" },
            "chunk_hashes_hex": {
                "type": "array",
                "items": { "type": "string" }
            }
        }
    })
}

fn human_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["approver_id", "decision"],
        "properties": {
            "approver_id": { "type": "string" },
            "decision": {
                "type": "string",
                "enum": ["approve", "reject", "escalate", "override"]
            },
            "rationale_hash_hex": { "type": "string" }
        }
    })
}

fn sub_agent_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "required": ["sub_agent_id"],
        "properties": {
            "sub_agent_id": { "type": "string" },
            "reason": { "type": "string" }
        }
    })
}

fn query_schema() -> serde_json::Value {
    json!({
        "type": "object",
        "properties": {
            "sequence": { "type": "integer", "minimum": 0 },
            "decision_id": { "type": "string" },
            "subject_id": { "type": "string" },
            "limit": { "type": "integer", "minimum": 1, "maximum": 1000 }
        }
    })
}

fn ulid_schema() -> serde_json::Value {
    json!({ "type": "string", "description": "ULID identifier." })
}

#[derive(Debug, Deserialize)]
struct CallParams {
    name: String,
    #[serde(default)]
    arguments: ToolArgs,
}

#[derive(Debug, Default, Deserialize)]
struct ToolArgs {
    #[serde(default)]
    auth_token: String,
    #[serde(default)]
    parent_record_id: Option<Ulid>,
    #[serde(default)]
    input: Option<ContentRefArgs>,
    #[serde(default)]
    output: Option<ContentRefArgs>,
    #[serde(default)]
    model: Option<ModelArgs>,
    #[serde(default)]
    decision: Option<DecisionArgs>,
    #[serde(default)]
    tool: Option<ToolInvocationArgs>,
    #[serde(default)]
    retrieval: Option<RetrievalArgs>,
    #[serde(default)]
    human: Option<HumanArgs>,
    #[serde(default)]
    sub_agent: Option<SubAgentArgs>,
    #[serde(default)]
    query: Option<QueryArgs>,
    #[serde(default)]
    verify: Option<VerifyArgs>,
}

#[derive(Debug, Deserialize)]
struct ContentRefArgs {
    #[serde(default)]
    hash_algorithm: Option<HashAlgorithm>,
    hash_hex: String,
    byte_size: u64,
    #[serde(default)]
    mime_type: Option<String>,
}

impl ContentRefArgs {
    fn into_content_ref(self) -> ContentRef {
        ContentRef {
            hash_algorithm: self.hash_algorithm.unwrap_or_default(),
            hash_hex: self.hash_hex,
            byte_size: self.byte_size,
            mime_type: self.mime_type,
        }
    }
}

#[derive(Debug, Deserialize)]
struct ModelArgs {
    provider: String,
    model_name: String,
    model_version: String,
}

impl ModelArgs {
    fn into_model(self) -> ModelFingerprint {
        ModelFingerprint {
            provider: self.provider,
            model_name: self.model_name,
            model_version: self.model_version,
            sampling: None,
        }
    }
}

#[derive(Debug, Deserialize)]
struct DecisionArgs {
    decision_id: String,
    #[serde(default)]
    subject_id: Option<String>,
    #[serde(default)]
    jurisdiction: Option<String>,
    #[serde(default)]
    outcome: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ToolInvocationArgs {
    name: String,
    args_hash_hex: String,
    #[serde(default)]
    result_hash_hex: Option<String>,
    #[serde(default)]
    latency_ms: Option<u64>,
    #[serde(default)]
    success: Option<bool>,
}

#[derive(Debug, Deserialize)]
struct RetrievalArgs {
    corpus_id: String,
    corpus_version: String,
    #[serde(default)]
    chunk_hashes_hex: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct HumanArgs {
    approver_id: String,
    decision: String,
    #[serde(default)]
    rationale_hash_hex: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SubAgentArgs {
    sub_agent_id: String,
    #[serde(default)]
    reason: Option<String>,
}

#[derive(Debug, Deserialize)]
struct QueryArgs {
    #[serde(default)]
    sequence: Option<u64>,
    #[serde(default)]
    decision_id: Option<String>,
    #[serde(default)]
    subject_id: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct VerifyArgs {
    sequence: u64,
}

// Silences a dead-code warning where Serialize is otherwise only used
// via derive on protocol types.
#[derive(Serialize)]
struct _Unused;

#[cfg(test)]
mod tests {
    use super::*;
    use glassbox_core::SCHEMA_VERSION;
    use glassbox_core::chain::sign_record;
    use glassbox_core::key_registry::{KeyRegistryEntry, KeyStatus};
    use glassbox_core::record::{Record, RecordBody};
    use std::io::Cursor;
    use time::Duration;

    fn init_stream(backend: &mut SqliteBackend, kp: &HybridKeypair) -> String {
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
            stream_id: "acme/sys".into(),
            sequence: 0,
            occurred_at: OffsetDateTime::now_utc(),
            received_at: OffsetDateTime::now_utc(),
            schema_version: SCHEMA_VERSION.into(),
            source_sdk: "test/0.4.0".into(),
            key_id: "k".into(),
            prev_hash_hex: hex::encode([0u8; 32]),
            body: RecordBody::KeyRegistry(entry),
        };
        backend.append(sign_record(r0, kp).unwrap()).unwrap();
        "k".into()
    }

    fn token() -> CapabilityToken {
        CapabilityToken {
            token_id: "t1".into(),
            scope: crate::token::TokenScope {
                tenant_id: "acme".into(),
                stream_id: "acme/sys".into(),
                allowed_tools: vec![],
                expires_at: OffsetDateTime::now_utc() + Duration::hours(1),
            },
            secret: "sssh".into(),
        }
    }

    fn fresh_server() -> (tempfile::TempDir, McpServer) {
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("ledger.db");
        let kp = HybridKeypair::generate().unwrap();
        let mut backend = SqliteBackend::open(&ledger).unwrap();
        let key_id = init_stream(&mut backend, &kp);
        drop(backend);
        let server = McpServer::new(
            kp,
            ServerConfig {
                ledger,
                stream_id: "acme/sys".into(),
                key_id,
                token: token(),
            },
        )
        .unwrap();
        (dir, server)
    }

    fn drive(server: &mut McpServer, lines: &[&str]) -> Vec<String> {
        let input = lines.join("\n") + "\n";
        let mut output: Vec<u8> = Vec::new();
        server
            .run(Cursor::new(input.as_bytes()), &mut output)
            .unwrap();
        String::from_utf8(output)
            .unwrap()
            .lines()
            .map(String::from)
            .collect()
    }

    #[test]
    fn initialize_then_tools_list_returns_seven_tools() {
        let (_dir, mut server) = fresh_server();
        let out = drive(
            &mut server,
            &[
                r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#,
                r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#,
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}"#,
            ],
        );
        assert_eq!(out.len(), 2);
        let list: serde_json::Value = serde_json::from_str(&out[1]).unwrap();
        let tools = list["result"]["tools"].as_array().unwrap();
        assert_eq!(tools.len(), 7);
    }

    #[test]
    fn record_interaction_appends_to_ledger() {
        let (_dir, mut server) = fresh_server();
        let out = drive(
            &mut server,
            &[
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"record_interaction","arguments":{"auth_token":"sssh","model":{"provider":"anthropic","model_name":"claude-opus-4-7","model_version":"v"},"decision":{"decision_id":"loan-1","outcome":"approved"}}}}"#,
            ],
        );
        let resp: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
        assert_eq!(resp["result"]["isError"], false);
        assert!(
            resp["result"]["content"][0]["text"]
                .as_str()
                .unwrap()
                .contains("recorded interaction")
        );
    }

    #[test]
    fn forbidden_token_secret_is_rejected() {
        let (_dir, mut server) = fresh_server();
        let out = drive(
            &mut server,
            &[
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"record_interaction","arguments":{"auth_token":"wrong"}}}"#,
            ],
        );
        let resp: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
        assert_eq!(resp["error"]["code"], codes::FORBIDDEN);
    }

    #[test]
    fn unknown_method_returns_method_not_found() {
        let (_dir, mut server) = fresh_server();
        let out = drive(
            &mut server,
            &[r#"{"jsonrpc":"2.0","id":1,"method":"made-up","params":{}}"#],
        );
        let resp: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
        assert_eq!(resp["error"]["code"], codes::METHOD_NOT_FOUND);
    }

    #[test]
    fn malformed_json_returns_parse_error() {
        let (_dir, mut server) = fresh_server();
        let out = drive(&mut server, &["{not json"]);
        let resp: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
        assert_eq!(resp["error"]["code"], codes::PARSE_ERROR);
    }

    #[test]
    fn verify_inclusion_returns_proof_with_local_root() {
        let (_dir, mut server) = fresh_server();
        drive(
            &mut server,
            &[
                r#"{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"record_interaction","arguments":{"auth_token":"sssh"}}}"#,
            ],
        );
        let out = drive(
            &mut server,
            &[
                r#"{"jsonrpc":"2.0","id":2,"method":"tools/call","params":{"name":"verify_inclusion","arguments":{"auth_token":"sssh","verify":{"sequence":1}}}}"#,
            ],
        );
        let resp: serde_json::Value = serde_json::from_str(&out[0]).unwrap();
        let text = resp["result"]["content"][0]["text"].as_str().unwrap();
        let proof: serde_json::Value = serde_json::from_str(text).unwrap();
        assert_eq!(proof["root_hex"].as_str().unwrap().len(), 64);
        assert_eq!(proof["leaf_hex"].as_str().unwrap().len(), 64);
    }
}
