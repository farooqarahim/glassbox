//! Model Context Protocol (MCP) server exposing the Glassbox ledger.
//!
//! Per spec §18, an MCP-capable agent can record its own interactions,
//! tool calls, retrievals, sub-agent delegations, and human-in-the-loop
//! checkpoints directly into a Glassbox stream without the host
//! application needing to instrument any code path. The seven tools
//! enumerated in §18.2 are exposed here.
//!
//! ## Transport
//!
//! MCP is JSON-RPC 2.0. v0.4 ships **stdio transport** — the standard
//! transport for IDE/host integrations like Claude Desktop. One request
//! per line on stdin; one response per line on stdout. HTTPS / SSE
//! transports are straightforward additions and are on the v0.5 list.
//!
//! ## Authentication
//!
//! Per spec §18.3, MCP authentication uses per-tenant, per-agent
//! capability tokens scoped to: a tenant, a stream, a set of tools,
//! and an expiration. In v0.4 a single capability token is supplied
//! out-of-band when starting the server; every request must include
//! that token in its parameters under `auth_token`. Issuance of new
//! tokens (and their on-ledger record) is operator-side tooling and
//! lands with the multi-tenant resolver in v0.5.
//!
//! ## Circular references (spec §18.4)
//!
//! Meta-records — records *about* MCP tool calls themselves — are
//! NOT automatically recorded. The server processes its own tool
//! invocations without re-recording them, avoiding infinite regress.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(missing_docs)]

mod protocol;
mod server;
mod token;

pub use server::{McpError, McpServer, ServerConfig};
pub use token::{CapabilityToken, TokenScope};
