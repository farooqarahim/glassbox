//! `glassbox-mcp` — Model Context Protocol server.
//!
//! Speaks JSON-RPC 2.0 on stdin/stdout (standard MCP stdio transport).
//! Configured per-invocation with: ledger path, stream id, key id,
//! keypair file, and a capability-token JSON file.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(missing_docs)]

use std::fs;
use std::io::{BufReader, BufWriter};
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use glassbox_core::crypto::HybridKeypair;
use glassbox_mcp::{CapabilityToken, McpServer, ServerConfig};

#[derive(Debug, Parser)]
#[command(
    name = "glassbox-mcp",
    version,
    about = "MCP server exposing the Glassbox audit ledger.",
    long_about = None,
)]
struct Cli {
    /// SQLite ledger file.
    #[arg(long)]
    ledger: PathBuf,
    /// `<tenant>/<system>` stream identifier the server records into.
    #[arg(long)]
    stream: String,
    /// `key_id` of the active signing key on the stream.
    #[arg(long)]
    key_id: String,
    /// Glassbox keypair file used to sign appended records.
    #[arg(long)]
    key: PathBuf,
    /// Capability-token JSON file.
    #[arg(long)]
    token: PathBuf,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("glassbox-mcp: {e}");
            ExitCode::from(1)
        }
    }
}

fn run(cli: Cli) -> Result<(), String> {
    let kp_bytes = read_keypair_bytes(&cli.key)?;
    let keypair = HybridKeypair::from_bytes(&kp_bytes);
    let token = CapabilityToken::load(&cli.token).map_err(|e| e.to_string())?;
    let config = ServerConfig {
        ledger: cli.ledger,
        stream_id: cli.stream,
        key_id: cli.key_id,
        token,
    };
    let mut server = McpServer::new(keypair, config).map_err(|e| e.to_string())?;
    let stdin = std::io::stdin();
    let stdout = std::io::stdout();
    server
        .run(BufReader::new(stdin.lock()), BufWriter::new(stdout.lock()))
        .map_err(|e| e.to_string())
}

fn read_keypair_bytes(path: &std::path::Path) -> Result<[u8; 64], String> {
    let text = fs::read_to_string(path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let mut lines = text.lines();
    let header = lines.next().unwrap_or_default();
    if header.trim() != "glassbox-hybrid-v1" {
        return Err(format!(
            "{} is not a glassbox-hybrid-v1 keypair",
            path.display()
        ));
    }
    let hex_body = lines.next().unwrap_or_default().trim();
    let bytes = hex::decode(hex_body).map_err(|e| format!("malformed key body: {e}"))?;
    bytes
        .try_into()
        .map_err(|_| "keypair body is not 64 bytes".to_string())
}
