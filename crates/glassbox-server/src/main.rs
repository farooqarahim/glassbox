//! `glassbox-server` — HTTP/JSON server.
//!
//! Bind address, ledger path, signing keypair, and capability token
//! are configured on the command line. The server runs until SIGINT.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(missing_docs)]

use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::Parser;

use glassbox_core::crypto::HybridKeypair;
use glassbox_server::{AppState, CapabilityToken, serve};

#[derive(Debug, Parser)]
#[command(
    name = "glassbox-server",
    version,
    about = "HTTP/JSON server for the Glassbox audit ledger."
)]
struct Cli {
    /// SQLite ledger file.
    #[arg(long)]
    ledger: PathBuf,
    /// Operator signing keypair file.
    #[arg(long)]
    key: PathBuf,
    /// Capability token JSON file (clients present its `secret`
    /// as a `Bearer` token on every authenticated route).
    #[arg(long)]
    token: PathBuf,
    /// Bind address.
    #[arg(long, default_value = "127.0.0.1:7878")]
    bind: SocketAddr,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let rt = match tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
    {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("glassbox-server: tokio runtime: {e}");
            return ExitCode::from(1);
        }
    };
    rt.block_on(async move {
        match run(cli).await {
            Ok(()) => ExitCode::SUCCESS,
            Err(e) => {
                eprintln!("glassbox-server: {e}");
                ExitCode::from(1)
            }
        }
    })
}

async fn run(cli: Cli) -> Result<(), String> {
    let kp_bytes = read_keypair_bytes(&cli.key)?;
    let keypair = HybridKeypair::from_bytes(&kp_bytes);
    let token = CapabilityToken::load(&cli.token).map_err(|e| e.to_string())?;
    let state = AppState::new(cli.ledger, keypair, token).map_err(|e| e.to_string())?;
    println!("glassbox-server listening on {}", cli.bind);
    serve(state, cli.bind).await.map_err(|e| e.to_string())
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
