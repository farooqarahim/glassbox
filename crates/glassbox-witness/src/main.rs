//! `glassbox-witness` — reference witness daemon.
//!
//! In v0.3 the witness binary is a one-shot file-watching utility: it
//! reads a JSON file containing an STH to observe, writes a JSON file
//! containing the counter-signature, and exits. A long-running
//! network surface (gRPC/HTTPS) is on the v0.4 roadmap.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(missing_docs)]

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

use glassbox_core::SignedTreeHead;
use glassbox_core::crypto::HybridKeypair;
use glassbox_witness::WitnessServer;

#[derive(Debug, Parser)]
#[command(
    name = "glassbox-witness",
    version,
    about = "Reference witness server for the Glassbox tamper-evidence network.",
    long_about = None,
    propagate_version = true,
)]
struct Cli {
    /// Witness identifier (matches the witness operator's stable name).
    #[arg(long)]
    id: String,
    /// Witness keypair file (produced by `glassbox keygen`).
    #[arg(long)]
    key: PathBuf,
    /// Directory holding the witness's observation log.
    #[arg(long)]
    storage: PathBuf,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Read an STH from JSON, observe it, and write a counter-signature.
    Observe {
        /// JSON file containing a `SignedTreeHead`.
        #[arg(long)]
        sth: PathBuf,
        /// Where to write the resulting `WitnessCountersignature`.
        #[arg(long)]
        out: PathBuf,
    },
    /// Dump every observation this witness has on a stream.
    History {
        /// `<tenant>/<system>` stream identifier.
        #[arg(long)]
        stream: String,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("glassbox-witness: {e}");
            ExitCode::from(1)
        }
    }
}

fn dispatch(cli: Cli) -> Result<(), String> {
    let kp_bytes = read_keypair_bytes(&cli.key)?;
    let keypair = HybridKeypair::from_bytes(&kp_bytes);
    let mut server =
        WitnessServer::new(cli.id, keypair, &cli.storage).map_err(|e| e.to_string())?;

    match cli.command {
        Command::Observe { sth, out } => {
            let sth_text =
                fs::read_to_string(&sth).map_err(|e| format!("read {}: {e}", sth.display()))?;
            let sth: SignedTreeHead =
                serde_json::from_str(&sth_text).map_err(|e| format!("parse STH: {e}"))?;
            let cs = server.observe(sth).map_err(|e| e.to_string())?;
            let json = serde_json::to_string_pretty(&cs).map_err(|e| e.to_string())?;
            let mut f =
                fs::File::create(&out).map_err(|e| format!("create {}: {e}", out.display()))?;
            f.write_all(json.as_bytes())
                .map_err(|e| format!("write {}: {e}", out.display()))?;
            println!("observed and counter-signed; wrote {}", out.display());
            Ok(())
        }
        Command::History { stream } => {
            let observations = server.observations(&stream).map_err(|e| e.to_string())?;
            println!(
                "{}",
                serde_json::to_string_pretty(&observations).map_err(|e| e.to_string())?
            );
            Ok(())
        }
    }
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
