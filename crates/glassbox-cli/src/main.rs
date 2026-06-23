//! The `glassbox` command-line binary.
//!
//! See `glassbox --help` for the full surface. Subcommands operate on a
//! single SQLite ledger file plus a single keypair file at a time;
//! multi-tenant deployments use one file per tenant.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(missing_docs)]

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};

mod commands;

/// Top-level CLI.
#[derive(Debug, Parser)]
#[command(
    name = "glassbox",
    version,
    about = "Tamper-evident audit ledger for AI systems.",
    long_about = None,
    propagate_version = true,
)]
struct Cli {
    /// Subcommand.
    #[command(subcommand)]
    command: Command,
}

/// Subcommands.
#[derive(Debug, Subcommand)]
enum Command {
    /// Generate a new hybrid Ed25519 + ML-DSA-65 keypair.
    Keygen {
        /// Path to write the keypair file. Refuses to overwrite.
        #[arg(long)]
        out: PathBuf,
    },
    /// Initialise a new ledger with a genesis key-registry record.
    Init {
        /// Path to the SQLite ledger file (created if missing).
        #[arg(long)]
        ledger: PathBuf,
        /// Tenant id (left side of the `tenant/system` stream identifier).
        #[arg(long)]
        tenant: String,
        /// System id (right side of the stream identifier).
        #[arg(long)]
        system: String,
        /// Keypair file produced by `glassbox keygen`.
        #[arg(long)]
        key: PathBuf,
        /// `key_id` to register under (defaults to `<tenant>-active`).
        #[arg(long)]
        key_id: Option<String>,
    },
    /// Append an interaction record from a JSON body.
    Append {
        /// Path to the SQLite ledger file.
        #[arg(long)]
        ledger: PathBuf,
        /// Stream identifier, `<tenant>/<system>`.
        #[arg(long)]
        stream: String,
        /// Keypair file.
        #[arg(long)]
        key: PathBuf,
        /// `key_id` to use (defaults to the most recently appended key on the stream).
        #[arg(long)]
        key_id: Option<String>,
        /// Path to a JSON file describing the interaction body. See README.
        #[arg(long)]
        body: PathBuf,
    },
    /// Show a single record by sequence number.
    Show {
        /// Path to the SQLite ledger file.
        #[arg(long)]
        ledger: PathBuf,
        /// Stream identifier.
        #[arg(long)]
        stream: String,
        /// Sequence number.
        #[arg(long)]
        sequence: u64,
    },
    /// Walk a stream and verify every signature, hash link, and Merkle root.
    Verify {
        /// Path to the SQLite ledger file.
        #[arg(long)]
        ledger: PathBuf,
        /// Stream identifier.
        #[arg(long)]
        stream: String,
    },
    /// Compute a Merkle root over the most recent uncommitted batch and
    /// append it as a `merkle_root` record.
    MerkleCommit {
        /// Path to the SQLite ledger file.
        #[arg(long)]
        ledger: PathBuf,
        /// Stream identifier.
        #[arg(long)]
        stream: String,
        /// Keypair file.
        #[arg(long)]
        key: PathBuf,
        /// `key_id` to use (defaults to the most recently appended key on the stream).
        #[arg(long)]
        key_id: Option<String>,
    },
    /// Rotate the active signing key by registering a new key-registry record.
    KeyRotate {
        /// Path to the SQLite ledger file.
        #[arg(long)]
        ledger: PathBuf,
        /// Stream identifier.
        #[arg(long)]
        stream: String,
        /// The current active keypair (signs the new registry record).
        #[arg(long)]
        current_key: PathBuf,
        /// The new keypair (its public material is what gets registered).
        #[arg(long)]
        new_key: PathBuf,
        /// `key_id` for the new key (defaults to `rotated-<seq>`).
        #[arg(long)]
        new_key_id: Option<String>,
    },
    /// List every stream stored in the ledger.
    Streams {
        /// Path to the SQLite ledger file.
        #[arg(long)]
        ledger: PathBuf,
    },
    /// Publish the most recent Merkle root to a witness storage
    /// directory (the witness operator runs `glassbox-witness observe`
    /// against it). Records the returned counter-signature back into a
    /// follow-up Merkle-root record.
    WitnessPublish {
        /// Path to the SQLite ledger file.
        #[arg(long)]
        ledger: PathBuf,
        /// Stream identifier.
        #[arg(long)]
        stream: String,
        /// Keypair file (used to sign the follow-up Merkle-root record).
        #[arg(long)]
        key: PathBuf,
        /// Witness storage directory.
        #[arg(long)]
        witness_storage: PathBuf,
        /// Witness keypair file.
        #[arg(long)]
        witness_key: PathBuf,
        /// Witness identifier.
        #[arg(long)]
        witness_id: String,
    },
    /// Cross-reference the witness's published view against the ledger.
    WitnessCheck {
        /// Path to the SQLite ledger file.
        #[arg(long)]
        ledger: PathBuf,
        /// Stream identifier.
        #[arg(long)]
        stream: String,
        /// Witness storage directory to compare against.
        #[arg(long)]
        witness_storage: PathBuf,
    },
    /// Generate an Annex IV export (JSON sidecar + manifest, zipped).
    ExportAnnexIv {
        /// Path to the SQLite ledger file.
        #[arg(long)]
        ledger: PathBuf,
        /// Stream identifier.
        #[arg(long)]
        stream: String,
        /// Keypair file (used to sign the manifest).
        #[arg(long)]
        key: PathBuf,
        /// Output zip path.
        #[arg(long)]
        out: PathBuf,
        /// Operator's system display name for §1 of the export.
        #[arg(long)]
        system_name: String,
        /// Annex III category identifier (e.g. `5b` for credit scoring).
        #[arg(long)]
        annex_iii_category: String,
    },
    /// Append a retention policy record. The most recent policy on a
    /// stream is the active one.
    RetentionSet {
        /// Path to the SQLite ledger file.
        #[arg(long)]
        ledger: PathBuf,
        /// Stream identifier.
        #[arg(long)]
        stream: String,
        /// Keypair file.
        #[arg(long)]
        key: PathBuf,
        /// Policy template identifier.
        #[arg(long, value_enum)]
        template: RetentionTemplate,
    },
    /// Place a legal hold on a sequence range.
    LegalHoldPlace {
        /// Path to the SQLite ledger file.
        #[arg(long)]
        ledger: PathBuf,
        /// Stream identifier.
        #[arg(long)]
        stream: String,
        /// Keypair file.
        #[arg(long)]
        key: PathBuf,
        /// Caller-meaningful hold id (e.g. a case number).
        #[arg(long)]
        hold_id: String,
        /// First sequence covered (inclusive).
        #[arg(long)]
        first_sequence: u64,
        /// Last sequence covered (inclusive). Omit for an open hold.
        #[arg(long)]
        last_sequence: Option<u64>,
        /// Opaque identifier of the actor placing the hold.
        #[arg(long)]
        placed_by: String,
    },
    /// Release a legal hold.
    LegalHoldRelease {
        /// Path to the SQLite ledger file.
        #[arg(long)]
        ledger: PathBuf,
        /// Stream identifier.
        #[arg(long)]
        stream: String,
        /// Keypair file.
        #[arg(long)]
        key: PathBuf,
        /// Hold id to release.
        #[arg(long)]
        hold_id: String,
        /// Opaque identifier of the releasing actor.
        #[arg(long)]
        released_by: String,
    },
    /// Append a tombstone marking an earlier record as redacted.
    ///
    /// The redaction is auditable: the tombstone is itself a signed
    /// record on the chain, references the target by ULID and sequence,
    /// and preserves the target's original `this_hash` so any later
    /// inspection can compare against what was originally signed.
    Redact {
        /// Path to the SQLite ledger file.
        #[arg(long)]
        ledger: PathBuf,
        /// Stream identifier.
        #[arg(long)]
        stream: String,
        /// Keypair file used to sign the tombstone.
        #[arg(long)]
        key: PathBuf,
        /// Sequence number of the record to redact.
        #[arg(long)]
        target_sequence: u64,
        /// Why the redaction is being performed.
        #[arg(long, value_enum)]
        reason: RedactReason,
        /// Opaque identifier of the actor (never a raw identity).
        #[arg(long)]
        actor: String,
    },
}

/// Reference retention-policy templates per spec §20.2.
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum RetentionTemplate {
    /// EU AI Act high-risk: 10-year retention, hot 90 d / warm 1 y / cold 9 y,
    /// no redaction outside GDPR pathway.
    EuAiActHighRisk,
    /// HIPAA: minimum 6 years retention from creation or last effective date.
    Hipaa,
    /// NYC AEDT bias-audit-relevant rolling annual.
    NycAedt,
    /// Colorado AI Act `consequential decision` retention.
    ColoradoAiAct,
    /// Generic low-risk 3 year retention default.
    Generic3y,
}

/// CLI surface form of [`glassbox_core::RedactionReason`].
#[derive(Debug, Clone, Copy, clap::ValueEnum)]
enum RedactReason {
    /// GDPR Article 17.
    GdprErasure,
    /// Retention policy required deletion after a legal hold was released.
    LegalHoldRelease,
    /// Operator-initiated under documented authority.
    OperatorRequest,
    /// Court order or regulator coercion.
    CourtOrder,
}

impl RetentionTemplate {
    fn into_policy(self) -> glassbox_core::RetentionPolicy {
        use glassbox_core::{EndOfRetentionAction, RetentionPolicy};
        match self {
            Self::EuAiActHighRisk => RetentionPolicy {
                template_id: "eu-ai-act-high-risk".into(),
                hot_days: 90,
                warm_days: 365,
                cold_days: 365 * 9,
                end_of_retention: EndOfRetentionAction::ArchiveDeepCold,
                allow_redaction: false,
                notes: Some(
                    "Annex IV + Article 18 (10y). Redaction only via GDPR Article 17 pathway."
                        .into(),
                ),
            },
            Self::Hipaa => RetentionPolicy {
                template_id: "hipaa".into(),
                hot_days: 365,
                warm_days: 365,
                cold_days: 365 * 5,
                end_of_retention: EndOfRetentionAction::ArchiveDeepCold,
                allow_redaction: true,
                notes: Some("45 CFR 164.316(b)(2)(i): six years minimum.".into()),
            },
            Self::NycAedt => RetentionPolicy {
                template_id: "nyc-aedt".into(),
                hot_days: 90,
                warm_days: 365,
                cold_days: 0,
                end_of_retention: EndOfRetentionAction::DeleteWithProof,
                allow_redaction: false,
                notes: Some("Local Law 144 §5-303: bias-audit-relevant rolling annual.".into()),
            },
            Self::ColoradoAiAct => RetentionPolicy {
                template_id: "colorado-ai-act".into(),
                hot_days: 90,
                warm_days: 365 * 2,
                cold_days: 365 * 4,
                end_of_retention: EndOfRetentionAction::ArchiveDeepCold,
                allow_redaction: false,
                notes: Some("Colorado SB24-205 consequential-decision retention.".into()),
            },
            Self::Generic3y => RetentionPolicy {
                template_id: "generic-3-year".into(),
                hot_days: 30,
                warm_days: 90,
                cold_days: 365 * 3 - 120,
                end_of_retention: EndOfRetentionAction::DeleteWithProof,
                allow_redaction: true,
                notes: None,
            },
        }
    }
}

impl From<RedactReason> for glassbox_core::RedactionReason {
    fn from(v: RedactReason) -> Self {
        match v {
            RedactReason::GdprErasure => Self::GdprErasure,
            RedactReason::LegalHoldRelease => Self::LegalHoldRelease,
            RedactReason::OperatorRequest => Self::OperatorRequest,
            RedactReason::CourtOrder => Self::CourtOrder,
        }
    }
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match dispatch(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("glassbox: {e}");
            ExitCode::from(1)
        }
    }
}

fn dispatch(cli: Cli) -> Result<(), commands::CliError> {
    match cli.command {
        Command::Keygen { out } => commands::keygen(&out),
        Command::Init {
            ledger,
            tenant,
            system,
            key,
            key_id,
        } => commands::init(&ledger, &tenant, &system, &key, key_id),
        Command::Append {
            ledger,
            stream,
            key,
            key_id,
            body,
        } => commands::append(&ledger, &stream, &key, key_id, &body),
        Command::Show {
            ledger,
            stream,
            sequence,
        } => commands::show(&ledger, &stream, sequence),
        Command::Verify { ledger, stream } => commands::verify(&ledger, &stream),
        Command::MerkleCommit {
            ledger,
            stream,
            key,
            key_id,
        } => commands::merkle_commit(&ledger, &stream, &key, key_id),
        Command::KeyRotate {
            ledger,
            stream,
            current_key,
            new_key,
            new_key_id,
        } => commands::key_rotate(&ledger, &stream, &current_key, &new_key, new_key_id),
        Command::Streams { ledger } => commands::streams(&ledger),
        Command::Redact {
            ledger,
            stream,
            key,
            target_sequence,
            reason,
            actor,
        } => commands::redact(
            &ledger,
            &stream,
            &key,
            target_sequence,
            reason.into(),
            &actor,
        ),
        Command::WitnessPublish {
            ledger,
            stream,
            key,
            witness_storage,
            witness_key,
            witness_id,
        } => commands::witness_publish(
            &ledger,
            &stream,
            &key,
            &witness_storage,
            &witness_key,
            &witness_id,
        ),
        Command::WitnessCheck {
            ledger,
            stream,
            witness_storage,
        } => commands::witness_check(&ledger, &stream, &witness_storage),
        Command::ExportAnnexIv {
            ledger,
            stream,
            key,
            out,
            system_name,
            annex_iii_category,
        } => commands::export_annex_iv(
            &ledger,
            &stream,
            &key,
            &out,
            &system_name,
            &annex_iii_category,
        ),
        Command::RetentionSet {
            ledger,
            stream,
            key,
            template,
        } => commands::retention_set(&ledger, &stream, &key, template.into_policy()),
        Command::LegalHoldPlace {
            ledger,
            stream,
            key,
            hold_id,
            first_sequence,
            last_sequence,
            placed_by,
        } => commands::legal_hold_place(
            &ledger,
            &stream,
            &key,
            &hold_id,
            first_sequence,
            last_sequence,
            &placed_by,
        ),
        Command::LegalHoldRelease {
            ledger,
            stream,
            key,
            hold_id,
            released_by,
        } => commands::legal_hold_release(&ledger, &stream, &key, &hold_id, &released_by),
    }
}
