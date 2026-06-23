//! Subcommand implementations for the `glassbox` binary.

use std::fs;
use std::io::Write as _;
use std::path::Path;

use thiserror::Error;
use time::OffsetDateTime;
use ulid::Ulid;

use glassbox_core::SCHEMA_VERSION;
use glassbox_core::chain::sign_record;
use glassbox_core::crypto::HybridKeypair;
use glassbox_core::key_registry::{KeyRegistryEntry, KeyStatus};
use glassbox_core::record::{
    InteractionBody, LegalHold, LegalHoldRelease, MerkleRootEntry, Record, RecordBody,
    RedactionReason, RedactionRecord, RetentionPolicy, SignedRecord, SignedTreeHead,
    WitnessCountersignature,
};
use glassbox_storage::Backend;
use glassbox_storage::sqlite::SqliteBackend;
use glassbox_witness::WitnessServer;

/// SDK identifier emitted on every record this CLI writes.
const SOURCE_SDK: &str = concat!("glassbox-cli/", env!("CARGO_PKG_VERSION"));

/// Errors surfaced by the CLI layer.
#[derive(Debug, Error)]
pub(crate) enum CliError {
    /// I/O.
    #[error("i/o error: {0}")]
    Io(String),
    /// Storage layer error.
    #[error(transparent)]
    Storage(#[from] glassbox_storage::StorageError),
    /// Core layer error.
    #[error(transparent)]
    Core(#[from] glassbox_core::Error),
    /// JSON shape error from the user-supplied body file.
    #[error("invalid body file: {0}")]
    Body(String),
    /// Refusing to overwrite an existing file.
    #[error("refusing to overwrite existing file: {0}")]
    Exists(String),
    /// User-error / lookup failure.
    #[error("{0}")]
    Other(String),
}

fn io<E: std::fmt::Display>(e: E) -> CliError {
    CliError::Io(e.to_string())
}

/// `glassbox keygen --out <path>`
pub(crate) fn keygen(out: &Path) -> Result<(), CliError> {
    if out.exists() {
        return Err(CliError::Exists(out.display().to_string()));
    }
    let kp = HybridKeypair::generate()?;
    let bytes = kp.to_bytes();
    write_key_file(out, &bytes)?;
    println!("wrote keypair to {}", out.display());
    Ok(())
}

fn write_key_file(out: &Path, bytes: &[u8; 64]) -> Result<(), CliError> {
    let mut file = open_create_secret(out)?;
    file.write_all(b"glassbox-hybrid-v1\n").map_err(io)?;
    file.write_all(hex::encode(bytes).as_bytes()).map_err(io)?;
    file.write_all(b"\n").map_err(io)?;
    Ok(())
}

#[cfg(unix)]
fn open_create_secret(out: &Path) -> Result<fs::File, CliError> {
    use std::os::unix::fs::OpenOptionsExt;
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(out)
        .map_err(io)
}

#[cfg(not(unix))]
fn open_create_secret(out: &Path) -> Result<fs::File, CliError> {
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(out)
        .map_err(io)
}

fn read_keypair(path: &Path) -> Result<HybridKeypair, CliError> {
    let text = fs::read_to_string(path).map_err(io)?;
    let mut lines = text.lines();
    let header = lines.next().unwrap_or_default();
    if header.trim() != "glassbox-hybrid-v1" {
        return Err(CliError::Other(format!(
            "{} is not a glassbox-hybrid-v1 keypair file",
            path.display()
        )));
    }
    let hex = lines.next().unwrap_or_default().trim();
    let bytes = hex::decode(hex).map_err(|e| {
        CliError::Other(format!("malformed keypair body in {}: {e}", path.display()))
    })?;
    let bytes: [u8; 64] = bytes
        .try_into()
        .map_err(|_| CliError::Other("keypair body is not 64 bytes".into()))?;
    Ok(HybridKeypair::from_bytes(&bytes))
}

fn open_ledger(path: &Path) -> Result<SqliteBackend, CliError> {
    Ok(SqliteBackend::open(path)?)
}

fn now() -> OffsetDateTime {
    OffsetDateTime::now_utc()
}

fn parse_stream(stream: &str) -> Result<(&str, &str), CliError> {
    let Some((tenant, system)) = stream.split_once('/') else {
        return Err(CliError::Other(format!(
            "stream must be `<tenant>/<system>`, got `{stream}`"
        )));
    };
    if tenant.is_empty() || system.is_empty() || system.contains('/') {
        return Err(CliError::Other(format!(
            "stream must be `<tenant>/<system>`, got `{stream}`"
        )));
    }
    Ok((tenant, system))
}

fn lookup_active_key_id<B: Backend + ?Sized>(
    backend: &B,
    stream: &str,
) -> Result<String, CliError> {
    let chain = backend.iter_stream(stream)?;
    let mut active: Option<&str> = None;
    for sr in &chain {
        if let RecordBody::KeyRegistry(entry) = &sr.record.body {
            if matches!(entry.status, KeyStatus::Active) {
                active = Some(entry.key_id.as_str());
            }
        }
    }
    active
        .map(str::to_string)
        .ok_or_else(|| CliError::Other(format!("no active key registered on stream `{stream}`")))
}

fn current_prev_and_seq<B: Backend + ?Sized>(
    backend: &B,
    stream: &str,
) -> Result<([u8; 32], u64), CliError> {
    match backend.last(stream)? {
        Some(last) => {
            let prev: [u8; 32] = hex::decode(&last.this_hash_hex)
                .map_err(|e| CliError::Other(e.to_string()))?
                .try_into()
                .map_err(|_| CliError::Other("stored this_hash_hex was not 32 bytes".into()))?;
            Ok((prev, last.record.sequence + 1))
        }
        None => Ok(([0u8; 32], 0)),
    }
}

/// `glassbox init`
pub(crate) fn init(
    ledger: &Path,
    tenant: &str,
    system: &str,
    key: &Path,
    key_id: Option<String>,
) -> Result<(), CliError> {
    if tenant.contains('/') {
        return Err(CliError::Other("tenant id may not contain `/`".to_string()));
    }
    if system.contains('/') {
        return Err(CliError::Other("system id may not contain `/`".to_string()));
    }
    let kp = read_keypair(key)?;
    let mut backend = open_ledger(ledger)?;
    let stream_id = format!("{tenant}/{system}");
    if !backend.iter_stream(&stream_id)?.is_empty() {
        return Err(CliError::Other(format!(
            "stream `{stream_id}` already initialised"
        )));
    }
    let key_id = key_id.unwrap_or_else(|| format!("{tenant}-active"));
    let entry = KeyRegistryEntry {
        key_id: key_id.clone(),
        algorithm: glassbox_core::ALGORITHM_HYBRID_ED25519_MLDSA65.into(),
        public_key: kp.public_key(),
        valid_from: now(),
        valid_to: None,
        status: KeyStatus::Active,
    };
    let r = Record {
        record_id: Ulid::new(),
        stream_id: stream_id.clone(),
        sequence: 0,
        occurred_at: now(),
        received_at: now(),
        schema_version: SCHEMA_VERSION.into(),
        source_sdk: SOURCE_SDK.into(),
        key_id,
        prev_hash_hex: hex::encode([0u8; 32]),
        body: RecordBody::KeyRegistry(entry),
    };
    let sr = sign_record(r, &kp)?;
    backend.append(sr)?;
    println!("initialised stream `{stream_id}` in {}", ledger.display());
    Ok(())
}

/// `glassbox append`
pub(crate) fn append(
    ledger: &Path,
    stream: &str,
    key: &Path,
    key_id: Option<String>,
    body: &Path,
) -> Result<(), CliError> {
    parse_stream(stream)?;
    let kp = read_keypair(key)?;
    let mut backend = open_ledger(ledger)?;

    let key_id = match key_id {
        Some(k) => k,
        None => lookup_active_key_id(&backend, stream)?,
    };
    let (prev, seq) = current_prev_and_seq(&backend, stream)?;
    if seq == 0 {
        return Err(CliError::Other(format!(
            "stream `{stream}` is empty; run `glassbox init` first"
        )));
    }

    let body_bytes = fs::read(body).map_err(io)?;
    let body_value: InteractionBody = serde_json::from_slice(&body_bytes)
        .map_err(|e| CliError::Body(format!("{}: {e}", body.display())))?;

    let r = glassbox_core::record::make_interaction(
        stream,
        seq,
        now(),
        now(),
        prev,
        key_id,
        SOURCE_SDK,
        body_value,
    )?;
    let sr = sign_record(r, &kp)?;
    let json = serde_json::to_string_pretty(&sr).map_err(|e| CliError::Body(e.to_string()))?;
    backend.append(sr)?;
    println!("appended sequence {seq} on `{stream}`");
    println!("{json}");
    Ok(())
}

/// `glassbox show`
pub(crate) fn show(ledger: &Path, stream: &str, sequence: u64) -> Result<(), CliError> {
    parse_stream(stream)?;
    let backend = open_ledger(ledger)?;
    match backend.get(stream, sequence)? {
        Some(sr) => {
            let json =
                serde_json::to_string_pretty(&sr).map_err(|e| CliError::Body(e.to_string()))?;
            println!("{json}");
            Ok(())
        }
        None => Err(CliError::Other(format!(
            "no record at sequence {sequence} on `{stream}`"
        ))),
    }
}

/// `glassbox verify`
pub(crate) fn verify(ledger: &Path, stream: &str) -> Result<(), CliError> {
    parse_stream(stream)?;
    let backend = open_ledger(ledger)?;
    match glassbox_storage::verify_stream(&backend, stream) {
        Ok(report) if report.is_ok() => {
            println!(
                "OK  stream={stream}  records={}  signatures={}  merkle_roots={}",
                report.records_walked, report.signatures_verified, report.merkle_roots_checked
            );
            Ok(())
        }
        Ok(report) => {
            let fail = report.failure.expect("non-ok report implies failure");
            Err(CliError::Other(format!(
                "verification FAILED on stream {stream} at sequence {}: {}",
                fail.sequence, fail.reason
            )))
        }
        Err(glassbox_storage::StorageError::Core(core_err)) => Err(CliError::Other(format!(
            "verification FAILED on stream {stream}: {core_err}"
        ))),
        Err(other) => Err(other.into()),
    }
}

/// `glassbox merkle-commit`
pub(crate) fn merkle_commit(
    ledger: &Path,
    stream: &str,
    key: &Path,
    key_id: Option<String>,
) -> Result<(), CliError> {
    parse_stream(stream)?;
    let kp = read_keypair(key)?;
    let mut backend = open_ledger(ledger)?;
    let chain = backend.iter_stream(stream)?;
    if chain.is_empty() {
        return Err(CliError::Other(format!("stream `{stream}` is empty")));
    }
    let key_id = match key_id {
        Some(k) => k,
        None => lookup_active_key_id(&backend, stream)?,
    };

    let (accumulated, first, last) = uncommitted_batch(&chain);
    if accumulated.is_empty() {
        return Err(CliError::Other(
            "no uncommitted records since the last merkle_root".to_string(),
        ));
    }
    let root = glassbox_core::merkle::compute_root(&accumulated)?;
    let last_record = chain.last().expect("non-empty chain");
    let prev: [u8; 32] = hex::decode(&last_record.this_hash_hex)
        .map_err(|e| CliError::Other(e.to_string()))?
        .try_into()
        .map_err(|_| CliError::Other("stored this_hash_hex was not 32 bytes".into()))?;
    let entry = MerkleRootEntry {
        first_sequence: first,
        last_sequence: last,
        root_hash_hex: hex::encode(root),
        ..Default::default()
    };
    let r = Record {
        record_id: Ulid::new(),
        stream_id: stream.into(),
        sequence: last_record.record.sequence + 1,
        occurred_at: now(),
        received_at: now(),
        schema_version: SCHEMA_VERSION.into(),
        source_sdk: SOURCE_SDK.into(),
        key_id,
        prev_hash_hex: hex::encode(prev),
        body: RecordBody::MerkleRoot(entry),
    };
    let sr = sign_record(r, &kp)?;
    backend.append(sr)?;
    println!(
        "committed merkle root [{first}..={last}] root={}",
        hex::encode(root)
    );
    Ok(())
}

fn uncommitted_batch(chain: &[SignedRecord]) -> (Vec<[u8; 32]>, u64, u64) {
    let mut accumulated: Vec<[u8; 32]> = Vec::new();
    let mut first: Option<u64> = None;
    let mut last: u64 = 0;
    for sr in chain {
        match &sr.record.body {
            RecordBody::MerkleRoot(_) => {
                accumulated.clear();
                first = None;
                last = 0;
            }
            _ => {
                if first.is_none() {
                    first = Some(sr.record.sequence);
                }
                last = sr.record.sequence;
                let h: [u8; 32] = hex::decode(&sr.this_hash_hex)
                    .expect("valid hex from storage")
                    .try_into()
                    .expect("32 bytes");
                accumulated.push(h);
            }
        }
    }
    (accumulated, first.unwrap_or(0), last)
}

/// `glassbox key-rotate`
pub(crate) fn key_rotate(
    ledger: &Path,
    stream: &str,
    current_key: &Path,
    new_key: &Path,
    new_key_id: Option<String>,
) -> Result<(), CliError> {
    parse_stream(stream)?;
    let current = read_keypair(current_key)?;
    let new = read_keypair(new_key)?;
    let mut backend = open_ledger(ledger)?;

    let chain = backend.iter_stream(stream)?;
    let Some(last) = chain.last() else {
        return Err(CliError::Other(format!(
            "stream `{stream}` is empty; nothing to rotate"
        )));
    };
    let current_key_id = lookup_active_key_id(&backend, stream)?;
    let new_key_id = new_key_id.unwrap_or_else(|| format!("rotated-{}", last.record.sequence + 1));
    if new_key_id == current_key_id {
        return Err(CliError::Other(format!(
            "new key_id {new_key_id} collides with current active key_id"
        )));
    }
    let prev: [u8; 32] = hex::decode(&last.this_hash_hex)
        .map_err(|e| CliError::Other(e.to_string()))?
        .try_into()
        .map_err(|_| CliError::Other("stored this_hash_hex was not 32 bytes".into()))?;
    let entry = KeyRegistryEntry {
        key_id: new_key_id.clone(),
        algorithm: glassbox_core::ALGORITHM_HYBRID_ED25519_MLDSA65.into(),
        public_key: new.public_key(),
        valid_from: now(),
        valid_to: None,
        status: KeyStatus::Active,
    };
    let r = Record {
        record_id: Ulid::new(),
        stream_id: stream.into(),
        sequence: last.record.sequence + 1,
        occurred_at: now(),
        received_at: now(),
        schema_version: SCHEMA_VERSION.into(),
        source_sdk: SOURCE_SDK.into(),
        key_id: current_key_id.clone(),
        prev_hash_hex: hex::encode(prev),
        body: RecordBody::KeyRegistry(entry),
    };
    let sr = sign_record(r, &current)?;
    backend.append(sr)?;
    println!("rotated `{current_key_id}` -> `{new_key_id}` on `{stream}`");
    Ok(())
}

/// `glassbox streams`
pub(crate) fn streams(ledger: &Path) -> Result<(), CliError> {
    let backend = open_ledger(ledger)?;
    for s in backend.list_streams()? {
        println!("{s}");
    }
    Ok(())
}

/// `glassbox retention set`
pub(crate) fn retention_set(
    ledger: &Path,
    stream: &str,
    key: &Path,
    policy: RetentionPolicy,
) -> Result<(), CliError> {
    parse_stream(stream)?;
    let kp = read_keypair(key)?;
    let mut backend = open_ledger(ledger)?;
    let key_id = lookup_active_key_id(&backend, stream)?;
    let (prev, seq) = current_prev_and_seq(&backend, stream)?;
    let r = Record {
        record_id: Ulid::new(),
        stream_id: stream.into(),
        sequence: seq,
        occurred_at: now(),
        received_at: now(),
        schema_version: SCHEMA_VERSION.into(),
        source_sdk: SOURCE_SDK.into(),
        key_id,
        prev_hash_hex: hex::encode(prev),
        body: RecordBody::RetentionPolicy(policy.clone()),
    };
    let sr = sign_record(r, &kp)?;
    backend.append(sr)?;
    println!(
        "set retention policy `{}` on `{stream}` (hot={}d warm={}d cold={}d)",
        policy.template_id, policy.hot_days, policy.warm_days, policy.cold_days
    );
    Ok(())
}

/// `glassbox legal-hold place`
pub(crate) fn legal_hold_place(
    ledger: &Path,
    stream: &str,
    key: &Path,
    hold_id: &str,
    first_sequence: u64,
    last_sequence: Option<u64>,
    placed_by: &str,
) -> Result<(), CliError> {
    parse_stream(stream)?;
    if hold_id.is_empty() {
        return Err(CliError::Other("--hold-id must be non-empty".into()));
    }
    if placed_by.is_empty() {
        return Err(CliError::Other("--placed-by must be non-empty".into()));
    }
    if let Some(last) = last_sequence {
        if last < first_sequence {
            return Err(CliError::Other(format!(
                "--last-sequence ({last}) must be >= --first-sequence ({first_sequence})"
            )));
        }
    }
    let kp = read_keypair(key)?;
    let mut backend = open_ledger(ledger)?;
    if open_hold_with_id(&backend, stream, hold_id)?.is_some() {
        return Err(CliError::Other(format!(
            "hold `{hold_id}` is already open on `{stream}`"
        )));
    }
    let key_id = lookup_active_key_id(&backend, stream)?;
    let (prev, seq) = current_prev_and_seq(&backend, stream)?;
    let hold = LegalHold {
        hold_id: hold_id.into(),
        first_sequence,
        last_sequence,
        placed_by: placed_by.into(),
        rationale_hash_hex: None,
    };
    let r = Record {
        record_id: Ulid::new(),
        stream_id: stream.into(),
        sequence: seq,
        occurred_at: now(),
        received_at: now(),
        schema_version: SCHEMA_VERSION.into(),
        source_sdk: SOURCE_SDK.into(),
        key_id,
        prev_hash_hex: hex::encode(prev),
        body: RecordBody::LegalHold(hold),
    };
    let sr = sign_record(r, &kp)?;
    backend.append(sr)?;
    println!("placed legal hold `{hold_id}` on `{stream}`");
    Ok(())
}

/// `glassbox legal-hold release`
pub(crate) fn legal_hold_release(
    ledger: &Path,
    stream: &str,
    key: &Path,
    hold_id: &str,
    released_by: &str,
) -> Result<(), CliError> {
    parse_stream(stream)?;
    if hold_id.is_empty() {
        return Err(CliError::Other("--hold-id must be non-empty".into()));
    }
    if released_by.is_empty() {
        return Err(CliError::Other("--released-by must be non-empty".into()));
    }
    let kp = read_keypair(key)?;
    let mut backend = open_ledger(ledger)?;
    if open_hold_with_id(&backend, stream, hold_id)?.is_none() {
        return Err(CliError::Other(format!(
            "no open hold `{hold_id}` on `{stream}` to release"
        )));
    }
    let key_id = lookup_active_key_id(&backend, stream)?;
    let (prev, seq) = current_prev_and_seq(&backend, stream)?;
    let release = LegalHoldRelease {
        hold_id: hold_id.into(),
        released_by: released_by.into(),
        rationale_hash_hex: None,
    };
    let r = Record {
        record_id: Ulid::new(),
        stream_id: stream.into(),
        sequence: seq,
        occurred_at: now(),
        received_at: now(),
        schema_version: SCHEMA_VERSION.into(),
        source_sdk: SOURCE_SDK.into(),
        key_id,
        prev_hash_hex: hex::encode(prev),
        body: RecordBody::LegalHoldRelease(release),
    };
    let sr = sign_record(r, &kp)?;
    backend.append(sr)?;
    println!("released legal hold `{hold_id}` on `{stream}`");
    Ok(())
}

fn open_hold_with_id<B: Backend + ?Sized>(
    backend: &B,
    stream: &str,
    hold_id: &str,
) -> Result<Option<LegalHold>, CliError> {
    let chain = backend.iter_stream(stream)?;
    let mut current: Option<LegalHold> = None;
    for sr in chain {
        match sr.record.body {
            RecordBody::LegalHold(h) if h.hold_id == hold_id => current = Some(h),
            RecordBody::LegalHoldRelease(r) if r.hold_id == hold_id => current = None,
            _ => {}
        }
    }
    Ok(current)
}

/// `glassbox witness publish` — emit an STH file, hand it to a
/// configured witness storage directory, collect the counter-signature,
/// and append a new `merkle_root` record that includes both the new
/// root over the most recent batch and the counter-signature from
/// the witness.
pub(crate) fn witness_publish(
    ledger: &Path,
    stream: &str,
    key: &Path,
    witness_storage: &Path,
    witness_key: &Path,
    witness_id: &str,
) -> Result<(), CliError> {
    parse_stream(stream)?;
    let kp = read_keypair(key)?;
    let witness_kp = read_keypair(witness_key)?;
    let mut backend = open_ledger(ledger)?;
    let chain = backend.iter_stream(stream)?;
    if chain.is_empty() {
        return Err(CliError::Other(format!("stream `{stream}` is empty")));
    }

    let key_id = lookup_active_key_id(&backend, stream)?;
    let (accumulated, first, last) = uncommitted_batch_with_hashes(&chain);
    if accumulated.is_empty() {
        return Err(CliError::Other(
            "no uncommitted records since the last merkle_root".into(),
        ));
    }
    let root = glassbox_core::merkle::compute_root(&accumulated)?;
    let last_record = chain.last().expect("non-empty chain");
    let prev: [u8; 32] = hex::decode(&last_record.this_hash_hex)
        .map_err(|e| CliError::Other(e.to_string()))?
        .try_into()
        .map_err(|_| CliError::Other("stored this_hash_hex was not 32 bytes".into()))?;

    let sth = SignedTreeHead {
        stream_id: stream.into(),
        first_sequence: first,
        last_sequence: last,
        root_hash_hex: hex::encode(root),
        // Compute the root-record's `this_hash` deterministically by
        // sealing the entry without witness signatures first.
        root_record_this_hash_hex: String::new(),
    };

    let mut witness = WitnessServer::new(witness_id, witness_kp, witness_storage)
        .map_err(|e| CliError::Other(e.to_string()))?;
    let countersignature: WitnessCountersignature = witness
        .observe(sth.clone())
        .map_err(|e| CliError::Other(e.to_string()))?;

    let entry = MerkleRootEntry {
        first_sequence: first,
        last_sequence: last,
        root_hash_hex: hex::encode(root),
        timestamp_anchors: Vec::new(),
        witness_signatures: vec![countersignature.clone()],
    };
    let r = Record {
        record_id: Ulid::new(),
        stream_id: stream.into(),
        sequence: last_record.record.sequence + 1,
        occurred_at: now(),
        received_at: now(),
        schema_version: SCHEMA_VERSION.into(),
        source_sdk: SOURCE_SDK.into(),
        key_id,
        prev_hash_hex: hex::encode(prev),
        body: RecordBody::MerkleRoot(entry),
    };
    let sr = sign_record(r, &kp)?;
    backend.append(sr)?;
    println!(
        "published root [{first}..={last}] {} witnessed by `{witness_id}`",
        hex::encode(root)
    );
    Ok(())
}

/// `glassbox witness check` — re-check every witness counter-signature
/// stored in the ledger against the witness's published observation
/// log on disk.
pub(crate) fn witness_check(
    ledger: &Path,
    stream: &str,
    witness_storage: &Path,
) -> Result<(), CliError> {
    parse_stream(stream)?;
    let backend = open_ledger(ledger)?;
    let chain = backend.iter_stream(stream)?;
    let mut checked = 0u64;
    let mut warnings = 0u64;
    for sr in &chain {
        if let RecordBody::MerkleRoot(entry) = &sr.record.body {
            for cs in &entry.witness_signatures {
                // Reconstruct the STH the witness signed.
                let sth = SignedTreeHead {
                    stream_id: sr.record.stream_id.clone(),
                    first_sequence: entry.first_sequence,
                    last_sequence: entry.last_sequence,
                    root_hash_hex: entry.root_hash_hex.clone(),
                    root_record_this_hash_hex: String::new(),
                };
                glassbox_witness::verify_countersignature(&sth, cs)
                    .map_err(|e| CliError::Other(e.to_string()))?;
                checked += 1;

                // Cross-reference with the witness's observation log
                // (best effort — if the witness lives elsewhere this
                // surfaces a warning rather than failing the check).
                let dir = witness_storage.join(cs.witness_id.as_str());
                let log_dir = if dir.exists() {
                    dir
                } else {
                    witness_storage.to_path_buf()
                };
                let view = match glassbox_witness::WitnessServer::new(
                    cs.witness_id.clone(),
                    glassbox_core::crypto::HybridKeypair::generate()?, // unused; observe API needs a kp
                    &log_dir,
                ) {
                    Ok(srv) => srv
                        .observations(&sr.record.stream_id)
                        .map_err(|e| CliError::Other(e.to_string()))?,
                    Err(_) => Vec::new(),
                };
                let hit = view
                    .iter()
                    .any(|obs| obs.sth.root_hash_hex == entry.root_hash_hex);
                if !hit {
                    eprintln!(
                        "warning: witness `{}` has no recorded observation of root {} in {}",
                        cs.witness_id,
                        entry.root_hash_hex,
                        log_dir.display()
                    );
                    warnings += 1;
                }
            }
        }
    }
    println!("checked {checked} witness counter-signatures on `{stream}`; {warnings} warnings");
    Ok(())
}

/// `glassbox export annex-iv`
pub(crate) fn export_annex_iv(
    ledger: &Path,
    stream: &str,
    key: &Path,
    out: &Path,
    system_name: &str,
    annex_iii_category: &str,
) -> Result<(), CliError> {
    parse_stream(stream)?;
    let kp = read_keypair(key)?;
    let backend = open_ledger(ledger)?;
    let chain = backend.iter_stream(stream)?;
    if chain.is_empty() {
        return Err(CliError::Other(format!("stream `{stream}` is empty")));
    }
    let key_id = lookup_active_key_id(&backend, stream)?;
    let req = glassbox_export::ExportRequest {
        system_name: system_name.into(),
        annex_iii_category: annex_iii_category.into(),
        period_from: None,
        period_to: None,
    };
    if out.exists() {
        return Err(CliError::Exists(out.display().to_string()));
    }
    let f = std::fs::File::create(out).map_err(io)?;
    glassbox_export::write_zip(f, stream, &chain, &req, &key_id, &kp)
        .map_err(|e| CliError::Other(e.to_string()))?;
    println!("wrote Annex IV export to {}", out.display());
    Ok(())
}

fn uncommitted_batch_with_hashes(chain: &[SignedRecord]) -> (Vec<[u8; 32]>, u64, u64) {
    let mut accumulated: Vec<[u8; 32]> = Vec::new();
    let mut first: Option<u64> = None;
    let mut last: u64 = 0;
    for sr in chain {
        match &sr.record.body {
            RecordBody::MerkleRoot(_) => {
                accumulated.clear();
                first = None;
                last = 0;
            }
            _ => {
                if first.is_none() {
                    first = Some(sr.record.sequence);
                }
                last = sr.record.sequence;
                let h: [u8; 32] = hex::decode(&sr.this_hash_hex)
                    .expect("valid hex from storage")
                    .try_into()
                    .expect("32 bytes");
                accumulated.push(h);
            }
        }
    }
    (accumulated, first.unwrap_or(0), last)
}

/// `glassbox redact`
pub(crate) fn redact(
    ledger: &Path,
    stream: &str,
    key: &Path,
    target_sequence: u64,
    reason: RedactionReason,
    actor: &str,
) -> Result<(), CliError> {
    parse_stream(stream)?;
    if actor.is_empty() {
        return Err(CliError::Other("--actor must be non-empty".into()));
    }
    let kp = read_keypair(key)?;
    let mut backend = open_ledger(ledger)?;
    let target: SignedRecord = backend.get(stream, target_sequence)?.ok_or_else(|| {
        CliError::Other(format!(
            "no record at sequence {target_sequence} on `{stream}` to redact"
        ))
    })?;
    if matches!(target.record.body, RecordBody::Tombstone(_)) {
        return Err(CliError::Other(format!(
            "sequence {target_sequence} is itself a tombstone; refusing to redact a tombstone"
        )));
    }
    let key_id = lookup_active_key_id(&backend, stream)?;
    let (prev, seq) = current_prev_and_seq(&backend, stream)?;
    let redaction = RedactionRecord {
        target_record_id: target.record.record_id,
        target_sequence,
        original_this_hash_hex: target.this_hash_hex.clone(),
        reason,
        actor_id: actor.into(),
        rationale_hash_hex: None,
    };
    let r = Record {
        record_id: Ulid::new(),
        stream_id: stream.into(),
        sequence: seq,
        occurred_at: now(),
        received_at: now(),
        schema_version: SCHEMA_VERSION.into(),
        source_sdk: SOURCE_SDK.into(),
        key_id,
        prev_hash_hex: hex::encode(prev),
        body: RecordBody::Tombstone(redaction),
    };
    let sr = sign_record(r, &kp)?;
    backend.append(sr)?;
    println!("redacted sequence {target_sequence} on `{stream}` via tombstone at sequence {seq}");
    Ok(())
}
