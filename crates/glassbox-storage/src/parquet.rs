//! Parquet cold-tier backend (spec §14.1, §14.5).
//!
//! v0.5 ships the **read** side of cold tier and the **export** writer.
//! Layout: one Parquet file per `<tenant>__<system>.parquet` under the
//! configured directory. Each row stores one [`SignedRecord`]'s JSON
//! plus the indexed projections (`stream_id`, `sequence`,
//! `this_hash_hex`, `prev_hash_hex`, `record_id`).
//!
//! ## What's intentionally not here in v0.5
//!
//! - **Per-month partitioning** (`year=YYYY/month=MM/`). Single-file
//!   per stream is sufficient up to ~10^7 records on commodity disk;
//!   the partition scheme is a v0.6 extension on the same writer.
//! - **Compression policy**: we use Snappy because it's the default
//!   feature of the `parquet` crate; spec §14.5 prefers ZSTD level 9
//!   which is enabled by adding the `zstd` feature on the crate side.
//! - **Manifest as administrative-stream record**. The manifest exists
//!   as a side-channel JSON file (`<stream>.manifest.json`) in the
//!   same directory; folding it into the administrative stream is a
//!   migration step in v0.6 alongside the §11.1 separation of admin
//!   records onto their own stream.
//!
//! The [`ColdTierBackend`] is **read-only**; appends always go through
//! a hot-tier backend. The [`migrate_to_parquet`] function snapshots a
//! hot-tier stream to a cold-tier Parquet file.

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use arrow_array::{Int64Array, RecordBatch, StringArray, builder::StringBuilder};
use arrow_schema::{DataType, Field, Schema, SchemaRef};
use parquet::arrow::ArrowWriter;
use parquet::arrow::arrow_reader::ParquetRecordBatchReaderBuilder;
use parquet::basic::Compression;
use parquet::file::properties::WriterProperties;

use glassbox_core::record::SignedRecord;

use crate::{Backend, Result, StorageError};

/// Read-only Parquet-backed Backend implementation.
pub struct ColdTierBackend {
    root: PathBuf,
}

impl ColdTierBackend {
    /// Open a cold tier rooted at `dir`. The directory must exist.
    pub fn open(dir: impl AsRef<Path>) -> Result<Self> {
        let root = dir.as_ref().to_path_buf();
        if !root.is_dir() {
            return Err(StorageError::Io(format!(
                "cold-tier root {} is not a directory",
                root.display()
            )));
        }
        Ok(Self { root })
    }

    fn parquet_path_for(&self, stream_id: &str) -> PathBuf {
        let safe = stream_id.replace('/', "__");
        self.root.join(format!("{safe}.parquet"))
    }

    fn manifest_path_for(&self, stream_id: &str) -> PathBuf {
        let safe = stream_id.replace('/', "__");
        self.root.join(format!("{safe}.manifest.json"))
    }

    fn read_stream_rows(&self, stream_id: &str) -> Result<Vec<SignedRecord>> {
        let path = self.parquet_path_for(stream_id);
        if !path.exists() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(&path).map_err(io)?;
        let builder = ParquetRecordBatchReaderBuilder::try_new(file)
            .map_err(|e| StorageError::Io(format!("parquet open: {e}")))?;
        let reader = builder
            .build()
            .map_err(|e| StorageError::Io(format!("parquet reader: {e}")))?;
        let mut out: Vec<SignedRecord> = Vec::new();
        for batch in reader {
            let batch = batch.map_err(|e| StorageError::Io(format!("parquet batch: {e}")))?;
            let payload = batch
                .column_by_name("payload_json")
                .ok_or_else(|| StorageError::Io("missing column `payload_json`".into()))?
                .as_any()
                .downcast_ref::<StringArray>()
                .ok_or_else(|| StorageError::Io("payload_json is not Utf8".into()))?;
            for i in 0..batch.num_rows() {
                let s = payload.value(i);
                let sr: SignedRecord = serde_json::from_str(s)
                    .map_err(|e| StorageError::Serde(format!("parquet row {i}: {e}")))?;
                out.push(sr);
            }
        }
        out.sort_by_key(|sr| sr.record.sequence);
        Ok(out)
    }
}

fn io<E: std::fmt::Display>(e: E) -> StorageError {
    StorageError::Io(e.to_string())
}

impl Backend for ColdTierBackend {
    fn append(&mut self, _record: SignedRecord) -> Result<()> {
        Err(StorageError::Io(
            "ColdTierBackend is read-only; use migrate_to_parquet to populate it".into(),
        ))
    }

    fn last(&self, stream_id: &str) -> Result<Option<SignedRecord>> {
        Ok(self.read_stream_rows(stream_id)?.into_iter().next_back())
    }

    fn get(&self, stream_id: &str, sequence: u64) -> Result<Option<SignedRecord>> {
        Ok(self
            .read_stream_rows(stream_id)?
            .into_iter()
            .find(|sr| sr.record.sequence == sequence))
    }

    fn iter_stream(&self, stream_id: &str) -> Result<Vec<SignedRecord>> {
        self.read_stream_rows(stream_id)
    }

    fn list_streams(&self) -> Result<Vec<String>> {
        let mut out: Vec<String> = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(io)? {
            let entry = entry.map_err(io)?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "parquet") {
                if let Some(stem) = path.file_stem().and_then(|s| s.to_str()) {
                    out.push(stem.replace("__", "/"));
                }
            }
        }
        out.sort();
        Ok(out)
    }
}

/// Take a snapshot of `stream_id` from `hot` and write it as a Parquet
/// file under the cold-tier directory. Existing rows for the stream
/// are overwritten — the writer is single-shot.
///
/// Also writes a side-channel manifest containing the file's SHA-256
/// hash, sequence range, and (record_id, this_hash) tuples for every
/// Merkle root observed in the batch. Spec §14.5.
pub fn migrate_to_parquet<B: Backend + ?Sized>(
    hot: &B,
    cold: &ColdTierBackend,
    stream_id: &str,
) -> Result<MigrationReport> {
    let rows = hot.iter_stream(stream_id)?;
    if rows.is_empty() {
        return Ok(MigrationReport {
            stream_id: stream_id.into(),
            records: 0,
            parquet_path: cold.parquet_path_for(stream_id),
            file_sha256_hex: None,
            manifest_path: cold.manifest_path_for(stream_id),
        });
    }

    let schema: SchemaRef = Arc::new(Schema::new(vec![
        Field::new("stream_id", DataType::Utf8, false),
        Field::new("sequence", DataType::Int64, false),
        Field::new("record_id", DataType::Utf8, false),
        Field::new("this_hash_hex", DataType::Utf8, false),
        Field::new("prev_hash_hex", DataType::Utf8, false),
        Field::new("payload_json", DataType::Utf8, false),
    ]));
    let mut stream_arr = StringBuilder::new();
    let mut record_id_arr = StringBuilder::new();
    let mut this_hash_arr = StringBuilder::new();
    let mut prev_hash_arr = StringBuilder::new();
    let mut payload_arr = StringBuilder::new();
    let mut sequences: Vec<i64> = Vec::with_capacity(rows.len());
    for sr in &rows {
        stream_arr.append_value(&sr.record.stream_id);
        sequences.push(sr.record.sequence as i64);
        record_id_arr.append_value(sr.record.record_id.to_string());
        this_hash_arr.append_value(&sr.this_hash_hex);
        prev_hash_arr.append_value(&sr.record.prev_hash_hex);
        let payload = serde_json::to_string(sr).map_err(|e| StorageError::Serde(e.to_string()))?;
        payload_arr.append_value(payload);
    }
    let batch = RecordBatch::try_new(
        schema.clone(),
        vec![
            Arc::new(stream_arr.finish()),
            Arc::new(Int64Array::from(sequences.clone())),
            Arc::new(record_id_arr.finish()),
            Arc::new(this_hash_arr.finish()),
            Arc::new(prev_hash_arr.finish()),
            Arc::new(payload_arr.finish()),
        ],
    )
    .map_err(|e| StorageError::Io(format!("arrow batch: {e}")))?;

    let parquet_path = cold.parquet_path_for(stream_id);
    let file = fs::File::create(&parquet_path).map_err(io)?;
    let props = WriterProperties::builder()
        .set_compression(Compression::SNAPPY)
        .build();
    let mut writer = ArrowWriter::try_new(file, schema, Some(props))
        .map_err(|e| StorageError::Io(format!("arrow writer: {e}")))?;
    writer
        .write(&batch)
        .map_err(|e| StorageError::Io(format!("write batch: {e}")))?;
    writer
        .close()
        .map_err(|e| StorageError::Io(format!("close writer: {e}")))?;

    let bytes = fs::read(&parquet_path).map_err(io)?;
    let file_sha = glassbox_core::canonical::sha256(&bytes);
    let manifest = serde_json::json!({
        "stream_id": stream_id,
        "records": rows.len() as u64,
        "first_sequence": rows.first().map(|sr| sr.record.sequence),
        "last_sequence": rows.last().map(|sr| sr.record.sequence),
        "parquet_sha256_hex": hex::encode(file_sha),
        "merkle_roots": rows.iter().filter_map(|sr| {
            if let glassbox_core::record::RecordBody::MerkleRoot(e) = &sr.record.body {
                Some(serde_json::json!({
                    "sequence": sr.record.sequence,
                    "first": e.first_sequence,
                    "last":  e.last_sequence,
                    "root":  e.root_hash_hex,
                }))
            } else { None }
        }).collect::<Vec<_>>(),
    });
    let manifest_path = cold.manifest_path_for(stream_id);
    fs::write(
        &manifest_path,
        serde_json::to_string_pretty(&manifest).map_err(|e| StorageError::Serde(e.to_string()))?,
    )
    .map_err(io)?;

    Ok(MigrationReport {
        stream_id: stream_id.into(),
        records: rows.len() as u64,
        parquet_path,
        file_sha256_hex: Some(hex::encode(file_sha)),
        manifest_path,
    })
}

/// Output of [`migrate_to_parquet`].
#[derive(Debug, Clone)]
pub struct MigrationReport {
    /// Stream that was migrated.
    pub stream_id: String,
    /// Number of records written.
    pub records: u64,
    /// Path of the Parquet file.
    pub parquet_path: PathBuf,
    /// Hex SHA-256 of the Parquet file's bytes, or `None` for empty
    /// migrations.
    pub file_sha256_hex: Option<String>,
    /// Path of the side-channel manifest file.
    pub manifest_path: PathBuf,
}

#[cfg(test)]
mod tests {
    use super::*;
    use glassbox_core::SCHEMA_VERSION;
    use glassbox_core::chain::sign_record;
    use glassbox_core::crypto::HybridKeypair;
    use glassbox_core::key_registry::{KeyRegistryEntry, KeyStatus};
    use glassbox_core::record::{InteractionBody, Record, RecordBody, make_interaction};
    use time::OffsetDateTime;
    use ulid::Ulid;

    fn make_hot_stream() -> (
        tempfile::TempDir,
        crate::sqlite::SqliteBackend,
        HybridKeypair,
    ) {
        let dir = tempfile::tempdir().unwrap();
        let mut be = crate::sqlite::SqliteBackend::open(dir.path().join("hot.db")).unwrap();
        let kp = HybridKeypair::generate().unwrap();
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
            stream_id: "tenant/sys".into(),
            sequence: 0,
            occurred_at: OffsetDateTime::now_utc(),
            received_at: OffsetDateTime::now_utc(),
            schema_version: SCHEMA_VERSION.into(),
            source_sdk: "test".into(),
            key_id: "k".into(),
            prev_hash_hex: hex::encode([0u8; 32]),
            body: RecordBody::KeyRegistry(entry),
        };
        let sr0 = sign_record(r0, &kp).unwrap();
        let mut prev: [u8; 32] = hex::decode(&sr0.this_hash_hex).unwrap().try_into().unwrap();
        be.append(sr0).unwrap();
        for i in 1..=3 {
            let r = make_interaction(
                "tenant/sys",
                i,
                OffsetDateTime::now_utc(),
                OffsetDateTime::now_utc(),
                prev,
                "k",
                "test",
                InteractionBody::default(),
            )
            .unwrap();
            let sr = sign_record(r, &kp).unwrap();
            prev = hex::decode(&sr.this_hash_hex).unwrap().try_into().unwrap();
            be.append(sr).unwrap();
        }
        (dir, be, kp)
    }

    #[test]
    fn migrate_and_read_back() {
        let (_dir, hot, _kp) = make_hot_stream();
        let cold_dir = tempfile::tempdir().unwrap();
        let cold = ColdTierBackend::open(cold_dir.path()).unwrap();
        let report = migrate_to_parquet(&hot, &cold, "tenant/sys").unwrap();
        assert_eq!(report.records, 4);
        assert!(report.file_sha256_hex.is_some());
        assert!(report.parquet_path.exists());
        assert!(report.manifest_path.exists());

        let chain = cold.iter_stream("tenant/sys").unwrap();
        assert_eq!(chain.len(), 4);
        assert_eq!(cold.list_streams().unwrap(), vec!["tenant/sys"]);

        // Verify integrity end-to-end against the read-back chain.
        let report = crate::verify_stream(&cold, "tenant/sys").expect("verify cold-tier");
        assert!(report.is_ok());
    }

    #[test]
    fn append_returns_error_on_cold_tier() {
        let dir = tempfile::tempdir().unwrap();
        let mut cold = ColdTierBackend::open(dir.path()).unwrap();
        let kp = HybridKeypair::generate().unwrap();
        let r = make_interaction(
            "t/s",
            0,
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc(),
            [0u8; 32],
            "k",
            "test",
            InteractionBody::default(),
        )
        .unwrap();
        let sr = sign_record(r, &kp).unwrap();
        assert!(cold.append(sr).is_err());
    }
}
