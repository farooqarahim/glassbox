//! SQLite-backed implementation of [`Backend`].
//!
//! Schema (one table; indices keep verification walks linear-time):
//!
//! ```sql
//! CREATE TABLE records (
//!     stream_id     TEXT    NOT NULL,
//!     sequence      INTEGER NOT NULL,
//!     record_id     TEXT    NOT NULL,
//!     this_hash_hex TEXT    NOT NULL,
//!     prev_hash_hex TEXT    NOT NULL,
//!     payload_json  TEXT    NOT NULL,
//!     PRIMARY KEY (stream_id, sequence)
//! );
//! CREATE INDEX idx_records_record_id ON records(record_id);
//! ```
//!
//! Appends run inside `BEGIN IMMEDIATE` so that two concurrent writers
//! cannot race past each other and produce divergent sequence numbers.
//! `journal_mode=WAL` and `synchronous=FULL` are set on open so an
//! `Ok(())` from [`Backend::append`] reflects durable storage.

use rusqlite::{Connection, OptionalExtension, params};

use glassbox_core::record::SignedRecord;

use crate::{Backend, Result, StorageError};

/// SQLite-backed storage.
pub struct SqliteBackend {
    conn: Connection,
}

impl SqliteBackend {
    /// Open or create the database at `path`.
    pub fn open(path: impl AsRef<std::path::Path>) -> Result<Self> {
        let conn = Connection::open(path.as_ref()).map_err(io)?;
        Self::configure_and_migrate(&conn)?;
        Ok(Self { conn })
    }

    /// In-memory SQLite for tests.
    pub fn in_memory() -> Result<Self> {
        let conn = Connection::open_in_memory().map_err(io)?;
        Self::configure_and_migrate(&conn)?;
        Ok(Self { conn })
    }

    fn configure_and_migrate(conn: &Connection) -> Result<()> {
        conn.execute_batch(
            r"
            PRAGMA journal_mode = WAL;
            PRAGMA synchronous  = FULL;
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS records (
                stream_id     TEXT    NOT NULL,
                sequence      INTEGER NOT NULL,
                record_id     TEXT    NOT NULL,
                this_hash_hex TEXT    NOT NULL,
                prev_hash_hex TEXT    NOT NULL,
                payload_json  TEXT    NOT NULL,
                PRIMARY KEY (stream_id, sequence)
            );
            CREATE INDEX IF NOT EXISTS idx_records_record_id ON records(record_id);
            ",
        )
        .map_err(io)?;
        Ok(())
    }

    fn last_locked(conn: &Connection, stream_id: &str) -> Result<Option<SignedRecord>> {
        let mut stmt = conn
            .prepare(
                "SELECT payload_json FROM records WHERE stream_id = ?1 ORDER BY sequence DESC LIMIT 1",
            )
            .map_err(io)?;
        let row: Option<String> = stmt
            .query_row(params![stream_id], |r| r.get::<_, String>(0))
            .optional()
            .map_err(io)?;
        row.map(deserialize_payload).transpose()
    }
}

fn io<E: std::fmt::Display>(e: E) -> StorageError {
    StorageError::Io(e.to_string())
}

fn serialize_payload(sr: &SignedRecord) -> Result<String> {
    serde_json::to_string(sr).map_err(|e| StorageError::Serde(e.to_string()))
}

fn deserialize_payload(s: String) -> Result<SignedRecord> {
    serde_json::from_str(&s).map_err(|e| StorageError::Serde(e.to_string()))
}

impl Backend for SqliteBackend {
    fn append(&mut self, record: SignedRecord) -> Result<()> {
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(io)?;

        // Compute expected sequence and prev_hash, under transaction
        let last = Self::last_locked(&tx, &record.record.stream_id)?;
        let (expected_seq, expected_prev) = match last {
            Some(prev) => (prev.record.sequence + 1, prev.this_hash_hex),
            None => (0, hex::encode([0u8; 32])),
        };
        if record.record.sequence != expected_seq {
            return Err(StorageError::Invariant(format!(
                "expected sequence {expected_seq}, got {} on {}",
                record.record.sequence, record.record.stream_id
            )));
        }
        if record.record.prev_hash_hex != expected_prev {
            return Err(StorageError::Invariant(format!(
                "expected prev_hash {expected_prev}, got {}",
                record.record.prev_hash_hex
            )));
        }

        let payload = serialize_payload(&record)?;
        tx.execute(
            "INSERT INTO records (stream_id, sequence, record_id, this_hash_hex, prev_hash_hex, payload_json)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![
                record.record.stream_id,
                record.record.sequence as i64,
                record.record.record_id.to_string(),
                record.this_hash_hex,
                record.record.prev_hash_hex,
                payload,
            ],
        )
        .map_err(io)?;
        tx.commit().map_err(io)?;
        Ok(())
    }

    fn last(&self, stream_id: &str) -> Result<Option<SignedRecord>> {
        Self::last_locked(&self.conn, stream_id)
    }

    fn get(&self, stream_id: &str, sequence: u64) -> Result<Option<SignedRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM records WHERE stream_id = ?1 AND sequence = ?2")
            .map_err(io)?;
        let row: Option<String> = stmt
            .query_row(params![stream_id, sequence as i64], |r| {
                r.get::<_, String>(0)
            })
            .optional()
            .map_err(io)?;
        row.map(deserialize_payload).transpose()
    }

    fn iter_stream(&self, stream_id: &str) -> Result<Vec<SignedRecord>> {
        let mut stmt = self
            .conn
            .prepare("SELECT payload_json FROM records WHERE stream_id = ?1 ORDER BY sequence ASC")
            .map_err(io)?;
        let rows = stmt
            .query_map(params![stream_id], |r| r.get::<_, String>(0))
            .map_err(io)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(deserialize_payload(row.map_err(io)?)?);
        }
        Ok(out)
    }

    fn list_streams(&self) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT DISTINCT stream_id FROM records ORDER BY stream_id ASC")
            .map_err(io)?;
        let rows = stmt.query_map([], |r| r.get::<_, String>(0)).map_err(io)?;
        let mut out = Vec::new();
        for row in rows {
            out.push(row.map_err(io)?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use glassbox_core::SCHEMA_VERSION;
    use glassbox_core::chain::sign_record;
    use glassbox_core::crypto::HybridKeypair;
    use glassbox_core::key_registry::{KeyRegistryEntry, KeyStatus};
    use glassbox_core::record::{InteractionBody, Record, RecordBody, make_interaction};
    use time::macros::datetime;
    use ulid::Ulid;

    fn now() -> time::OffsetDateTime {
        datetime!(2026-05-12 12:00:00 UTC)
    }

    fn make_chain(be: &mut SqliteBackend, kp: &HybridKeypair, len: u64) {
        let pk = kp.public_key();
        let entry = KeyRegistryEntry {
            key_id: "k".into(),
            algorithm: glassbox_core::ALGORITHM_HYBRID_ED25519_MLDSA65.into(),
            public_key: pk,
            valid_from: now(),
            valid_to: None,
            status: KeyStatus::Active,
        };
        let r0 = Record {
            record_id: Ulid::new(),
            stream_id: "t/s".into(),
            sequence: 0,
            occurred_at: now(),
            received_at: now(),
            schema_version: SCHEMA_VERSION.into(),
            source_sdk: "test/0.1.0".into(),
            key_id: "k".into(),
            prev_hash_hex: hex::encode([0u8; 32]),
            body: RecordBody::KeyRegistry(entry),
        };
        let sr0 = sign_record(r0, kp).unwrap();
        let mut prev: [u8; 32] = hex::decode(&sr0.this_hash_hex).unwrap().try_into().unwrap();
        be.append(sr0).unwrap();

        for seq in 1..=len {
            let r = make_interaction(
                "t/s",
                seq,
                now(),
                now(),
                prev,
                "k",
                "test/0.1.0",
                InteractionBody::default(),
            )
            .unwrap();
            let sr = sign_record(r, kp).unwrap();
            prev = hex::decode(&sr.this_hash_hex).unwrap().try_into().unwrap();
            be.append(sr).unwrap();
        }
    }

    #[test]
    fn open_and_persist() {
        let dir = tempfile::tempdir().unwrap();
        let db_path = dir.path().join("ledger.db");
        let kp = HybridKeypair::generate().unwrap();
        {
            let mut be = SqliteBackend::open(&db_path).unwrap();
            make_chain(&mut be, &kp, 3);
        }
        let be = SqliteBackend::open(&db_path).unwrap();
        assert_eq!(be.iter_stream("t/s").unwrap().len(), 4);
        assert_eq!(be.last("t/s").unwrap().unwrap().record.sequence, 3);
    }

    #[test]
    fn verify_stream_passes_on_clean_chain() {
        let mut be = SqliteBackend::in_memory().unwrap();
        let kp = HybridKeypair::generate().unwrap();
        make_chain(&mut be, &kp, 5);
        let report = crate::verify_stream(&be, "t/s").unwrap();
        assert!(report.is_ok());
        assert_eq!(report.records_walked, 6);
    }

    #[test]
    fn append_rejects_skipped_sequence() {
        let mut be = SqliteBackend::in_memory().unwrap();
        let kp = HybridKeypair::generate().unwrap();
        let r = make_interaction(
            "t/s",
            10,
            now(),
            now(),
            [0u8; 32],
            "k",
            "test/0.1.0",
            InteractionBody::default(),
        )
        .unwrap();
        let sr = sign_record(r, &kp).unwrap();
        assert!(matches!(be.append(sr), Err(StorageError::Invariant(_))));
    }

    #[test]
    fn list_streams_returns_distinct_sorted() {
        let mut be = SqliteBackend::in_memory().unwrap();
        let kp = HybridKeypair::generate().unwrap();
        for s in ["b/x", "a/y"] {
            let entry = KeyRegistryEntry {
                key_id: format!("k-{s}"),
                algorithm: glassbox_core::ALGORITHM_HYBRID_ED25519_MLDSA65.into(),
                public_key: kp.public_key(),
                valid_from: now(),
                valid_to: None,
                status: KeyStatus::Active,
            };
            let r0 = Record {
                record_id: Ulid::new(),
                stream_id: s.into(),
                sequence: 0,
                occurred_at: now(),
                received_at: now(),
                schema_version: SCHEMA_VERSION.into(),
                source_sdk: "t".into(),
                key_id: format!("k-{s}"),
                prev_hash_hex: hex::encode([0u8; 32]),
                body: RecordBody::KeyRegistry(entry),
            };
            be.append(sign_record(r0, &kp).unwrap()).unwrap();
        }
        assert_eq!(
            be.list_streams().unwrap(),
            vec!["a/y".to_string(), "b/x".to_string()]
        );
    }
}
