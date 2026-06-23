//! Postgres-backed implementation of [`Backend`].
//!
//! Mirrors the SQLite logical schema (one `records` table with the
//! same six columns plus a composite primary key) so that the same
//! `SignedRecord` JSON payload moves between backends without
//! transformation. The append path is wrapped in `BEGIN; SELECT ...
//! FOR UPDATE ... ; INSERT; COMMIT;` so that two concurrent writers
//! cannot race past each other and produce divergent sequence numbers
//! — the same property `BEGIN IMMEDIATE` gives in SQLite.
//!
//! Tests against a live Postgres are gated on the `GLASSBOX_PG_TEST_URL`
//! environment variable. Set it to a `postgres://` URL pointing at a
//! disposable database to enable integration tests; unset, they are
//! skipped.
//!
//! Feature flag: enable with `glassbox-storage = { features = ["postgres"] }`.

use std::cell::RefCell;

use postgres::{Client, NoTls};

use glassbox_core::record::SignedRecord;

use crate::{Backend, Result, StorageError};

/// Postgres-backed Backend implementation.
///
/// `Client` from the `postgres` crate requires `&mut self` for every
/// query. The `Backend` trait's read methods take `&self`, so we wrap
/// the client in a `RefCell` for interior mutability. This is safe in
/// single-threaded use; multi-threaded use should wrap the whole
/// backend in a `Mutex` or use a connection pool, which is on the
/// v0.5 list (spec §25.2 mentions partition-by-stream parallelism as
/// the appropriate scaling axis).
pub struct PostgresBackend {
    client: RefCell<Client>,
}

impl PostgresBackend {
    /// Connect to Postgres and run migrations.
    pub fn connect(url: &str) -> Result<Self> {
        let mut client = Client::connect(url, NoTls).map_err(io)?;
        Self::migrate(&mut client)?;
        Ok(Self {
            client: RefCell::new(client),
        })
    }

    fn migrate(client: &mut Client) -> Result<()> {
        client
            .batch_execute(
                r"
                CREATE TABLE IF NOT EXISTS records (
                    stream_id     TEXT    NOT NULL,
                    sequence      BIGINT  NOT NULL CHECK (sequence >= 0),
                    record_id     TEXT    NOT NULL,
                    this_hash_hex TEXT    NOT NULL,
                    prev_hash_hex TEXT    NOT NULL,
                    payload_json  JSONB   NOT NULL,
                    PRIMARY KEY (stream_id, sequence)
                );
                CREATE INDEX IF NOT EXISTS idx_records_record_id ON records(record_id);
                CREATE INDEX IF NOT EXISTS idx_records_stream    ON records(stream_id);
                ",
            )
            .map_err(io)?;
        Ok(())
    }
}

fn io<E: std::fmt::Display>(e: E) -> StorageError {
    StorageError::Io(e.to_string())
}

fn serialize_payload(sr: &SignedRecord) -> Result<serde_json::Value> {
    serde_json::to_value(sr).map_err(|e| StorageError::Serde(e.to_string()))
}

fn deserialize_payload(v: serde_json::Value) -> Result<SignedRecord> {
    serde_json::from_value(v).map_err(|e| StorageError::Serde(e.to_string()))
}

impl Backend for PostgresBackend {
    fn append(&mut self, record: SignedRecord) -> Result<()> {
        let mut client = self.client.borrow_mut();
        let mut tx = client.transaction().map_err(io)?;
        // Lock the stream's row range. SELECT ... FOR UPDATE on the
        // last record (if any) serializes concurrent appenders.
        let last: Option<postgres::Row> = tx
            .query_opt(
                "SELECT sequence, this_hash_hex FROM records
                 WHERE stream_id = $1
                 ORDER BY sequence DESC LIMIT 1
                 FOR UPDATE",
                &[&record.record.stream_id],
            )
            .map_err(io)?;
        let (expected_seq, expected_prev) = match last {
            Some(row) => {
                let seq: i64 = row.get(0);
                let prev_hex: String = row.get(1);
                (u64::try_from(seq + 1).unwrap_or(0), prev_hex)
            }
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
             VALUES ($1, $2, $3, $4, $5, $6)",
            &[
                &record.record.stream_id,
                &(record.record.sequence as i64),
                &record.record.record_id.to_string(),
                &record.this_hash_hex,
                &record.record.prev_hash_hex,
                &payload,
            ],
        )
        .map_err(io)?;
        tx.commit().map_err(io)?;
        Ok(())
    }

    fn last(&self, stream_id: &str) -> Result<Option<SignedRecord>> {
        let row = self
            .client
            .borrow_mut()
            .query_opt(
                "SELECT payload_json FROM records WHERE stream_id = $1
                 ORDER BY sequence DESC LIMIT 1",
                &[&stream_id],
            )
            .map_err(io)?;
        row.map(|r| deserialize_payload(r.get(0))).transpose()
    }

    fn get(&self, stream_id: &str, sequence: u64) -> Result<Option<SignedRecord>> {
        let row = self
            .client
            .borrow_mut()
            .query_opt(
                "SELECT payload_json FROM records WHERE stream_id = $1 AND sequence = $2",
                &[&stream_id, &(sequence as i64)],
            )
            .map_err(io)?;
        row.map(|r| deserialize_payload(r.get(0))).transpose()
    }

    fn iter_stream(&self, stream_id: &str) -> Result<Vec<SignedRecord>> {
        let rows = self
            .client
            .borrow_mut()
            .query(
                "SELECT payload_json FROM records WHERE stream_id = $1 ORDER BY sequence ASC",
                &[&stream_id],
            )
            .map_err(io)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(deserialize_payload(row.get(0))?);
        }
        Ok(out)
    }

    fn list_streams(&self) -> Result<Vec<String>> {
        let rows = self
            .client
            .borrow_mut()
            .query(
                "SELECT DISTINCT stream_id FROM records ORDER BY stream_id ASC",
                &[],
            )
            .map_err(io)?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            out.push(row.get(0));
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::env;

    /// Returns Some(url) if integration tests are enabled.
    fn live_url() -> Option<String> {
        env::var("GLASSBOX_PG_TEST_URL")
            .ok()
            .filter(|s| !s.is_empty())
    }

    #[test]
    fn migrations_create_records_table() {
        let Some(url) = live_url() else {
            eprintln!("GLASSBOX_PG_TEST_URL not set; skipping postgres integration test");
            return;
        };
        let be = PostgresBackend::connect(&url).expect("connect");
        // Truncate so the test is repeatable.
        be.client
            .borrow_mut()
            .batch_execute("TRUNCATE TABLE records")
            .unwrap();
        assert!(be.list_streams().unwrap().is_empty());
    }

    #[test]
    fn append_and_read_roundtrip() {
        let Some(url) = live_url() else {
            eprintln!("GLASSBOX_PG_TEST_URL not set; skipping postgres integration test");
            return;
        };
        let mut be = PostgresBackend::connect(&url).expect("connect");
        be.client
            .borrow_mut()
            .batch_execute("TRUNCATE TABLE records")
            .unwrap();

        use glassbox_core::SCHEMA_VERSION;
        use glassbox_core::chain::sign_record;
        use glassbox_core::crypto::HybridKeypair;
        use glassbox_core::key_registry::{KeyRegistryEntry, KeyStatus};
        use glassbox_core::record::{Record, RecordBody};
        use time::OffsetDateTime;
        use ulid::Ulid;

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
            stream_id: "t/s".into(),
            sequence: 0,
            occurred_at: OffsetDateTime::now_utc(),
            received_at: OffsetDateTime::now_utc(),
            schema_version: SCHEMA_VERSION.into(),
            source_sdk: "test/0.4.0".into(),
            key_id: "k".into(),
            prev_hash_hex: hex::encode([0u8; 32]),
            body: RecordBody::KeyRegistry(entry),
        };
        let sr0 = sign_record(r0, &kp).unwrap();
        be.append(sr0.clone()).unwrap();

        let got = be.iter_stream("t/s").unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].this_hash_hex, sr0.this_hash_hex);
    }
}
