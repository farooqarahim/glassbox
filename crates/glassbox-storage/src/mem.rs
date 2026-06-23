//! In-memory backend for tests and as a reference implementation.

use std::collections::HashMap;

use glassbox_core::record::SignedRecord;

use crate::{Backend, Result, StorageError};

/// A simple in-memory backend keyed by stream id.
#[derive(Default, Debug)]
pub struct InMemoryBackend {
    streams: HashMap<String, Vec<SignedRecord>>,
}

impl InMemoryBackend {
    /// Create an empty backend.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }
}

impl Backend for InMemoryBackend {
    fn append(&mut self, record: SignedRecord) -> Result<()> {
        let stream = self
            .streams
            .entry(record.record.stream_id.clone())
            .or_default();
        let expected_seq = stream.len() as u64;
        if record.record.sequence != expected_seq {
            return Err(StorageError::Invariant(format!(
                "expected sequence {expected_seq}, got {} on {}",
                record.record.sequence, record.record.stream_id
            )));
        }
        let expected_prev_hex = match stream.last() {
            Some(prev) => prev.this_hash_hex.clone(),
            None => hex::encode([0u8; 32]),
        };
        if record.record.prev_hash_hex != expected_prev_hex {
            return Err(StorageError::Invariant(format!(
                "expected prev_hash {expected_prev_hex}, got {}",
                record.record.prev_hash_hex
            )));
        }
        stream.push(record);
        Ok(())
    }

    fn last(&self, stream_id: &str) -> Result<Option<SignedRecord>> {
        Ok(self.streams.get(stream_id).and_then(|v| v.last().cloned()))
    }

    fn get(&self, stream_id: &str, sequence: u64) -> Result<Option<SignedRecord>> {
        Ok(self
            .streams
            .get(stream_id)
            .and_then(|v| v.get(sequence as usize).cloned()))
    }

    fn iter_stream(&self, stream_id: &str) -> Result<Vec<SignedRecord>> {
        Ok(self.streams.get(stream_id).cloned().unwrap_or_default())
    }

    fn list_streams(&self) -> Result<Vec<String>> {
        let mut v: Vec<String> = self.streams.keys().cloned().collect();
        v.sort();
        Ok(v)
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

    #[test]
    fn append_get_iter_roundtrip() {
        let mut be = InMemoryBackend::new();
        let kp = HybridKeypair::generate().unwrap();
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
        let sr0 = sign_record(r0, &kp).unwrap();
        be.append(sr0.clone()).unwrap();

        let prev: [u8; 32] = hex::decode(&sr0.this_hash_hex).unwrap().try_into().unwrap();
        let r1 = make_interaction(
            "t/s",
            1,
            now(),
            now(),
            prev,
            "k",
            "test/0.1.0",
            InteractionBody::default(),
        )
        .unwrap();
        let sr1 = sign_record(r1, &kp).unwrap();
        be.append(sr1.clone()).unwrap();

        assert_eq!(be.last("t/s").unwrap().unwrap().record.sequence, 1);
        assert_eq!(be.get("t/s", 0).unwrap().unwrap().record.sequence, 0);
        assert_eq!(be.iter_stream("t/s").unwrap().len(), 2);
        assert_eq!(be.list_streams().unwrap(), vec!["t/s".to_string()]);
    }

    #[test]
    fn append_rejects_wrong_sequence() {
        let mut be = InMemoryBackend::new();
        let kp = HybridKeypair::generate().unwrap();
        let r = make_interaction(
            "t/s",
            5,
            now(),
            now(),
            [0u8; 32],
            "k",
            "test/0.1.0",
            InteractionBody::default(),
        )
        .unwrap();
        let sr = sign_record(r, &kp).unwrap();
        let err = be.append(sr).unwrap_err();
        assert!(matches!(err, StorageError::Invariant(_)));
    }

    #[test]
    fn append_rejects_wrong_prev_hash() {
        let mut be = InMemoryBackend::new();
        let kp = HybridKeypair::generate().unwrap();
        let r0 = make_interaction(
            "t/s",
            0,
            now(),
            now(),
            [0u8; 32],
            "k",
            "test/0.1.0",
            InteractionBody::default(),
        )
        .unwrap();
        let sr0 = sign_record(r0, &kp).unwrap();
        be.append(sr0).unwrap();

        let bad_prev = [0xffu8; 32];
        let r1 = make_interaction(
            "t/s",
            1,
            now(),
            now(),
            bad_prev,
            "k",
            "test/0.1.0",
            InteractionBody::default(),
        )
        .unwrap();
        let sr1 = sign_record(r1, &kp).unwrap();
        assert!(matches!(be.append(sr1), Err(StorageError::Invariant(_))));
    }
}
