//! Cross-version canonical-form regression test.
//!
//! Reads `tests/corpus/canonical_corpus.jsonl` and asserts that every
//! entry's canonical bytes and SHA-256 hash are reproducible from this
//! build's `glassbox_core::canonical::canonicalize`. A single mismatch
//! is a cryptographic-bar regression — fix the code or, if the change
//! is deliberate, regenerate the corpus and review the diff.
//!
//! Per spec §26.2, the long-term target is ≥10^5 records exercised
//! across all official SDKs. v0.2 ships 10^4 records single-language;
//! cross-language extension is tracked in the v0.3 roadmap.

use std::fs;
use std::path::PathBuf;

use base64ct::{Base64, Encoding as _};
use glassbox_core::canonical;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct CorpusEntry {
    id: u64,
    value: serde_json::Value,
    canonical_b64: String,
    hash_hex: String,
}

fn corpus_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join("canonical_corpus.jsonl")
}

#[test]
fn canonical_corpus_is_reproducible() {
    let path = corpus_path();
    let text = fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!(
            "missing corpus at {}: {e}.\n\
             Regenerate with: cargo run --example gen_corpus -p glassbox-core",
            path.display()
        )
    });
    let mut n: usize = 0;
    for line in text.lines() {
        if line.trim().is_empty() {
            continue;
        }
        let entry: CorpusEntry = serde_json::from_str(line)
            .unwrap_or_else(|e| panic!("entry {n} malformed: {e}\nline: {line}"));
        let bytes = canonical::canonicalize(&entry.value).expect("canonicalize ok");
        let bytes_b64 = Base64::encode_string(&bytes);
        let hash_hex = hex::encode(canonical::sha256(&bytes));
        assert_eq!(
            bytes_b64, entry.canonical_b64,
            "entry id={} ({n}th): canonical bytes drifted. value={:?}",
            entry.id, entry.value
        );
        assert_eq!(
            hash_hex, entry.hash_hex,
            "entry id={} ({n}th): hash drifted",
            entry.id
        );
        n += 1;
    }
    assert!(n >= 2000, "corpus shrank to {n} entries; expected >=2000");
}
