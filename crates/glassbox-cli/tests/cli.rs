//! End-to-end CLI tests: drive the `glassbox` binary against a real
//! SQLite ledger in a tempdir, exercising the same workflow a user
//! would follow from the README.

use std::fs;
use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;
use tempfile::TempDir;

fn glassbox() -> Command {
    Command::cargo_bin("glassbox").expect("binary built")
}

struct Env {
    _dir: TempDir,
    ledger: PathBuf,
    key: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let ledger = dir.path().join("ledger.db");
        let key = dir.path().join("tenant.key");
        let env = Self {
            _dir: dir,
            ledger,
            key,
        };
        glassbox()
            .args(["keygen", "--out"])
            .arg(&env.key)
            .assert()
            .success();
        env
    }

    fn init(&self, tenant: &str, system: &str) {
        glassbox()
            .args(["init", "--ledger"])
            .arg(&self.ledger)
            .args(["--tenant", tenant, "--system", system, "--key"])
            .arg(&self.key)
            .assert()
            .success();
    }

    fn append(&self, stream: &str, body_path: &std::path::Path) {
        glassbox()
            .args(["append", "--ledger"])
            .arg(&self.ledger)
            .args(["--stream", stream, "--key"])
            .arg(&self.key)
            .args(["--body"])
            .arg(body_path)
            .assert()
            .success();
    }
}

fn sample_body() -> serde_json::Value {
    serde_json::json!({
        "input": {
            "hash_algorithm": "SHA-256",
            "hash_hex": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
            "byte_size": 3
        },
        "output": {
            "hash_algorithm": "SHA-256",
            "hash_hex": "0000000000000000000000000000000000000000000000000000000000000000",
            "byte_size": 0
        },
        "model": {
            "provider": "anthropic",
            "model_name": "claude-opus-4-7",
            "model_version": "20260119"
        },
        "tags": [{"key": "decision_id", "value": "loan-1"}]
    })
}

#[test]
fn keygen_writes_a_file_and_refuses_to_overwrite() {
    let dir = tempfile::tempdir().unwrap();
    let key = dir.path().join("k");
    glassbox()
        .args(["keygen", "--out"])
        .arg(&key)
        .assert()
        .success();
    assert!(key.exists());
    glassbox()
        .args(["keygen", "--out"])
        .arg(&key)
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to overwrite"));
}

#[test]
fn end_to_end_init_append_verify() {
    let env = Env::new();
    env.init("acme", "credit-v1");

    let body_path = env._dir.path().join("body.json");
    fs::write(&body_path, sample_body().to_string()).unwrap();
    env.append("acme/credit-v1", &body_path);
    env.append("acme/credit-v1", &body_path);
    env.append("acme/credit-v1", &body_path);

    glassbox()
        .args(["verify", "--ledger"])
        .arg(&env.ledger)
        .args(["--stream", "acme/credit-v1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("OK"));
}

#[test]
fn show_returns_record_json() {
    let env = Env::new();
    env.init("acme", "system");
    let body_path = env._dir.path().join("body.json");
    fs::write(&body_path, sample_body().to_string()).unwrap();
    env.append("acme/system", &body_path);
    glassbox()
        .args(["show", "--ledger"])
        .arg(&env.ledger)
        .args(["--stream", "acme/system", "--sequence", "1"])
        .assert()
        .success()
        .stdout(predicate::str::contains("\"sequence\": 1"))
        .stdout(predicate::str::contains("\"kind\": \"interaction\""));
}

#[test]
fn merkle_commit_and_verify() {
    let env = Env::new();
    env.init("acme", "system");
    let body_path = env._dir.path().join("body.json");
    fs::write(&body_path, sample_body().to_string()).unwrap();
    for _ in 0..3 {
        env.append("acme/system", &body_path);
    }
    glassbox()
        .args(["merkle-commit", "--ledger"])
        .arg(&env.ledger)
        .args(["--stream", "acme/system", "--key"])
        .arg(&env.key)
        .assert()
        .success()
        .stdout(predicate::str::contains("committed merkle root"));
    glassbox()
        .args(["verify", "--ledger"])
        .arg(&env.ledger)
        .args(["--stream", "acme/system"])
        .assert()
        .success()
        .stdout(predicate::str::contains("merkle_roots=1"));
}

#[test]
fn key_rotate_then_verify() {
    let env = Env::new();
    env.init("acme", "system");
    let body_path = env._dir.path().join("body.json");
    fs::write(&body_path, sample_body().to_string()).unwrap();
    env.append("acme/system", &body_path);

    let new_key = env._dir.path().join("new.key");
    glassbox()
        .args(["keygen", "--out"])
        .arg(&new_key)
        .assert()
        .success();
    glassbox()
        .args(["key-rotate", "--ledger"])
        .arg(&env.ledger)
        .args(["--stream", "acme/system", "--current-key"])
        .arg(&env.key)
        .args(["--new-key"])
        .arg(&new_key)
        .assert()
        .success();

    // Now append under the rotated key.
    glassbox()
        .args(["append", "--ledger"])
        .arg(&env.ledger)
        .args(["--stream", "acme/system", "--key"])
        .arg(&new_key)
        .args(["--body"])
        .arg(&body_path)
        .assert()
        .success();

    glassbox()
        .args(["verify", "--ledger"])
        .arg(&env.ledger)
        .args(["--stream", "acme/system"])
        .assert()
        .success();
}

#[test]
fn streams_lists_initialised_streams() {
    let env = Env::new();
    env.init("a", "x");
    env.init("b", "y");
    glassbox()
        .args(["streams", "--ledger"])
        .arg(&env.ledger)
        .assert()
        .success()
        .stdout(predicate::str::contains("a/x"))
        .stdout(predicate::str::contains("b/y"));
}

#[test]
fn append_rejects_invalid_stream_format() {
    let env = Env::new();
    glassbox()
        .args(["append", "--ledger"])
        .arg(&env.ledger)
        .args(["--stream", "no-slash", "--key"])
        .arg(&env.key)
        .args(["--body", "/dev/null"])
        .assert()
        .failure();
}

#[test]
fn verify_detects_tampered_ledger() {
    let env = Env::new();
    env.init("acme", "system");
    let body_path = env._dir.path().join("body.json");
    fs::write(&body_path, sample_body().to_string()).unwrap();
    env.append("acme/system", &body_path);
    env.append("acme/system", &body_path);

    // Mutate one row's payload_json to break canonical hash linkage.
    let conn = rusqlite::Connection::open(&env.ledger).unwrap();
    conn.execute(
        "UPDATE records SET payload_json = REPLACE(payload_json, 'loan-1', 'loan-2') WHERE sequence = 1",
        [],
    )
    .unwrap();
    drop(conn);

    glassbox()
        .args(["verify", "--ledger"])
        .arg(&env.ledger)
        .args(["--stream", "acme/system"])
        .assert()
        .failure()
        .stderr(predicate::str::contains("verification FAILED"));
}

#[test]
fn redact_appends_tombstone_and_verify_passes() {
    let env = Env::new();
    env.init("acme", "system");
    let body_path = env._dir.path().join("body.json");
    fs::write(&body_path, sample_body().to_string()).unwrap();
    env.append("acme/system", &body_path);
    env.append("acme/system", &body_path);

    glassbox()
        .args(["redact", "--ledger"])
        .arg(&env.ledger)
        .args(["--stream", "acme/system", "--key"])
        .arg(&env.key)
        .args([
            "--target-sequence",
            "1",
            "--reason",
            "gdpr-erasure",
            "--actor",
            "dpo-1",
        ])
        .assert()
        .success()
        .stdout(predicate::str::contains("redacted sequence 1"));

    glassbox()
        .args(["verify", "--ledger"])
        .arg(&env.ledger)
        .args(["--stream", "acme/system"])
        .assert()
        .success();
}

#[test]
fn redact_refuses_to_target_a_tombstone() {
    let env = Env::new();
    env.init("acme", "system");
    let body_path = env._dir.path().join("body.json");
    fs::write(&body_path, sample_body().to_string()).unwrap();
    env.append("acme/system", &body_path);

    // First redaction targets the interaction at sequence 1.
    glassbox()
        .args(["redact", "--ledger"])
        .arg(&env.ledger)
        .args(["--stream", "acme/system", "--key"])
        .arg(&env.key)
        .args([
            "--target-sequence",
            "1",
            "--reason",
            "operator-request",
            "--actor",
            "ops",
        ])
        .assert()
        .success();

    // Second attempt targets the tombstone itself (sequence 2) — refused.
    glassbox()
        .args(["redact", "--ledger"])
        .arg(&env.ledger)
        .args(["--stream", "acme/system", "--key"])
        .arg(&env.key)
        .args([
            "--target-sequence",
            "2",
            "--reason",
            "operator-request",
            "--actor",
            "ops",
        ])
        .assert()
        .failure()
        .stderr(predicate::str::contains("refusing to redact a tombstone"));
}
