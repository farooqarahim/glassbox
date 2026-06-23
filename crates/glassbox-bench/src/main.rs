//! `glassbox-bench` — reproducible micro-benchmarks for the audit
//! ledger primitives.
//!
//! Three workloads, all running against a tempdir SQLite ledger:
//!
//! 1. **append throughput** — how many records/sec the hot tier can
//!    accept with full hybrid signing and chain linkage.
//! 2. **verify throughput** — how many records/sec the verifier walks,
//!    parallelism left to a future flag.
//! 3. **signature ops/sec** — pure crypto: ed25519 sign+verify,
//!    ml-dsa-65 sign+verify, hybrid AND verify.
//!
//! All numbers are wall-clock; latency distribution is sampled per
//! workload and printed as p50 / p99 / p999.
//!
//! Per spec §25.1, the benchmark methodology is reproducibility-first:
//! every run prints the toolchain version, the workload size, and the
//! commit hash if the binary was built from a git checkout. Compare
//! across versions by running on the same hardware.

#![cfg_attr(not(test), forbid(unsafe_code))]
#![deny(missing_docs)]

use std::time::{Duration, Instant};

use clap::Parser;
use time::OffsetDateTime;
use ulid::Ulid;

use glassbox_core::SCHEMA_VERSION;
use glassbox_core::chain::sign_record;
use glassbox_core::combiner::SignatureCombiner;
use glassbox_core::crypto::HybridKeypair;
use glassbox_core::key_registry::{KeyRegistryEntry, KeyStatus};
use glassbox_core::record::{InteractionBody, Record, RecordBody, make_interaction};
use glassbox_storage::Backend;
use glassbox_storage::sqlite::SqliteBackend;

#[derive(Debug, Parser)]
#[command(
    name = "glassbox-bench",
    version,
    about = "Reproducible benchmarks for Glassbox primitives."
)]
struct Cli {
    /// How many records to insert for the append + verify workloads.
    #[arg(long, default_value_t = 1000)]
    records: u64,
    /// How many sign+verify iterations to run for the signature workload.
    #[arg(long, default_value_t = 200)]
    sig_iters: u64,
    /// Skip the append + verify workloads (signature-only).
    #[arg(long)]
    skip_storage: bool,
}

fn main() {
    let cli = Cli::parse();
    println!("# glassbox-bench v{}", env!("CARGO_PKG_VERSION"));
    println!("# rustc           {}", rustc_version());
    println!("# build profile   {}", profile());

    bench_signatures(cli.sig_iters);
    if !cli.skip_storage {
        bench_append(cli.records);
        bench_verify(cli.records);
    }
}

fn bench_signatures(iters: u64) {
    let kp = HybridKeypair::generate().expect("kp");
    let pk = kp.public_key();
    let msg = b"glassbox benchmark fixed-length message for signing micro-benchmarks";

    let mut sign_samples = Vec::with_capacity(iters as usize);
    let mut verify_samples = Vec::with_capacity(iters as usize);
    let combiner = SignatureCombiner::And;

    for _ in 0..iters {
        let t0 = Instant::now();
        let sig = kp.sign(msg);
        sign_samples.push(t0.elapsed());
        let t1 = Instant::now();
        combiner.verify(&pk, msg, &sig).expect("verify");
        verify_samples.push(t1.elapsed());
    }
    report("hybrid sign  (Ed25519+ML-DSA-65)", &sign_samples);
    report("hybrid verify (AND)", &verify_samples);
}

fn bench_append(records: u64) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut backend = SqliteBackend::open(dir.path().join("bench.db")).expect("open");
    let kp = HybridKeypair::generate().expect("kp");
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
        stream_id: "bench/sys".into(),
        sequence: 0,
        occurred_at: OffsetDateTime::now_utc(),
        received_at: OffsetDateTime::now_utc(),
        schema_version: SCHEMA_VERSION.into(),
        source_sdk: "glassbox-bench".into(),
        key_id: "k".into(),
        prev_hash_hex: hex::encode([0u8; 32]),
        body: RecordBody::KeyRegistry(entry),
    };
    let sr0 = sign_record(r0, &kp).expect("sign genesis");
    let mut prev: [u8; 32] = hex::decode(&sr0.this_hash_hex)
        .expect("hex")
        .try_into()
        .expect("32");
    backend.append(sr0).expect("append genesis");

    let mut samples: Vec<Duration> = Vec::with_capacity(records as usize);
    let t_total = Instant::now();
    for i in 1..=records {
        let r = make_interaction(
            "bench/sys",
            i,
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc(),
            prev,
            "k",
            "glassbox-bench",
            InteractionBody::default(),
        )
        .expect("make_interaction");
        let t0 = Instant::now();
        let sr = sign_record(r, &kp).expect("sign");
        prev = hex::decode(&sr.this_hash_hex)
            .expect("hex")
            .try_into()
            .expect("32");
        backend.append(sr).expect("append");
        samples.push(t0.elapsed());
    }
    let total = t_total.elapsed();
    let rate = records as f64 / total.as_secs_f64();
    println!(
        "append SQLite       {records} records in {:.3}s  ({rate:.1} rec/sec)",
        total.as_secs_f64()
    );
    report("append latency", &samples);
}

fn bench_verify(records: u64) {
    let dir = tempfile::tempdir().expect("tempdir");
    let mut backend = SqliteBackend::open(dir.path().join("verify.db")).expect("open");
    let kp = HybridKeypair::generate().expect("kp");
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
        stream_id: "bench/verify".into(),
        sequence: 0,
        occurred_at: OffsetDateTime::now_utc(),
        received_at: OffsetDateTime::now_utc(),
        schema_version: SCHEMA_VERSION.into(),
        source_sdk: "glassbox-bench".into(),
        key_id: "k".into(),
        prev_hash_hex: hex::encode([0u8; 32]),
        body: RecordBody::KeyRegistry(entry),
    };
    let sr0 = sign_record(r0, &kp).expect("sign");
    let mut prev: [u8; 32] = hex::decode(&sr0.this_hash_hex)
        .expect("hex")
        .try_into()
        .expect("32");
    backend.append(sr0).expect("append");
    for i in 1..=records {
        let r = make_interaction(
            "bench/verify",
            i,
            OffsetDateTime::now_utc(),
            OffsetDateTime::now_utc(),
            prev,
            "k",
            "glassbox-bench",
            InteractionBody::default(),
        )
        .expect("make_interaction");
        let sr = sign_record(r, &kp).expect("sign");
        prev = hex::decode(&sr.this_hash_hex)
            .expect("hex")
            .try_into()
            .expect("32");
        backend.append(sr).expect("append");
    }

    let t = Instant::now();
    let report = glassbox_storage::verify_stream(&backend, "bench/verify").expect("verify");
    let total = t.elapsed();
    assert!(report.is_ok(), "verify failed: {:?}", report.failure);
    let walked = report.records_walked;
    let rate = walked as f64 / total.as_secs_f64();
    println!(
        "verify              {walked} records in {:.3}s  ({rate:.1} rec/sec)",
        total.as_secs_f64()
    );
}

fn report(label: &str, samples: &[Duration]) {
    if samples.is_empty() {
        println!("{label}: no samples");
        return;
    }
    let mut us: Vec<u128> = samples.iter().map(Duration::as_micros).collect();
    us.sort_unstable();
    let p = |q: f64| -> u128 {
        let idx = ((us.len() as f64) * q) as usize;
        us[idx.min(us.len() - 1)]
    };
    let p50 = p(0.50);
    let p99 = p(0.99);
    let p999 = p(0.999);
    let mean: u128 = us.iter().sum::<u128>() / us.len() as u128;
    println!(
        "{label:32}  n={:5} mean={mean}μs p50={p50}μs p99={p99}μs p999={p999}μs",
        samples.len()
    );
}

fn rustc_version() -> &'static str {
    option_env!("RUSTC_SEMVER").unwrap_or("unknown")
}

fn profile() -> &'static str {
    if cfg!(debug_assertions) {
        "dev (debug — performance numbers will be much lower than release)"
    } else {
        "release"
    }
}
