//! Generator for the canonical-form regression corpus.
//!
//! Run:
//!
//! ```sh
//! cargo run --example gen_corpus -p glassbox-core
//! ```
//!
//! Writes `crates/glassbox-core/tests/corpus/canonical_corpus.jsonl`,
//! a JSON-Lines file with one curated input per line plus its expected
//! SHA-256 canonical hash. The companion test `tests/corpus.rs` reads
//! the file back and asserts that every entry's hash is reproducible
//! from the canonicalizer in this build.
//!
//! The generator is deterministic: seeded by a fixed `u64`, so running
//! it twice on the same code produces byte-identical output. If a
//! cryptographic-grade change to canonical form ever lands, regenerate
//! the corpus deliberately and review every diff.

#![allow(missing_docs, clippy::missing_panics_doc)]

use std::fs;
use std::io::Write as _;
use std::path::PathBuf;

use glassbox_core::canonical;

fn main() {
    let target = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("corpus")
        .join("canonical_corpus.jsonl");
    fs::create_dir_all(target.parent().unwrap()).unwrap();
    let mut f = fs::File::create(&target).unwrap();

    // 2000 entries is enough to catch any canonical-form drift while
    // keeping the on-disk corpus under ~5 MB. The 10^5 cross-language
    // target in spec §26.2 lives outside this single-language file.
    let entries: Vec<serde_json::Value> = build_corpus(2_000);
    for (idx, value) in entries.iter().enumerate() {
        let bytes = canonical::canonicalize(value).unwrap();
        let hash = canonical::sha256(&bytes);
        let line = serde_json::json!({
            "id": idx,
            "value": value,
            "canonical_b64": base64ct::Base64::encode_string(&bytes),
            "hash_hex": hex::encode(hash),
        });
        writeln!(f, "{line}").unwrap();
    }

    println!("wrote {} entries to {}", entries.len(), target.display());
}

use base64ct::{Base64, Encoding as _};

/// Deterministic xorshift64* PRNG. Fine for shuffling test cases.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn range(&mut self, n: usize) -> usize {
        (self.next() as usize) % n
    }
    fn bool(&mut self) -> bool {
        self.next() & 1 == 1
    }
}

fn build_corpus(target: usize) -> Vec<serde_json::Value> {
    let mut out: Vec<serde_json::Value> = Vec::with_capacity(target);

    // Curated edge cases first. Each one exercises a specific RFC 8785
    // requirement we don't want to regress on.
    out.extend(curated_edges());

    // Algorithmic fill to reach the target count.
    let mut rng = Rng(0xC0FF_EEDE_ADBE_EF42);
    while out.len() < target {
        out.push(random_value(&mut rng, 0));
    }
    out
}

fn curated_edges() -> Vec<serde_json::Value> {
    use serde_json::{Map, Value, json};
    let mut v = Vec::new();

    // 1. Empty structures.
    v.push(json!({}));
    v.push(json!([]));
    v.push(json!(""));
    v.push(json!(null));

    // 2. Booleans + integers + negatives + zero forms.
    v.push(json!(true));
    v.push(json!(false));
    v.push(json!(0));
    v.push(json!(-0));
    v.push(json!(1));
    v.push(json!(-1));
    v.push(json!(i64::MAX));
    v.push(json!(i64::MIN));
    v.push(json!(u64::MAX));

    // 3. Key-order canonicalisation. Both forms must produce the same
    //    canonical bytes; we record only the unordered form so the
    //    canonicalizer has work to do.
    v.push(json!({"c": 3, "b": 2, "a": 1}));
    v.push(json!({"z": {"y": 1, "x": 2}, "a": [3, 2, 1]}));
    v.push(json!({"a":[{"z":1,"a":2},{"b":3,"a":4}],"\u{0041}":"capital a"}));

    // 4. Unicode edges. RFC 8785 §3.2.2.2 mandates UTF-16 code-unit
    //    ordering for keys. These pairs differ only by BMP/SMP keys.
    v.push(json!({"\u{007E}": "tilde", "\u{0041}": "A"}));
    v.push(json!({"a": "café", "b": "cafe\u{0301}"})); // NFC vs NFD: distinct after JCS
    v.push(json!({"emoji": "👩‍🚀", "ascii": "x"}));
    v.push(json!({"chinese": "你好", "thai": "สวัสดี"}));
    v.push(json!({"escape": "tab\tnewline\nquote\"backslash\\"}));
    v.push(json!({"control": "\u{0000}\u{0001}\u{001F}"}));

    // 5. Number representation.
    v.push(json!({"int": 0, "fnz": 1.0, "neg": -42}));
    v.push(json!({"big": 9_007_199_254_740_992u64})); // 2^53
    v.push(json!({"small_neg": -9_007_199_254_740_992_i64}));

    // 6. Deep nesting (16 levels).
    let mut deep = json!("leaf");
    for _ in 0..16 {
        deep = json!({"nest": deep});
    }
    v.push(deep);

    // 7. Wide arrays.
    v.push(Value::Array((0..64).map(Value::from).collect()));

    // 8. Wide objects.
    let mut wide = Map::new();
    for i in 0..32 {
        wide.insert(format!("k{i:02}"), Value::from(i));
    }
    v.push(Value::Object(wide));

    // 9. Heterogeneous arrays.
    v.push(json!([1, "two", null, true, [3, 4], {"x": 5}]));

    // 10. Realistic record shape (mirrors InteractionBody minus signing).
    v.push(json!({
        "input":  {"hash_algorithm": "SHA-256", "hash_hex": "ba7816bf", "byte_size": 3},
        "output": {"hash_algorithm": "SHA-256", "hash_hex": "00", "byte_size": 0},
        "model":  {"provider": "anthropic", "model_name": "claude-opus-4-7", "model_version": "v"},
        "tags":   [{"key": "decision_id", "value": "loan-1"}],
        "metadata": {"z": 1, "a": 2}
    }));

    v
}

fn random_value(rng: &mut Rng, depth: usize) -> serde_json::Value {
    if depth > 4 {
        return random_scalar(rng);
    }
    match rng.range(8) {
        0..=2 => random_scalar(rng),
        3..=4 => random_array(rng, depth),
        _ => random_object(rng, depth),
    }
}

fn random_scalar(rng: &mut Rng) -> serde_json::Value {
    match rng.range(8) {
        0 => serde_json::Value::Null,
        1 => serde_json::Value::Bool(rng.bool()),
        2 => serde_json::Value::from(rng.next() as i64),
        3 => serde_json::Value::from(-(rng.next() as i64).abs()),
        4 => serde_json::Value::from(rng.next()),
        5 => serde_json::Value::from(random_string(rng, 8)),
        6 => serde_json::Value::from(random_unicode_string(rng)),
        _ => serde_json::Value::from(String::new()),
    }
}

fn random_array(rng: &mut Rng, depth: usize) -> serde_json::Value {
    let n = rng.range(4);
    let mut out = Vec::with_capacity(n);
    for _ in 0..n {
        out.push(random_value(rng, depth + 1));
    }
    serde_json::Value::Array(out)
}

fn random_object(rng: &mut Rng, depth: usize) -> serde_json::Value {
    let n = rng.range(4);
    let mut out = serde_json::Map::new();
    for _ in 0..n {
        let key = random_string(rng, 4);
        out.insert(key, random_value(rng, depth + 1));
    }
    serde_json::Value::Object(out)
}

fn random_string(rng: &mut Rng, max_len: usize) -> String {
    let len = rng.range(max_len) + 1;
    let alphabet: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_/.";
    let mut s = String::with_capacity(len);
    for _ in 0..len {
        let idx = rng.range(alphabet.len());
        s.push(alphabet[idx] as char);
    }
    s
}

fn random_unicode_string(rng: &mut Rng) -> String {
    let chunks: &[&str] = &[
        "café",
        "naïve",
        "Москва",
        "東京",
        "🔒",
        "👩‍🚀",
        "🇪🇺",
        "\u{0000}",
        "\u{007F}",
        "𝄞",
    ];
    let count = rng.range(3) + 1;
    let mut s = String::new();
    for _ in 0..count {
        s.push_str(chunks[rng.range(chunks.len())]);
    }
    s
}

// Re-export the Encoding trait via the explicit `use` above so the
// example compiles whether or not the consumer pulls base64ct in.
const _: Option<&dyn Fn() -> String> = Some(&|| Base64::encode_string(b""));
