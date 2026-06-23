# Fuzz harnesses for `glassbox-core`

These targets exercise the cryptographic and shape-validation surfaces
that the spec §11.2 marks as airframe-grade. A panic or assertion
failure under fuzzing is a security issue and follows the disclosure
process in [../../../SECURITY.md](../../../SECURITY.md).

## Targets

| Target | What it asserts |
|---|---|
| `canonicalize_roundtrip` | RFC 8785 canonical form is a fixed point under canonicalize → parse → canonicalize. |
| `signed_record_deserialize` | The verifier's shape checks terminate without panic on arbitrary bytes. |
| `merkle_proof_verify` | The Merkle proof verifier terminates and returns cleanly on any input. |

## Running

`cargo-fuzz` requires nightly Rust and `cargo install cargo-fuzz`.

```sh
# from the workspace root
rustup install nightly
cargo install cargo-fuzz

cd crates/glassbox-core
cargo +nightly fuzz run canonicalize_roundtrip -- -max_total_time=300
cargo +nightly fuzz run signed_record_deserialize -- -max_total_time=300
cargo +nightly fuzz run merkle_proof_verify -- -max_total_time=300
```

The fuzz subproject deliberately declares its own empty `[workspace]`
table in `Cargo.toml` so it is **not** a member of the main glassbox
workspace; stable Rust still builds and tests the rest of the repo
without touching nightly tooling.

## Corpus

Seed corpora live under `fuzz/corpus/<target>/` after the first run.
They are reproducible from the fixed-seed `gen_corpus` example in
`crates/glassbox-core/examples/gen_corpus.rs`.
