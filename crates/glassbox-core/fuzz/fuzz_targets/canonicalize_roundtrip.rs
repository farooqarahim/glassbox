//! Fuzz target: canonicalize-then-parse-then-canonicalize should be
//! a fixed point. The first canonicalization may collapse some legal
//! variation (key order, whitespace); after that, the bytes must be
//! invariant under any number of further round trips.
//!
//! A failure here means RFC 8785 was violated by the canonicalizer for
//! some input the fuzzer found — a cryptographic-bar bug.

#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Ok(value) = serde_json::from_slice::<serde_json::Value>(data) else {
        return;
    };
    let Ok(canon1) = glassbox_core::canonical::canonicalize(&value) else {
        return;
    };
    let value2: serde_json::Value =
        serde_json::from_slice(&canon1).expect("canonical bytes must reparse");
    let canon2 =
        glassbox_core::canonical::canonicalize(&value2).expect("canonical reparse must succeed");
    assert_eq!(canon1, canon2, "canonical form is not a fixed point");
});
