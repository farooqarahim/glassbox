//! Fuzz target: deserialise arbitrary bytes as `SignedRecord` and run
//! the verifier shape checks. A panic here is a denial-of-service vector
//! on the verification API.

#![no_main]

use libfuzzer_sys::fuzz_target;

use glassbox_core::record::SignedRecord;

fuzz_target!(|data: &[u8]| {
    let Ok(sr) = serde_json::from_slice::<SignedRecord>(data) else {
        return;
    };
    // We are not allowed to construct a HybridPublicKey from fuzz
    // bytes; verifying the signature requires the real key. We do
    // exercise canonical_bytes() and validate_shape(), which is where
    // any panic-on-attacker-input would live.
    let _ = sr.record.canonical_bytes();
    let _ = sr.record.validate_shape();
});
