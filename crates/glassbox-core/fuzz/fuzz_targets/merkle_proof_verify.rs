//! Fuzz target: the Merkle proof verifier must terminate and return
//! cleanly (Ok or Err) on any input. Panics are denial-of-service.

#![no_main]

use libfuzzer_sys::fuzz_target;

use arbitrary::Arbitrary;

#[derive(Debug, Arbitrary)]
struct Input {
    leaf: [u8; 32],
    root: [u8; 32],
    steps: Vec<MerkleStep>,
}

#[derive(Debug, Arbitrary)]
struct MerkleStep {
    sibling: [u8; 32],
    sibling_is_right: bool,
}

fuzz_target!(|input: Input| {
    let steps: Vec<glassbox_core::merkle::ProofStep> = input
        .steps
        .into_iter()
        .map(|s| glassbox_core::merkle::ProofStep {
            sibling: s.sibling,
            sibling_is_right: s.sibling_is_right,
        })
        .collect();
    let _ = glassbox_core::merkle::verify_proof(&input.leaf, &steps, &input.root);
});
