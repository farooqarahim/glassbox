//! Binary SHA-256 Merkle tree with O(log N) inclusion proofs.
//!
//! Construction follows RFC 6962 (the Certificate Transparency tree):
//!
//! - Leaves are hashed with a 0x00 prefix: `H(0x00 || leaf_bytes)`.
//! - Internal nodes are hashed with a 0x01 prefix:
//!   `H(0x01 || left || right)`.
//! - When a level has an odd count, the last node is **promoted**
//!   (carried up as-is, not duplicated).
//!
//! The prefix discipline prevents second-preimage attacks where a leaf
//! and an internal node could otherwise share the same SHA-256 input.

use crate::canonical::sha256;
use crate::errors::{Error, Result};

/// Domain-separation prefix for leaf hashes.
const LEAF_PREFIX: u8 = 0x00;
/// Domain-separation prefix for internal node hashes.
const NODE_PREFIX: u8 = 0x01;

/// Hash a single leaf input.
#[must_use]
pub fn hash_leaf(bytes: &[u8]) -> [u8; 32] {
    let mut buf = Vec::with_capacity(1 + bytes.len());
    buf.push(LEAF_PREFIX);
    buf.extend_from_slice(bytes);
    sha256(&buf)
}

/// Hash an internal node from its two children.
#[must_use]
pub fn hash_node(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut buf = [0u8; 1 + 32 + 32];
    buf[0] = NODE_PREFIX;
    buf[1..33].copy_from_slice(left);
    buf[33..].copy_from_slice(right);
    sha256(&buf)
}

/// Compute the Merkle root over a slice of already-hashed leaves.
///
/// The `leaves` slice is the per-record `this_hash` values, in
/// sequence order. Each is wrapped via [`hash_leaf`] before the first
/// level of internal hashing.
pub fn compute_root(leaves: &[[u8; 32]]) -> Result<[u8; 32]> {
    if leaves.is_empty() {
        return Err(Error::Merkle("cannot compute root over zero leaves".into()));
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|h| hash_leaf(h)).collect();
    while level.len() > 1 {
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(hash_node(&level[i], &level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            next.push(level[i]); // odd promotion
        }
        level = next;
    }
    Ok(level[0])
}

/// One step in an inclusion proof: the sibling hash, and whether that
/// sibling sat on the right of the current node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofStep {
    /// The sibling hash at this level.
    pub sibling: [u8; 32],
    /// `true` if the sibling is to the **right** of the current path
    /// (i.e. the path node is the left child); `false` otherwise.
    pub sibling_is_right: bool,
}

/// Build an inclusion proof for `index` over the given leaves.
///
/// Returns the steps in order from the leaf level upward.
pub fn build_proof(leaves: &[[u8; 32]], index: usize) -> Result<Vec<ProofStep>> {
    if leaves.is_empty() {
        return Err(Error::Merkle("cannot build proof over zero leaves".into()));
    }
    if index >= leaves.len() {
        return Err(Error::Merkle(format!(
            "index {index} out of range for {} leaves",
            leaves.len()
        )));
    }
    let mut level: Vec<[u8; 32]> = leaves.iter().map(|h| hash_leaf(h)).collect();
    let mut idx = index;
    let mut steps: Vec<ProofStep> = Vec::new();

    while level.len() > 1 {
        let pair_left = idx & !1;
        let is_right_sibling = idx == pair_left; // we are left, sibling is right
        let sibling_idx = if is_right_sibling { idx + 1 } else { idx - 1 };

        if sibling_idx < level.len() {
            steps.push(ProofStep {
                sibling: level[sibling_idx],
                sibling_is_right: is_right_sibling,
            });
        }
        // promoted odd at the end: no sibling, just advance.

        // build next level
        let mut next: Vec<[u8; 32]> = Vec::with_capacity(level.len().div_ceil(2));
        let mut i = 0;
        while i + 1 < level.len() {
            next.push(hash_node(&level[i], &level[i + 1]));
            i += 2;
        }
        if i < level.len() {
            next.push(level[i]);
        }
        idx /= 2;
        level = next;
    }
    Ok(steps)
}

/// Verify an inclusion proof: starting from `leaf`, apply each step
/// until reaching `root`. Returns `Ok(())` only if the root matches.
pub fn verify_proof(leaf: &[u8; 32], proof: &[ProofStep], root: &[u8; 32]) -> Result<()> {
    let mut acc = hash_leaf(leaf);
    for step in proof {
        acc = if step.sibling_is_right {
            hash_node(&acc, &step.sibling)
        } else {
            hash_node(&step.sibling, &acc)
        };
    }
    if &acc == root {
        Ok(())
    } else {
        Err(Error::Merkle(format!(
            "computed root {} does not match {}",
            hex::encode(acc),
            hex::encode(root)
        )))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fake_leaf(byte: u8) -> [u8; 32] {
        let mut a = [0u8; 32];
        a[0] = byte;
        a
    }

    #[test]
    fn root_of_single_leaf_is_hash_leaf() {
        let l = fake_leaf(1);
        assert_eq!(compute_root(&[l]).unwrap(), hash_leaf(&l));
    }

    #[test]
    fn proof_verifies_for_every_index_in_power_of_two() {
        let leaves: Vec<_> = (0..8u8).map(fake_leaf).collect();
        let root = compute_root(&leaves).unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = build_proof(&leaves, i).unwrap();
            verify_proof(leaf, &proof, &root).unwrap_or_else(|e| panic!("idx {i}: {e:?}"));
        }
    }

    #[test]
    fn proof_verifies_for_odd_count() {
        // 5 leaves exercises odd promotion at multiple levels.
        let leaves: Vec<_> = (0..5u8).map(fake_leaf).collect();
        let root = compute_root(&leaves).unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = build_proof(&leaves, i).unwrap();
            verify_proof(leaf, &proof, &root).unwrap_or_else(|e| panic!("idx {i}: {e:?}"));
        }
    }

    #[test]
    fn proof_verifies_for_seven_leaves() {
        let leaves: Vec<_> = (0..7u8).map(fake_leaf).collect();
        let root = compute_root(&leaves).unwrap();
        for (i, leaf) in leaves.iter().enumerate() {
            let proof = build_proof(&leaves, i).unwrap();
            verify_proof(leaf, &proof, &root).unwrap_or_else(|e| panic!("idx {i}: {e:?}"));
        }
    }

    #[test]
    fn mutated_leaf_fails_verify() {
        let leaves: Vec<_> = (0..4u8).map(fake_leaf).collect();
        let root = compute_root(&leaves).unwrap();
        let proof = build_proof(&leaves, 2).unwrap();
        let mut bad_leaf = leaves[2];
        bad_leaf[0] ^= 0x01;
        assert!(verify_proof(&bad_leaf, &proof, &root).is_err());
    }

    #[test]
    fn second_preimage_resistance_leaf_vs_node() {
        // hash_leaf and hash_node must produce different hashes for
        // the same 64-byte input; the 0x00/0x01 domain prefix is what
        // gives us second-preimage resistance.
        let a = fake_leaf(1);
        let b = fake_leaf(2);
        let mut sixty_four = Vec::new();
        sixty_four.extend_from_slice(&a);
        sixty_four.extend_from_slice(&b);
        assert_ne!(hash_leaf(&sixty_four), hash_node(&a, &b));
    }

    #[test]
    fn empty_leaves_is_an_error() {
        assert!(compute_root(&[]).is_err());
        assert!(build_proof(&[], 0).is_err());
    }
}
