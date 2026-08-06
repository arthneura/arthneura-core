//! Cross-crate parity suite: off-chain `merkle::Blake2bHasher` vs the actual
//! on-chain `pallet_vector_db::Blake2bHasher` (imported as a dev-dependency,
//! not re-implemented). This is the highest-priority correctness check in
//! the workspace — every downstream extrinsic client (register_commitment,
//! counter_dispute) is worthless if this diverges, since committed roots
//! and dispute proofs would silently fail on-chain verification without
//! ever raising a compile or type error.
//!
//! `#[path]` include is required because `offchain-vector-db` is a binary
//! crate (no `lib.rs`); standard `tests/*.rs` files cannot `use` a module
//! from a bin target, so `merkle.rs` is pulled in directly by path.

#[path = "../src/merkle.rs"]
mod merkle;

use merkle::{build_merkle_tree, generate_inclusion_proof, Blake2bHasher};
use rs_merkle::{Hasher, MerkleProof, MerkleTree};

/// Single-leaf hash parity: `sp_core::blake2_256` (off-chain, native)
/// vs `sp_io::hashing::blake2_256` (on-chain, as used by the pallet).
#[test]
fn leaf_hash_matches_onchain_hasher() {
    let data = b"arthneura-parity-check-vector-01";
    let offchain = Blake2bHasher::hash(data);
    let onchain = pallet_vector_db::Blake2bHasher::hash(data);
    assert_eq!(offchain, onchain, "leaf hash diverges from on-chain Blake2bHasher");
}

/// Sibling concatenation parity, both branches: two-child node and the
/// odd-leaf promotion case (`right = None`) used at tree-depth boundaries.
#[test]
fn concat_and_hash_matches_onchain_hasher() {
    let left = Blake2bHasher::hash(b"left-leaf");
    let right = Blake2bHasher::hash(b"right-leaf");

    let offchain_pair = Blake2bHasher::concat_and_hash(&left, Some(&right));
    let onchain_pair = pallet_vector_db::Blake2bHasher::concat_and_hash(&left, Some(&right));
    assert_eq!(offchain_pair, onchain_pair, "sibling concat hash diverges from on-chain Blake2bHasher");

    let offchain_single = Blake2bHasher::concat_and_hash(&left, None);
    let onchain_single = pallet_vector_db::Blake2bHasher::concat_and_hash(&left, None);
    assert_eq!(offchain_single, onchain_single, "odd-leaf promotion hash diverges from on-chain Blake2bHasher");
}

/// End-to-end parity: a full multi-chunk tree root, not just isolated
/// hash calls. This is the check that actually matters for
/// `register_commitment`'s `merkle_root` argument.
#[test]
fn full_tree_root_matches_onchain_construction() {
    let chunks: Vec<Vec<u8>> = vec![
        b"chunk-0-payload".to_vec(),
        b"chunk-1-payload".to_vec(),
        b"chunk-2-payload".to_vec(),
    ];

    let (offchain_root, _tree) = build_merkle_tree(&chunks);

    let onchain_leaves: Vec<[u8; 32]> = chunks.iter().map(|c| pallet_vector_db::Blake2bHasher::hash(c)).collect();
    let onchain_tree = MerkleTree::<pallet_vector_db::Blake2bHasher>::from_leaves(&onchain_leaves);
    let onchain_root = onchain_tree.root().expect("on-chain-equivalent tree must produce a root");

    assert_eq!(offchain_root, onchain_root, "full tree root diverges from on-chain construction");
}

/// Inclusion proof parity: a proof generated off-chain must verify against
/// a root computed independently via the on-chain hasher — this is the
/// exact check `counter_dispute` performs on-chain.
#[test]
fn inclusion_proof_verifies_against_onchain_root() {
    let chunks: Vec<Vec<u8>> = (0..5u8).map(|i| vec![i; 64]).collect();
    let (_root, tree) = build_merkle_tree(&chunks);

    let target_index = 2;
    let proof_hashes = generate_inclusion_proof(&tree, target_index);

    let onchain_leaves: Vec<[u8; 32]> = chunks.iter().map(|c| pallet_vector_db::Blake2bHasher::hash(c)).collect();
    let onchain_tree = MerkleTree::<pallet_vector_db::Blake2bHasher>::from_leaves(&onchain_leaves);
    let onchain_root = onchain_tree.root().expect("valid root");

    let onchain_proof = MerkleProof::<pallet_vector_db::Blake2bHasher>::new(proof_hashes);
    let target_leaf = pallet_vector_db::Blake2bHasher::hash(&chunks[target_index]);

    assert!(
        onchain_proof.verify(onchain_root, &[target_index], &[target_leaf], chunks.len()),
        "off-chain-generated proof failed on-chain-equivalent verification"
    );
}
