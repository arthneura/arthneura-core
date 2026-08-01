//! Cryptographic data slicing and Merkle proof generation engine.
//!
//! `Blake2bHasher` mirrors `pallet_vector_db::Blake2bHasher` exactly
//! (`sp_io::hashing::blake2_256`). The previous implementation used
//! `rs_merkle::algorithms::Blake2b`, which is NOT the same hash function
//! as Substrate's runtime blake2b — roots computed off-chain never matched
//! on-chain `merkle_root`, and every `counter_dispute` proof would have
//! failed `rs_merkle::MerkleProof::verify` at the pallet boundary.

use rs_merkle::{Hasher, MerkleTree};
use sp_core::blake2_256;
use std::fs::File;
use std::io::{Error as IoError, Read};
use std::path::Path;

/// Off-chain mirror of `pallet_vector_db::Blake2bHasher`. Byte-for-byte
/// parity with the on-chain implementation is a hard invariant — any
/// divergence here silently invalidates every dispute proof submitted.
#[derive(Clone)]
pub struct Blake2bHasher;

impl Hasher for Blake2bHasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        blake2_256(data)
    }

    /// Sibling concatenation order (left || right) must match the on-chain
    /// implementation; swapping order desyncs every non-leaf node hash.
    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
        match right {
            Some(r) => {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(left);
                buf[32..].copy_from_slice(r);
                blake2_256(&buf)
            }
            None => *left,
        }
    }
}

/// Slices a raw file into sequential chunks of a specified maximum size.
/// Caller is responsible for enforcing `MAX_CHUNK_LEN` (1024) from the
/// on-chain pallet — this function performs no bound validation itself.
pub fn slice_file_into_chunks(file_path: &Path, chunk_size: usize) -> Result<Vec<Vec<u8>>, IoError> {
    let mut file = File::open(file_path)?;
    let mut chunks = Vec::new();
    let mut buffer = vec![0u8; chunk_size];
    loop {
        let bytes_read = file.read(&mut buffer)?;
        if bytes_read == 0 {
            break;
        }
        chunks.push(buffer[..bytes_read].to_vec());
    }
    Ok(chunks)
}

/// Builds a Blake2b (blake2_256-parity) Merkle tree from raw byte chunks.
/// Returns the derived 32-byte root and the generated Merkle tree.
/// Leaf ordering is positional and gapless — it is the `chunk_index`
/// domain that `counter_dispute` verifies against on-chain.
pub fn build_merkle_tree(chunks: &[Vec<u8>]) -> ([u8; 32], MerkleTree<Blake2bHasher>) {
    let leaves: Vec<[u8; 32]> = chunks.iter().map(|chunk| Blake2bHasher::hash(chunk)).collect();
    let tree = MerkleTree::<Blake2bHasher>::from_leaves(&leaves);
    let root = tree.root().expect("Merkle tree must evaluate to a valid root");
    (root, tree)
}

/// Generates a positional Merkle inclusion proof for a target chunk index.
/// Sibling ordering matches `rs_merkle::MerkleProof<Blake2bHasher>::verify`
/// as invoked by `pallet_vector_db::counter_dispute` on-chain.
pub fn generate_inclusion_proof(tree: &MerkleTree<Blake2bHasher>, leaf_index: usize) -> Vec<[u8; 32]> {
    let proof = tree.proof(&[leaf_index]);
    proof.proof_hashes().to_vec()
}
