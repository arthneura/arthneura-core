//! Cryptographic data slicing and Merkle proof generation engine.

use rs_merkle::{algorithms::Blake2b, Hasher, MerkleTree};
use std::fs::File;
use std::io::{Error as IoError, Read};
use std::path::Path;

/// Slices a raw file into sequential chunks of a specified maximum size.
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

/// Builds a Blake2b Merkle tree from raw bytes chunks.
/// Returns the derived 32-byte root and the generated Merkle tree.
pub fn build_merkle_tree(chunks: &[Vec<u8>]) -> ([u8; 32], MerkleTree<Blake2b>) {
    let leaves: Vec<[u8; 32]> = chunks
        .iter()
        .map(|chunk| Blake2b::hash(chunk))
        .collect();

    let tree = MerkleTree::<Blake2b>::from_leaves(&leaves);
    let root = tree.root().expect("Merkle tree must evaluate to a valid root");
    (root, tree)
}

/// Generates a positional Merkle inclusion proof for a target chunk index.
pub fn generate_inclusion_proof(tree: &MerkleTree<Blake2b>, leaf_index: usize) -> Vec<[u8; 32]> {
    let proof = tree.proof(&[leaf_index]);
    proof.proof_hashes().to_vec()
}