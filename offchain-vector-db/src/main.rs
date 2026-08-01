//! Main entry point for the `offchain-vector-db` companion service.

mod merkle;

use merkle::{build_merkle_tree, Blake2bHasher};
use rs_merkle::Hasher;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use subxt::dynamic::Value;
use subxt::tx::Signer;
use subxt::{OnlineClient, PolkadotConfig};

/// Exact pallet name as registered in `construct_runtime!` — required
/// verbatim, case-sensitive, for dynamic call/event lookup. Confirm
/// against `runtime/src/lib.rs` before first live submission.
const PALLET_NAME: &str = "VectorDb";

/// On-chain `MAX_CHUNK_LEN` from `pallet_vector_db`. Must stay in lockstep
/// with the pallet's `BoundedVec<u8, ConstU32<1024>>` chunk bound.
const MAX_CHUNK_LEN: usize = 1024;

/// On-chain metadata bound. Adjust to match `T::MaxMetadataLen` if the
/// pallet's `Config` trait defines a different constant.
const MAX_METADATA_LEN: usize = 256;

type Did = [u8; 32];
type MerkleRoot = [u8; 32];
type CommitmentId = [u8; 32];

// -----------------------------------------------------------------------
// Local chunk persistence
// -----------------------------------------------------------------------

/// Backend-agnostic persistence for raw chunk payloads, keyed by
/// `commitment_id`. Filesystem implementation below; swap for sled/rocksdb
/// by re-implementing this trait without touching call sites.
trait ChunkStore {
    fn persist(&self, commitment_id: CommitmentId, chunks: &[Vec<u8>]) -> io::Result<()>;
    fn load_chunk(&self, commitment_id: CommitmentId, index: u64) -> io::Result<Vec<u8>>;
    fn rekey(&self, old_id: CommitmentId, new_id: CommitmentId) -> io::Result<()>;
}

struct FsChunkStore {
    root_dir: PathBuf,
}

impl FsChunkStore {
    fn new<P: AsRef<Path>>(root_dir: P) -> Self {
        Self { root_dir: root_dir.as_ref().to_path_buf() }
    }

    fn commitment_dir(&self, commitment_id: CommitmentId) -> PathBuf {
        self.root_dir.join(hex::encode(commitment_id))
    }
}

impl ChunkStore for FsChunkStore {
    /// Writes each chunk as `<index>.bin` under `<root>/<commitment_id_hex>/`.
    /// Overwrites on collision; caller guarantees id uniqueness upstream.
    fn persist(&self, commitment_id: CommitmentId, chunks: &[Vec<u8>]) -> io::Result<()> {
        let dir = self.commitment_dir(commitment_id);
        fs::create_dir_all(&dir)?;
        for (i, chunk) in chunks.iter().enumerate() {
            fs::write(dir.join(format!("{i}.bin")), chunk)?;
        }
        Ok(())
    }

    fn load_chunk(&self, commitment_id: CommitmentId, index: u64) -> io::Result<Vec<u8>> {
        let path = self.commitment_dir(commitment_id).join(format!("{index}.bin"));
        fs::read(path)
    }

    /// Renames the staging directory to the true on-chain `commitment_id`.
    /// Required because the id is derived on-chain (block-number-dependent)
    /// and is unknown until `register_commitment` finalizes.
    fn rekey(&self, old_id: CommitmentId, new_id: CommitmentId) -> io::Result<()> {
        fs::rename(self.commitment_dir(old_id), self.commitment_dir(new_id))
    }
}

// -----------------------------------------------------------------------
// register_commitment client
// -----------------------------------------------------------------------

/// Pre-submission and transport errors only. On-chain `Error<T>` variants
/// surface via `subxt::Error` from the dispatch result and are not
/// re-modeled here.
#[derive(Debug, thiserror::Error)]
enum RegisterCommitmentError {
    #[error("metadata exceeds MAX_METADATA_LEN ({0} > {1})")]
    MetadataTooLarge(usize, usize),
    #[error("payload is empty; total_chunks must be positive on-chain")]
    EmptyPayload,
    #[error("subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("storage error: {0}")]
    Storage(#[from] io::Error),
    #[error("CommitmentRegistered event not found in finalized block")]
    EventMissing,
}

struct RegisterCommitmentResult {
    commitment_id: CommitmentId,
    merkle_root: MerkleRoot,
    total_chunks: u64,
}

/// Chunks `payload`, derives its Merkle root, submits `register_commitment`,
/// waits for finalization, reads back the on-chain-derived `commitment_id`
/// from the emitted event, and persists chunks under that final key.
///
/// Chunks are staged under a temporary key (blake2_256 of the payload)
/// before submission — the true `commitment_id` depends on `current_block`
/// at inclusion time and cannot be predicted client-side.
async fn register_commitment<S: ChunkStore>(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl Signer<PolkadotConfig> + Send + Sync),
    store: &S,
    provider_did: Did,
    consumer_did: Did,
    payload: &[u8],
    metadata: Vec<u8>,
    expires_in_blocks: u32,
) -> Result<RegisterCommitmentResult, RegisterCommitmentError> {
    if metadata.len() > MAX_METADATA_LEN {
        return Err(RegisterCommitmentError::MetadataTooLarge(metadata.len(), MAX_METADATA_LEN));
    }
    if payload.is_empty() {
        return Err(RegisterCommitmentError::EmptyPayload);
    }

    let chunks: Vec<Vec<u8>> = payload.chunks(MAX_CHUNK_LEN).map(|c| c.to_vec()).collect();
    let (root, _tree) = build_merkle_tree(&chunks);
    let total_chunks = chunks.len() as u64;

    // Staging key: content hash of the raw payload — stable regardless of
    // block timing, never exposed on-chain.
    let staging_id: CommitmentId = Blake2bHasher::hash(payload);
    store.persist(staging_id, &chunks)?;

    // --- subxt dynamic call construction ------------------------------------
    // No compile-time metadata file required — the pallet/call are resolved
    // by name against metadata fetched live from `client` at submission time.
    // Argument order MUST match the on-chain extrinsic signature exactly;
    // there is no compiler check for this under the dynamic API.
    let tx = subxt::dynamic::tx(
        PALLET_NAME,
        "register_commitment",
        vec![
            Value::from_bytes(provider_did),
            Value::from_bytes(consumer_did),
            Value::from_bytes(root),
            Value::u128(total_chunks as u128),
            Value::from_bytes(metadata),
            Value::u128(expires_in_blocks as u128),
        ],
    );

    let events = client
        .tx()
        .sign_and_submit_then_watch_default(&tx, signer)
        .await?
        .wait_for_finalized_success()
        .await?;

    // Dynamic event lookup: match by pallet + variant name, then decode
    // fields positionally. Field order/types must match the on-chain
    // `CommitmentRegistered` event definition exactly.
    let event_details = events
        .iter()
        .filter_map(|e| e.ok())
        .find(|e| e.pallet_name() == PALLET_NAME && e.variant_name() == "CommitmentRegistered")
        .ok_or(RegisterCommitmentError::EventMissing)?;

    let field_values = event_details.field_values().map_err(|_| RegisterCommitmentError::EventMissing)?;
    let commitment_id: CommitmentId = decode_fixed_bytes_field(&field_values, 0)
        .ok_or(RegisterCommitmentError::EventMissing)?;

    // Promote staged chunks to their final, on-chain-addressable key.
    store.rekey(staging_id, commitment_id)?;

    Ok(RegisterCommitmentResult { commitment_id, merkle_root: root, total_chunks })
}

/// Extracts the `index`-th field of a dynamic event's composite value as
/// fixed 32-byte data. Returns `None` on shape/length mismatch rather than
/// panicking — a malformed event should surface as `EventMissing`, not a crash.
fn decode_fixed_bytes_field(
    composite: &subxt::ext::scale_value::Composite<u32>,
    index: usize,
) -> Option<[u8; 32]> {
    use subxt::ext::scale_value::{Composite, ValueDef};

    let value = match composite {
        Composite::Unnamed(vals) => vals.get(index)?,
        Composite::Named(vals) => vals.get(index).map(|(_, v)| v)?,
    };

    match &value.value {
        ValueDef::Composite(Composite::Unnamed(bytes)) => {
            let mut out = [0u8; 32];
            if bytes.len() != 32 {
                return None;
            }
            for (i, b) in bytes.iter().enumerate() {
                out[i] = match &b.value {
                    ValueDef::Primitive(p) => p.as_u128()? as u8,
                    _ => return None,
                };
            }
            Some(out)
        }
        _ => None,
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ArthNeura Off-Chain Companion Node Initialized.");
    Ok(())
}
