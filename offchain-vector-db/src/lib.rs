//! Off-chain client library for `pallet_vector_db`.
//! Exposes all 7 pallet extrinsic clients plus shared chunk-storage and
//! Merkle infrastructure. `main.rs` is a thin smoke-test binary built on
//! top of this library; integration tests also depend on it directly.

pub mod merkle;

use merkle::{build_merkle_tree, generate_inclusion_proof, Blake2bHasher};
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
pub const PALLET_NAME: &str = "VectorDb";

/// On-chain `MAX_CHUNK_LEN` from `pallet_vector_db`. Must stay in lockstep
/// with the pallet's `BoundedVec<u8, ConstU32<1024>>` chunk bound.
pub const MAX_CHUNK_LEN: usize = 1024;

/// On-chain metadata bound. Adjust to match `T::MaxMetadataLen` if the
/// pallet's `Config` trait defines a different constant.
pub const MAX_METADATA_LEN: usize = 256;

/// On-chain `MAX_PROOF_DEPTH` from `pallet_vector_db`. Must stay in
/// lockstep with `BoundedVec<[u8; 32], ConstU32<32>>` on the proof arg.
pub const MAX_PROOF_DEPTH: usize = 32;

pub type Did = [u8; 32];
pub type MerkleRoot = [u8; 32];
pub type CommitmentId = [u8; 32];

// -----------------------------------------------------------------------
// Local chunk persistence
// -----------------------------------------------------------------------

/// Backend-agnostic persistence for raw chunk payloads, keyed by
/// `commitment_id`. Filesystem implementation below; swap for sled/rocksdb
/// by re-implementing this trait without touching call sites.
pub trait ChunkStore {
    fn persist(&self, commitment_id: CommitmentId, chunks: &[Vec<u8>]) -> io::Result<()>;
    fn load_chunk(&self, commitment_id: CommitmentId, index: u64) -> io::Result<Vec<u8>>;
    fn rekey(&self, old_id: CommitmentId, new_id: CommitmentId) -> io::Result<()>;
}

pub struct FsChunkStore {
    root_dir: PathBuf,
}

impl FsChunkStore {
    pub fn new<P: AsRef<Path>>(root_dir: P) -> Self {
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
pub enum RegisterCommitmentError {
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

#[derive(Debug)]
pub struct RegisterCommitmentResult {
    pub commitment_id: CommitmentId,
    pub merkle_root: MerkleRoot,
    pub total_chunks: u64,
}

/// Chunks `payload`, derives its Merkle root, submits `register_commitment`,
/// waits for finalization, reads back the on-chain-derived `commitment_id`
/// from the emitted event, and persists chunks under that final key.
///
/// Chunks are staged under a temporary key (blake2_256 of the payload)
/// before submission — the true `commitment_id` depends on `current_block`
/// at inclusion time and cannot be predicted client-side.
pub async fn register_commitment<S: ChunkStore>(
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

    let field_values = event_details
        .field_values()
        .map_err(|_| RegisterCommitmentError::EventMissing)?;
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

// -----------------------------------------------------------------------
// acknowledge_commitment client
// -----------------------------------------------------------------------

/// Pre-submission and transport errors only. On-chain `Error<T>` variants
/// (CommitmentNotFound, NotPending, ConsumerNotEligible, etc.) surface via
/// `subxt::Error` from the dispatch result and are not re-modeled here.
#[derive(Debug, thiserror::Error)]
pub enum AcknowledgeCommitmentError {
    #[error("subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("CommitmentAcknowledged event not found in finalized block")]
    EventMissing,
}

/// Consumer-side acknowledgement: transitions `commitment_id` from
/// `Pending` to `Active`. Caller must be the `consumer_did`'s registered
/// controller — enforced on-chain, not re-validated here.
pub async fn acknowledge_commitment(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl Signer<PolkadotConfig> + Send + Sync),
    commitment_id: CommitmentId,
    consumer_did: Did,
) -> Result<(), AcknowledgeCommitmentError> {
    let tx = subxt::dynamic::tx(
        PALLET_NAME,
        "acknowledge_commitment",
        vec![Value::from_bytes(commitment_id), Value::from_bytes(consumer_did)],
    );

    let events = client
        .tx()
        .sign_and_submit_then_watch_default(&tx, signer)
        .await?
        .wait_for_finalized_success()
        .await?;

    events
        .iter()
        .filter_map(|e| e.ok())
        .find(|e| e.pallet_name() == PALLET_NAME && e.variant_name() == "CommitmentAcknowledged")
        .ok_or(AcknowledgeCommitmentError::EventMissing)?;

    Ok(())
}

// -----------------------------------------------------------------------
// close_commitment client
// -----------------------------------------------------------------------

/// Pre-submission and transport errors only. On-chain `Error<T>` variants
/// (NotActive, StreamHashMismatch, CommitmentExpiredError, etc.) surface
/// via `subxt::Error` from the dispatch result and are not re-modeled here.
#[derive(Debug, thiserror::Error)]
pub enum CloseCommitmentError {
    #[error("subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("CommitmentSettled event not found in finalized block")]
    EventMissing,
}

/// Consumer-side settlement: submits the final stream hash (must exactly
/// equal the originally committed `merkle_root`) to close an `Active`
/// commitment. Mismatch is a pallet-level rejection, not caught here —
/// this client does not independently recompute the expected hash.
pub async fn close_commitment(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl Signer<PolkadotConfig> + Send + Sync),
    commitment_id: CommitmentId,
    consumer_did: Did,
    final_stream_hash: MerkleRoot,
    chunk_count: u64,
) -> Result<(), CloseCommitmentError> {
    let tx = subxt::dynamic::tx(
        PALLET_NAME,
        "close_commitment",
        vec![
            Value::from_bytes(commitment_id),
            Value::from_bytes(consumer_did),
            Value::from_bytes(final_stream_hash),
            Value::u128(chunk_count as u128),
        ],
    );

    let events = client
        .tx()
        .sign_and_submit_then_watch_default(&tx, signer)
        .await?
        .wait_for_finalized_success()
        .await?;

    events
        .iter()
        .filter_map(|e| e.ok())
        .find(|e| e.pallet_name() == PALLET_NAME && e.variant_name() == "CommitmentSettled")
        .ok_or(CloseCommitmentError::EventMissing)?;

    Ok(())
}

// -----------------------------------------------------------------------
// raise_dispute client
// -----------------------------------------------------------------------

/// Pre-submission and transport errors only. On-chain `Error<T>` variants
/// (NotActive, DisputeAlreadyRaised, ConsumerNotEligible, etc.) surface
/// via `subxt::Error` from the dispatch result and are not re-modeled here.
#[derive(Debug, thiserror::Error)]
pub enum RaiseDisputeError {
    #[error("subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("DisputeRaised event not found in finalized block")]
    EventMissing,
}

/// Consumer-side dispute initiation: flags a mismatch between the
/// originally committed data and what was actually received off-chain.
/// `disputed_chunk_index` identifies WHICH chunk is being disputed --
/// `counter_dispute` will later be bound to exactly this index, so it
/// must be correct. `received_chunk_hash` is the consumer's
/// locally-computed hash of the corrupted/suspect chunk -- not
/// re-derived here, caller supplies it. Opens the provider's response
/// window (`counter_deadline`); a second dispute on the same
/// `commitment_id` is rejected on-chain.
pub async fn raise_dispute(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl Signer<PolkadotConfig> + Send + Sync),
    commitment_id: CommitmentId,
    consumer_did: Did,
    disputed_chunk_index: u64,
    received_chunk_hash: [u8; 32],
    chunk_count: u64,
) -> Result<(), RaiseDisputeError> {
    let tx = subxt::dynamic::tx(
        PALLET_NAME,
        "raise_dispute",
        vec![
            Value::from_bytes(commitment_id),
            Value::from_bytes(consumer_did),
            Value::u128(disputed_chunk_index as u128),
            Value::from_bytes(received_chunk_hash),
            Value::u128(chunk_count as u128),
        ],
    );

    let events = client
        .tx()
        .sign_and_submit_then_watch_default(&tx, signer)
        .await?
        .wait_for_finalized_success()
        .await?;

    events
        .iter()
        .filter_map(|e| e.ok())
        .find(|e| e.pallet_name() == PALLET_NAME && e.variant_name() == "DisputeRaised")
        .ok_or(RaiseDisputeError::EventMissing)?;

    Ok(())
}

// -----------------------------------------------------------------------
// finalize_dispute client
// -----------------------------------------------------------------------

/// Pre-submission and transport errors only. On-chain `Error<T>` variants
/// (NotDisputed, DisputeWindowStillOpen, etc.) surface via `subxt::Error`
/// from the dispatch result and are not re-modeled here.
#[derive(Debug, thiserror::Error)]
pub enum FinalizeDisputeError {
    #[error("subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("DisputeFinalized event not found in finalized block")]
    EventMissing,
}

/// Permissionless: any signed account may finalize a dispute once its
/// `counter_deadline` has lapsed without a provider response. Always
/// resolves to `ProviderGuilty` -- there is no alternate verdict path
/// through this extrinsic (a timely `counter_dispute` prevents reaching
/// this state at all).
pub async fn finalize_dispute(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl Signer<PolkadotConfig> + Send + Sync),
    commitment_id: CommitmentId,
) -> Result<(), FinalizeDisputeError> {
    let tx = subxt::dynamic::tx(PALLET_NAME, "finalize_dispute", vec![Value::from_bytes(commitment_id)]);

    let events = client
        .tx()
        .sign_and_submit_then_watch_default(&tx, signer)
        .await?
        .wait_for_finalized_success()
        .await?;

    events
        .iter()
        .filter_map(|e| e.ok())
        .find(|e| e.pallet_name() == PALLET_NAME && e.variant_name() == "DisputeFinalized")
        .ok_or(FinalizeDisputeError::EventMissing)?;

    Ok(())
}

// -----------------------------------------------------------------------
// expire_commitment client
// -----------------------------------------------------------------------

/// Pre-submission and transport errors only. On-chain `Error<T>` variants
/// (AlreadyFinalized, NotYetExpired, etc.) surface via `subxt::Error` from
/// the dispatch result and are not re-modeled here.
#[derive(Debug, thiserror::Error)]
pub enum ExpireCommitmentError {
    #[error("subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("CommitmentExpired event not found in finalized block")]
    EventMissing,
}

/// Permissionless cleanup: purges a `Pending` or `Active` commitment that
/// has passed `expires_at` without acknowledgement or settlement. Any
/// signed account may call this -- it is a storage-reclamation operation,
/// not a party-specific action.
pub async fn expire_commitment(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl Signer<PolkadotConfig> + Send + Sync),
    commitment_id: CommitmentId,
) -> Result<(), ExpireCommitmentError> {
    let tx = subxt::dynamic::tx(PALLET_NAME, "expire_commitment", vec![Value::from_bytes(commitment_id)]);

    let events = client
        .tx()
        .sign_and_submit_then_watch_default(&tx, signer)
        .await?
        .wait_for_finalized_success()
        .await?;

    events
        .iter()
        .filter_map(|e| e.ok())
        .find(|e| e.pallet_name() == PALLET_NAME && e.variant_name() == "CommitmentExpired")
        .ok_or(ExpireCommitmentError::EventMissing)?;

    Ok(())
}

// -----------------------------------------------------------------------
// counter_dispute client
// -----------------------------------------------------------------------

/// Pre-submission and transport errors only. On-chain `Error<T>` variants
/// (NotDisputed, DisputeWindowExpired, InvalidMerkleProof, etc.) surface
/// via `subxt::Error` from the dispatch result and are not re-modeled here.
#[derive(Debug, thiserror::Error)]
pub enum CounterDisputeError {
    #[error("chunk_data exceeds MAX_CHUNK_LEN ({0} > {1})")]
    ChunkTooLarge(usize, usize),
    #[error("merkle proof exceeds MAX_PROOF_DEPTH ({0} > {1}); tree too deep for on-chain bound")]
    ProofTooDeep(usize, usize),
    #[error("chunk_index {0} out of bounds for total_chunks {1}")]
    ChunkIndexOutOfBounds(u64, u64),
    #[error("subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("storage error: {0}")]
    Storage(#[from] io::Error),
    #[error("DisputeCountered event not found in finalized block")]
    EventMissing,
}

/// Reassembles the full chunk set for `commitment_id` from local storage,
/// in positional order. Required to rebuild the exact Merkle tree whose
/// root matches the on-chain `commitment.merkle_root` — a partial or
/// misordered set produces a structurally different (and useless) tree.
pub fn load_all_chunks<S: ChunkStore>(
    store: &S,
    commitment_id: CommitmentId,
    total_chunks: u64,
) -> io::Result<Vec<Vec<u8>>> {
    (0..total_chunks).map(|i| store.load_chunk(commitment_id, i)).collect()
}

/// Refutes an open dispute for `commitment_id` at `chunk_index` by
/// reloading the original chunk from local storage, rebuilding the
/// Merkle tree, generating an inclusion proof, and submitting
/// `counter_dispute`. Fails closed: any bound violation is caught
/// client-side before submission rather than left for pallet rejection.
pub async fn counter_dispute<S: ChunkStore>(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl Signer<PolkadotConfig> + Send + Sync),
    store: &S,
    commitment_id: CommitmentId,
    provider_did: Did,
    disputed_chunk_index: u64,
    total_chunks: u64,
) -> Result<(), CounterDisputeError> {
    if disputed_chunk_index >= total_chunks {
        return Err(CounterDisputeError::ChunkIndexOutOfBounds(disputed_chunk_index, total_chunks));
    }

    let chunks = load_all_chunks(store, commitment_id, total_chunks)?;

    let target_chunk = chunks[disputed_chunk_index as usize].clone();
    if target_chunk.len() > MAX_CHUNK_LEN {
        return Err(CounterDisputeError::ChunkTooLarge(target_chunk.len(), MAX_CHUNK_LEN));
    }

    // Rebuild the tree from the full local chunk set — proof siblings must
    // come from the same tree whose root was originally committed on-chain.
    let (_root, tree) = build_merkle_tree(&chunks);
    let proof_hashes = generate_inclusion_proof(&tree, disputed_chunk_index as usize);
    if proof_hashes.len() > MAX_PROOF_DEPTH {
        return Err(CounterDisputeError::ProofTooDeep(proof_hashes.len(), MAX_PROOF_DEPTH));
    }

    // --- subxt dynamic call construction ------------------------------------
    // Argument order MUST match the on-chain extrinsic signature exactly:
    // (commitment_id, provider_did, chunk_data, merkle_proof). The pallet
    // no longer accepts a caller-supplied chunk_index -- it reads
    // `disputed_chunk_index` back from the DisputeRecord set by
    // `raise_dispute`, so this client's `disputed_chunk_index` param is
    // used only to pick the right local chunk/proof, not sent on-chain.
    let tx = subxt::dynamic::tx(
        PALLET_NAME,
        "counter_dispute",
        vec![
            Value::from_bytes(commitment_id),
            Value::from_bytes(provider_did),
            Value::from_bytes(target_chunk),
            Value::unnamed_composite(proof_hashes.into_iter().map(Value::from_bytes)),
        ],
    );

    let events = client
        .tx()
        .sign_and_submit_then_watch_default(&tx, signer)
        .await?
        .wait_for_finalized_success()
        .await?;

    // Confirm resolution actually landed — absence here means the tx was
    // finalized but the pallet did not emit the expected event, which
    // should never happen on success and warrants surfacing as an error
    // rather than being silently treated as "probably fine".
    events
        .iter()
        .filter_map(|e| e.ok())
        .find(|e| e.pallet_name() == PALLET_NAME && e.variant_name() == "DisputeCountered")
        .ok_or(CounterDisputeError::EventMissing)?;

    Ok(())
}
