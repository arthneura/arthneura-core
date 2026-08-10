//! # Pallet Vector DB
//!
//! On-chain Merkle Root commitment registry and transactional dispute adjudicator.
//! Anchors cryptographic Merkle roots to facilitate secure, scalable off-chain data streaming
//! between AI agents. Disputes are resolved via chunk-level Merkle inclusion proofs.

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::weights::Weight;
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

// ── Custom Cryptographic Hasher ──────────────────────────────────────────────

/// Custom Blake2b Hasher implementing rs_merkle::Hasher natively.
///
/// This decouples the on-chain WASM runtime from rs_merkle's std-only hashing libraries,
/// utilizing Substrate's highly optimized sp_io::hashing::blake2_256 directly in no_std.
#[derive(Clone)]
pub struct Blake2bHasher;

impl rs_merkle::Hasher for Blake2bHasher {
    type Hash = [u8; 32];

    fn hash(data: &[u8]) -> Self::Hash {
        sp_io::hashing::blake2_256(data)
    }

    /// Reconstructs sibling node hashes using stack-allocated buffer (no heap allocation).
    fn concat_and_hash(left: &Self::Hash, right: Option<&Self::Hash>) -> Self::Hash {
        match right {
            Some(r) => {
                let mut buf = [0u8; 64];
                buf[..32].copy_from_slice(left);
                buf[32..].copy_from_slice(r);
                sp_io::hashing::blake2_256(&buf)
            }
            None => *left,
        }
    }
}

// ── Cross-Pallet Interface ───────────────────────────────────────────────────

/// Interface for validating off-pallet agent registration and verification states.
pub trait AgentLookup<AccountId> {
    fn controller_of(did: &[u8; 32]) -> Option<AccountId>;
    fn is_active_verified(did: &[u8; 32]) -> bool;
}

impl<AccountId> AgentLookup<AccountId> for () {
    fn controller_of(_did: &[u8; 32]) -> Option<AccountId> {
        None
    }
    fn is_active_verified(_did: &[u8; 32]) -> bool {
        false
    }
}

/// Hook into `pallet-agent-registry`'s reputation ledger, invoked when a
/// dispute resolves. Deliberately fire-and-forget (no `Result`, no
/// `Weight`) -- a protocol-level reputation penalty must never be able
/// to block or revert the caller's own dispute-resolution extrinsic
/// (both `finalize_dispute` and `counter_dispute` are load-bearing for
/// unwinding a `Disputed` commitment; permissionless `finalize_dispute`
/// in particular must always succeed once its preconditions are met).
/// Implementations should silently no-op if `did` can no longer be
/// found (e.g. deregistered mid-dispute) rather than propagate an error.
///
/// Two methods, not one, by design: if only a guilty provider could be
/// penalized, a consumer could raise disputes at zero cost -- free to
/// spam-dispute every delivery on the chance of a payout, since a lost
/// dispute would cost them nothing. `penalize_false_disputer` gives a
/// baseless dispute a real (smaller) cost, closing that incentive gap.
pub trait ReputationHandler {
    /// A provider was found guilty (dispute went uncountered past the
    /// response window, or was countered with an invalid proof).
    fn penalize_provider(did: &Did);
    /// A consumer's dispute was proven baseless -- the provider
    /// successfully countered with a valid proof for the exact disputed
    /// chunk.
    fn penalize_false_disputer(did: &Did);
}

impl ReputationHandler for () {
    fn penalize_provider(_did: &Did) {}
    fn penalize_false_disputer(_did: &Did) {}
}

// ── Pallet Module ────────────────────────────────────────────────────────────

#[frame_support::pallet]
pub mod pallet {
    use crate::{AgentLookup, Blake2bHasher, ReputationHandler, WeightInfo};
    use frame_support::traits::Get;
    use frame_support::{pallet_prelude::*, sp_runtime::Saturating};
    use frame_system::pallet_prelude::*;
    use rs_merkle::MerkleProof;

    // -- Constants ------------------------------------------------------------

    pub const MAX_METADATA_LEN: u32 = 256;
    pub const MAX_CHUNK_LEN: u32 = 1024;
    pub const MAX_PROOF_DEPTH: u32 = 32;

    // -- Core Type Aliases ----------------------------------------------------

    pub type Did = [u8; 32];
    pub type MerkleRoot = [u8; 32];
    pub type ChunkIndex = u64;
    pub type CommitmentId = [u8; 32];

    // -- Commitment Status ----------------------------------------------------

    #[derive(
        Clone,
        Copy,
        PartialEq,
        Eq,
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        MaxEncodedLen,
        RuntimeDebug,
        Default,
    )]
    pub enum CommitmentStatus {
        #[default]
        Pending,
        Active,
        Settled,
        Disputed,
        DisputeResolved,
        Expired,
    }

    // -- Vector Commitment Structure ------------------------------------------

    #[derive(
        Clone,
        PartialEq,
        Eq,
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        MaxEncodedLen,
        RuntimeDebug,
    )]
    #[scale_info(skip_type_params(T))]
    pub struct VectorCommitment<T: Config> {
        pub commitment_id: CommitmentId,
        pub provider: Did,
        pub consumer: Did,
        pub merkle_root: MerkleRoot,
        pub total_chunks: u64,
        pub metadata: BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>,
        pub status: CommitmentStatus,
        pub created_at: BlockNumberFor<T>,
        pub expires_at: BlockNumberFor<T>,
        pub acknowledged_at: Option<BlockNumberFor<T>>,
    }

    // -- Stream Receipt Structure ---------------------------------------------

    #[derive(
        Clone,
        PartialEq,
        Eq,
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        MaxEncodedLen,
        RuntimeDebug,
    )]
    #[scale_info(skip_type_params(T))]
    pub struct StreamReceipt<T: Config> {
        pub commitment_id: CommitmentId,
        pub final_stream_hash: MerkleRoot,
        pub chunk_count: u64,
        pub submitted_at: BlockNumberFor<T>,
    }

    // -- Dispute Verdict ------------------------------------------------------

    #[derive(
        Clone,
        Copy,
        PartialEq,
        Eq,
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        MaxEncodedLen,
        RuntimeDebug,
    )]
    pub enum DisputeVerdict {
        ProviderGuilty,
        ClaimantUnsubstantiated,
    }

    // -- Dispute Record Structure ---------------------------------------------

    #[derive(
        Clone,
        PartialEq,
        Eq,
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        MaxEncodedLen,
        RuntimeDebug,
    )]
    #[scale_info(skip_type_params(T))]
    pub struct DisputeRecord<T: Config> {
        pub commitment_id: CommitmentId,
        pub merkle_root: MerkleRoot,
        pub received_chunk_hash: [u8; 32],
        /// The specific chunk index the consumer is claiming was corrupted.
        /// `counter_dispute` binds its Merkle-proof verification to exactly
        /// this index — the provider can no longer choose which chunk to
        /// prove, closing the loophole where an unrelated-but-valid chunk
        /// could be used to falsely refute a legitimate corruption claim.
        pub disputed_chunk_index: ChunkIndex,
        pub raised_at: BlockNumberFor<T>,
        pub counter_deadline: BlockNumberFor<T>,
        pub verdict: Option<DisputeVerdict>,
    }

    // -- Config Trait ---------------------------------------------------------

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        type WeightInfo: WeightInfo;
        type AgentRegistry: AgentLookup<Self::AccountId>;
        #[pallet::constant]
        type DisputeWindow: Get<BlockNumberFor<Self>>;
        #[pallet::constant]
        type MaxCommitmentLifetime: Get<BlockNumberFor<Self>>;
        /// Reputation-ledger hook, invoked on dispute resolution.
        type ReputationHandler: ReputationHandler;
        /// Reputation points deducted from a provider found guilty.
        /// Deliberately larger than `FalseDisputeSlash` -- failing to
        /// deliver (or defend) is a more severe protocol violation than
        /// a good-faith but mistaken dispute.
        ///
        /// TODO(governance): migrate to a storage-backed, governance-
        /// adjustable value once the governance pallet lands, matching
        /// the same deferred treatment as `DisputeWindow` above.
        #[pallet::constant]
        type ProviderGuiltySlash: Get<u32>;
        /// Reputation points deducted from a consumer whose dispute was
        /// proven baseless. Nonzero so spam-disputing carries real
        /// cost; smaller than `ProviderGuiltySlash` since a mistaken
        /// dispute is less severe than a confirmed bad delivery.
        ///
        /// TODO(governance): see `ProviderGuiltySlash`.
        #[pallet::constant]
        type FalseDisputeSlash: Get<u32>;
    }

    const STORAGE_VERSION: frame_support::traits::StorageVersion =
        frame_support::traits::StorageVersion::new(1);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    // -- Storage Declarations -------------------------------------------------

    #[pallet::storage]
    #[pallet::getter(fn vector_commitment)]
    pub type VectorCommitments<T: Config> =
        StorageMap<_, Blake2_128Concat, CommitmentId, VectorCommitment<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn active_commitment_count)]
    pub type ActiveCommitmentCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    #[pallet::storage]
    #[pallet::getter(fn stream_receipt)]
    pub type StreamReceipts<T: Config> =
        StorageMap<_, Blake2_128Concat, CommitmentId, StreamReceipt<T>, OptionQuery>;

    #[pallet::storage]
    #[pallet::getter(fn dispute_record)]
    pub type DisputeRecords<T: Config> =
        StorageMap<_, Blake2_128Concat, CommitmentId, DisputeRecord<T>, OptionQuery>;

    // -- Events ---------------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        CommitmentRegistered {
            commitment_id: CommitmentId,
            provider: Did,
            consumer: Did,
            merkle_root: MerkleRoot,
            total_chunks: u64,
            expires_at: BlockNumberFor<T>,
        },
        CommitmentAcknowledged {
            commitment_id: CommitmentId,
            acknowledged_at: BlockNumberFor<T>,
        },
        CommitmentSettled {
            commitment_id: CommitmentId,
            final_stream_hash: MerkleRoot,
            chunk_count: u64,
        },
        DisputeRaised {
            commitment_id: CommitmentId,
            merkle_root: MerkleRoot,
            disputed_chunk_index: ChunkIndex,
            received_chunk_hash: [u8; 32],
            counter_deadline: BlockNumberFor<T>,
        },
        DisputeCountered {
            commitment_id: CommitmentId,
            verdict: DisputeVerdict,
        },
        DisputeFinalized {
            commitment_id: CommitmentId,
            verdict: DisputeVerdict,
            provider: Did,
            consumer: Did,
        },
        CommitmentExpired {
            commitment_id: CommitmentId,
        },
    }

    // -- Errors ---------------------------------------------------------------

    #[pallet::error]
    pub enum Error<T> {
        CommitmentAlreadyExists,
        CommitmentNotFound,
        NotProvider,
        NotConsumer,
        ProviderNotEligible,
        ConsumerNotEligible,
        SelfTrade,
        ExpiryMustBePositive,
        ExpiryTooFar,
        CommitmentExpiredError,
        NotPending,
        NotActive,
        NotDisputed,
        AlreadyFinalized,
        StreamHashMismatch,
        InvalidMerkleProof,
        DisputeAlreadyRaised,
        DisputeWindowStillOpen,
        DisputeWindowExpired,
        NotYetExpired,
        TotalChunksMustBePositive,
        InvalidMerkleRoot,
        ChunkIndexOutOfBounds,
    }

    // -- Dispatchables (Extrinsics) -------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Anchors a provider's data-quality Merkle root commitment on-chain.
        ///
        /// Invariants: Provider/consumer DIDs must be active and verified.
        /// Expiry block must be within limits. Commitment ID must be unique.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::register_commitment())]
        pub fn register_commitment(
            origin: OriginFor<T>,
            provider_did: Did,
            consumer_did: Did,
            merkle_root: MerkleRoot,
            total_chunks: u64,
            metadata: BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>,
            expires_in_blocks: BlockNumberFor<T>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            // 1. Prevent self-trades
            ensure!(provider_did != consumer_did, Error::<T>::SelfTrade);
            ensure!(total_chunks > 0, Error::<T>::TotalChunksMustBePositive);
            ensure!(merkle_root != [0u8; 32], Error::<T>::InvalidMerkleRoot);

            // 2. Validate provider controller bounds
            let provider_controller = T::AgentRegistry::controller_of(&provider_did)
                .ok_or(Error::<T>::ProviderNotEligible)?;
            ensure!(provider_controller == caller, Error::<T>::NotProvider);

            // 3. Enforce identity verification and status invariants
            ensure!(
                T::AgentRegistry::is_active_verified(&provider_did),
                Error::<T>::ProviderNotEligible
            );
            ensure!(
                T::AgentRegistry::is_active_verified(&consumer_did),
                Error::<T>::ConsumerNotEligible
            );

            // 4. Validate and calculate block-based expiration bounds
            let current_block = <frame_system::Pallet<T>>::block_number();
            ensure!(
                expires_in_blocks > 0u32.into(),
                Error::<T>::ExpiryMustBePositive
            );
            ensure!(
                expires_in_blocks <= T::MaxCommitmentLifetime::get(),
                Error::<T>::ExpiryTooFar
            );
            let expires_at = current_block.saturating_add(expires_in_blocks);

            // 5. Generate unique, domain-separated commitment identifier
            let commitment_id: CommitmentId = {
                let mut preimage = b"ArthNeura-Vector-v1".to_vec();
                preimage.extend_from_slice(&provider_did);
                preimage.extend_from_slice(&consumer_did);
                preimage.extend_from_slice(&merkle_root);
                preimage.extend_from_slice(&current_block.encode());
                sp_io::hashing::blake2_256(&preimage)
            };

            ensure!(
                !VectorCommitments::<T>::contains_key(commitment_id),
                Error::<T>::CommitmentAlreadyExists
            );

            // 6. Write commitment record and increment global metrics
            let commitment = VectorCommitment::<T> {
                commitment_id,
                provider: provider_did,
                consumer: consumer_did,
                merkle_root,
                total_chunks,
                metadata,
                status: CommitmentStatus::Pending,
                created_at: current_block,
                expires_at,
                acknowledged_at: None,
            };

            VectorCommitments::<T>::insert(commitment_id, commitment);
            ActiveCommitmentCount::<T>::mutate(|n| *n = n.saturating_add(1));

            Self::deposit_event(Event::CommitmentRegistered {
                commitment_id,
                provider: provider_did,
                consumer: consumer_did,
                merkle_root,
                total_chunks,
                expires_at,
            });
            Ok(())
        }

        /// Acknowledges a pending vector commitment, transitioning status to `Active`.
        ///
        /// Invariants: Only callable by the consumer's controller before the
        /// commitment expires. Consumer DID must remain active and verified.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::acknowledge_commitment())]
        pub fn acknowledge_commitment(
            origin: OriginFor<T>,
            commitment_id: CommitmentId,
            consumer_did: Did,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            let mut commitment =
                VectorCommitments::<T>::get(commitment_id).ok_or(Error::<T>::CommitmentNotFound)?;

            ensure!(
                commitment.status == CommitmentStatus::Pending,
                Error::<T>::NotPending
            );

            let current_block = <frame_system::Pallet<T>>::block_number();
            ensure!(
                current_block < commitment.expires_at,
                Error::<T>::CommitmentExpiredError
            );

            ensure!(commitment.consumer == consumer_did, Error::<T>::NotConsumer);
            let consumer_controller = T::AgentRegistry::controller_of(&consumer_did)
                .ok_or(Error::<T>::ConsumerNotEligible)?;
            ensure!(consumer_controller == caller, Error::<T>::NotConsumer);
            ensure!(
                T::AgentRegistry::is_active_verified(&consumer_did),
                Error::<T>::ConsumerNotEligible
            );

            commitment.status = CommitmentStatus::Active;
            commitment.acknowledged_at = Some(current_block);
            VectorCommitments::<T>::insert(commitment_id, commitment);

            Self::deposit_event(Event::CommitmentAcknowledged {
                commitment_id,
                acknowledged_at: current_block,
            });
            Ok(())
        }

        /// Settles an active commitment upon successful, verified off-chain data delivery.
        ///
        /// Invariants: Callable by consumer controller. Stream hash must
        /// exactly match the registered committed Merkle root.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::close_commitment())]
        pub fn close_commitment(
            origin: OriginFor<T>,
            commitment_id: CommitmentId,
            consumer_did: Did,
            final_stream_hash: MerkleRoot,
            chunk_count: u64,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            let mut commitment =
                VectorCommitments::<T>::get(commitment_id).ok_or(Error::<T>::CommitmentNotFound)?;

            ensure!(
                commitment.status == CommitmentStatus::Active,
                Error::<T>::NotActive
            );

            let current_block = <frame_system::Pallet<T>>::block_number();
            ensure!(
                current_block < commitment.expires_at,
                Error::<T>::CommitmentExpiredError
            );

            ensure!(commitment.consumer == consumer_did, Error::<T>::NotConsumer);
            let consumer_controller = T::AgentRegistry::controller_of(&consumer_did)
                .ok_or(Error::<T>::ConsumerNotEligible)?;
            ensure!(consumer_controller == caller, Error::<T>::NotConsumer);
            ensure!(
                T::AgentRegistry::is_active_verified(&consumer_did),
                Error::<T>::ConsumerNotEligible
            );

            ensure!(
                final_stream_hash == commitment.merkle_root,
                Error::<T>::StreamHashMismatch
            );

            StreamReceipts::<T>::insert(
                commitment_id,
                StreamReceipt::<T> {
                    commitment_id,
                    final_stream_hash,
                    chunk_count,
                    submitted_at: current_block,
                },
            );

            commitment.status = CommitmentStatus::Settled;
            VectorCommitments::<T>::insert(commitment_id, commitment);
            ActiveCommitmentCount::<T>::mutate(|n| *n = n.saturating_sub(1));

            Self::deposit_event(Event::CommitmentSettled {
                commitment_id,
                final_stream_hash,
                chunk_count,
            });
            Ok(())
        }

        /// Opens an on-chain dispute on cryptographic hash mismatch.
        ///
        /// Invariants: Callable by consumer controller. Received chunk hash
        /// represents the corrupted leaf on-chain. `disputed_chunk_index`
        /// must be within `commitment.total_chunks` — this is the ONLY
        /// index `counter_dispute` will later accept a refutation for,
        /// closing the gap where a provider could prove an unrelated chunk.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::raise_dispute())]
        pub fn raise_dispute(
            origin: OriginFor<T>,
            commitment_id: CommitmentId,
            consumer_did: Did,
            disputed_chunk_index: ChunkIndex,
            received_chunk_hash: [u8; 32],
            _chunk_count: u64,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            let mut commitment =
                VectorCommitments::<T>::get(commitment_id).ok_or(Error::<T>::CommitmentNotFound)?;

            ensure!(
                commitment.status == CommitmentStatus::Active,
                Error::<T>::NotActive
            );
            ensure!(commitment.consumer == consumer_did, Error::<T>::NotConsumer);

            // 1b. Enforce the same expiry boundary as close_commitment — a dispute
            // must not be raisable against a commitment that has already lapsed.
            let current_block = <frame_system::Pallet<T>>::block_number();
            ensure!(
                current_block < commitment.expires_at,
                Error::<T>::CommitmentExpiredError
            );

            // 2. Authenticate consumer origin parameters
            let consumer_controller = T::AgentRegistry::controller_of(&consumer_did)
                .ok_or(Error::<T>::ConsumerNotEligible)?;
            ensure!(consumer_controller == caller, Error::<T>::NotConsumer);
            ensure!(
                T::AgentRegistry::is_active_verified(&consumer_did),
                Error::<T>::ConsumerNotEligible
            );
            ensure!(
                !DisputeRecords::<T>::contains_key(commitment_id),
                Error::<T>::DisputeAlreadyRaised
            );

            // 2b. Bind the dispute to a specific, in-bounds chunk. This is
            // the record `counter_dispute` will later check against — it
            // no longer trusts a caller-supplied index at refutation time.
            ensure!(
                disputed_chunk_index < commitment.total_chunks,
                Error::<T>::ChunkIndexOutOfBounds
            );

            // 3. Initialize dispute record with provider response deadline
            let counter_deadline = current_block.saturating_add(T::DisputeWindow::get());

            // NOTE: StreamReceipts is reserved exclusively for verified, successful
            // closures (see `close_commitment`). An active dispute must never write
            // a receipt here — doing so would record a corrupt/disputed chunk hash
            // as if it were a finalized settlement, and since a Disputed commitment
            // can never return to Active, that corrupt entry would persist forever.
            DisputeRecords::<T>::insert(
                commitment_id,
                DisputeRecord::<T> {
                    commitment_id,
                    merkle_root: commitment.merkle_root,
                    received_chunk_hash,
                    disputed_chunk_index,
                    raised_at: current_block,
                    counter_deadline,
                    verdict: None,
                },
            );

            // 4. Transition commitment status to Disputed
            let merkle_root = commitment.merkle_root; // Copy before move
            commitment.status = CommitmentStatus::Disputed;
            VectorCommitments::<T>::insert(commitment_id, commitment);

            Self::deposit_event(Event::DisputeRaised {
                commitment_id,
                merkle_root, // Use copy variable (Resolved E0382)
                disputed_chunk_index,
                received_chunk_hash,
                counter_deadline,
            });
            Ok(())
        }

        /// Refutes an open dispute by submitting the raw data chunk and Merkle proof.
        ///
        /// Invariants: Callable by provider controller before the deadline.
        /// Merkle proof validation MUST evaluate to true against registered root,
        /// AT THE EXACT INDEX RECORDED IN THE DISPUTE (`disputed_chunk_index`,
        /// set by `raise_dispute`) — the caller no longer chooses which chunk
        /// to prove. Proving an unrelated-but-valid chunk can no longer be
        /// used to falsely refute a legitimate corruption claim.
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::counter_dispute())]
        pub fn counter_dispute(
            origin: OriginFor<T>,
            commitment_id: CommitmentId,
            provider_did: Did,
            chunk_data: BoundedVec<u8, ConstU32<MAX_CHUNK_LEN>>,
            merkle_proof: BoundedVec<[u8; 32], ConstU32<MAX_PROOF_DEPTH>>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;
            let mut commitment =
                VectorCommitments::<T>::get(commitment_id).ok_or(Error::<T>::CommitmentNotFound)?;

            ensure!(
                commitment.status == CommitmentStatus::Disputed,
                Error::<T>::NotDisputed
            );
            ensure!(commitment.provider == provider_did, Error::<T>::NotProvider);

            // 2. Authenticate provider origin parameters
            let provider_controller = T::AgentRegistry::controller_of(&provider_did)
                .ok_or(Error::<T>::ProviderNotEligible)?;
            ensure!(provider_controller == caller, Error::<T>::NotProvider);
            ensure!(
                T::AgentRegistry::is_active_verified(&provider_did),
                Error::<T>::ProviderNotEligible
            );

            // 3. Verify execution occurs within the allotted response window
            let current_block = <frame_system::Pallet<T>>::block_number();
            let mut dispute =
                DisputeRecords::<T>::get(commitment_id).ok_or(Error::<T>::CommitmentNotFound)?;
            ensure!(
                current_block <= dispute.counter_deadline,
                Error::<T>::DisputeWindowExpired
            );
            // Defense-in-depth only: `raise_dispute` already rejects any
            // out-of-bounds index before a DisputeRecord can ever be
            // written, so in practice this branch is unreachable — same
            // pattern as `DisputeAlreadyRaised` elsewhere in this pallet.
            ensure!(
                dispute.disputed_chunk_index < commitment.total_chunks,
                Error::<T>::ChunkIndexOutOfBounds
            );

            // 4. Verify cryptographic Merkle proof on-chain, bound to the
            // index recorded at dispute-raise time, not a caller-supplied one.
            let leaf_hash = sp_io::hashing::blake2_256(&chunk_data);

            // rs-merkle with Blake2bHasher
            let proof = MerkleProof::<Blake2bHasher>::new(merkle_proof.into_inner());

            // 5. Verify and resolve (Resolved E0308: Swapped parameters and removed reference borrow on root)
            ensure!(
                proof.verify(
                    commitment.merkle_root, // Removed `&` borrow here (Resolved E0308)
                    &[dispute.disputed_chunk_index as usize],
                    &[leaf_hash],
                    commitment.total_chunks as usize
                ),
                Error::<T>::InvalidMerkleProof
            );

            let verdict = DisputeVerdict::ClaimantUnsubstantiated;
            dispute.verdict = Some(verdict);
            DisputeRecords::<T>::insert(commitment_id, dispute);

            let consumer = commitment.consumer;
            commitment.status = CommitmentStatus::DisputeResolved;
            VectorCommitments::<T>::insert(commitment_id, commitment);
            ActiveCommitmentCount::<T>::mutate(|n| *n = n.saturating_sub(1));

            T::ReputationHandler::penalize_false_disputer(&consumer);

            Self::deposit_event(Event::DisputeCountered {
                commitment_id,
                verdict,
            });
            Ok(())
        }

        /// Finalizes an open dispute after the counter deadline has expired.
        ///
        /// Permissionless. Transitions status to resolved with a guilty verdict.
        /// Emits `DisputeFinalized` for external slashes/suspensions.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::finalize_dispute())]
        pub fn finalize_dispute(
            origin: OriginFor<T>,
            commitment_id: CommitmentId,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // 1. Fetch record and verify Disputed state precondition
            let mut commitment =
                VectorCommitments::<T>::get(commitment_id).ok_or(Error::<T>::CommitmentNotFound)?;
            ensure!(
                commitment.status == CommitmentStatus::Disputed,
                Error::<T>::NotDisputed
            );

            // 2. Verify temporal boundary: execution must occur after the counter deadline block
            let current_block = <frame_system::Pallet<T>>::block_number();
            let mut dispute =
                DisputeRecords::<T>::get(commitment_id).ok_or(Error::<T>::CommitmentNotFound)?;
            ensure!(
                current_block > dispute.counter_deadline,
                Error::<T>::DisputeWindowStillOpen
            );

            // 3. Cache identities prior to storage mutations
            let provider = commitment.provider;
            let consumer = commitment.consumer;

            // 4. Record ProviderGuilty verdict, update status to DisputeResolved, and decrement tracking count
            let verdict = DisputeVerdict::ProviderGuilty;
            dispute.verdict = Some(verdict);
            DisputeRecords::<T>::insert(commitment_id, dispute);

            commitment.status = CommitmentStatus::DisputeResolved;
            VectorCommitments::<T>::insert(commitment_id, commitment);
            ActiveCommitmentCount::<T>::mutate(|n| *n = n.saturating_sub(1));

            T::ReputationHandler::penalize_provider(&provider);

            Self::deposit_event(Event::DisputeFinalized {
                commitment_id,
                verdict,
                provider,
                consumer,
            });
            Ok(())
        }

        /// Reclaims storage for an expired commitment past its lifespan threshold.
        ///
        /// Permissionless. Only Pending and Active commitments are eligible.
        /// Terminal states and open disputes are explicitly rejected.
        #[pallet::call_index(6)]
        #[pallet::weight(T::WeightInfo::expire_commitment())]
        pub fn expire_commitment(
            origin: OriginFor<T>,
            commitment_id: CommitmentId,
        ) -> DispatchResult {
            ensure_signed(origin)?;

            // 1. Fetch record and verify Pending/Active state preconditions
            let commitment =
                VectorCommitments::<T>::get(commitment_id).ok_or(Error::<T>::CommitmentNotFound)?;

            ensure!(
                matches!(
                    commitment.status,
                    CommitmentStatus::Pending | CommitmentStatus::Active
                ),
                Error::<T>::AlreadyFinalized
            );

            // 2. Verify current block exceeds expiration block
            let current_block = <frame_system::Pallet<T>>::block_number();
            ensure!(
                current_block >= commitment.expires_at,
                Error::<T>::NotYetExpired
            );

            // 3. Purge record from storage and decrement active count
            VectorCommitments::<T>::remove(commitment_id);
            ActiveCommitmentCount::<T>::mutate(|n| *n = n.saturating_sub(1));

            Self::deposit_event(Event::CommitmentExpired { commitment_id });
            Ok(())
        }
    }
}

// ── Weight Definitions ───────────────────────────────────────────────────────

pub trait WeightInfo {
    fn register_commitment() -> Weight;
    fn acknowledge_commitment() -> Weight;
    fn close_commitment() -> Weight;
    fn raise_dispute() -> Weight;
    fn counter_dispute() -> Weight;
    fn finalize_dispute() -> Weight;
    fn expire_commitment() -> Weight;
}

impl WeightInfo for () {
    fn register_commitment() -> Weight {
        Weight::from_parts(175_000_000, 0)
    }
    fn acknowledge_commitment() -> Weight {
        Weight::from_parts(150_006_000, 0)
    }
    fn close_commitment() -> Weight {
        Weight::from_parts(250_006_000, 0)
    }
    fn raise_dispute() -> Weight {
        Weight::from_parts(300_008_000, 0)
    }
    fn counter_dispute() -> Weight {
        Weight::from_parts(500_034_000, 0)
    }
    fn finalize_dispute() -> Weight {
        Weight::from_parts(250_006_000, 0)
    }
    fn expire_commitment() -> Weight {
        Weight::from_parts(175_004_000, 0)
    }
}
