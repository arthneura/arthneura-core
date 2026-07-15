//! # Pallet Vector DB
//!
//! On-chain commitment registry and transactional dispute adjudicator.
//! Anchors cryptographic vector hashes to facilitate secure, off-chain data streaming.

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::weights::Weight;
pub use pallet::*;

// STANDBY: Test modules temporarily decoupled for standalone workspace compilation.
// #[cfg(test)]
// mod mock;
// #[cfg(test)]
// mod tests;

// ── Cross-Pallet Interface ───────────────────────────────────────────────────

/// Interface for validating off-pallet agent registration and verification states.
pub trait AgentLookup<AccountId> {
    /// Resolves the controller account for a given DID.
    fn controller_of(did: &[u8; 32]) -> Option<AccountId>;
    /// Validates that an agent is active and holds a verified identity state.
    fn is_active_verified(did: &[u8; 32]) -> bool;
}

/// Default fallback implementation for tests/dependency isolation.
impl<AccountId> AgentLookup<AccountId> for () {
    fn controller_of(_did: &[u8; 32]) -> Option<AccountId> {
        None
    }
    fn is_active_verified(_did: &[u8; 32]) -> bool {
        false
    }
}

// ── Pallet Module ────────────────────────────────────────────────────────────

#[frame_support::pallet]
pub mod pallet {
    use crate::{AgentLookup, WeightInfo};
    use frame_support::{pallet_prelude::*, sp_runtime::Saturating};
    use frame_system::pallet_prelude::*;

    // -- Constants ------------------------------------------------------------

    /// Max bytes allowed for commitment metadata payload.
    pub const MAX_METADATA_LEN: u32 = 256;

    /// Max bytes allowed for raw vector preimage verification.
    pub const MAX_PREIMAGE_LEN: u32 = 4096;

    // -- Core Type Aliases ----------------------------------------------------

    pub type Did = [u8; 32];
    pub type VectorHash = [u8; 32];
    pub type CommitmentId = [u8; 32];

    // -- Commitment Status ----------------------------------------------------

    /// Lifecycle states of an active on-chain vector commitment.
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
        /// Initial state; provider anchored commitment, awaiting consumer acknowledgment.
        #[default]
        Pending,
        /// Consumer acknowledged; off-chain streaming authorized to begin.
        Active,
        /// Execution verified; clean cryptographic settlement achieved. Terminal state.
        Settled,
        /// Hash mismatch reported; dispute response window is open. Active state.
        Disputed,
        /// Dispute adjudicated and finalized. Terminal state.
        DisputeResolved,
        /// Commitment lifespan exceeded without settlement or dispute. Terminal state.
        Expired,
    }

    // -- Vector Commitment Structure ------------------------------------------

    /// Structural definition of an anchored vector hash commitment.
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
        pub vector_hash: VectorHash,
        pub metadata: BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>,
        pub status: CommitmentStatus,
        pub created_at: BlockNumberFor<T>,
        pub expires_at: BlockNumberFor<T>,
        pub acknowledged_at: Option<BlockNumberFor<T>>,
    }

    // -- Stream Receipt Structure ---------------------------------------------

    /// Immutable cryptographic evidence submitted at stream completion.
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
        pub final_stream_hash: VectorHash,
        pub chunk_count: u64,
        pub submitted_at: BlockNumberFor<T>,
    }

    // -- Dispute Verdict ------------------------------------------------------

    /// Core outcome of the dispute adjudication phase.
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
        /// Provider failed to submit a valid counter-proof within the dispute window.
        ProviderGuilty,
        /// Provider submitted a valid preimage; `blake2_256(preimage) == committed_hash`.
        ClaimantUnsubstantiated,
    }

    // -- Dispute Record Structure ---------------------------------------------

    /// Evidence record created on hash mismatch, facilitating counter-proof claims.
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
        pub committed_hash: VectorHash,
        pub received_hash: VectorHash,
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
            vector_hash: VectorHash,
            expires_at: BlockNumberFor<T>,
        },
        CommitmentAcknowledged {
            commitment_id: CommitmentId,
            acknowledged_at: BlockNumberFor<T>,
        },
        CommitmentSettled {
            commitment_id: CommitmentId,
            final_stream_hash: VectorHash,
            chunk_count: u64,
        },
        DisputeRaised {
            commitment_id: CommitmentId,
            committed_hash: VectorHash,
            received_hash: VectorHash,
            counter_deadline: BlockNumberFor<T>,
        },
        /// Provider submitted a valid vector preimage within the dispute window.
        DisputeCountered {
            commitment_id: CommitmentId,
            verdict: DisputeVerdict,
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
        StreamHashMatches,
        DisputeAlreadyRaised,
        DisputeWindowStillOpen,
        DisputeWindowExpired,
        InvalidCounterProof,
        NotYetExpired,
    }

    // -- Dispatchables (Extrinsics) -------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Anchors a provider's data-quality commitment hash on-chain.
        ///
        /// # Preconditions:
        /// - `provider_did` MUST NOT equal `consumer_did` (wash-trading prevention).
        /// - Caller MUST be the authorized controller of the `provider_did`.
        /// - Both identities MUST be registered, `Active`, and `is_verified == true`.
        /// - `expires_in_blocks` MUST be within `[1, MaxCommitmentLifetime]`.
        /// - The derived `CommitmentId` MUST NOT already exist in storage.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::register_commitment())]
        pub fn register_commitment(
            origin: OriginFor<T>,
            provider_did: Did,
            consumer_did: Did,
            vector_hash: VectorHash,
            metadata: BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>,
            expires_in_blocks: BlockNumberFor<T>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            // 1. Prevent self-trades (Sybil vectors)
            ensure!(provider_did != consumer_did, Error::<T>::SelfTrade);

            // 2. Authorize provider controller
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
                expires_in_blocks > BlockNumberFor::<T>::from(0u32),
                Error::<T>::ExpiryMustBePositive
            );
            ensure!(
                expires_in_blocks <= T::MaxCommitmentLifetime::get(),
                Error::<T>::ExpiryTooFar
            );
            let expires_at = current_block.saturating_add(expires_in_blocks);

            // 5. Generate block-anchored, domain-separated commitment identifier
            let commitment_id: CommitmentId = {
                let mut preimage = b"ArthNeura-Vector-v1".to_vec();
                preimage.extend_from_slice(&provider_did);
                preimage.extend_from_slice(&consumer_did);
                preimage.extend_from_slice(&vector_hash);
                preimage.extend_from_slice(&current_block.encode());
                sp_io::hashing::blake2_256(&preimage)
            };

            ensure!(
                !VectorCommitments::<T>::contains_key(commitment_id),
                Error::<T>::CommitmentAlreadyExists
            );

            // 6. Persist state and increment global tracking metrics
            let commitment = VectorCommitment::<T> {
                commitment_id,
                provider: provider_did,
                consumer: consumer_did,
                vector_hash,
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
                vector_hash,
                expires_at,
            });
            Ok(())
        }

        /// Acknowledges a pending vector commitment, transitioning its status to `Active`.
        ///
        /// # Preconditions:
        /// - Target commitment MUST exist and have a status of `CommitmentStatus::Pending`.
        /// - Current block height MUST be strictly less than `expires_at` (expiry prevention).
        /// - The registered consumer DID MUST match the provided `consumer_did`.
        /// - The caller MUST be the authorized controller of the `consumer_did`.
        /// - The consumer agent MUST still be `Active` and `is_verified == true`.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::acknowledge_commitment())]
        pub fn acknowledge_commitment(
            origin: OriginFor<T>,
            commitment_id: CommitmentId,
            consumer_did: Did,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            // 1. Fetch record and verify Pending state precondition
            let mut commitment =
                VectorCommitments::<T>::get(commitment_id).ok_or(Error::<T>::CommitmentNotFound)?;

            ensure!(
                commitment.status == CommitmentStatus::Pending,
                Error::<T>::NotPending
            );

            // 2. Reject if execution block meets or exceeds expiration block
            let current_block = <frame_system::Pallet<T>>::block_number();
            ensure!(
                current_block < commitment.expires_at,
                Error::<T>::CommitmentExpiredError
            );

            // 3. Authenticate consumer origin against registered parameters
            ensure!(commitment.consumer == consumer_did, Error::<T>::NotConsumer);
            let consumer_controller = T::AgentRegistry::controller_of(&consumer_did)
                .ok_or(Error::<T>::ConsumerNotEligible)?;
            ensure!(consumer_controller == caller, Error::<T>::NotConsumer);

            // 4. Validate consumer identity eligibility
            ensure!(
                T::AgentRegistry::is_active_verified(&consumer_did),
                Error::<T>::ConsumerNotEligible
            );

            // 5. Transition state to Active and record block timestamp
            commitment.status = CommitmentStatus::Active;
            commitment.acknowledged_at = Some(current_block);
            VectorCommitments::<T>::insert(commitment_id, commitment);

            Self::deposit_event(Event::CommitmentAcknowledged {
                commitment_id,
                acknowledged_at: current_block,
            });
            Ok(())
        }

        /// Settles an active commitment upon successful, verified off-chain delivery.
        ///
        /// # Preconditions:
        /// - Target commitment MUST exist and have a status of `CommitmentStatus::Active`.
        /// - Current block height MUST be strictly less than `expires_at` (expiry prevention).
        /// - The registered consumer DID MUST match the provided `consumer_did`.
        /// - The caller MUST be the authorized controller of the `consumer_did`.
        /// - `final_stream_hash` MUST exactly equal the registered `vector_hash` (quality gate).
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::close_commitment())]
        pub fn close_commitment(
            origin: OriginFor<T>,
            commitment_id: CommitmentId,
            consumer_did: Did,
            final_stream_hash: VectorHash,
            chunk_count: u64,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            // 1. Fetch record and verify Active state precondition
            let mut commitment =
                VectorCommitments::<T>::get(commitment_id).ok_or(Error::<T>::CommitmentNotFound)?;

            ensure!(
                commitment.status == CommitmentStatus::Active,
                Error::<T>::NotActive
            );

            // 2. Verify temporal bounds
            let current_block = <frame_system::Pallet<T>>::block_number();
            ensure!(
                current_block < commitment.expires_at,
                Error::<T>::CommitmentExpiredError
            );

            // 3. Authenticate consumer origin parameters
            ensure!(commitment.consumer == consumer_did, Error::<T>::NotConsumer);
            let consumer_controller = T::AgentRegistry::controller_of(&consumer_did)
                .ok_or(Error::<T>::ConsumerNotEligible)?;
            ensure!(consumer_controller == caller, Error::<T>::NotConsumer);

            // 4. Enforce cryptographic matching between stream and commitment
            ensure!(
                final_stream_hash == commitment.vector_hash,
                Error::<T>::StreamHashMismatch
            );

            // 5. Persist final receipt, set status to Settled, and decrement tracking count
            let receipt = StreamReceipt::<T> {
                commitment_id,
                final_stream_hash,
                chunk_count,
                submitted_at: current_block,
            };
            StreamReceipts::<T>::insert(commitment_id, receipt);

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

        /// Open an on-chain dispute when the terminal stream hash differs from the committed hash.
        ///
        /// # Preconditions:
        /// - Target commitment MUST exist and have a status of `CommitmentStatus::Active`.
        /// - The registered consumer DID MUST match the provided `consumer_did`.
        /// - Caller MUST be the authorized controller of the `consumer_did`.
        /// - `received_hash` MUST NOT equal the registered `vector_hash`.
        /// - No dispute record MUST already exist for this commitment.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::raise_dispute())]
        pub fn raise_dispute(
            origin: OriginFor<T>,
            commitment_id: CommitmentId,
            consumer_did: Did,
            received_hash: VectorHash,
            chunk_count: u64,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            // 1. Fetch record and verify Active state precondition
            let mut commitment =
                VectorCommitments::<T>::get(commitment_id).ok_or(Error::<T>::CommitmentNotFound)?;

            ensure!(
                commitment.status == CommitmentStatus::Active,
                Error::<T>::NotActive
            );

            // 2. Authenticate consumer origin parameters
            ensure!(commitment.consumer == consumer_did, Error::<T>::NotConsumer);
            let consumer_controller = T::AgentRegistry::controller_of(&consumer_did)
                .ok_or(Error::<T>::ConsumerNotEligible)?;
            ensure!(consumer_controller == caller, Error::<T>::NotConsumer);

            // 3. Reject if received hash matches committed hash (use close_commitment)
            ensure!(
                received_hash != commitment.vector_hash,
                Error::<T>::StreamHashMatches
            );

            // 4. Enforce single-dispute invariant
            ensure!(
                !DisputeRecords::<T>::contains_key(commitment_id),
                Error::<T>::DisputeAlreadyRaised
            );

            // 5. Clone parameters prior to storage mutations
            let committed_hash = commitment.vector_hash;
            let current_block = <frame_system::Pallet<T>>::block_number();

            // 6. Record stream receipt as immutable dispute evidence
            let receipt = StreamReceipt::<T> {
                commitment_id,
                final_stream_hash: received_hash,
                chunk_count,
                submitted_at: current_block,
            };
            StreamReceipts::<T>::insert(commitment_id, receipt);

            // 7. Initialize dispute record with provider response deadline
            let counter_deadline = current_block.saturating_add(T::DisputeWindow::get());
            let dispute = DisputeRecord::<T> {
                commitment_id,
                committed_hash,
                received_hash,
                raised_at: current_block,
                counter_deadline,
                verdict: None,
            };
            DisputeRecords::<T>::insert(commitment_id, dispute);

            // 8. Transition commitment status to Disputed
            commitment.status = CommitmentStatus::Disputed;
            VectorCommitments::<T>::insert(commitment_id, commitment);

            Self::deposit_event(Event::DisputeRaised {
                commitment_id,
                committed_hash,
                received_hash,
                counter_deadline,
            });
            Ok(())
        }

        /// Refutes an open dispute by submitting the raw vector preimage within the dispute window.
        ///
        /// # Preconditions:
        /// - Target commitment MUST exist and have a status of `CommitmentStatus::Disputed`.
        /// - Caller MUST be the authorized controller of the `provider_did`.
        /// - Current block height MUST be less than or equal to `dispute.counter_deadline`.
        /// - `blake2_256(vector_preimage)` MUST exactly equal `dispute.committed_hash`.
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::counter_dispute())]
        pub fn counter_dispute(
            origin: OriginFor<T>,
            commitment_id: CommitmentId,
            provider_did: Did,
            vector_preimage: BoundedVec<u8, ConstU32<MAX_PREIMAGE_LEN>>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            // 1. Fetch record and verify Disputed state precondition
            let mut commitment =
                VectorCommitments::<T>::get(commitment_id).ok_or(Error::<T>::CommitmentNotFound)?;

            ensure!(
                commitment.status == CommitmentStatus::Disputed,
                Error::<T>::NotDisputed
            );

            // 2. Authenticate provider origin parameters
            ensure!(commitment.provider == provider_did, Error::<T>::NotProvider);
            let provider_controller = T::AgentRegistry::controller_of(&provider_did)
                .ok_or(Error::<T>::ProviderNotEligible)?;
            ensure!(provider_controller == caller, Error::<T>::NotProvider);

            // 3. Verify execution occurs within the allotted response window
            let current_block = <frame_system::Pallet<T>>::block_number();
            let mut dispute =
                DisputeRecords::<T>::get(commitment_id).ok_or(Error::<T>::CommitmentNotFound)?;
            ensure!(
                current_block <= dispute.counter_deadline,
                Error::<T>::DisputeWindowExpired
            );

            // 4. Cryptographic validation of the submitted preimage
            let preimage_hash: VectorHash = sp_io::hashing::blake2_256(&vector_preimage);
            ensure!(
                preimage_hash == dispute.committed_hash,
                Error::<T>::InvalidCounterProof
            );

            // 5. Persist the verdict, update status to DisputeResolved, and decrement tracking count
            let verdict = DisputeVerdict::ClaimantUnsubstantiated;
            dispute.verdict = Some(verdict);
            DisputeRecords::<T>::insert(commitment_id, dispute);

            commitment.status = CommitmentStatus::DisputeResolved;
            VectorCommitments::<T>::insert(commitment_id, commitment);
            ActiveCommitmentCount::<T>::mutate(|n| *n = n.saturating_sub(1));

            Self::deposit_event(Event::DisputeCountered {
                commitment_id,
                verdict,
            });
            Ok(())
        }
    }
}

// ── Weight Definitions ───────────────────────────────────────────────────────

/// Weight trait definition for the dispatchable methods of `pallet-vector-db`.
pub trait WeightInfo {
    /// Evaluates execution weight for the `register_commitment` extrinsic.
    fn register_commitment() -> Weight;
    /// Evaluates execution weight for the `acknowledge_commitment` extrinsic.
    fn acknowledge_commitment() -> Weight;
    /// Evaluates execution weight for the `close_commitment` extrinsic.
    fn close_commitment() -> Weight;
    /// Evaluates execution weight for the `raise_dispute` extrinsic.
    fn raise_dispute() -> Weight;
    /// Evaluates execution weight for the `counter_dispute` extrinsic.
    fn counter_dispute() -> Weight;
}

impl WeightInfo for () {
    fn register_commitment() -> Weight {
        Weight::default()
    }
    /// Evaluates estimated execution weight for the `acknowledge_commitment` extrinsic.
    fn acknowledge_commitment() -> Weight {
        Weight::from_parts(150_006_000, 0)
    }
    /// Evaluates estimated execution weight for the `close_commitment` extrinsic.
    fn close_commitment() -> Weight {
        Weight::from_parts(350_006_000, 0)
    }
    /// Evaluates estimated execution weight for the `raise_dispute` extrinsic.
    fn raise_dispute() -> Weight {
        Weight::from_parts(375_008_000, 0)
    }
    /// Evaluates estimated execution weight for the `counter_dispute` extrinsic.
    fn counter_dispute() -> Weight {
        Weight::from_parts(405_010_000, 0)
    }
}
