//! # pallet-vector-db
//!
//! On-chain vector hash commitment registry and dispute adjudicator for ArthNeura.
//!
//! This pallet acts as a secure, decentralized anchor for machine-to-machine data-quality promises.
//! Raw vectors are never stored on-chain; only their cryptographic hashes (commitments) are registered.

#![cfg_attr(not(feature = "std"), no_std)]

use frame_support::weights::Weight;
pub use pallet::*;

// NOTE: The unit test modules `mock` and `tests` are temporarily commented out
// to facilitate incremental compilation checks of the core logic prior to the
// implementation of the local test suite.
// #[cfg(test)]
// mod mock;
// #[cfg(test)]
// mod tests;

// ── Cross-Pallet Interface ───────────────────────────────────────────────────

/// Read-only identity queries issued to `pallet-agent-registry` at execution time.
///
/// This trait decouples `pallet-vector-db` from `pallet-agent-registry`'s concrete
/// types, preventing circular dependency graphs within the runtime workspace.
pub trait AgentLookup<AccountId> {
    /// Returns the controller `AccountId` for a given `did`, or `None` if the identity is absent.
    fn controller_of(did: &[u8; 32]) -> Option<AccountId>;
    /// Returns `true` if the agent exists, is active, and is cryptographically verified.
    fn is_active_verified(did: &[u8; 32]) -> bool;
}

/// Blanket no-op implementation of `AgentLookup` to satisfy the trait bounds
/// during testing or mock runtime configurations where identities are injected manually.
impl<AccountId> AgentLookup<AccountId> for () {
    fn controller_of(_did: &[u8; 32]) -> Option<AccountId> { None }
    fn is_active_verified(_did: &[u8; 32]) -> bool { false }
}

// ── Pallet Module ────────────────────────────────────────────────────────────

#[frame_support::pallet]
pub mod pallet {
    use crate::{AgentLookup, WeightInfo};
    use frame_support::{pallet_prelude::*, sp_runtime::Saturating};
    use frame_system::pallet_prelude::*;

    // -- Constants ------------------------------------------------------------

    /// Maximum byte length for the metadata string (e.g., schema descriptors, IPFS CID).
    pub const MAX_METADATA_LEN: u32 = 256;

    /// Maximum byte length for the vector preimage submitted during dispute countering.
    /// 4096 bytes corresponds to 512 × i64 fixed-point components.
    pub const MAX_PREIMAGE_LEN: u32 = 4096;

    // -- Core Type Aliases ----------------------------------------------------

    /// 32-byte Decentralized Identifier. Matches `pallet-agent-registry::Did`.
    pub type Did = [u8; 32];

    /// Blake2-256 hash of an off-chain fixed-point quantized vector.
    pub type VectorHash = [u8; 32];

    /// Unique transaction commitment identifier.
    pub type CommitmentId = [u8; 32];

    // -- Commitment Status ----------------------------------------------------

    /// Lifecycle states of an active on-chain vector commitment.
    #[derive(
        Clone, Copy, PartialEq, Eq,
        Encode, Decode, DecodeWithMemTracking,
        TypeInfo, MaxEncodedLen, RuntimeDebug, Default,
    )]
    pub enum CommitmentStatus {
        /// Provider anchored the promise; awaiting consumer acknowledgement.
        #[default]
        Pending,
        /// Consumer acknowledged the terms; off-chain gRPC data streaming may begin.
        Active,
        /// Final stream hash matches the committed hash. Settlement complete. Terminal.
        Settled,
        /// Consumer reported a stream hash mismatch; dispute window is open. Active.
        Disputed,
        /// Dispute adjudicated and finalized. Terminal.
        DisputeResolved,
        /// Passed the expiration block without being closed or disputed. Terminal.
        Expired,
    }

    // -- Vector Commitment Structure ------------------------------------------

    /// On-chain registry record anchoring a data-quality promise between two agents.
    #[derive(
        Clone, PartialEq, Eq,
        Encode, Decode, DecodeWithMemTracking,
        TypeInfo, MaxEncodedLen, RuntimeDebug,
    )]
    #[scale_info(skip_type_params(T))]
    pub struct VectorCommitment<T: Config> {
        /// Unique commitment ID derived from transaction parameters. Immutable.
        pub commitment_id:    CommitmentId,
        /// Decentralized Identifier (DID) of the data provider (Agent A). Immutable.
        pub provider:         Did,
        /// Decentralized Identifier (DID) of the data consumer (Agent B). Immutable.
        pub consumer:         Did,
        /// Blake2-256 hash representing the expected data qualities. Immutable.
        pub vector_hash:      VectorHash,
        /// Arbitrary metadata (e.g., schema parameters, descriptors). Max 256 bytes.
        pub metadata:         BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>,
        /// Current state of the commitment in its lifecycle.
        pub status:           CommitmentStatus,
        /// Block number when the commitment was registered. Immutable.
        pub created_at:       BlockNumberFor<T>,
        /// Block number after which the commitment can be pruned. Immutable.
        pub expires_at:       BlockNumberFor<T>,
        /// Block number when the consumer acknowledged. `None` if status is `Pending`.
        pub acknowledged_at:  Option<BlockNumberFor<T>>,
    }

    // -- Config Trait ---------------------------------------------------------

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// The overarching runtime event type.
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        
        /// Weight specifications for dispatchable calls.
        type WeightInfo: WeightInfo;
        
        /// Association with the external identity registry pallet.
        type AgentRegistry: AgentLookup<Self::AccountId>;
        
        /// Number of blocks allowed for a provider to submit a counter-proof.
        #[pallet::constant]
        type DisputeWindow: Get<BlockNumberFor<Self>>;
        
        /// Hard ceiling on commitment lifetimes to prevent storage exhaustion.
        #[pallet::constant]
        type MaxCommitmentLifetime: Get<BlockNumberFor<Self>>;
    }

    const STORAGE_VERSION: frame_support::traits::StorageVersion =
        frame_support::traits::StorageVersion::new(1);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    // -- Storage Declarations -------------------------------------------------

    /// Map of active and historical vector commitments: CommitmentId -> VectorCommitment.
    #[pallet::storage]
    #[pallet::getter(fn vector_commitment)]
    pub type VectorCommitments<T: Config> =
        StorageMap<_, Blake2_128Concat, CommitmentId, VectorCommitment<T>, OptionQuery>;

    /// Running count of active commitments (Pending + Active) to monitor network load.
    #[pallet::storage]
    #[pallet::getter(fn active_commitment_count)]
    pub type ActiveCommitmentCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    // -- Events ---------------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// A data provider has registered a vector hash promise on-chain.
        CommitmentRegistered {
            commitment_id: CommitmentId,
            provider:      Did,
            consumer:      Did,
            vector_hash:   VectorHash,
            expires_at:    BlockNumberFor<T>,
        },
    }

    // -- Errors ---------------------------------------------------------------

    #[pallet::error]
    pub enum Error<T> {
        /// Derived `CommitmentId` is already present in storage.
        CommitmentAlreadyExists,
        /// Commitment was not found in storage maps.
        CommitmentNotFound,
        /// Origin is not the authorized controller of the provider DID.
        NotProvider,
        /// Origin is not the authorized controller of the consumer DID.
        NotConsumer,
        /// Provider DID is suspended, revoked, or unverified.
        ProviderNotEligible,
        /// Consumer DID is suspended, revoked, or unverified.
        ConsumerNotEligible,
        /// Self-trades (provider == consumer) are rejected to prevent Sybil reputation wash-trading.
        SelfTrade,
        /// Lifetime must be greater than zero blocks.
        ExpiryMustBePositive,
        /// Expiry parameter exceeds `MaxCommitmentLifetime`.
        ExpiryTooFar,
    }

    // -- Dispatchables (Extrinsics) -------------------------------------------

    #[pallet::call]
    impl<T: Config> Pallet<T> {

        /// Registers a new vector commitment on-chain.
        ///
        /// Provider (Agent A) locks in their cryptographic data-quality promise.
        /// Emits `CommitmentRegistered` on success.
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

            // 1. Self-trade prevention
            ensure!(provider_did != consumer_did, Error::<T>::SelfTrade);

            // 2. Authorization authority check
            let provider_controller = T::AgentRegistry::controller_of(&provider_did)
                .ok_or(Error::<T>::ProviderNotEligible)?;
            ensure!(provider_controller == caller, Error::<T>::NotProvider);

            // 3. Status eligibility checks
            ensure!(
                T::AgentRegistry::is_active_verified(&provider_did),
                Error::<T>::ProviderNotEligible
            );
            ensure!(
                T::AgentRegistry::is_active_verified(&consumer_did),
                Error::<T>::ConsumerNotEligible
            );

            // 4. Lifespan checks
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

            // 5. Unique, domain-separated commitment ID derivation
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

            // 6. Write record to storage
            let commitment = VectorCommitment::<T> {
                commitment_id,
                provider:        provider_did,
                consumer:        consumer_did,
                vector_hash,
                metadata,
                status:          CommitmentStatus::Pending,
                created_at:      current_block,
                expires_at,
                acknowledged_at: None,
            };
            VectorCommitments::<T>::insert(commitment_id, commitment);
            ActiveCommitmentCount::<T>::mutate(|n| *n = n.saturating_add(1));

            Self::deposit_event(Event::CommitmentRegistered {
                commitment_id,
                provider:   provider_did,
                consumer:   consumer_did,
                vector_hash,
                expires_at,
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
}

impl WeightInfo for () {
    fn register_commitment() -> Weight {
        Weight::default()
    }
}