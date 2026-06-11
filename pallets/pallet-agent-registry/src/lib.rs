//! # pallet-agent-registry
//!
//! On-chain DID registry for ArthNeura autonomous agents.
//!
//! Each agent gets a [`AgentProfile`] keyed by a 32-byte [`Did`].
//! This pallet only stores and serves identity — it does not route
//! trades or enforce decisions between agents.
//!
//! ### Storage
//! - [`AgentProfiles`]: primary DID → profile index
//! - [`ControllerAgents`]: reverse index, controller → DIDs
//! - [`ActiveAgentCount`]: live agent population counter

#![cfg_attr(not(feature = "std"), no_std)]
#![allow(missing_docs)]
#![allow(dead_code)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;
    use crate::WeightInfo;

    // -- Constants ------------------------------------------------------------

    /// Max bytes for the `metadata` field in [`AgentProfile`].
    pub const MAX_METADATA_LEN: u32 = 256;

    /// Max bytes for the display `label` field in [`AgentProfile`].
    pub const MAX_LABEL_LEN: u32 = 64;

    // -- Types ----------------------------------------------------------------

    /// 32-byte Decentralized Identifier derived from the agent's public key.
    pub type Did = [u8; 32];

    /// 64-bit permission mask. Each bit unlocks a specific network capability.
    /// Check with: `profile.capabilities & CAP_X != 0`
    pub type CapabilityBitmap = u64;

    pub const CAP_DATA_PROVIDER:      CapabilityBitmap = 1 << 0; // publish data feeds
    pub const CAP_INFERENCE_ENGINE:   CapabilityBitmap = 1 << 1; // run ML inference
    pub const CAP_ORCHESTRATOR:       CapabilityBitmap = 1 << 2; // coordinate agent pipelines
    pub const CAP_VERIFIER:           CapabilityBitmap = 1 << 3; // attest agent outputs
    pub const CAP_MARKETPLACE_SELLER: CapabilityBitmap = 1 << 4; // list services
    pub const CAP_MARKETPLACE_BUYER:  CapabilityBitmap = 1 << 5; // purchase services

    // -- AgentStatus ----------------------------------------------------------

    /// Lifecycle state of a registered agent.
    ///
    /// Transitions: `Active` → `Suspended` → `Revoked`.
    /// Revoked is terminal. Suspended → Active requires governance origin.
    #[derive(
        Clone, PartialEq, Eq, Encode, Decode,
        DecodeWithMemTracking, TypeInfo, MaxEncodedLen, RuntimeDebug,
    )]
    pub enum AgentStatus {
        /// Profile is live and queryable.
        Active,
        /// Temporarily blocked. Reads allowed, writes blocked.
        Suspended,
        /// Permanently revoked. Kept on-chain for audit trail.
        Revoked,
    }

    impl Default for AgentStatus {
        fn default() -> Self { AgentStatus::Active }
    }

    // -- AgentProfile ---------------------------------------------------------

    /// On-chain identity card for an ArthNeura agent.
    ///
    /// Everything a verifying agent needs to make a trust decision
    /// lives here — no off-chain oracle required.
    #[derive(
        Clone, PartialEq, Eq, Encode, Decode,
        DecodeWithMemTracking, TypeInfo, MaxEncodedLen, RuntimeDebug,
    )]
    #[scale_info(skip_type_params(T))]
    pub struct AgentProfile<T: Config> {
        /// Unique 32-byte identity hash. Immutable after registration.
        pub did: Did,
        /// Account that owns and controls this profile.
        pub controller: T::AccountId,
        /// Permission bitmap. See `CAP_*` constants.
        pub capabilities: CapabilityBitmap,
        /// Peer-star reputation score. Starts at 0.
        pub reputation_score: u32,
        /// Current lifecycle state.
        pub status: AgentStatus,
        /// Block number when this profile was registered.
        pub registered_at: BlockNumberFor<T>,
        /// Optional IPFS CID or structured metadata. Max 256 bytes.
        pub metadata: BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>,
        /// Optional human-readable display name. Max 64 bytes.
        pub label: BoundedVec<u8, ConstU32<MAX_LABEL_LEN>>,
    }

    // -- Config ---------------------------------------------------------------

    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Runtime event type.
        type RuntimeEvent: From<Event<Self>>
            + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// Benchmarked weight provider. Use `()` in dev/test.
        type WeightInfo: WeightInfo;
    }

    // -- Pallet ---------------------------------------------------------------

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // -- Storage --------------------------------------------------------------

    /// Primary registry: DID → AgentProfile.
    #[pallet::storage]
    #[pallet::getter(fn agent_profile)]
    pub type AgentProfiles<T: Config> =
        StorageMap<_, Blake2_128Concat, Did, AgentProfile<T>, OptionQuery>;

    /// Reverse index: controller AccountId → list of DIDs (max 64).
    /// Bounded to prevent storage DoS from a single controller.
    #[pallet::storage]
    #[pallet::getter(fn controller_agents)]
    pub type ControllerAgents<T: Config> = StorageMap<
        _,
        Blake2_128Concat,
        T::AccountId,
        BoundedVec<Did, ConstU32<64>>,
        ValueQuery,
    >;

    /// Running count of non-revoked agents on the network.
    #[pallet::storage]
    #[pallet::getter(fn active_agent_count)]
    pub type ActiveAgentCount<T: Config> = StorageValue<_, u32, ValueQuery>;

    // -- Events ---------------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// New agent registered on the network.
        AgentRegistered { did: Did, controller: T::AccountId },
        /// Agent profile metadata or label updated.
        AgentProfileUpdated { did: Did },
        /// Agent lifecycle status changed.
        AgentStatusChanged { did: Did, new_status: AgentStatus },
    }

    // -- Errors ---------------------------------------------------------------

    #[pallet::error]
    pub enum Error<T> {
        /// DID already exists in the registry.
        DidAlreadyRegistered,
        /// DID not found in the registry.
        DidNotFound,
        /// Caller is not the registered controller for this DID.
        NotController,
        /// Operation rejected — agent status is Revoked (terminal).
        AgentRevoked,
        /// Controller has reached the 64-agent registration limit.
        TooManyAgentsForController,
    }

    // -- Calls ----------------------------------------------------------------

    /// Dispatchable calls. Full implementation in Phase 4:
    /// `register_agent`, `deregister_agent`, `give_star`,
    /// `remove_star`, `verify_agent_quantum_proof`.
    #[pallet::call]
    impl<T: Config> Pallet<T> {}
}

// -- Weights ------------------------------------------------------------------

/// Weight interface for pallet calls.
/// Supply a benchmarked impl in production. Use `()` in dev.
pub trait WeightInfo {}

pub struct SubstrateWeight<T>(core::marker::PhantomData<T>);
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {}
impl WeightInfo for () {}