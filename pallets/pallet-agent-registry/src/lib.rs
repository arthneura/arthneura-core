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

use frame_support::weights::Weight;
pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use crate::WeightInfo;
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

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

    pub const CAP_DATA_PROVIDER: CapabilityBitmap = 1 << 0; // publish data feeds
    pub const CAP_INFERENCE_ENGINE: CapabilityBitmap = 1 << 1; // run ML inference
    pub const CAP_ORCHESTRATOR: CapabilityBitmap = 1 << 2; // coordinate agent pipelines
    pub const CAP_VERIFIER: CapabilityBitmap = 1 << 3; // attest agent outputs
    pub const CAP_MARKETPLACE_SELLER: CapabilityBitmap = 1 << 4; // list services
    pub const CAP_MARKETPLACE_BUYER: CapabilityBitmap = 1 << 5; // purchase services

    // -- AgentStatus ----------------------------------------------------------

    /// Lifecycle state of a registered agent.
    ///
    /// Transitions: `Active` → `Suspended` → `Revoked`.
    /// Revoked is terminal. Suspended → Active requires governance origin.
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
    pub enum AgentStatus {
        /// Profile is live and queryable.
        #[default]
        Active,
        /// Temporarily blocked. Reads allowed, writes blocked.
        Suspended,
        /// Permanently revoked. Kept on-chain for audit trail.
        Revoked,
    }

    // -- AgentProfile ---------------------------------------------------------

    /// On-chain identity card for an ArthNeura agent.
    ///
    /// Everything a verifying agent needs to make a trust decision
    /// lives here — no off-chain oracle required.
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
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
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
    pub type ControllerAgents<T: Config> =
        StorageMap<_, Blake2_128Concat, T::AccountId, BoundedVec<Did, ConstU32<64>>, ValueQuery>;

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

    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Register a new agent DID on the ArthNeura network.
        ///
        /// Caller becomes the controller of this identity.
        /// Fails if `did` already exists or caller controls >= 64 agents.
        /// Emits [`Event::AgentRegistered`] on success.
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::register_agent())]
        pub fn register_agent(
            origin: OriginFor<T>,
            did: Did,
            capabilities: CapabilityBitmap,
            metadata: BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>,
            label: BoundedVec<u8, ConstU32<MAX_LABEL_LEN>>,
        ) -> DispatchResult {
            let controller = ensure_signed(origin)?;

            ensure!(
                !AgentProfiles::<T>::contains_key(did),
                Error::<T>::DidAlreadyRegistered
            );

            let agent_count = ControllerAgents::<T>::get(&controller).len();
            ensure!(agent_count < 64, Error::<T>::TooManyAgentsForController);

            let profile = AgentProfile::<T> {
                did,
                controller: controller.clone(),
                capabilities,
                reputation_score: 0_u32,
                status: AgentStatus::Active,
                registered_at: <frame_system::Pallet<T>>::block_number(),
                metadata,
                label,
            };

            AgentProfiles::<T>::insert(did, profile);

            ControllerAgents::<T>::try_mutate(&controller, |dids| dids.try_push(did))
                .map_err(|_| Error::<T>::TooManyAgentsForController)?;

            ActiveAgentCount::<T>::mutate(|n| *n = n.saturating_add(1));

            Self::deposit_event(Event::AgentRegistered { did, controller });

            Ok(())
        }

        /// Update mutable fields of an existing agent profile.
        ///
        /// Only the registered controller may call this.
        /// Revoked agents cannot be updated.
        /// Emits [`Event::AgentProfileUpdated`] on success.
        #[pallet::call_index(1)]
        #[pallet::weight(T::WeightInfo::update_profile())]
        pub fn update_profile(
            origin: OriginFor<T>,
            did: Did,
            capabilities: CapabilityBitmap,
            metadata: BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>,
            label: BoundedVec<u8, ConstU32<MAX_LABEL_LEN>>,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            let mut profile = AgentProfiles::<T>::get(did).ok_or(Error::<T>::DidNotFound)?;

            ensure!(profile.controller == caller, Error::<T>::NotController);
            ensure!(
                profile.status != AgentStatus::Revoked,
                Error::<T>::AgentRevoked
            );

            profile.capabilities = capabilities;
            profile.metadata = metadata;
            profile.label = label;

            AgentProfiles::<T>::insert(did, profile);

            Self::deposit_event(Event::AgentProfileUpdated { did });

            Ok(())
        }

        /// Change the lifecycle status of a registered agent.
        ///
        /// Only the registered controller may call this.
        /// Revoked is a terminal state — no further transitions permitted.
        /// Emits [`Event::AgentStatusChanged`] on success.
        #[pallet::call_index(2)]
        #[pallet::weight(T::WeightInfo::set_agent_status())]
        pub fn set_agent_status(
            origin: OriginFor<T>,
            did: Did,
            new_status: AgentStatus,
        ) -> DispatchResult {
            let caller = ensure_signed(origin)?;

            let mut profile = AgentProfiles::<T>::get(did).ok_or(Error::<T>::DidNotFound)?;

            ensure!(profile.controller == caller, Error::<T>::NotController);
            ensure!(
                profile.status != AgentStatus::Revoked,
                Error::<T>::AgentRevoked
            );

            profile.status = new_status;
            AgentProfiles::<T>::insert(did, profile);

            if new_status == AgentStatus::Revoked {
                ActiveAgentCount::<T>::mutate(|n| *n = n.saturating_sub(1));
            }

            Self::deposit_event(Event::AgentStatusChanged { did, new_status });

            Ok(())
        }
    }
}

// -- Weights ------------------------------------------------------------------

/// Weight interface for pallet calls.
/// Supply a benchmarked impl in production. Use `()` in dev.
pub trait WeightInfo {
    fn register_agent() -> Weight;
    fn update_profile() -> Weight;
    fn set_agent_status() -> Weight;
}

pub struct SubstrateWeight<T>(core::marker::PhantomData<T>);

impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    fn register_agent() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn update_profile() -> Weight {
        Weight::from_parts(8_000, 0)
    }
    fn set_agent_status() -> Weight {
        Weight::from_parts(6_000, 0)
    }
}

impl WeightInfo for () {
    fn register_agent() -> Weight {
        Weight::from_parts(10_000, 0)
    }
    fn update_profile() -> Weight {
        Weight::from_parts(8_000, 0)
    }
    fn set_agent_status() -> Weight {
        Weight::from_parts(6_000, 0)
    }
}
