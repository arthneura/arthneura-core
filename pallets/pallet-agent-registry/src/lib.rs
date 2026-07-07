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
    use frame_support::{pallet_prelude::*, sp_runtime::Saturating};
    use frame_support::traits::{Currency, ReservableCurrency};
    use frame_system::pallet_prelude::*;
    use ml_dsa::{KeyInit, MlDsa65, Signature, Verifier, VerifyingKey};
 
    // -- Constants ------------------------------------------------------------
 
    /// Max bytes for the `metadata` field in [`AgentProfile`].
    pub const MAX_METADATA_LEN: u32 = 256;
 
    /// Max bytes for the display `label` field in [`AgentProfile`].
    pub const MAX_LABEL_LEN: u32 = 64;
 
    /// ML-DSA-65 public key length in bytes (FIPS 204 fixed constant).
    pub const MAX_PUBKEY_LEN: u32 = 1952;
 
    /// ML-DSA-65 signature length in bytes (FIPS 204 fixed constant).
    pub const MAX_SIG_LEN: u32 = 3309;
 
    /// Registration challenge replay window. ~6 min at 6s/block.
    pub const REPLAY_WINDOW: u32 = 64;
 
    // -- Types ----------------------------------------------------------------
 
    /// 32-byte Decentralized Identifier derived from the agent's public key.
    pub type Did = [u8; 32];
 
    /// 64-bit permission mask; each bit unlocks a network capability (`CAP_X != 0` check).
    /// Undefined bits accepted without validation — forward-compatible.
    /// Semantics are caller-defined; the registry records, not enforces.
    pub type CapabilityBitmap = u64;
 
    pub const CAP_DATA_PROVIDER: CapabilityBitmap = 1 << 0; // publish data feeds
    pub const CAP_INFERENCE_ENGINE: CapabilityBitmap = 1 << 1; // run ML inference
    pub const CAP_ORCHESTRATOR: CapabilityBitmap = 1 << 2; // coordinate agent pipelines
    pub const CAP_VERIFIER: CapabilityBitmap = 1 << 3; // attest agent outputs
    pub const CAP_MARKETPLACE_SELLER: CapabilityBitmap = 1 << 4; // list services
    pub const CAP_MARKETPLACE_BUYER: CapabilityBitmap = 1 << 5; // purchase services
 
    // -- AgentStatus ----------------------------------------------------------
 
    /// Lifecycle state of a registered agent.
    /// Transitions: `Active` ↔ `Suspended` (controller-gated); `Revoked` is terminal.
    /// Governance-enforced suspension deferred pending a governance pallet.
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
 
    // -- QuantumScheme ----------------------------------------------------------
 
    /// Post-quantum signature scheme used for an agent's identity proof.
    /// Per-agent field — new variants can be added without invalidating existing agents.
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
    pub enum QuantumScheme {
        /// FIPS 204 ML-DSA, parameter set 65 (NIST security category 3).
        #[default]
        MlDsa65,
    }
 
    // -- AgentProfile ---------------------------------------------------------
 
    /// On-chain identity record for an ArthNeura agent.
    ///
    /// All trust-relevant fields are stored here; no off-chain lookup needed.
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
        /// Always `true` — verification is atomic; failed proof reverts the call.
        /// Explicit field for indexer convenience.
        pub is_verified: bool,
        /// Post-quantum scheme used for this agent's identity proof.
        pub quantum_scheme: QuantumScheme,
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
        /// Per-pair star cooldown. Production: 1200 (~2 h at 6s/block). Tests: 10.
        #[pallet::constant]
        type StarCooldown: Get<BlockNumberFor<Self>>;
        /// Currency used for the anti-spam registration deposit.
        /// Reserved in `register_agent`; unreserved in `deregister_agent`.
        type Currency: ReservableCurrency<Self::AccountId>;
        /// Per-agent sybil-resistance deposit. Production: 100 ART.
        #[pallet::constant]
        type RegistrationDeposit: Get<BalanceOf<Self>>;
    }
 
    /// Balance type for [`Config::Currency`].
    pub type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;
 
    // -- Pallet ---------------------------------------------------------------
 
    /// Bumped from 0 -> 1 for the `quantum_scheme` field added to [`AgentProfile`].
    /// No migration shipped: pre-launch, no persistent state to upgrade yet.
    const STORAGE_VERSION: frame_support::traits::StorageVersion =
        frame_support::traits::StorageVersion::new(1);
 
    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
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
 
    /// Star ledger: (giver, receiver) → block of last star.
    /// Zero = never starred; non-zero = cooldown reference point.
    #[pallet::storage]
    #[pallet::getter(fn star_givers)]
    pub type StarGivers<T: Config> = StorageDoubleMap<
        _,
        Blake2_128Concat,
        Did,
        Blake2_128Concat,
        Did,
        BlockNumberFor<T>,
        ValueQuery,
    >;
 
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
        /// A star was given to an agent.
        StarGiven { giver: Did, receiver: Did },
        /// A star was removed from an agent.
        StarRemoved { giver: Did, receiver: Did },
        /// Agent voluntarily deregistered; deposit returned to controller.
        AgentDeregistered { did: Did, controller: T::AccountId },
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
        /// Star cooldown not yet expired.
        CooldownNotExpired,
        /// Giver has not starred this receiver.
        NotStarred,
        /// Self-starring not permitted.
        CannotStarSelf,
        /// Public key length != MAX_PUBKEY_LEN.
        InvalidPubkeyLength,
        /// Signature length != MAX_SIG_LEN.
        InvalidSignatureLength,
        /// `signed_at_block` is ahead of the current block.
        InvalidChallengeBlock,
        /// `signed_at_block` is outside the replay window.
        ChallengeExpired,
        /// ML-DSA verification failed.
        InvalidQuantumProof,
        /// Free balance below RegistrationDeposit.
        InsufficientBalanceForDeposit,
        /// Revoked profile — deregistration rejected; slot retained for audit.
        AgentAlreadyRevoked,
    }
 
    // -- Calls ----------------------------------------------------------------
 
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// Derive `did = blake2_256("ArthNeura-DID-v1" ++ pubkey)`, verify an ML-DSA
        /// proof-of-key-possession over a chain-bound replay-window challenge, reserve
        /// the deposit, and store the profile. Emits [`Event::AgentRegistered`].
        #[pallet::call_index(0)]
        #[pallet::weight(T::WeightInfo::register_agent())]
        pub fn register_agent(
            origin: OriginFor<T>,
            pubkey: BoundedVec<u8, ConstU32<MAX_PUBKEY_LEN>>,
            signature: BoundedVec<u8, ConstU32<MAX_SIG_LEN>>,
            signed_at_block: BlockNumberFor<T>,
            capabilities: CapabilityBitmap,
            metadata: BoundedVec<u8, ConstU32<MAX_METADATA_LEN>>,
            label: BoundedVec<u8, ConstU32<MAX_LABEL_LEN>>,
        ) -> DispatchResult {
            let controller = ensure_signed(origin)?;
 
            // -- 1. Derive DID from pubkey (domain-separated hash) ------------
            let did: Did = {
                let mut preimage = b"ArthNeura-DID-v1".to_vec();
                preimage.extend_from_slice(&pubkey);
                sp_io::hashing::blake2_256(&preimage)
            };
 
            ensure!(
                !AgentProfiles::<T>::contains_key(did),
                Error::<T>::DidAlreadyRegistered
            );
 
            let agent_count = ControllerAgents::<T>::get(&controller).len();
            ensure!(agent_count < 64, Error::<T>::TooManyAgentsForController);
 
            // -- 2. Replay-window bounds check ---------------------------------
            // `<=` permits same-block registration; `block_hash(current_block)` is zero
            // at submission time — both sides agree, so the challenge remains binding.
            let current_block = <frame_system::Pallet<T>>::block_number();
            ensure!(
                signed_at_block <= current_block,
                Error::<T>::InvalidChallengeBlock
            );
            ensure!(
                current_block.saturating_sub(signed_at_block)
                    <= BlockNumberFor::<T>::from(REPLAY_WINDOW),
                Error::<T>::ChallengeExpired
            );
 
            // -- 3. Build chain-bound, replay-window-bound challenge -----------
            let genesis_hash = <frame_system::Pallet<T>>::block_hash(BlockNumberFor::<T>::zero());
            let signed_at_hash = <frame_system::Pallet<T>>::block_hash(signed_at_block);
            let challenge = (
                genesis_hash,
                did,
                controller.clone(),
                signed_at_block,
                signed_at_hash,
            )
                .encode();
 
            // -- 4. Parse pubkey + signature (length-checked, no panics) ------
            let verifying_key = VerifyingKey::<MlDsa65>::new_from_slice(&pubkey)
                .map_err(|_| Error::<T>::InvalidPubkeyLength)?;
            let parsed_signature = Signature::<MlDsa65>::try_from(signature.as_slice())
                .map_err(|_| Error::<T>::InvalidSignatureLength)?;
 
            // -- 5. Verify ML-DSA signature over the challenge -----------------
            verifying_key
                .verify(&challenge, &parsed_signature)
                .map_err(|_| Error::<T>::InvalidQuantumProof)?;
 
            // -- 6. Reserve the anti-spam registration deposit -----------------
            // Last fallible step by design — earlier reservation mutates Balances
            // on side-effect-free paths, breaking assert_noop! guarantees.
            T::Currency::reserve(&controller, T::RegistrationDeposit::get())
                .map_err(|_| Error::<T>::InsufficientBalanceForDeposit)?;
 
            let profile = AgentProfile::<T> {
                did,
                controller: controller.clone(),
                capabilities,
                reputation_score: 0_u32,
                status: AgentStatus::Active,
                registered_at: current_block,
                is_verified: true,
                quantum_scheme: QuantumScheme::MlDsa65,
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
 
        /// Update mutable fields (`capabilities`, `metadata`, `label`) of an existing profile.
        /// Only the controller may call; Revoked agents are rejected.
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
        /// Only the controller may call; `Revoked` is terminal — no further transitions.
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
 
        /// Give a reputation star; increments receiver's `reputation_score` by 1.
        /// `giver_did` must be controller-owned; self-starring rejected; rate-limited by [`Config::StarCooldown`].
        /// Emits [`Event::StarGiven`] on success.
        #[pallet::call_index(3)]
        #[pallet::weight(T::WeightInfo::give_star(*giver_did, *receiver))]
        pub fn give_star(origin: OriginFor<T>, giver_did: Did, receiver: Did) -> DispatchResult {
            // -- 1. Authenticate caller ---------------------------------------
            let giver = ensure_signed(origin)?;
 
            // -- 2. Verify caller controls the claimed giver_did --------------
            let giver_dids = ControllerAgents::<T>::get(&giver);
            ensure!(giver_dids.contains(&giver_did), Error::<T>::NotController);
 
            // -- 3. Guard: cannot star yourself -------------------------------
            ensure!(giver_did != receiver, Error::<T>::CannotStarSelf);
 
            // -- 4. Guard: receiver must exist and be active ------------------
            let receiver_profile =
                AgentProfiles::<T>::get(receiver).ok_or(Error::<T>::DidNotFound)?;
            ensure!(
                receiver_profile.status != AgentStatus::Revoked,
                Error::<T>::AgentRevoked
            );
 
            // -- 5. Cooldown check -------------------------------------------
            // Zero means never starred. Non-zero is the last star block.
            let last_star = StarGivers::<T>::get(giver_did, receiver);
            let current_block = <frame_system::Pallet<T>>::block_number();
            if last_star > BlockNumberFor::<T>::from(0u32) {
                ensure!(
                    current_block >= last_star.saturating_add(T::StarCooldown::get()),
                    Error::<T>::CooldownNotExpired
                );
            }
            // -- 6. Record star with current block number --------------------
            StarGivers::<T>::insert(giver_did, receiver, current_block);
 
            // -- 7. Increment receiver reputation ----------------------------
            AgentProfiles::<T>::try_mutate(receiver, |maybe_profile| {
                let profile = maybe_profile.as_mut().ok_or(Error::<T>::DidNotFound)?;
                profile.reputation_score = profile.reputation_score.saturating_add(1);
                Ok::<(), DispatchError>(())
            })?;
 
            // -- 8. Emit event -----------------------------------------------
            Self::deposit_event(Event::StarGiven {
                giver: giver_did,
                receiver,
            });
 
            Ok(())
        }
 
        /// Remove a previously given star; decrements receiver's `reputation_score` by 1 (saturating).
        /// `giver_did` must be controller-owned; star entry reset to zero, cooldown history preserved.
        /// Emits [`Event::StarRemoved`] on success.
        #[pallet::call_index(4)]
        #[pallet::weight(T::WeightInfo::remove_star(*giver_did, *receiver))]
        pub fn remove_star(origin: OriginFor<T>, giver_did: Did, receiver: Did) -> DispatchResult {
            // -- 1. Authenticate caller ---------------------------------------
            let giver = ensure_signed(origin)?;
 
            // -- 2. Verify caller controls the claimed giver_did --------------
            let giver_dids = ControllerAgents::<T>::get(&giver);
            ensure!(giver_dids.contains(&giver_did), Error::<T>::NotController);
 
            // -- 3. Guard: star must exist (non-zero = previously starred) ----
            let last_star = StarGivers::<T>::get(giver_did, receiver);
            ensure!(
                last_star > BlockNumberFor::<T>::from(0u32),
                Error::<T>::NotStarred
            );
 
            // -- 4. Reset star to zero — preserves slot, clears cooldown -----
            StarGivers::<T>::insert(giver_did, receiver, BlockNumberFor::<T>::from(0u32));
 
            // -- 5. Decrement receiver reputation (saturating) ----------------
            AgentProfiles::<T>::try_mutate(receiver, |maybe_profile| {
                let profile = maybe_profile.as_mut().ok_or(Error::<T>::DidNotFound)?;
                profile.reputation_score = profile.reputation_score.saturating_sub(1);
                Ok::<(), DispatchError>(())
            })?;
 
            // -- 6. Emit event -----------------------------------------------
            Self::deposit_event(Event::StarRemoved {
                giver: giver_did,
                receiver,
            });
 
            Ok(())
        }
 
        /// Deregister an agent, prune [`ControllerAgents`], and unreserve [`Config::RegistrationDeposit`].
        /// `Revoked` agents cannot exit — profile and deposit are permanently locked.
        /// Emits [`Event::AgentDeregistered`] on success.
        #[pallet::call_index(5)]
        #[pallet::weight(T::WeightInfo::deregister_agent(*did))]
        pub fn deregister_agent(origin: OriginFor<T>, did: Did) -> DispatchResult {
            // -- 1. Authenticate caller ---------------------------------------
            let controller = ensure_signed(origin)?;
 
            // -- 2. Fetch profile — DidNotFound if absent ---------------------
            let profile = AgentProfiles::<T>::get(did).ok_or(Error::<T>::DidNotFound)?;
 
            // -- 3. Verify caller is registered controller --------------------
            ensure!(profile.controller == controller, Error::<T>::NotController);
 
            // -- 4. Guard: Revoked is terminal — deposit forfeited, no exit --
            ensure!(
                profile.status != AgentStatus::Revoked,
                Error::<T>::AgentAlreadyRevoked
            );
 
            // -- 5. Unreserve registration deposit — returned in full ---------
            T::Currency::unreserve(&controller, T::RegistrationDeposit::get());
 
            // -- 6. Prune did from reverse-index — sibling DIDs unaffected ----
            ControllerAgents::<T>::try_mutate(&controller, |dids| {
                dids.retain(|d| *d != did);
                Ok::<(), DispatchError>(())
            })?;
 
            // -- 7. Delete primary profile — slot reclaimed (cf. Revoked) -----
            AgentProfiles::<T>::remove(did);
 
            // -- 8. Decrement active agent count (saturating) -----------------
            ActiveAgentCount::<T>::mutate(|n| *n = n.saturating_sub(1));
 
            // -- 9. Emit event -----------------------------------------------
            Self::deposit_event(Event::AgentDeregistered { did, controller });
 
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
    fn give_star(giver_did: Did, receiver: Did) -> Weight;
    fn remove_star(giver_did: Did, receiver: Did) -> Weight;
    fn deregister_agent(did: Did) -> Weight;
}
 
pub struct SubstrateWeight<T>(core::marker::PhantomData<T>);
 
impl<T: frame_system::Config> WeightInfo for SubstrateWeight<T> {
    /// 6 reads (AgentProfiles, ControllerAgents, 2× block_hash, try_mutate internals),
    /// 3 writes (AgentProfiles::insert, ControllerAgents, ActiveAgentCount).
    /// +300_000_000 for ML-DSA-65 verify (3.4× scaled placeholder; pending benchmarking).
    fn register_agent() -> Weight {
        Weight::from_parts(10_000, 0)
            .saturating_add(Weight::from_parts(25_000_000 * 6, 0))
            .saturating_add(Weight::from_parts(100_000_000 * 3, 0))
            .saturating_add(Weight::from_parts(300_000_000, 0))
    }
    /// 1 read: AgentProfiles::get. 1 write: AgentProfiles::insert.
    fn update_profile() -> Weight {
        Weight::from_parts(8_000, 0)
            .saturating_add(Weight::from_parts(25_000_000, 0))
            .saturating_add(Weight::from_parts(100_000_000, 0))
    }
    /// 2 reads, 2 writes: AgentProfiles::get + insert, plus the
    /// worst-case Revoked path's ActiveAgentCount::mutate (get + put).
    fn set_agent_status() -> Weight {
        Weight::from_parts(6_000, 0)
            .saturating_add(Weight::from_parts(25_000_000 * 2, 0))
            .saturating_add(Weight::from_parts(100_000_000 * 2, 0))
    }
    /// 4 reads (ControllerAgents, AgentProfiles×2 incl. try_mutate internal, StarGivers),
    /// 2 writes (StarGivers::insert, AgentProfiles::try_mutate). Flat per-call estimate;
    /// params unused — signature required by `#[pallet::weight]` convention.
    fn give_star(_giver_did: Did, _receiver: Did) -> Weight {
        Weight::from_parts(8_000, 0)
            .saturating_add(Weight::from_parts(25_000_000 * 4, 0))
            .saturating_add(Weight::from_parts(100_000_000 * 2, 0))
    }
    /// 3 reads: ControllerAgents::get, StarGivers::get, plus the
    /// internal get() inside AgentProfiles::try_mutate. 2 writes:
    /// StarGivers::insert, AgentProfiles::try_mutate.
    fn remove_star(_giver_did: Did, _receiver: Did) -> Weight {
        Weight::from_parts(8_000, 0)
            .saturating_add(Weight::from_parts(25_000_000 * 3, 0))
            .saturating_add(Weight::from_parts(100_000_000 * 2, 0))
    }
    /// 3 reads: AgentProfiles::get, ControllerAgents::try_mutate internal,
    /// ActiveAgentCount::mutate internal (get-then-put, confirmed via frame-support).
    /// 3 writes: ControllerAgents::try_mutate, AgentProfiles::remove, ActiveAgentCount.
    fn deregister_agent(_did: Did) -> Weight {
        Weight::from_parts(6_000, 0)
            .saturating_add(Weight::from_parts(25_000_000 * 3, 0))
            .saturating_add(Weight::from_parts(100_000_000 * 3, 0))
    }
}
 
impl WeightInfo for () {
    // Dev/test mirror of SubstrateWeight<T> — values are identical on purpose
    // so test environments surface the same cost profile as production.
 
    /// = 10_000 + (25_000_000 * 6) + (100_000_000 * 3) + 300_000_000
    fn register_agent() -> Weight {
        Weight::from_parts(750_010_000, 0)
    }
    /// = 8_000 + 25_000_000 + 100_000_000
    fn update_profile() -> Weight {
        Weight::from_parts(125_008_000, 0)
    }
    /// = 6_000 + (25_000_000 * 2) + (100_000_000 * 2)
    fn set_agent_status() -> Weight {
        Weight::from_parts(250_006_000, 0)
    }
    /// = 8_000 + (25_000_000 * 4) + (100_000_000 * 2)
    fn give_star(_giver_did: Did, _receiver: Did) -> Weight {
        Weight::from_parts(300_008_000, 0)
    }
    /// = 8_000 + (25_000_000 * 3) + (100_000_000 * 2)
    fn remove_star(_giver_did: Did, _receiver: Did) -> Weight {
        Weight::from_parts(275_008_000, 0)
    }
    /// = 6_000 + (25_000_000 * 3) + (100_000_000 * 3)
    fn deregister_agent(_did: Did) -> Weight {
        Weight::from_parts(375_006_000, 0)
    }
}
 