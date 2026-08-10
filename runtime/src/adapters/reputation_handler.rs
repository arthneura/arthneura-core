//! Bridges `pallet_vector_db::ReputationHandler` to `pallet_agent_registry`'s
//! non-extrinsic `slash_reputation` function.
//!
//! Same decoupling philosophy as `AgentRegistryAdapter`: `pallet-vector-db`
//! only knows about the `ReputationHandler` trait it declares, not the
//! concrete pallet that answers it. This adapter is the one place in the
//! runtime where that decoupling is bridged back together.
//!
//! The slash amounts (`ProviderGuiltySlash`, `FalseDisputeSlash`) live in
//! `pallet_vector_db::Config` — read here via the trait, not hardcoded --
//! so the runtime's `configs/mod.rs` remains the single source of truth for
//! both values.

use crate::Runtime;
use frame_support::traits::Get;

/// Bridges `pallet_vector_db::ReputationHandler` onto
/// `pallet_agent_registry::Pallet::slash_reputation`.
///
/// Stateless by design — no caching, no business logic beyond reading the
/// configured slash amount and forwarding the call.
pub struct ReputationHandlerAdapter;

impl pallet_vector_db::ReputationHandler for ReputationHandlerAdapter {
    fn penalize_provider(did: &pallet_vector_db::Did) {
        let amount = <Runtime as pallet_vector_db::Config>::ProviderGuiltySlash::get();
        pallet_agent_registry::Pallet::<Runtime>::slash_reputation(did, amount);
    }

    fn penalize_false_disputer(did: &pallet_vector_db::Did) {
        let amount = <Runtime as pallet_vector_db::Config>::FalseDisputeSlash::get();
        pallet_agent_registry::Pallet::<Runtime>::slash_reputation(did, amount);
    }
}
