//! Bridges `pallet_vector_db::AgentLookup` to `pallet_agent_registry`'s
//! on-chain `AgentProfiles` storage.
//!
//! `pallet-vector-db` is deliberately decoupled from `pallet-agent-registry` at
//! the type level — it only knows about the `AgentLookup` trait it declares,
//! not the concrete pallet that answers it. This adapter is the one place in
//! the runtime where that decoupling is bridged back together, so it is kept
//! deliberately small and free of any business logic beyond a direct storage
//! read and field projection.

use crate::Runtime;
use pallet_agent_registry::{AgentProfiles, AgentStatus};

/// Bridges `pallet_vector_db::AgentLookup` onto `pallet_agent_registry`'s
/// `AgentProfiles` storage map.
///
/// Stateless by design — implements the lookup trait directly against runtime
/// storage rather than caching or duplicating any agent-registry data.
pub struct AgentRegistryAdapter;

impl pallet_vector_db::AgentLookup<<Runtime as frame_system::Config>::AccountId>
    for AgentRegistryAdapter
{
    fn controller_of(
        did: &[u8; 32],
    ) -> Option<<Runtime as frame_system::Config>::AccountId> {
        AgentProfiles::<Runtime>::get(did).map(|profile| profile.controller)
    }

    fn is_active_verified(did: &[u8; 32]) -> bool {
        AgentProfiles::<Runtime>::get(did)
            .map(|profile| profile.status == AgentStatus::Active && profile.is_verified)
            .unwrap_or(false)
    }
}
