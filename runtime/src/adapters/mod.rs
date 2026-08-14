//! Cross-pallet adapters.
//!
//! This module houses small, focused bridge types that translate between a
//! pallet's expected `Config` trait (e.g. `pallet_vector_db::AgentLookup`) and
//! another pallet's concrete on-chain storage (e.g. `pallet_agent_registry`).
//!
//! Keeping these translations here — rather than inline in `configs::mod` —
//! keeps each adapter independently readable, auditable, and reusable by any
//! future pallet that needs the same lookup surface.

pub mod agent_registry;
pub mod escrow;
pub mod reputation_handler;
