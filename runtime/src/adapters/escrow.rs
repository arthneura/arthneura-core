//! Bridges `pallet_vector_db::EscrowHandler` to `pallet_escrow`'s
//! internal `lock`/`release`/`refund` functions.
//!
//! Same decoupling philosophy as the other adapters in this module:
//! `pallet-vector-db` only knows about the `EscrowHandler` trait it
//! declares, not the concrete pallet that answers it. `pallet-escrow`
//! itself knows nothing about commitments, disputes, or data delivery
//! -- it only knows how to hold a payer's funds against an ID and,
//! later, move or return them. This adapter is the one place in the
//! runtime where the two are bridged together.

use crate::Runtime;

/// Bridges `pallet_vector_db::EscrowHandler` onto
/// `pallet_escrow::Pallet::{lock, release, refund}`.
///
/// Stateless by design -- no caching, no business logic beyond
/// forwarding the call. `pallet-escrow`'s `EscrowId` and
/// `pallet-vector-db`'s `CommitmentId` are both `[u8; 32]`, so no
/// translation is needed between the two identifiers -- the commitment
/// ID is reused directly as the escrow ID.
pub struct EscrowAdapter;

impl pallet_vector_db::EscrowHandler<<Runtime as frame_system::Config>::AccountId, pallet_escrow::BalanceOf<Runtime>>
    for EscrowAdapter
{
    fn lock(
        escrow_id: pallet_vector_db::CommitmentId,
        payer: <Runtime as frame_system::Config>::AccountId,
        payee: <Runtime as frame_system::Config>::AccountId,
        amount: pallet_escrow::BalanceOf<Runtime>,
    ) -> sp_runtime::DispatchResult {
        pallet_escrow::Pallet::<Runtime>::lock(escrow_id, payer, payee, amount)
    }

    fn release(escrow_id: pallet_vector_db::CommitmentId) -> sp_runtime::DispatchResult {
        pallet_escrow::Pallet::<Runtime>::release(escrow_id)
    }

    fn refund(escrow_id: pallet_vector_db::CommitmentId) -> sp_runtime::DispatchResult {
        pallet_escrow::Pallet::<Runtime>::refund(escrow_id)
    }
}
