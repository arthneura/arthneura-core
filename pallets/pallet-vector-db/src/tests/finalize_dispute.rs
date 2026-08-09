//! Standard test suite verifying invariants of the `finalize_dispute` extrinsic.

use super::*;
use crate::mock::RuntimeEvent;

// --- Shared Fixture Helpers ---

/// Provisions a valid, active, and verified provider-consumer agent pair.
/// Provider controller is account 1, Consumer controller is account 2.
fn setup_valid_pair() -> ([u8; 32], [u8; 32]) {
    let p = test_did(1);
    let c = test_did(2);
    register_test_agent(p, 1, true);
    register_test_agent(c, 2, true);
    (p, c)
}

/// Sets up a complete disputed commitment state with standard counter deadline.
fn setup_disputed_commitment(expires_in_blocks: u64) -> ([u8; 32], [u8; 32], [u8; 32]) {
    let (p, c) = setup_valid_pair();
    let root = test_vector_hash(1);
    let block = System::block_number();

    assert_ok!(VectorDb::register_commitment(
        RuntimeOrigin::signed(1),
        p,
        c,
        root,
        10u64,
        metadata(),
        expires_in_blocks,
    ));
    let cid = derive_commitment_id(p, c, root, block);

    assert_ok!(VectorDb::acknowledge_commitment(
        RuntimeOrigin::signed(2),
        cid,
        c,
    ));

    assert_ok!(VectorDb::raise_dispute(
        RuntimeOrigin::signed(2),
        cid,
        c,
        0u64,
        [0xEEu8; 32],
        10u64,
    ));

    (cid, p, c)
}

// --- 1. Happy-Path Integration ---

#[test]
fn finalize_dispute_happy_path_succeeds() {
    new_test_ext().execute_with(|| {
        let (cid, _p, _c) = setup_disputed_commitment(1000u64);

        System::set_block_number(12);
        assert_ok!(VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid));
    });
}

// --- 2. Storage & Verdict Fields Integrity Check ---

#[test]
fn finalize_dispute_stores_correct_fields() {
    new_test_ext().execute_with(|| {
        let (cid, _p, _c) = setup_disputed_commitment(1000u64);

        System::set_block_number(20);
        assert_ok!(VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid));

        let commitment = VectorDb::vector_commitment(cid).expect("commitment must exist");
        assert_eq!(
            commitment.status,
            CommitmentStatus::DisputeResolved,
            "status must transition to DisputeResolved"
        );

        let dispute = VectorDb::dispute_record(cid).expect("DisputeRecord must persist");
        assert_eq!(
            dispute.verdict,
            Some(DisputeVerdict::ProviderGuilty),
            "an uncontested dispute must resolve with ProviderGuilty"
        );
        assert_eq!(dispute.counter_deadline, 11u64);
    });
}

// --- 3. Event Emission Verification ---

#[test]
fn finalize_dispute_emits_correct_event() {
    new_test_ext().execute_with(|| {
        let (cid, p, c) = setup_disputed_commitment(1000u64);

        System::set_block_number(50);
        assert_ok!(VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid));

        System::assert_last_event(RuntimeEvent::VectorDb(Event::DisputeFinalized {
            commitment_id: cid,
            verdict: DisputeVerdict::ProviderGuilty,
            provider: p,
            consumer: c,
        }));
    });
}

// --- 4. Event Uniqueness Verification ---

#[test]
fn finalize_dispute_only_one_event_on_success() {
    new_test_ext().execute_with(|| {
        let (cid, _p, _c) = setup_disputed_commitment(1000u64);
        System::set_block_number(12);
        System::reset_events();

        assert_ok!(VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid));

        assert_eq!(System::events().len(), 1);
    });
}

// --- 5. Active Commitment Counter Decrement ---

#[test]
fn finalize_dispute_decrements_active_commitment_count() {
    new_test_ext().execute_with(|| {
        let (cid, _p, _c) = setup_disputed_commitment(1000u64);
        assert_eq!(VectorDb::active_commitment_count(), 1);

        System::set_block_number(12);
        assert_ok!(VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid));

        assert_eq!(VectorDb::active_commitment_count(), 0);
    });
}

// --- 6. Unsigned Origin Rejection ---

#[test]
fn finalize_dispute_rejects_unsigned_origin() {
    new_test_ext().execute_with(|| {
        let (cid, _p, _c) = setup_disputed_commitment(1000u64);
        System::set_block_number(12);

        assert_noop!(
            VectorDb::finalize_dispute(RuntimeOrigin::none(), cid),
            DispatchError::BadOrigin
        );
    });
}

// --- 7. Sudo Origin Rejection ---

#[test]
fn finalize_dispute_rejects_root_origin() {
    new_test_ext().execute_with(|| {
        let (cid, _p, _c) = setup_disputed_commitment(1000u64);
        System::set_block_number(12);

        assert_noop!(
            VectorDb::finalize_dispute(RuntimeOrigin::root(), cid),
            DispatchError::BadOrigin
        );
    });
}

// --- 8. Nonexistent Commitment Rejection ---

#[test]
fn finalize_dispute_rejects_nonexistent_commitment() {
    new_test_ext().execute_with(|| {
        let bogus_cid = [0x5Cu8; 32];

        assert_noop!(
            VectorDb::finalize_dispute(RuntimeOrigin::signed(1), bogus_cid),
            Error::<Runtime>::CommitmentNotFound
        );
    });
}

// --- 9. Precondition Check: Awaiting Dispute Rejection ---

#[test]
fn finalize_dispute_rejects_still_active() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let root = test_vector_hash(1);
        let block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            10u64,
            metadata(),
            1000u64,
        ));
        let cid = derive_commitment_id(p, c, root, block);
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));

        assert_noop!(
            VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::NotDisputed
        );
    });
}

// --- 10. Precondition Check: Pending State Rejection ---

#[test]
fn finalize_dispute_rejects_still_pending() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let root = test_vector_hash(1);
        let block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            10u64,
            metadata(),
            1000u64,
        ));
        let cid = derive_commitment_id(p, c, root, block);

        assert_noop!(
            VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::NotDisputed
        );
    });
}

// --- 11. Precondition Check: Settled State Rejection ---

#[test]
fn finalize_dispute_rejects_settled_commitment() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let root = test_vector_hash(1);
        let block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            10u64,
            metadata(),
            1000u64,
        ));
        let cid = derive_commitment_id(p, c, root, block);
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));
        assert_ok!(VectorDb::close_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
            root,
            10u64,
        ));

        assert_noop!(
            VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::NotDisputed
        );
    });
}

// --- 12. Precondition Check: Post-Counter Rejection ---

#[test]
fn finalize_dispute_rejects_after_successful_counter() {
    new_test_ext().execute_with(|| {
        use crate::{Blake2bHasher, MAX_CHUNK_LEN, MAX_PROOF_DEPTH};
        use frame_support::traits::ConstU32;
        use frame_support::BoundedVec;
        use rs_merkle::{Hasher, MerkleTree};

        let (p, c) = setup_valid_pair();
        let chunks: Vec<Vec<u8>> = (0u8..4).map(|i| vec![i; 64]).collect();
        let leaves: Vec<[u8; 32]> = chunks.iter().map(|ch| Blake2bHasher::hash(ch)).collect();
        let tree = MerkleTree::<Blake2bHasher>::from_leaves(&leaves);
        let root = tree.root().unwrap();
        let block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            4u64,
            metadata(),
            1000u64,
        ));
        let cid = derive_commitment_id(p, c, root, block);
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));
        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid,
            c,
            0u64,
            [0xEEu8; 32],
            4u64,
        ));

        let proof = tree.proof(&[0]);
        let bounded_proof: BoundedVec<[u8; 32], ConstU32<MAX_PROOF_DEPTH>> =
            BoundedVec::try_from(proof.proof_hashes().to_vec()).unwrap();
        let bounded_chunk: BoundedVec<u8, ConstU32<MAX_CHUNK_LEN>> =
            BoundedVec::try_from(chunks[0].clone()).unwrap();

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            p,
            bounded_chunk,
            bounded_proof,
        ));

        System::set_block_number(1000);
        assert_noop!(
            VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::NotDisputed
        );
    });
}

// --- 13. Idempotency Check: Double Finalize Rejection ---

#[test]
fn finalize_dispute_double_finalize_fails_with_not_disputed() {
    new_test_ext().execute_with(|| {
        let (cid, _p, _c) = setup_disputed_commitment(1000u64);

        System::set_block_number(12);
        assert_ok!(VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid));

        assert_noop!(
            VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::NotDisputed
        );
    });
}

// --- 14. Temporal Deadline: Boundary Rejection ---

#[test]
fn finalize_dispute_rejects_at_exact_deadline_block() {
    new_test_ext().execute_with(|| {
        let (cid, _p, _c) = setup_disputed_commitment(1000u64);

        System::set_block_number(11);
        assert_noop!(
            VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::DisputeWindowStillOpen
        );
    });
}

// --- 15. Temporal Deadline: Over-Boundary Acceptance ---

#[test]
fn finalize_dispute_accepts_one_block_past_deadline() {
    new_test_ext().execute_with(|| {
        let (cid, _p, _c) = setup_disputed_commitment(1000u64);

        System::set_block_number(12);
        assert_ok!(VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid));
    });
}

// --- 16. Temporal Deadline: Under-Boundary Rejection ---

#[test]
fn finalize_dispute_rejects_well_before_deadline() {
    new_test_ext().execute_with(|| {
        let (cid, _p, _c) = setup_disputed_commitment(1000u64);

        System::set_block_number(3);
        assert_noop!(
            VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::DisputeWindowStillOpen
        );
    });
}

// --- 17. Temporal Deadline: Long-After-Deadline Acceptance ---

#[test]
fn finalize_dispute_accepts_long_after_deadline() {
    new_test_ext().execute_with(|| {
        let (cid, _p, _c) = setup_disputed_commitment(1000u64);

        System::set_block_number(999);
        assert_ok!(VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid));
    });
}

// --- 18. Permissionless Call: Third-Party Access ---

#[test]
fn finalize_dispute_any_signed_account_can_call_it() {
    new_test_ext().execute_with(|| {
        let (cid, _p, _c) = setup_disputed_commitment(1000u64);
        System::set_block_number(12);

        assert_ok!(VectorDb::finalize_dispute(RuntimeOrigin::signed(9999), cid));
    });
}

// --- 19. Resiliency Check: Suspended Identity Processing ---

#[test]
fn finalize_dispute_succeeds_even_if_both_parties_are_suspended() {
    new_test_ext().execute_with(|| {
        let (cid, p, c) = setup_disputed_commitment(1000u64);

        register_test_agent(p, 1, false);
        register_test_agent(c, 2, false);

        System::set_block_number(12);
        assert_ok!(VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid));
    });
}

// --- 20. State Mutability Safety on Rejection ---

#[test]
fn finalize_dispute_failed_call_does_not_mutate_storage() {
    new_test_ext().execute_with(|| {
        let (cid, _p, _c) = setup_disputed_commitment(1000u64);

        System::set_block_number(5);
        let _ = VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid);

        let commitment = VectorDb::vector_commitment(cid).expect("commitment must still exist");
        assert_eq!(
            commitment.status,
            CommitmentStatus::Disputed,
            "status must remain Disputed after a failed finalize_dispute"
        );

        let dispute = VectorDb::dispute_record(cid).expect("DisputeRecord must still exist");
        assert_eq!(
            dispute.verdict, None,
            "verdict must remain unset after a failed finalize_dispute"
        );

        assert_eq!(
            VectorDb::active_commitment_count(),
            1,
            "active count must remain unchanged after a failed finalize_dispute"
        );
    });
}

// --- 21. Event Identity Integrity ---

#[test]
fn finalize_dispute_event_identities_are_immune_to_caller_identity() {
    new_test_ext().execute_with(|| {
        let (cid, p, c) = setup_disputed_commitment(1000u64);
        System::set_block_number(12);

        assert_ok!(VectorDb::finalize_dispute(
            RuntimeOrigin::signed(424242),
            cid
        ));

        System::assert_last_event(RuntimeEvent::VectorDb(Event::DisputeFinalized {
            commitment_id: cid,
            verdict: DisputeVerdict::ProviderGuilty,
            provider: p,
            consumer: c,
        }));
    });
}

// --- 22. Multi-Dispute Independence Verification ---

#[test]
fn finalize_dispute_multiple_commitments_are_independent() {
    new_test_ext().execute_with(|| {
        let p = test_did(1);
        let c1 = test_did(2);
        let c2 = test_did(3);
        register_test_agent(p, 1, true);
        register_test_agent(c1, 2, true);
        register_test_agent(c2, 3, true);

        let block = System::block_number();
        let root1 = test_vector_hash(1);
        let root2 = test_vector_hash(2);

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c1,
            root1,
            10u64,
            metadata(),
            1000u64,
        ));
        let cid1 = derive_commitment_id(p, c1, root1, block);
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid1,
            c1
        ));
        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid1,
            c1,
            0u64,
            [0xEEu8; 32],
            10u64,
        ));

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c2,
            root2,
            10u64,
            metadata(),
            1000u64,
        ));
        let cid2 = derive_commitment_id(p, c2, root2, block);
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(3),
            cid2,
            c2
        ));
        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(3),
            cid2,
            c2,
            0u64,
            [0xEEu8; 32],
            10u64,
        ));

        System::set_block_number(12);
        assert_ok!(VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid1));

        let stored2 = VectorDb::vector_commitment(cid2).unwrap();
        assert_eq!(stored2.status, CommitmentStatus::Disputed);
        assert_eq!(VectorDb::dispute_record(cid2).unwrap().verdict, None);

        let stored1 = VectorDb::vector_commitment(cid1).unwrap();
        assert_eq!(stored1.status, CommitmentStatus::DisputeResolved);
        assert_eq!(
            VectorDb::dispute_record(cid1).unwrap().verdict,
            Some(DisputeVerdict::ProviderGuilty)
        );
    });
}
