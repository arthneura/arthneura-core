//! Standard test suite verifying invariants of the `expire_commitment` extrinsic.

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

/// Registers a commitment and leaves it in `Pending` state.
fn setup_pending_commitment(expires_in_blocks: u64) -> [u8; 32] {
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
    derive_commitment_id(p, c, root, block)
}

/// Registers and acknowledges a commitment, leaving it in `Active` state.
fn setup_active_commitment(expires_in_blocks: u64) -> [u8; 32] {
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
    cid
}

// --- 1. Happy-Path: Pending Expiry ---

#[test]
fn expire_commitment_happy_path_pending_succeeds() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);

        System::set_block_number(11);
        assert_ok!(VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid));
    });
}

// --- 2. Happy-Path: Active Expiry ---

#[test]
fn expire_commitment_happy_path_active_succeeds() {
    new_test_ext().execute_with(|| {
        let cid = setup_active_commitment(10u64);

        System::set_block_number(11);
        assert_ok!(VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid));
    });
}

// --- 3. Complete Storage Removal Verification ---

#[test]
fn expire_commitment_fully_removes_storage_entry() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);

        System::set_block_number(11);
        assert_ok!(VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid));

        assert!(
            VectorDb::vector_commitment(cid).is_none(),
            "expire_commitment must fully purge the VectorCommitments entry"
        );
    });
}

// --- 4. Event Emission Verification ---

#[test]
fn expire_commitment_emits_correct_event() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);

        System::set_block_number(11);
        assert_ok!(VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid));

        System::assert_last_event(RuntimeEvent::VectorDb(Event::CommitmentExpired {
            commitment_id: cid,
        }));
    });
}

// --- 5. Event Uniqueness Verification ---

#[test]
fn expire_commitment_only_one_event_on_success() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);
        System::set_block_number(11);
        System::reset_events();

        assert_ok!(VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid));

        assert_eq!(System::events().len(), 1);
    });
}

// --- 6. Active Commitment Counter Decrement ---

#[test]
fn expire_commitment_decrements_active_commitment_count() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);
        assert_eq!(VectorDb::active_commitment_count(), 1);

        System::set_block_number(11);
        assert_ok!(VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid));

        assert_eq!(VectorDb::active_commitment_count(), 0);
    });
}

// --- 7. Unsigned Origin Rejection ---

#[test]
fn expire_commitment_rejects_unsigned_origin() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);
        System::set_block_number(11);

        assert_noop!(
            VectorDb::expire_commitment(RuntimeOrigin::none(), cid),
            DispatchError::BadOrigin
        );
    });
}

// --- 8. Sudo Origin Rejection ---

#[test]
fn expire_commitment_rejects_root_origin() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);
        System::set_block_number(11);

        assert_noop!(
            VectorDb::expire_commitment(RuntimeOrigin::root(), cid),
            DispatchError::BadOrigin
        );
    });
}

// --- 9. Nonexistent Commitment Rejection ---

#[test]
fn expire_commitment_rejects_nonexistent_commitment() {
    new_test_ext().execute_with(|| {
        let bogus_cid = [0x3Du8; 32];

        assert_noop!(
            VectorDb::expire_commitment(RuntimeOrigin::signed(1), bogus_cid),
            Error::<Runtime>::CommitmentNotFound
        );
    });
}

// --- 10. Temporal Boundary: Pre-Expiry Rejection ---

#[test]
fn expire_commitment_rejects_before_expiry() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);

        System::set_block_number(5);
        assert_noop!(
            VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::NotYetExpired
        );
    });
}

// --- 11. Temporal Boundary: Exact Expiry Acceptance ---

#[test]
fn expire_commitment_accepts_at_exact_expiry_block_inclusive() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);

        System::set_block_number(11);
        assert_ok!(VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid));
    });
}

// --- 12. Temporal Boundary: Immediate Pre-Expiry Rejection ---

#[test]
fn expire_commitment_rejects_one_block_before_expiry() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);

        System::set_block_number(10);
        assert_noop!(
            VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::NotYetExpired
        );
    });
}

// --- 13. Temporal Boundary: Post-Expiry Acceptance ---

#[test]
fn expire_commitment_accepts_long_after_expiry() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);

        System::set_block_number(999);
        assert_ok!(VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid));
    });
}

// --- 14. Precondition Check: Settled State Rejection ---

#[test]
fn expire_commitment_rejects_settled_commitment() {
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
            10u64,
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

        System::set_block_number(999);
        assert_noop!(
            VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::AlreadyFinalized
        );
    });
}

// --- 15. Precondition Check: Disputed State Rejection ---

#[test]
fn expire_commitment_rejects_disputed_commitment() {
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
            10u64,
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
            [0xEEu8; 32],
            10u64,
        ));

        System::set_block_number(999);
        assert_noop!(
            VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::AlreadyFinalized
        );
    });
}

// --- 16. Precondition Check: Resolved State Rejection ---

#[test]
fn expire_commitment_rejects_dispute_resolved_commitment() {
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
            10u64,
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
            [0xEEu8; 32],
            10u64,
        ));

        System::set_block_number(12);
        assert_ok!(VectorDb::finalize_dispute(RuntimeOrigin::signed(1), cid));

        System::set_block_number(999);
        assert_noop!(
            VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::AlreadyFinalized
        );
    });
}

// --- 17. Idempotency Check: Double Expire Rejection ---

#[test]
fn expire_commitment_double_expire_fails_with_commitment_not_found() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);

        System::set_block_number(11);
        assert_ok!(VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid));

        assert_noop!(
            VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::CommitmentNotFound
        );
    });
}

// --- 18. Permissionless Call: Third-Party Access ---

#[test]
fn expire_commitment_any_signed_account_can_call_it() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);
        System::set_block_number(11);

        assert_ok!(VectorDb::expire_commitment(
            RuntimeOrigin::signed(7777),
            cid
        ));
    });
}

// --- 19. Resiliency Check: Suspended Identity Processing ---

#[test]
fn expire_commitment_succeeds_even_if_both_parties_are_suspended() {
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
            10u64,
        ));
        let cid = derive_commitment_id(p, c, root, block);

        register_test_agent(p, 1, false);
        register_test_agent(c, 2, false);

        System::set_block_number(11);
        assert_ok!(VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid));
    });
}

// --- 20. Invariant Check: Storage Leak Prevention ---

#[test]
fn expire_commitment_leaves_no_orphaned_receipt_or_dispute_record() {
    new_test_ext().execute_with(|| {
        let cid = setup_active_commitment(10u64);

        System::set_block_number(11);
        assert_ok!(VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid));

        assert!(VectorDb::stream_receipt(cid).is_none());
        assert!(VectorDb::dispute_record(cid).is_none());
    });
}

// --- 21. State Mutability Safety on Rejection ---

#[test]
fn expire_commitment_failed_call_does_not_mutate_storage() {
    new_test_ext().execute_with(|| {
        let cid = setup_pending_commitment(10u64);

        System::set_block_number(5);
        let _ = VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid);

        let commitment = VectorDb::vector_commitment(cid);
        assert!(
            commitment.is_some(),
            "a failed expire_commitment call must NOT remove the commitment"
        );
        assert_eq!(
            commitment.unwrap().status,
            CommitmentStatus::Pending,
            "status must remain untouched after a failed expire_commitment"
        );
        assert_eq!(
            VectorDb::active_commitment_count(),
            1,
            "active count must remain unchanged after a failed expire_commitment"
        );
    });
}

// --- 22. Multi-Commitment Independence Verification ---

#[test]
fn expire_commitment_multiple_commitments_are_independent() {
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
            5u64,
        ));
        let cid1 = derive_commitment_id(p, c1, root1, block);

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c2,
            root2,
            10u64,
            metadata(),
            500u64,
        ));
        let cid2 = derive_commitment_id(p, c2, root2, block);

        System::set_block_number(6);
        assert_ok!(VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid1));

        assert!(VectorDb::vector_commitment(cid1).is_none());
        assert!(
            VectorDb::vector_commitment(cid2).is_some(),
            "cid2 must remain untouched by cid1's expiry"
        );
        assert_eq!(VectorDb::active_commitment_count(), 1);
    });
}

// --- 23. Guard Priority: AlreadyFinalized precedes NotYetExpired ---

#[test]
fn expire_commitment_already_finalized_check_precedes_not_yet_expired_check() {
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
            VectorDb::expire_commitment(RuntimeOrigin::signed(1), cid),
            Error::<Runtime>::AlreadyFinalized
        );
    });
}
