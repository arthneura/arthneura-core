//! Standard test suite verifying invariants of the `acknowledge_commitment` extrinsic.

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

/// Registers a commitment for the given pair at the current block and returns its
/// `CommitmentId`. Leaves the commitment in `Pending` status, ready to acknowledge.
fn register_default(p: [u8; 32], c: [u8; 32], expires_in_blocks: u64) -> [u8; 32] {
    let block = System::block_number();
    assert_ok!(VectorDb::register_commitment(
        RuntimeOrigin::signed(1),
        p,
        c,
        test_vector_hash(1),
        10u64,
        metadata(),
        expires_in_blocks,
    ));
    derive_commitment_id(p, c, test_vector_hash(1), block)
}

// --- 1. Happy-Path Integration ---

#[test]
fn acknowledge_commitment_happy_path_succeeds() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));
    });
}

// --- 2. Storage Fields Integrity Check ---

#[test]
fn acknowledge_commitment_stores_correct_fields() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        System::set_block_number(5);
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));

        let stored = VectorDb::vector_commitment(cid).expect("commitment must exist");
        assert_eq!(
            stored.status,
            CommitmentStatus::Active,
            "status must transition to Active"
        );
        assert_eq!(
            stored.acknowledged_at,
            Some(5u64),
            "acknowledged_at must equal the block acknowledge was called at"
        );
        // Fields untouched by acknowledge must remain exactly as registered.
        assert_eq!(stored.provider, p);
        assert_eq!(stored.consumer, c);
        assert_eq!(stored.created_at, 1u64);
    });
}

// --- 3. Event Emission Verification ---

#[test]
fn acknowledge_commitment_emits_correct_event() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        System::set_block_number(3);
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));

        System::assert_last_event(RuntimeEvent::VectorDb(Event::CommitmentAcknowledged {
            commitment_id: cid,
            acknowledged_at: 3u64,
        }));
    });
}

// --- 4. Event Emission Uniqueness ---

#[test]
fn acknowledge_commitment_only_one_event_on_success() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);
        System::reset_events();

        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));

        assert_eq!(System::events().len(), 1);
    });
}

// --- 5. Unsigned Origin Rejection ---

#[test]
fn acknowledge_commitment_rejects_unsigned_origin() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::none(), cid, c),
            DispatchError::BadOrigin
        );
    });
}

// --- 6. Root Origin Rejection (Sudo Guard) ---

#[test]
fn acknowledge_commitment_rejects_root_origin() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::root(), cid, c),
            DispatchError::BadOrigin
        );
    });
}

// --- 7. Nonexistent Commitment Rejection ---

#[test]
fn acknowledge_commitment_rejects_nonexistent_commitment() {
    new_test_ext().execute_with(|| {
        let (_p, c) = setup_valid_pair();
        let bogus_cid = [0xABu8; 32];

        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(2), bogus_cid, c),
            Error::<Runtime>::CommitmentNotFound
        );
    });
}

// --- 8. Double-Acknowledge Rejection (Already Active) ---

#[test]
fn acknowledge_commitment_double_acknowledge_fails_with_not_pending() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));

        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(2), cid, c),
            Error::<Runtime>::NotPending
        );
    });
}

// --- 9. Rejection After Settlement (Terminal State) ---

#[test]
fn acknowledge_commitment_fails_after_settlement() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);
        let root = test_vector_hash(1);

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
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(2), cid, c),
            Error::<Runtime>::NotPending
        );
    });
}

// --- 10. Exact Expiry Boundary Rejection ---

#[test]
fn acknowledge_commitment_rejects_at_exact_expiry_block() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        // Registered at block 1 with expires_in_blocks = 10 => expires_at = 11.
        let cid = register_default(p, c, 10u64);

        System::set_block_number(11);
        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(2), cid, c),
            Error::<Runtime>::CommitmentExpiredError
        );
    });
}

// --- 11. Last-Valid-Block Boundary Acceptance ---

#[test]
fn acknowledge_commitment_accepts_at_last_valid_block() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        // expires_at = 11; block 10 is the last block strictly less than expires_at.
        let cid = register_default(p, c, 10u64);

        System::set_block_number(10);
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));
    });
}

// --- 12. Post-Expiry Rejection (Well Past Deadline) ---

#[test]
fn acknowledge_commitment_rejects_long_after_expiry() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 10u64);

        System::set_block_number(500);
        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(2), cid, c),
            Error::<Runtime>::CommitmentExpiredError
        );
    });
}

// --- 13. Wrong Consumer DID Rejection ---

#[test]
fn acknowledge_commitment_rejects_wrong_consumer_did() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        let impostor_did = test_did(50);
        register_test_agent(impostor_did, 2, true); // same controller, different DID

        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(2), cid, impostor_did),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 14. Provider Attempting to Self-Acknowledge Rejection ---

#[test]
fn acknowledge_commitment_provider_cannot_acknowledge_as_consumer() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(1), cid, p),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 15. Wrong Controller Rejection (Correct DID, Wrong Caller) ---

#[test]
fn acknowledge_commitment_rejects_wrong_controller() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        // Account 99 never controls `c` — controller is account 2.
        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(99), cid, c),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 16. Registered Attacker Cannot Acknowledge Someone Else's Commitment ---

#[test]
fn acknowledge_commitment_registered_attacker_cannot_acknowledge_others() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        // Attacker is a fully legitimate, verified agent — just not this commitment's consumer.
        let attacker_did = test_did(66);
        register_test_agent(attacker_did, 66, true);

        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(66), cid, attacker_did),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 17. Consumer Suspended After Registration Rejection ---

#[test]
fn acknowledge_commitment_rejects_consumer_suspended_after_registration() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        // Consumer was active_verified at registration time, but is suspended before ack.
        register_test_agent(c, 2, false);

        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(2), cid, c),
            Error::<Runtime>::ConsumerNotEligible
        );
    });
}

// --- 18. Guard Ordering: NotPending Precedes CommitmentExpiredError ---

#[test]
fn acknowledge_commitment_not_pending_check_precedes_expiry_check() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 5u64); // expires_at = 6

        // Acknowledge successfully while still valid.
        System::set_block_number(2);
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));

        // Now well past the original expiry — commitment is Active, not Pending.
        // If status were not checked first, this would surface CommitmentExpiredError.
        System::set_block_number(1000);
        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(2), cid, c),
            Error::<Runtime>::NotPending
        );
    });
}

// --- 19. Guard Ordering: Expiry Check Precedes Consumer Identity Check ---

#[test]
fn acknowledge_commitment_expiry_check_precedes_consumer_check() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 5u64); // expires_at = 6, still Pending

        System::set_block_number(6); // exactly at boundary: expired, still Pending
        let wrong_consumer = test_did(123);
        register_test_agent(wrong_consumer, 123, true);

        // Status is still Pending, so we reach the expiry check next; the wrong consumer_did
        // is irrelevant because the extrinsic must reject on expiry before it even looks at identity.
        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(123), cid, wrong_consumer),
            Error::<Runtime>::CommitmentExpiredError
        );
    });
}

// --- 20. Guard Ordering: Consumer DID Match Precedes Controller Eligibility ---

#[test]
fn acknowledge_commitment_consumer_match_precedes_controller_lookup() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        // An entirely unregistered DID — controller_of would return None if we ever reached
        // that check. But consumer_did mismatch must be caught first.
        let unregistered_did = test_did(200);

        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(2), cid, unregistered_did),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 21. Controller Can Act Using Any Owned DID Correctly, But Not a Sibling DID ---

#[test]
fn acknowledge_commitment_controller_cannot_substitute_sibling_did() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        // Same controller (account 2) also owns a second, unrelated DID.
        let sibling_did = test_did(9);
        register_test_agent(sibling_did, 2, true);

        // Correct controller, wrong DID for *this* commitment.
        assert_noop!(
            VectorDb::acknowledge_commitment(RuntimeOrigin::signed(2), cid, sibling_did),
            Error::<Runtime>::NotConsumer
        );

        // The actual consumer DID still works.
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));
    });
}

// --- 22. Does Not Mutate `ActiveCommitmentCount` ---

#[test]
fn acknowledge_commitment_does_not_change_active_commitment_count() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);
        assert_eq!(VectorDb::active_commitment_count(), 1);

        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));

        assert_eq!(
            VectorDb::active_commitment_count(),
            1,
            "acknowledge must not touch the active commitment counter"
        );
    });
}

// --- 23. Does Not Create StreamReceipt or DisputeRecord ---

#[test]
fn acknowledge_commitment_does_not_create_receipt_or_dispute() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 100u64);

        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));

        assert!(VectorDb::stream_receipt(cid).is_none());
        assert!(VectorDb::dispute_record(cid).is_none());
    });
}

// --- 24. State Mutability Safety on Rejection ---

#[test]
fn acknowledge_commitment_failed_call_does_not_mutate_storage() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let cid = register_default(p, c, 5u64); // expires_at = 6

        System::set_block_number(50); // expired
        let _ = VectorDb::acknowledge_commitment(RuntimeOrigin::signed(2), cid, c);

        let stored = VectorDb::vector_commitment(cid).expect("commitment must still exist");
        assert_eq!(
            stored.status,
            CommitmentStatus::Pending,
            "status must remain Pending after a failed acknowledge"
        );
        assert!(
            stored.acknowledged_at.is_none(),
            "acknowledged_at must remain None after a failed acknowledge"
        );
    });
}

// --- 25. Minimum-Lifetime Commitment Can Still Be Acknowledged In-Window ---

#[test]
fn acknowledge_commitment_accepts_minimum_lifetime_commitment_in_window() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        // expires_in_blocks = 1 => expires_at = 2. Block 1 (< 2) is the only valid window.
        let cid = register_default(p, c, 1u64);

        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));
    });
}

// --- 26. Multiple Independent Commitments Acknowledge Independently ---

#[test]
fn acknowledge_commitment_multiple_commitments_are_independent() {
    new_test_ext().execute_with(|| {
        let p = test_did(1);
        let c1 = test_did(2);
        let c2 = test_did(3);
        register_test_agent(p, 1, true);
        register_test_agent(c1, 2, true);
        register_test_agent(c2, 3, true);

        let block = System::block_number();
        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c1,
            test_vector_hash(1),
            10u64,
            metadata(),
            100u64,
        ));
        let cid1 = derive_commitment_id(p, c1, test_vector_hash(1), block);

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c2,
            test_vector_hash(2),
            10u64,
            metadata(),
            100u64,
        ));
        let cid2 = derive_commitment_id(p, c2, test_vector_hash(2), block);

        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid1,
            c1,
        ));

        // cid2 must remain untouched — Pending, not yet acknowledged.
        let stored2 = VectorDb::vector_commitment(cid2).unwrap();
        assert_eq!(stored2.status, CommitmentStatus::Pending);
        assert!(stored2.acknowledged_at.is_none());

        // cid1 must reflect the acknowledge.
        let stored1 = VectorDb::vector_commitment(cid1).unwrap();
        assert_eq!(stored1.status, CommitmentStatus::Active);
    });
}
