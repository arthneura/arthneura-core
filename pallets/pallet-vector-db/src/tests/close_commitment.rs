//! Standard test suite verifying invariants of the `close_commitment` extrinsic.

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

/// Registers and immediately acknowledges a commitment, leaving it `Active`.
/// Returns `(commitment_id, merkle_root)`.
fn setup_active_commitment(expires_in_blocks: u64) -> ([u8; 32], [u8; 32]) {
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

    (cid, root)
}

// --- 1. Happy-Path Integration ---

#[test]
fn close_commitment_happy_path_succeeds() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        assert_ok!(VectorDb::close_commitment(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            root,
            10u64,
        ));
    });
}

// --- 2. Storage Fields Integrity Check (Commitment + StreamReceipt) ---

#[test]
fn close_commitment_stores_correct_fields() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        System::set_block_number(5);
        assert_ok!(VectorDb::close_commitment(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            root,
            42u64,
        ));

        let commitment = VectorDb::vector_commitment(cid).expect("commitment must exist");
        assert_eq!(
            commitment.status,
            CommitmentStatus::Settled,
            "status must transition to Settled"
        );

        let receipt = VectorDb::stream_receipt(cid).expect("StreamReceipt must exist");
        assert_eq!(receipt.commitment_id, cid);
        assert_eq!(receipt.final_stream_hash, root);
        assert_eq!(receipt.chunk_count, 42u64);
        assert_eq!(receipt.submitted_at, 5u64);
    });
}

// --- 3. Event Emission Verification ---

#[test]
fn close_commitment_emits_correct_event() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        assert_ok!(VectorDb::close_commitment(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            root,
            7u64,
        ));

        System::assert_last_event(RuntimeEvent::VectorDb(Event::CommitmentSettled {
            commitment_id: cid,
            final_stream_hash: root,
            chunk_count: 7u64,
        }));
    });
}

// --- 4. Event Emission Uniqueness ---

#[test]
fn close_commitment_only_one_event_on_success() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);
        System::reset_events();

        assert_ok!(VectorDb::close_commitment(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            root,
            1u64,
        ));

        assert_eq!(System::events().len(), 1);
    });
}

// --- 5. Unsigned Origin Rejection ---

#[test]
fn close_commitment_rejects_unsigned_origin() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        assert_noop!(
            VectorDb::close_commitment(RuntimeOrigin::none(), cid, test_did(2), root, 1u64),
            DispatchError::BadOrigin
        );
    });
}

// --- 6. Root Origin Rejection (Sudo Guard) ---

#[test]
fn close_commitment_rejects_root_origin() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        assert_noop!(
            VectorDb::close_commitment(RuntimeOrigin::root(), cid, test_did(2), root, 1u64),
            DispatchError::BadOrigin
        );
    });
}

// --- 7. Nonexistent Commitment Rejection ---

#[test]
fn close_commitment_rejects_nonexistent_commitment() {
    new_test_ext().execute_with(|| {
        let (_p, c) = setup_valid_pair();
        let bogus_cid = [0xCDu8; 32];

        assert_noop!(
            VectorDb::close_commitment(
                RuntimeOrigin::signed(2),
                bogus_cid,
                c,
                test_vector_hash(1),
                1u64,
            ),
            Error::<Runtime>::CommitmentNotFound
        );
    });
}

// --- 8. Rejection While Still Pending (Not Yet Acknowledged) ---

#[test]
fn close_commitment_rejects_still_pending() {
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
            100u64,
        ));
        let cid = derive_commitment_id(p, c, root, block);

        assert_noop!(
            VectorDb::close_commitment(RuntimeOrigin::signed(2), cid, c, root, 10u64),
            Error::<Runtime>::NotActive
        );
    });
}

// --- 9. Double-Close Rejection (Already Settled) ---

#[test]
fn close_commitment_double_close_fails_with_not_active() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        assert_ok!(VectorDb::close_commitment(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            root,
            10u64,
        ));

        assert_noop!(
            VectorDb::close_commitment(RuntimeOrigin::signed(2), cid, test_did(2), root, 10u64),
            Error::<Runtime>::NotActive
        );
    });
}

// --- 10. Rejection After Dispute Raised (Disputed State) ---

#[test]
fn close_commitment_fails_after_dispute_raised() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            0u64,
            [0xFFu8; 32],
            10u64,
        ));

        assert_noop!(
            VectorDb::close_commitment(RuntimeOrigin::signed(2), cid, test_did(2), root, 10u64),
            Error::<Runtime>::NotActive
        );
    });
}

// --- 11. Stream Hash Mismatch Rejection ---

#[test]
fn close_commitment_rejects_stream_hash_mismatch() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);
        let wrong_hash = [0x11u8; 32];

        assert_noop!(
            VectorDb::close_commitment(
                RuntimeOrigin::signed(2),
                cid,
                test_did(2),
                wrong_hash,
                10u64,
            ),
            Error::<Runtime>::StreamHashMismatch
        );
    });
}

// --- 12. Exact Expiry Boundary Rejection ---

#[test]
fn close_commitment_rejects_at_exact_expiry_block() {
    new_test_ext().execute_with(|| {
        // expires_in_blocks = 10 from block 1 => expires_at = 11.
        let (cid, root) = setup_active_commitment(10u64);

        System::set_block_number(11);
        assert_noop!(
            VectorDb::close_commitment(RuntimeOrigin::signed(2), cid, test_did(2), root, 10u64),
            Error::<Runtime>::CommitmentExpiredError
        );
    });
}

// --- 13. Last-Valid-Block Boundary Acceptance ---

#[test]
fn close_commitment_accepts_at_last_valid_block() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(10u64); // expires_at = 11

        System::set_block_number(10);
        assert_ok!(VectorDb::close_commitment(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            root,
            10u64,
        ));
    });
}

// --- 14. Post-Expiry Rejection (Well Past Deadline) ---

#[test]
fn close_commitment_rejects_long_after_expiry() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(10u64);

        System::set_block_number(1000);
        assert_noop!(
            VectorDb::close_commitment(RuntimeOrigin::signed(2), cid, test_did(2), root, 10u64),
            Error::<Runtime>::CommitmentExpiredError
        );
    });
}

// --- 15. Wrong Consumer DID Rejection ---

#[test]
fn close_commitment_rejects_wrong_consumer_did() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        let impostor_did = test_did(50);
        register_test_agent(impostor_did, 2, true); // same controller, different DID

        assert_noop!(
            VectorDb::close_commitment(RuntimeOrigin::signed(2), cid, impostor_did, root, 10u64),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 16. Provider Attempting to Self-Close Rejection ---

#[test]
fn close_commitment_provider_cannot_close_as_consumer() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        assert_noop!(
            VectorDb::close_commitment(RuntimeOrigin::signed(1), cid, test_did(1), root, 10u64),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 17. Wrong Controller Rejection (Correct DID, Wrong Caller) ---

#[test]
fn close_commitment_rejects_wrong_controller() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        assert_noop!(
            VectorDb::close_commitment(RuntimeOrigin::signed(99), cid, test_did(2), root, 10u64),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 18. Registered Attacker Cannot Close Someone Else's Commitment ---

#[test]
fn close_commitment_registered_attacker_cannot_close_others() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        let attacker_did = test_did(66);
        register_test_agent(attacker_did, 66, true);

        assert_noop!(
            VectorDb::close_commitment(
                RuntimeOrigin::signed(66),
                cid,
                attacker_did,
                root,
                10u64,
            ),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 19. Consumer Suspended After Acknowledge, Before Close ---

#[test]
fn close_commitment_rejects_consumer_suspended_before_close() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        // Consumer was active_verified through registration and acknowledge,
        // but gets suspended before settlement is attempted.
        register_test_agent(test_did(2), 2, false);

        assert_noop!(
            VectorDb::close_commitment(RuntimeOrigin::signed(2), cid, test_did(2), root, 10u64),
            Error::<Runtime>::ConsumerNotEligible
        );
    });
}

// --- 20. Guard Ordering: NotActive Precedes CommitmentExpiredError ---

#[test]
fn close_commitment_not_active_check_precedes_expiry_check() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let root = test_vector_hash(1);
        let block = System::block_number();

        // Register but never acknowledge — commitment stays Pending, expires quickly.
        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            10u64,
            metadata(),
            5u64,
        ));
        let cid = derive_commitment_id(p, c, root, block);

        // Well past expiry, but status is Pending, not Active — NotActive must fire first.
        System::set_block_number(1000);
        assert_noop!(
            VectorDb::close_commitment(RuntimeOrigin::signed(2), cid, c, root, 10u64),
            Error::<Runtime>::NotActive
        );
    });
}

// --- 21. Guard Ordering: Expiry Check Precedes Consumer Identity Check ---

#[test]
fn close_commitment_expiry_check_precedes_consumer_check() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(5u64); // expires_at = 6, now Active

        System::set_block_number(6); // exactly expired, still Active
        let wrong_consumer = test_did(123);
        register_test_agent(wrong_consumer, 123, true);

        assert_noop!(
            VectorDb::close_commitment(
                RuntimeOrigin::signed(123),
                cid,
                wrong_consumer,
                root,
                10u64,
            ),
            Error::<Runtime>::CommitmentExpiredError
        );
    });
}

// --- 22. Guard Ordering: Consumer Check Precedes Stream Hash Mismatch ---

#[test]
fn close_commitment_consumer_check_precedes_hash_mismatch() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);
        let wrong_consumer = test_did(55);
        register_test_agent(wrong_consumer, 55, true);
        let wrong_hash = [0x22u8; 32];

        // Wrong consumer entirely — must fail on identity, not hash mismatch,
        // even though the hash is also wrong.
        assert_noop!(
            VectorDb::close_commitment(
                RuntimeOrigin::signed(55),
                cid,
                wrong_consumer,
                wrong_hash,
                10u64,
            ),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 23. Guard Ordering: Controller Eligibility Precedes Hash Mismatch ---

#[test]
fn close_commitment_eligibility_check_precedes_hash_mismatch() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);
        register_test_agent(test_did(2), 2, false); // suspend consumer
        let wrong_hash = [0x33u8; 32];

        // Both suspended-consumer and hash-mismatch conditions are true here;
        // ConsumerNotEligible must surface, not StreamHashMismatch.
        assert_noop!(
            VectorDb::close_commitment(
                RuntimeOrigin::signed(2),
                cid,
                test_did(2),
                wrong_hash,
                10u64,
            ),
            Error::<Runtime>::ConsumerNotEligible
        );
    });
}

// --- 24. ActiveCommitmentCount Decrements on Settlement ---

#[test]
fn close_commitment_decrements_active_commitment_count() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);
        assert_eq!(VectorDb::active_commitment_count(), 1);

        assert_ok!(VectorDb::close_commitment(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            root,
            10u64,
        ));

        assert_eq!(VectorDb::active_commitment_count(), 0);
    });
}

// --- 25. ActiveCommitmentCount Never Underflows Below Zero ---

#[test]
fn close_commitment_active_count_does_not_underflow_on_repeat_failed_attempts() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        assert_ok!(VectorDb::close_commitment(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            root,
            10u64,
        ));
        assert_eq!(VectorDb::active_commitment_count(), 0);

        // Repeated failed close attempts on an already-Settled commitment must not
        // further decrement (or panic) the saturating counter.
        let _ = VectorDb::close_commitment(RuntimeOrigin::signed(2), cid, test_did(2), root, 10u64);
        let _ = VectorDb::close_commitment(RuntimeOrigin::signed(2), cid, test_did(2), root, 10u64);

        assert_eq!(VectorDb::active_commitment_count(), 0);
    });
}

// --- 26. Does Not Create a DisputeRecord on Successful Settlement ---

#[test]
fn close_commitment_does_not_create_dispute_record() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        assert_ok!(VectorDb::close_commitment(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            root,
            10u64,
        ));

        assert!(VectorDb::dispute_record(cid).is_none());
    });
}

// --- 27. State Mutability Safety on Rejection ---

#[test]
fn close_commitment_failed_call_does_not_mutate_storage() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);
        let wrong_hash = [0x44u8; 32];

        let _ = VectorDb::close_commitment(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            wrong_hash,
            10u64,
        );

        let commitment = VectorDb::vector_commitment(cid).expect("commitment must still exist");
        assert_eq!(
            commitment.status,
            CommitmentStatus::Active,
            "status must remain Active after a failed close"
        );
        assert!(
            VectorDb::stream_receipt(cid).is_none(),
            "no StreamReceipt must be written on a failed close"
        );
        assert_eq!(
            VectorDb::active_commitment_count(),
            1,
            "active count must remain unchanged after a failed close"
        );
    });
}

// --- 28. Chunk Count Zero Is Accepted (No Positivity Constraint on Close) ---

#[test]
fn close_commitment_accepts_zero_chunk_count() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        assert_ok!(VectorDb::close_commitment(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            root,
            0u64,
        ));

        let receipt = VectorDb::stream_receipt(cid).unwrap();
        assert_eq!(receipt.chunk_count, 0u64);
    });
}

// --- 29. Multiple Independent Commitments Settle Independently ---

#[test]
fn close_commitment_multiple_commitments_are_independent() {
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
            100u64,
        ));
        let cid1 = derive_commitment_id(p, c1, root1, block);
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid1,
            c1,
        ));

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c2,
            root2,
            10u64,
            metadata(),
            100u64,
        ));
        let cid2 = derive_commitment_id(p, c2, root2, block);
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(3),
            cid2,
            c2,
        ));

        assert_ok!(VectorDb::close_commitment(
            RuntimeOrigin::signed(2),
            cid1,
            c1,
            root1,
            10u64,
        ));

        // cid2 must remain untouched — still Active, no receipt.
        let stored2 = VectorDb::vector_commitment(cid2).unwrap();
        assert_eq!(stored2.status, CommitmentStatus::Active);
        assert!(VectorDb::stream_receipt(cid2).is_none());

        // cid1 must reflect settlement.
        let stored1 = VectorDb::vector_commitment(cid1).unwrap();
        assert_eq!(stored1.status, CommitmentStatus::Settled);
    });
}
