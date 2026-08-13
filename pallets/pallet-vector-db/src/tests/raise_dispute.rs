//! Standard test suite verifying invariants of the `raise_dispute` extrinsic.
//!
//! Special attention is paid here to the guard ordering, since `raise_dispute`
//! checks consumer-DID identity *before* the expiry boundary — the reverse of
//! `close_commitment`'s ordering — and to confirming the fix that stops
//! `StreamReceipts` from ever being written on an active dispute.
//!
//! Also covers the `disputed_chunk_index` binding fix: `raise_dispute` now
//! records WHICH chunk is being disputed, and rejects out-of-bounds indices
//! at raise time. This closes a soundness gap where `counter_dispute` could
//! previously accept a proof for any convenient chunk instead of the one
//! actually in dispute.

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
/// `total_chunks` is fixed at 10 — callers picking a `disputed_chunk_index`
/// must stay within that bound. Returns `(commitment_id, merkle_root)`.
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
                100u64, // price
            ));
    let cid = derive_commitment_id(p, c, root, block);

    assert_ok!(VectorDb::acknowledge_commitment(
        RuntimeOrigin::signed(2),
        cid,
        c,
    ));

    (cid, root)
}

const CORRUPT_HASH: [u8; 32] = [0xEEu8; 32];

// --- 1. Happy-Path Integration ---

#[test]
fn raise_dispute_happy_path_succeeds() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            0u64,
            CORRUPT_HASH,
            10u64,
        ));
    });
}

// --- 2. Storage Fields Integrity Check (Commitment + DisputeRecord) ---

#[test]
fn raise_dispute_stores_correct_fields() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        System::set_block_number(5);
        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            3u64,
            CORRUPT_HASH,
            99u64,
        ));

        let commitment = VectorDb::vector_commitment(cid).expect("commitment must exist");
        assert_eq!(
            commitment.status,
            CommitmentStatus::Disputed,
            "status must transition to Disputed"
        );

        let dispute = VectorDb::dispute_record(cid).expect("DisputeRecord must exist");
        assert_eq!(dispute.commitment_id, cid);
        assert_eq!(
            dispute.merkle_root, root,
            "DisputeRecord must store the ORIGINAL committed root, not the corrupt hash"
        );
        assert_eq!(dispute.received_chunk_hash, CORRUPT_HASH);
        assert_eq!(
            dispute.disputed_chunk_index, 3u64,
            "DisputeRecord must store exactly the chunk index the caller supplied"
        );
        assert_eq!(dispute.raised_at, 5u64);
        assert_eq!(dispute.counter_deadline, 15u64); // 5 + DisputeWindow(10)
        assert_eq!(dispute.verdict, None);
    });
}

// --- 3. Event Emission Verification ---

#[test]
fn raise_dispute_emits_correct_event() {
    new_test_ext().execute_with(|| {
        let (cid, root) = setup_active_commitment(100u64);

        System::set_block_number(3);
        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            0u64,
            CORRUPT_HASH,
            10u64,
        ));

        System::assert_last_event(RuntimeEvent::VectorDb(Event::DisputeRaised {
            commitment_id: cid,
            merkle_root: root,
            disputed_chunk_index: 0u64,
            received_chunk_hash: CORRUPT_HASH,
            counter_deadline: 13u64, // 3 + DisputeWindow(10)
        }));
    });
}

// --- 4. Event Emission Uniqueness ---

#[test]
fn raise_dispute_only_one_event_on_success() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);
        System::reset_events();

        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            0u64,
            CORRUPT_HASH,
            10u64,
        ));

        assert_eq!(System::events().len(), 1);
    });
}

// --- 5. THE CRITICAL REGRESSION TEST: Never Writes a StreamReceipt ---

#[test]
fn raise_dispute_never_writes_a_stream_receipt() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            0u64,
            CORRUPT_HASH,
            10u64,
        ));

        assert!(
            VectorDb::stream_receipt(cid).is_none(),
            "raise_dispute must NEVER write a StreamReceipt — that store is reserved \
             exclusively for verified settlements via close_commitment. Writing here \
             would permanently record the corrupt/disputed hash as if it were a \
             finalized settlement, since a Disputed commitment can never return to Active."
        );
    });
}

// --- 6. Unsigned Origin Rejection ---

#[test]
fn raise_dispute_rejects_unsigned_origin() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::none(),
                cid,
                test_did(2),
                0u64,
                CORRUPT_HASH,
                10u64,
            ),
            DispatchError::BadOrigin
        );
    });
}

// --- 7. Root Origin Rejection (Sudo Guard) ---

#[test]
fn raise_dispute_rejects_root_origin() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::root(),
                cid,
                test_did(2),
                0u64,
                CORRUPT_HASH,
                10u64,
            ),
            DispatchError::BadOrigin
        );
    });
}

// --- 8. Nonexistent Commitment Rejection ---

#[test]
fn raise_dispute_rejects_nonexistent_commitment() {
    new_test_ext().execute_with(|| {
        let (_p, c) = setup_valid_pair();
        let bogus_cid = [0x9Au8; 32];

        assert_noop!(
            VectorDb::raise_dispute(RuntimeOrigin::signed(2), bogus_cid, c, 0u64, CORRUPT_HASH, 10u64),
            Error::<Runtime>::CommitmentNotFound
        );
    });
}

// --- 9. Rejection While Still Pending (Not Yet Acknowledged) ---

#[test]
fn raise_dispute_rejects_still_pending() {
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
                100u64, // price
            ));
        let cid = derive_commitment_id(p, c, root, block);

        assert_noop!(
            VectorDb::raise_dispute(RuntimeOrigin::signed(2), cid, c, 0u64, CORRUPT_HASH, 10u64),
            Error::<Runtime>::NotActive
        );
    });
}

// --- 10. Rejection After Settlement (Terminal State) ---

#[test]
fn raise_dispute_fails_after_settlement() {
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
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(2),
                cid,
                test_did(2),
                0u64,
                CORRUPT_HASH,
                10u64
            ),
            Error::<Runtime>::NotActive
        );
    });
}

// --- 11. Double-Raise Rejection — Documents That DisputeAlreadyRaised Is Unreachable ---

/// NOTE: A second call to `raise_dispute` against an already-disputed commitment
/// fails with `NotActive`, not `DisputeAlreadyRaised`. This is because the very
/// first successful call flips `status` to `Disputed` in the same transaction that
/// inserts the `DisputeRecord`, so the status guard always fires first on any
/// re-entry. The `DisputeAlreadyRaised` branch is therefore defensive/unreachable
/// under the current state machine — documented here rather than silently assumed.
#[test]
fn raise_dispute_double_raise_fails_with_not_active_not_dispute_already_raised() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            0u64,
            CORRUPT_HASH,
            10u64,
        ));

        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(2),
                cid,
                test_did(2),
                0u64,
                CORRUPT_HASH,
                10u64
            ),
            Error::<Runtime>::NotActive
        );
    });
}

// --- 12. Exact Expiry Boundary Rejection ---

#[test]
fn raise_dispute_rejects_at_exact_expiry_block() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(10u64); // expires_at = 11

        System::set_block_number(11);
        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(2),
                cid,
                test_did(2),
                0u64,
                CORRUPT_HASH,
                10u64
            ),
            Error::<Runtime>::CommitmentExpiredError
        );
    });
}

// --- 13. Last-Valid-Block Boundary Acceptance ---

#[test]
fn raise_dispute_accepts_at_last_valid_block() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(10u64); // expires_at = 11

        System::set_block_number(10);
        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            0u64,
            CORRUPT_HASH,
            10u64,
        ));
    });
}

// --- 14. Post-Expiry Rejection (Well Past Deadline) ---

#[test]
fn raise_dispute_rejects_long_after_expiry() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(10u64);

        System::set_block_number(1000);
        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(2),
                cid,
                test_did(2),
                0u64,
                CORRUPT_HASH,
                10u64
            ),
            Error::<Runtime>::CommitmentExpiredError
        );
    });
}

// --- 15. Wrong Consumer DID Rejection ---

#[test]
fn raise_dispute_rejects_wrong_consumer_did() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        let impostor_did = test_did(50);
        register_test_agent(impostor_did, 2, true); // same controller, different DID

        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(2),
                cid,
                impostor_did,
                0u64,
                CORRUPT_HASH,
                10u64,
            ),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 16. Provider Attempting to Raise-as-Consumer Rejection ---

#[test]
fn raise_dispute_provider_cannot_raise_as_consumer() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                0u64,
                CORRUPT_HASH,
                10u64,
            ),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 17. Wrong Controller Rejection (Correct DID, Wrong Caller) ---

#[test]
fn raise_dispute_rejects_wrong_controller() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(99),
                cid,
                test_did(2),
                0u64,
                CORRUPT_HASH,
                10u64,
            ),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 18. Registered Attacker Cannot Raise Dispute on Someone Else's Commitment ---

#[test]
fn raise_dispute_registered_attacker_cannot_raise_for_others() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        let attacker_did = test_did(66);
        register_test_agent(attacker_did, 66, true);

        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(66),
                cid,
                attacker_did,
                0u64,
                CORRUPT_HASH,
                10u64,
            ),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 19. Consumer Suspended After Acknowledge, Before Dispute Raised ---

#[test]
fn raise_dispute_rejects_consumer_suspended_before_raising() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        // Consumer was active_verified through registration and acknowledge,
        // but gets suspended before it attempts to raise a dispute.
        register_test_agent(test_did(2), 2, false);

        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(2),
                cid,
                test_did(2),
                0u64,
                CORRUPT_HASH,
                10u64
            ),
            Error::<Runtime>::ConsumerNotEligible
        );
    });
}

// --- 20. Guard Ordering: NotActive Precedes Consumer-DID Match Check ---

#[test]
fn raise_dispute_not_active_check_precedes_consumer_check() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let root = test_vector_hash(1);
        let block = System::block_number();

        // Register but never acknowledge — commitment stays Pending.
        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            10u64,
            metadata(),
            100u64,
                100u64, // price
            ));
        let cid = derive_commitment_id(p, c, root, block);

        let wrong_consumer = test_did(77);
        register_test_agent(wrong_consumer, 77, true);

        // Status is Pending, not Active — NotActive must fire before the
        // wrong consumer_did is ever inspected.
        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(77),
                cid,
                wrong_consumer,
                0u64,
                CORRUPT_HASH,
                10u64,
            ),
            Error::<Runtime>::NotActive
        );
    });
}

// --- 21. Guard Ordering: Consumer-DID Match Precedes Expiry Check ---
//
// This is the inverse of close_commitment's ordering, and is the single most
// important ordering test in this file — a regression here would silently
// swap which error callers observe on malformed requests.

#[test]
fn raise_dispute_consumer_check_precedes_expiry_check() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(5u64); // expires_at = 6, now Active

        System::set_block_number(1000); // well past expiry
        let wrong_consumer = test_did(88);
        register_test_agent(wrong_consumer, 88, true);

        // Even though the commitment has long expired, the wrong consumer_did
        // must be caught FIRST — NotConsumer, not CommitmentExpiredError.
        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(88),
                cid,
                wrong_consumer,
                0u64,
                CORRUPT_HASH,
                10u64,
            ),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 22. Guard Ordering: Expiry Check Precedes Controller-Eligibility Checks ---

#[test]
fn raise_dispute_expiry_check_precedes_eligibility_checks() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(5u64); // expires_at = 6, now Active

        // Correct consumer_did, but suspend the consumer too — expiry must still
        // fire first since it is checked before the eligibility branch.
        register_test_agent(test_did(2), 2, false);
        System::set_block_number(1000);

        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(2),
                cid,
                test_did(2),
                0u64,
                CORRUPT_HASH,
                10u64
            ),
            Error::<Runtime>::CommitmentExpiredError
        );
    });
}

// --- 23. Guard Ordering: Controller Mismatch Precedes Not-Active-Verified Check ---

#[test]
fn raise_dispute_controller_mismatch_precedes_eligibility_check() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        // Suspend the real consumer AND call from a wrong controller — the
        // controller mismatch (NotConsumer) must surface first.
        register_test_agent(test_did(2), 2, false);

        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(99),
                cid,
                test_did(2),
                0u64,
                CORRUPT_HASH,
                10u64,
            ),
            Error::<Runtime>::NotConsumer
        );
    });
}

// --- 24. Does Not Mutate `ActiveCommitmentCount` ---

#[test]
fn raise_dispute_does_not_change_active_commitment_count() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);
        assert_eq!(VectorDb::active_commitment_count(), 1);

        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            0u64,
            CORRUPT_HASH,
            10u64,
        ));

        assert_eq!(
            VectorDb::active_commitment_count(),
            1,
            "raise_dispute must not touch the active commitment counter — only \
             close_commitment (settlement) and expire_commitment retire the count"
        );
    });
}

// --- 25. State Mutability Safety on Rejection ---

#[test]
fn raise_dispute_failed_call_does_not_mutate_storage() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(5u64); // expires_at = 6

        System::set_block_number(50); // expired
        let _ = VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            0u64,
            CORRUPT_HASH,
            10u64,
        );

        let commitment = VectorDb::vector_commitment(cid).expect("commitment must still exist");
        assert_eq!(
            commitment.status,
            CommitmentStatus::Active,
            "status must remain Active after a failed raise_dispute"
        );
        assert!(
            VectorDb::dispute_record(cid).is_none(),
            "no DisputeRecord must be written on a failed raise_dispute"
        );
        assert!(
            VectorDb::stream_receipt(cid).is_none(),
            "no StreamReceipt must be written on a failed raise_dispute"
        );
    });
}

// --- 26. Chunk-Count Parameter Is Accepted But Has No Bearing on Stored State ---
//
// `_chunk_count` is intentionally unused inside the extrinsic (see the fix that
// removed the corrupt StreamReceipts write) — it must not appear anywhere in the
// resulting DisputeRecord or event. Unlike `_chunk_count`, `disputed_chunk_index`
// IS stored — the two must not be confused.

#[test]
fn raise_dispute_chunk_count_param_does_not_leak_into_storage() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid,
            test_did(2),
            0u64,
            CORRUPT_HASH,
            123_456_789u64, // arbitrary, must have zero effect
        ));

        let dispute = VectorDb::dispute_record(cid).unwrap();
        assert_eq!(dispute.received_chunk_hash, CORRUPT_HASH);
        assert_eq!(dispute.disputed_chunk_index, 0u64);
    });
}

// --- 27. Multiple Independent Commitments Dispute Independently ---

#[test]
fn raise_dispute_multiple_commitments_are_independent() {
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
                100u64, // price
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
                100u64, // price
            ));
        let cid2 = derive_commitment_id(p, c2, root2, block);
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(3),
            cid2,
            c2,
        ));

        assert_ok!(VectorDb::raise_dispute(
            RuntimeOrigin::signed(2),
            cid1,
            c1,
            0u64,
            CORRUPT_HASH,
            10u64,
        ));

        // cid2 must remain untouched — still Active, no dispute record.
        let stored2 = VectorDb::vector_commitment(cid2).unwrap();
        assert_eq!(stored2.status, CommitmentStatus::Active);
        assert!(VectorDb::dispute_record(cid2).is_none());

        // cid1 must reflect the dispute.
        let stored1 = VectorDb::vector_commitment(cid1).unwrap();
        assert_eq!(stored1.status, CommitmentStatus::Disputed);
    });
}

// --- 28. Chunk-Index Bounds Rejection (moved here from counter_dispute.rs) ---
//
// Formerly tested in `counter_dispute.rs` against a caller-supplied
// `chunk_index`. After the binding fix, the bound is enforced HERE, at
// dispute-raise time, since `counter_dispute` no longer accepts an
// independent index at all — it only ever reads the one recorded here.

#[test]
fn raise_dispute_rejects_chunk_index_out_of_bounds() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64); // total_chunks = 10

        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(2),
                cid,
                test_did(2),
                10u64, // == total_chunks, one past the last valid index
                CORRUPT_HASH,
                10u64,
            ),
            Error::<Runtime>::ChunkIndexOutOfBounds
        );
    });
}

// --- 29. Chunk-Index Bounds Rejection: Max Value (moved from counter_dispute.rs) ---

#[test]
fn raise_dispute_rejects_chunk_index_far_out_of_bounds() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(2),
                cid,
                test_did(2),
                u64::MAX,
                CORRUPT_HASH,
                10u64,
            ),
            Error::<Runtime>::ChunkIndexOutOfBounds
        );
    });
}

// --- 30. Guard Ordering: Eligibility Checks Precede Chunk-Index Bounds Check ---

#[test]
fn raise_dispute_eligibility_check_precedes_chunk_index_check() {
    new_test_ext().execute_with(|| {
        let (cid, _root) = setup_active_commitment(100u64);

        // Wrong controller AND an out-of-bounds index — NotConsumer must
        // surface first, since identity/eligibility is verified before the
        // dispute record (and its bounds check) is ever constructed.
        assert_noop!(
            VectorDb::raise_dispute(
                RuntimeOrigin::signed(99),
                cid,
                test_did(2),
                999u64,
                CORRUPT_HASH,
                10u64,
            ),
            Error::<Runtime>::NotConsumer
        );
    });
}
