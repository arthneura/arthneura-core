//! Standard test suite verifying invariants of the `register_commitment` extrinsic.

use super::*;
use crate::mock::RuntimeEvent;
use frame_support::traits::ConstU32;
use frame_support::BoundedVec;

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

// --- 1. Happy-Path Integration ---

#[test]
fn register_commitment_happy_path_succeeds() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let root = test_vector_hash(1);
        let meta = metadata();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            100u64,
            meta.clone(),
            100u64,
                100u64, // price
            ));
    });
}

// --- 2. Storage Fields Integrity Check ---

#[test]
fn register_commitment_stores_correct_fields() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let root = test_vector_hash(7);
        let meta = metadata();
        let current_block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            10u64,
            meta.clone(),
            50u64,
                100u64, // price
            ));

        let cid = derive_commitment_id(p, c, root, current_block);
        let stored = VectorDb::vector_commitment(cid).expect("commitment must exist");

        assert_eq!(stored.commitment_id, cid, "commitment_id mismatch");
        assert_eq!(stored.provider, p, "provider mismatch");
        assert_eq!(stored.consumer, c, "consumer mismatch");
        assert_eq!(stored.merkle_root, root, "merkle_root mismatch");
        assert_eq!(stored.total_chunks, 10u64, "total_chunks mismatch");
        assert_eq!(stored.metadata, meta, "metadata mismatch");
        assert_eq!(
            stored.created_at, 1u64,
            "created_at must equal current block"
        );
        assert_eq!(
            stored.expires_at,
            1 + 50,
            "expires_at = created_at + expires_in_blocks"
        );
        assert_eq!(
            stored.status,
            CommitmentStatus::Pending,
            "initial status must be Pending"
        );
        assert!(
            stored.acknowledged_at.is_none(),
            "acknowledged_at must be None on registration"
        );
    });
}

// --- 3. Event Emission Verification ---

#[test]
fn register_commitment_emits_correct_event() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let root = test_vector_hash(3);
        let current_block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            50u64,
            metadata(),
            200u64,
                100u64, // price
            ));

        let cid = derive_commitment_id(p, c, root, current_block);
        System::assert_last_event(RuntimeEvent::VectorDb(Event::CommitmentRegistered {
            commitment_id: cid,
            provider: p,
            consumer: c,
            merkle_root: root,
            total_chunks: 50u64,
            expires_at: current_block + 200,
        }));
    });
}

// --- 4. Global Storage Counter Verification ---

#[test]
fn register_commitment_increments_active_count() {
    new_test_ext().execute_with(|| {
        assert_eq!(VectorDb::active_commitment_count(), 0, "should start at 0");

        let (p, c) = setup_valid_pair();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            test_vector_hash(1),
            10u64,
            metadata(),
            10u64,
                100u64, // price
            ));
        assert_eq!(VectorDb::active_commitment_count(), 1);

        System::set_block_number(2);

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            test_vector_hash(1),
            10u64,
            metadata(),
            10u64,
                100u64, // price
            ));
        assert_eq!(VectorDb::active_commitment_count(), 2);
    });
}

// --- 5. Key Derivation Consistency Check ---

#[test]
fn register_commitment_id_matches_offchain_derivation() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let root = test_vector_hash(42);
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

        let expected_cid = derive_commitment_id(p, c, root, block);
        assert!(
            VectorDb::vector_commitment(expected_cid).is_some(),
            "Storage key must match off-chain derivation"
        );
    });
}

// --- 6. Empty Secondary Storage Maps Verification ---

#[test]
fn register_commitment_does_not_create_receipt_or_dispute() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let root = test_vector_hash(5);
        let block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            10u64,
            metadata(),
            50u64,
                100u64, // price
            ));

        let cid = derive_commitment_id(p, c, root, block);
        assert!(
            VectorDb::stream_receipt(cid).is_none(),
            "no StreamReceipt on registration"
        );
        assert!(
            VectorDb::dispute_record(cid).is_none(),
            "no DisputeRecord on registration"
        );
    });
}

// --- 7. Unsigned Origin Rejection ---

#[test]
fn register_commitment_rejects_unsigned_origin() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::none(),
                p,
                c,
                test_vector_hash(1),
                10u64,
                metadata(),
                10u64,
                100u64, // price
            ),
            DispatchError::BadOrigin
        );
    });
}

// --- 8. Root Origin Rejection (Sudo Guard) ---

#[test]
fn register_commitment_rejects_root_origin() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::root(),
                p,
                c,
                test_vector_hash(1),
                10u64,
                metadata(),
                10u64,
                100u64, // price
            ),
            DispatchError::BadOrigin
        );
    });
}

// --- 9. Self-Trade Guard Rejection ---

#[test]
fn register_commitment_rejects_self_trade() {
    new_test_ext().execute_with(|| {
        let did = test_did(1);
        register_test_agent(did, 1, true);

        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::signed(1),
                did,
                did,
                test_vector_hash(1),
                10u64,
                metadata(),
                10u64,
                100u64, // price
            ),
            Error::<Runtime>::SelfTrade
        );
    });
}

// --- 10. Unregistered Identity Rejection ---

#[test]
fn register_commitment_rejects_unregistered_provider() {
    new_test_ext().execute_with(|| {
        let p = test_did(99);
        let c = test_did(2);
        register_test_agent(c, 2, true);

        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::signed(1),
                p,
                c,
                test_vector_hash(1),
                10u64,
                metadata(),
                10u64,
                100u64, // price
            ),
            Error::<Runtime>::ProviderNotEligible
        );
    });
}

// --- 11. Controller Ownership Rejection ---

#[test]
fn register_commitment_rejects_wrong_provider_controller() {
    new_test_ext().execute_with(|| {
        let p = test_did(1);
        let c = test_did(2);
        register_test_agent(p, 1, true);
        register_test_agent(c, 2, true);

        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::signed(99),
                p,
                c,
                test_vector_hash(1),
                10u64,
                metadata(),
                10u64,
                100u64, // price
            ),
            Error::<Runtime>::NotProvider
        );
    });
}

// --- 12. Inactive/Unverified Provider Rejection ---

#[test]
fn register_commitment_rejects_inactive_provider() {
    new_test_ext().execute_with(|| {
        let p = test_did(1);
        let c = test_did(2);
        register_test_agent(p, 1, false);
        register_test_agent(c, 2, true);

        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::signed(1),
                p,
                c,
                test_vector_hash(1),
                10u64,
                metadata(),
                10u64,
                100u64, // price
            ),
            Error::<Runtime>::ProviderNotEligible
        );
    });
}

// --- 13. Unregistered Consumer Rejection ---

#[test]
fn register_commitment_rejects_unregistered_consumer() {
    new_test_ext().execute_with(|| {
        let p = test_did(1);
        let c = test_did(99);
        register_test_agent(p, 1, true);

        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::signed(1),
                p,
                c,
                test_vector_hash(1),
                10u64,
                metadata(),
                10u64,
                100u64, // price
            ),
            Error::<Runtime>::ConsumerNotEligible
        );
    });
}

// --- 14. Inactive/Unverified Consumer Rejection ---

#[test]
fn register_commitment_rejects_inactive_consumer() {
    new_test_ext().execute_with(|| {
        let p = test_did(1);
        let c = test_did(2);
        register_test_agent(p, 1, true);
        register_test_agent(c, 2, false);

        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::signed(1),
                p,
                c,
                test_vector_hash(1),
                10u64,
                metadata(),
                10u64,
                100u64, // price
            ),
            Error::<Runtime>::ConsumerNotEligible
        );
    });
}

// --- 15. Zero Expiry Rejection ---

#[test]
fn register_commitment_rejects_zero_expiry() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::signed(1),
                p,
                c,
                test_vector_hash(1),
                10u64,
                metadata(),
                0u64,
                100u64, // price
            ),
            Error::<Runtime>::ExpiryMustBePositive
        );
    });
}

// --- 16. Minimum Lifespan Expiry Acceptance ---

#[test]
fn register_commitment_accepts_minimum_expiry() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            test_vector_hash(1),
            10u64,
            metadata(),
            1u64,
                100u64, // price
            ));
    });
}

// --- 17. Maximum Lifespan Expiry Acceptance ---

#[test]
fn register_commitment_accepts_max_lifetime_expiry() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            test_vector_hash(1),
            10u64,
            metadata(),
            1_000u64,
                100u64, // price
            ));
    });
}

// --- 18. Out-of-Bounds Expiry Rejection ---

#[test]
fn register_commitment_rejects_expiry_beyond_max_lifetime() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::signed(1),
                p,
                c,
                test_vector_hash(1),
                10u64,
                metadata(),
                1_001u64,
                100u64, // price
            ),
            Error::<Runtime>::ExpiryTooFar
        );
    });
}

// --- 19. Same-Block Duplicate Rejection ---

#[test]
fn register_commitment_rejects_duplicate_in_same_block() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let root = test_vector_hash(1);

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

        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::signed(1),
                p,
                c,
                root,
                10u64,
                metadata(),
                100u64,
                100u64, // price
            ),
            Error::<Runtime>::CommitmentAlreadyExists
        );
    });
}

// --- 20. Multi-Block Re-registration Acceptance ---

#[test]
fn register_commitment_different_blocks_produce_different_ids() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let root = test_vector_hash(1);

        let block1 = System::block_number();
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
        let cid1 = derive_commitment_id(p, c, root, block1);

        System::set_block_number(2);
        let block2 = System::block_number();
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
        let cid2 = derive_commitment_id(p, c, root, block2);

        assert_ne!(
            cid1, cid2,
            "different blocks must produce different commitment IDs"
        );
        assert!(VectorDb::vector_commitment(cid1).is_some());
        assert!(VectorDb::vector_commitment(cid2).is_some());
    });
}

// --- 21. Multi-Hash Same-Block Acceptance ---

#[test]
fn register_commitment_different_hashes_same_block_both_succeed() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            test_vector_hash(1),
            10u64,
            metadata(),
            100u64,
                100u64, // price
            ));
        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            test_vector_hash(2),
            10u64,
            metadata(),
            100u64,
                100u64, // price
            ));

        assert_eq!(VectorDb::active_commitment_count(), 2);
    });
}

// --- 22. Multi-Pair Active Counter Verification ---

#[test]
fn register_commitment_multiple_pairs_count_is_accurate() {
    new_test_ext().execute_with(|| {
        let c = test_did(10);
        register_test_agent(c, 10, true);

        for i in 1u8..=3 {
            let p = test_did(i);
            register_test_agent(p, i as u64, true);
            System::set_block_number(i as u64);

            assert_ok!(VectorDb::register_commitment(
                RuntimeOrigin::signed(i as u64),
                p,
                c,
                test_vector_hash(i),
                10u64,
                metadata(),
                50u64,
                100u64, // price
            ));
        }

        assert_eq!(VectorDb::active_commitment_count(), 3);
    });
}

// --- 23. Empty Metadata Bounds Acceptance ---

#[test]
fn register_commitment_accepts_empty_metadata() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let empty_meta: BoundedVec<u8, ConstU32<256>> = BoundedVec::try_from(vec![]).unwrap();
        let root = test_vector_hash(1);
        let block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            10u64,
            empty_meta.clone(),
            10u64,
                100u64, // price
            ));

        let cid = derive_commitment_id(p, c, root, block);
        let stored = VectorDb::vector_commitment(cid).unwrap();
        assert_eq!(stored.metadata.len(), 0);
    });
}

// --- 24. Max Metadata Bounds (256 bytes) Acceptance ---

#[test]
fn register_commitment_accepts_max_length_metadata() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let max_meta: BoundedVec<u8, ConstU32<256>> =
            BoundedVec::try_from(vec![0xABu8; 256]).unwrap();
        let root = test_vector_hash(1);
        let block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            10u64,
            max_meta.clone(),
            10u64,
                100u64, // price
            ));

        let cid = derive_commitment_id(p, c, root, block);
        let stored = VectorDb::vector_commitment(cid).unwrap();
        assert_eq!(stored.metadata, max_meta);
    });
}

// --- 25. Exact Chronological Arithmetic Verification ---

#[test]
fn register_commitment_expires_at_is_exactly_current_plus_duration() {
    new_test_ext().execute_with(|| {
        System::set_block_number(42);
        let (p, c) = setup_valid_pair();
        let root = test_vector_hash(1);

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            10u64,
            metadata(),
            300u64,
                100u64, // price
            ));

        let cid = derive_commitment_id(p, c, root, 42);
        let stored = VectorDb::vector_commitment(cid).unwrap();
        assert_eq!(stored.expires_at, 42 + 300);
        assert_eq!(stored.created_at, 42);
    });
}

// --- 26. Independent Controllers Verification ---

#[test]
fn register_commitment_provider_and_consumer_have_different_controllers() {
    new_test_ext().execute_with(|| {
        let p = test_did(1);
        let c = test_did(2);
        register_test_agent(p, 100, true);
        register_test_agent(c, 200, true);

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(100),
            p,
            c,
            test_vector_hash(1),
            10u64,
            metadata(),
            10u64,
                100u64, // price
            ));
    });
}

// --- 27. Guard Priority: SelfTrade fires before ProviderNotEligible ---

#[test]
fn register_commitment_self_trade_fires_before_eligibility_checks() {
    new_test_ext().execute_with(|| {
        let did = test_did(77);

        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::signed(1),
                did,
                did,
                test_vector_hash(1),
                10u64,
                metadata(),
                10u64,
                100u64, // price
            ),
            Error::<Runtime>::SelfTrade
        );
    });
}

// --- 28. Independent Consumer Verification Status ---

#[test]
fn register_commitment_consumer_suspended_after_provider_passes() {
    new_test_ext().execute_with(|| {
        let p = test_did(1);
        let c = test_did(2);
        register_test_agent(p, 1, true);
        register_test_agent(c, 2, false);

        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::signed(1),
                p,
                c,
                test_vector_hash(1),
                10u64,
                metadata(),
                10u64,
                100u64, // price
            ),
            Error::<Runtime>::ConsumerNotEligible
        );
    });
}

// --- 29. Zero-Hash Boundary Verification (Rejects Invalid Merkle Root) ---

#[test]
fn register_commitment_rejects_zero_merkle_root() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let zero_hash = [0u8; 32];

        assert_noop!(
            VectorDb::register_commitment(
                RuntimeOrigin::signed(1),
                p,
                c,
                zero_hash,
                10u64,
                metadata(),
                10u64,
                100u64, // price
            ),
            Error::<Runtime>::InvalidMerkleRoot
        );
    });
}

// --- 30. Max-Hash Boundary Verification ---

#[test]
fn register_commitment_accepts_max_value_vector_hash() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let max_hash = [0xFFu8; 32];
        let block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            max_hash,
            10u64,
            metadata(),
            10u64,
                100u64, // price
            ));

        let cid = derive_commitment_id(p, c, max_hash, block);
        let stored = VectorDb::vector_commitment(cid).unwrap();
        assert_eq!(stored.merkle_root, max_hash);
    });
}

// --- 31. Edge-Case DID Encoding Verification ---

#[test]
fn register_commitment_accepts_zero_did_as_consumer() {
    new_test_ext().execute_with(|| {
        let p = test_did(1);
        let c = [0u8; 32];
        register_test_agent(p, 1, true);
        register_test_agent(c, 99, true);

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            test_vector_hash(1),
            10u64,
            metadata(),
            10u64,
                100u64, // price
            ));
    });
}

// --- 32. Event Emission Uniqueness ---

#[test]
fn register_commitment_only_one_event_on_success() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        System::reset_events();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            test_vector_hash(1),
            10u64,
            metadata(),
            50u64,
                100u64, // price
            ));

        let events = System::events();
        assert_eq!(events.len(), 1);
    });
}

// --- 33. State Mutability Safety on Rejection ---

#[test]
fn register_commitment_failed_call_does_not_mutate_storage() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();

        let _ = VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            test_vector_hash(1),
            10u64,
            metadata(),
            0u64,
                100u64, // price
            );

        assert_eq!(VectorDb::active_commitment_count(), 0);
        assert!(
            VectorDb::vector_commitment(derive_commitment_id(p, c, test_vector_hash(1), 1))
                .is_none()
        );
    });
}
