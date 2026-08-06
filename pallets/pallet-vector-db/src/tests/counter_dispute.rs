//! Standard test suite verifying invariants of the `counter_dispute` extrinsic.

use super::*;
use crate::mock::RuntimeEvent;
use crate::{Blake2bHasher, ChunkIndex, MAX_CHUNK_LEN, MAX_PROOF_DEPTH};
use frame_support::traits::ConstU32;
use frame_support::BoundedVec;
use rs_merkle::{Hasher, MerkleTree};

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

/// Deterministically builds `n` distinct 64-byte chunks, one per leaf index.
fn build_chunks(n: u8) -> Vec<Vec<u8>> {
    (0..n).map(|i| vec![i; 64]).collect()
}

/// Builds a real Merkle tree over `chunks`, returning `(merkle_root, tree)`.
fn build_tree(chunks: &[Vec<u8>]) -> ([u8; 32], MerkleTree<Blake2bHasher>) {
    let leaves: Vec<[u8; 32]> = chunks.iter().map(|c| Blake2bHasher::hash(c)).collect();
    let tree = MerkleTree::<Blake2bHasher>::from_leaves(&leaves);
    let root = tree.root().expect("tree must have a root with >0 leaves");
    (root, tree)
}

/// Generates a real positional inclusion proof for the target `index`.
fn proof_for(
    tree: &MerkleTree<Blake2bHasher>,
    index: usize,
) -> BoundedVec<[u8; 32], ConstU32<MAX_PROOF_DEPTH>> {
    let proof = tree.proof(&[index]);
    BoundedVec::try_from(proof.proof_hashes().to_vec())
        .expect("proof depth must fit within MAX_PROOF_DEPTH")
}

fn bounded_chunk(data: Vec<u8>) -> BoundedVec<u8, ConstU32<MAX_CHUNK_LEN>> {
    BoundedVec::try_from(data).expect("chunk must fit within MAX_CHUNK_LEN")
}

/// Sets up a complete disputed commitment state backed by a real `n`-leaf Merkle tree.
fn setup_disputed_commitment(
    n: u8,
    expires_in_blocks: u64,
) -> ([u8; 32], MerkleTree<Blake2bHasher>, Vec<Vec<u8>>) {
    let (p, c) = setup_valid_pair();
    let chunks = build_chunks(n);
    let (root, tree) = build_tree(&chunks);
    let block = System::block_number();

    assert_ok!(VectorDb::register_commitment(
        RuntimeOrigin::signed(1),
        p,
        c,
        root,
        n as u64,
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
        [0xEEu8; 32],
        n as u64,
    ));

    (cid, tree, chunks)
}

// --- 1. Happy-Path Integration: Real Proof Verification ---

#[test]
fn counter_dispute_happy_path_succeeds_with_valid_proof() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(8, 100u64);
        let index = 3usize;

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            index as ChunkIndex,
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));
    });
}

// --- 2. Storage & Verdict Fields Integrity Check ---

#[test]
fn counter_dispute_stores_correct_fields() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(8, 100u64);
        let index = 5usize;

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            index as ChunkIndex,
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));

        let commitment = VectorDb::vector_commitment(cid).expect("commitment must exist");
        assert_eq!(
            commitment.status,
            CommitmentStatus::DisputeResolved,
            "status must transition to DisputeResolved"
        );

        let dispute = VectorDb::dispute_record(cid).expect("DisputeRecord must persist");
        assert_eq!(
            dispute.verdict,
            Some(DisputeVerdict::ClaimantUnsubstantiated),
            "verdict must be ClaimantUnsubstantiated"
        );
    });
}

// --- 3. Event Emission Verification ---

#[test]
fn counter_dispute_emits_correct_event() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        let index = 0usize;

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            index as ChunkIndex,
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));

        System::assert_last_event(RuntimeEvent::VectorDb(Event::DisputeCountered {
            commitment_id: cid,
            verdict: DisputeVerdict::ClaimantUnsubstantiated,
        }));
    });
}

// --- 4. Event Uniqueness Verification ---

#[test]
fn counter_dispute_only_one_event_on_success() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        let index = 1usize;
        System::reset_events();

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            index as ChunkIndex,
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));

        assert_eq!(System::events().len(), 1);
    });
}

// --- 5. Global Counter Decrement Check ---

#[test]
fn counter_dispute_decrements_active_commitment_count() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        assert_eq!(VectorDb::active_commitment_count(), 1);
        let index = 2usize;

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            index as ChunkIndex,
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));

        assert_eq!(VectorDb::active_commitment_count(), 0);
    });
}

// --- 6. Unsigned Origin Rejection ---

#[test]
fn counter_dispute_rejects_unsigned_origin() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        let index = 0usize;

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::none(),
                cid,
                test_did(1),
                index as ChunkIndex,
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            DispatchError::BadOrigin
        );
    });
}

// --- 7. Sudo Origin Rejection ---

#[test]
fn counter_dispute_rejects_root_origin() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        let index = 0usize;

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::root(),
                cid,
                test_did(1),
                index as ChunkIndex,
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            DispatchError::BadOrigin
        );
    });
}

// --- 8. Nonexistent Commitment Rejection ---

#[test]
fn counter_dispute_rejects_nonexistent_commitment() {
    new_test_ext().execute_with(|| {
        let (_p, _c) = setup_valid_pair();
        let chunks = build_chunks(4);
        let (_root, tree) = build_tree(&chunks);
        let bogus_cid = [0x7Bu8; 32];

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                bogus_cid,
                test_did(1),
                0u64,
                bounded_chunk(chunks[0].clone()),
                proof_for(&tree, 0),
            ),
            Error::<Runtime>::CommitmentNotFound
        );
    });
}

// --- 9. State Precondition: Active State Rejection ---

#[test]
fn counter_dispute_rejects_still_active() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let chunks = build_chunks(4);
        let (root, tree) = build_tree(&chunks);
        let block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            4u64,
            metadata(),
            100u64,
        ));
        let cid = derive_commitment_id(p, c, root, block);
        assert_ok!(VectorDb::acknowledge_commitment(
            RuntimeOrigin::signed(2),
            cid,
            c,
        ));

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                p,
                0u64,
                bounded_chunk(chunks[0].clone()),
                proof_for(&tree, 0),
            ),
            Error::<Runtime>::NotDisputed
        );
    });
}

// --- 10. State Precondition: Pending State Rejection ---

#[test]
fn counter_dispute_rejects_still_pending() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let chunks = build_chunks(4);
        let (root, tree) = build_tree(&chunks);
        let block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            4u64,
            metadata(),
            100u64,
        ));
        let cid = derive_commitment_id(p, c, root, block);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                p,
                0u64,
                bounded_chunk(chunks[0].clone()),
                proof_for(&tree, 0),
            ),
            Error::<Runtime>::NotDisputed
        );
    });
}

// --- 11. Idempotency Guard: Double Counter Rejection ---

#[test]
fn counter_dispute_double_counter_fails_with_not_disputed() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        let index = 0usize;

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            index as ChunkIndex,
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                index as ChunkIndex,
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::NotDisputed
        );
    });
}

// --- 12. Proof Verification: Sibling Hashes Mismatch ---

#[test]
fn counter_dispute_rejects_invalid_merkle_proof() {
    new_test_ext().execute_with(|| {
        let (cid, _tree, chunks) = setup_disputed_commitment(8, 100u64);
        let index = 2usize;

        let bogus_proof: BoundedVec<[u8; 32], ConstU32<MAX_PROOF_DEPTH>> =
            BoundedVec::try_from(vec![[0x99u8; 32], [0x88u8; 32], [0x77u8; 32]]).unwrap();

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                index as ChunkIndex,
                bounded_chunk(chunks[index].clone()),
                bogus_proof,
            ),
            Error::<Runtime>::InvalidMerkleProof
        );
    });
}

// --- 13. Proof Verification: Tampered Chunk Data ---

#[test]
fn counter_dispute_rejects_valid_proof_shape_with_tampered_chunk_data() {
    new_test_ext().execute_with(|| {
        let (cid, tree, _chunks) = setup_disputed_commitment(8, 100u64);
        let index = 4usize;
        let tampered_data = vec![0xFFu8; 64];

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                index as ChunkIndex,
                bounded_chunk(tampered_data),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::InvalidMerkleProof
        );
    });
}

// --- 14. Proof Verification: Sibling Index Mismatch ---

#[test]
fn counter_dispute_rejects_proof_for_wrong_index() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(8, 100u64);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                1u64,
                bounded_chunk(chunks[1].clone()),
                proof_for(&tree, 6),
            ),
            Error::<Runtime>::InvalidMerkleProof
        );
    });
}

// --- 15. Index Bounds Check: Total Chunks Out of Bounds ---

#[test]
fn counter_dispute_rejects_chunk_index_out_of_bounds() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                4u64,
                bounded_chunk(chunks[0].clone()),
                proof_for(&tree, 0),
            ),
            Error::<Runtime>::ChunkIndexOutOfBounds
        );
    });
}

// --- 16. Index Bounds Check: Max Value Rejection ---

#[test]
fn counter_dispute_rejects_chunk_index_far_out_of_bounds() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                u64::MAX,
                bounded_chunk(chunks[0].clone()),
                proof_for(&tree, 0),
            ),
            Error::<Runtime>::ChunkIndexOutOfBounds
        );
    });
}

// --- 17. Index Bounds Check: Upper Boundary Acceptance ---

#[test]
fn counter_dispute_accepts_last_valid_chunk_index() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        let index = 3usize;

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            index as ChunkIndex,
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));
    });
}

// --- 18. Edge Case: Single Leaf Tree Acceptance ---

#[test]
fn counter_dispute_accepts_single_leaf_tree_with_empty_proof() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(1, 100u64);

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            0u64,
            bounded_chunk(chunks[0].clone()),
            proof_for(&tree, 0),
        ));
    });
}

// --- 19. Temporal Deadline: Inclusive Boundary Acceptance ---

#[test]
fn counter_dispute_accepts_at_exact_deadline_block_inclusive() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 1000u64);
        let index = 0usize;

        System::set_block_number(11);
        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            index as ChunkIndex,
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));
    });
}

// --- 20. Temporal Deadline: Exclusive Boundary Rejection ---

#[test]
fn counter_dispute_rejects_one_block_past_deadline() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 1000u64);
        let index = 0usize;

        System::set_block_number(12);
        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                index as ChunkIndex,
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::DisputeWindowExpired
        );
    });
}

// --- 21. Temporal Deadline: Out of Bounds Rejection ---

#[test]
fn counter_dispute_rejects_long_after_deadline() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 1000u64);
        let index = 0usize;

        System::set_block_number(5000);
        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                index as ChunkIndex,
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::DisputeWindowExpired
        );
    });
}

// --- 22. Origin Check: Provider Identity Mismatch ---

#[test]
fn counter_dispute_rejects_wrong_provider_did() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        let index = 0usize;

        let impostor_did = test_did(50);
        register_test_agent(impostor_did, 1, true);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                impostor_did,
                index as ChunkIndex,
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::NotProvider
        );
    });
}

// --- 23. Origin Check: Consumer Hijack Rejection ---

#[test]
fn counter_dispute_consumer_cannot_counter_as_provider() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        let index = 0usize;

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(2),
                cid,
                test_did(2),
                index as ChunkIndex,
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::NotProvider
        );
    });
}

// --- 24. Origin Check: Controller Authority Rejection ---

#[test]
fn counter_dispute_rejects_wrong_controller() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        let index = 0usize;

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(99),
                cid,
                test_did(1),
                index as ChunkIndex,
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::NotProvider
        );
    });
}

// --- 25. Origin Check: Attacker Isolation ---

#[test]
fn counter_dispute_registered_attacker_cannot_counter_for_others() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        let index = 0usize;

        let attacker_did = test_did(66);
        register_test_agent(attacker_did, 66, true);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(66),
                cid,
                attacker_did,
                index as ChunkIndex,
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::NotProvider
        );
    });
}

// --- 26. Precondition Check: Late-Suspension Rejection ---

#[test]
fn counter_dispute_rejects_provider_suspended_before_countering() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        let index = 0usize;

        register_test_agent(test_did(1), 1, false);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                index as ChunkIndex,
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::ProviderNotEligible
        );
    });
}

// --- 27. Guard Priority: NotDisputed precedes Provider DID check ---

#[test]
fn counter_dispute_not_disputed_check_precedes_provider_check() {
    new_test_ext().execute_with(|| {
        let (p, c) = setup_valid_pair();
        let chunks = build_chunks(4);
        let (root, tree) = build_tree(&chunks);
        let block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c,
            root,
            4u64,
            metadata(),
            100u64,
        ));
        let cid = derive_commitment_id(p, c, root, block);

        let wrong_provider = test_did(77);
        register_test_agent(wrong_provider, 77, true);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(77),
                cid,
                wrong_provider,
                0u64,
                bounded_chunk(chunks[0].clone()),
                proof_for(&tree, 0),
            ),
            Error::<Runtime>::NotDisputed
        );
    });
}

// --- 28. Guard Priority: Provider DID check precedes Controller lookup ---

#[test]
fn counter_dispute_provider_match_precedes_controller_lookup() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        let unregistered_did = test_did(200);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                unregistered_did,
                0u64,
                bounded_chunk(chunks[0].clone()),
                proof_for(&tree, 0),
            ),
            Error::<Runtime>::NotProvider
        );
    });
}

// --- 29. Guard Priority: Deadline check precedes Chunk-Index check ---

#[test]
fn counter_dispute_deadline_check_precedes_chunk_index_check() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(4, 1000u64);

        System::set_block_number(5000);
        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                999u64,
                bounded_chunk(chunks[0].clone()),
                proof_for(&tree, 0),
            ),
            Error::<Runtime>::DisputeWindowExpired
        );
    });
}

// --- 30. Guard Priority: Chunk-Index check precedes Proof Verification ---

#[test]
fn counter_dispute_chunk_index_check_precedes_proof_verification() {
    new_test_ext().execute_with(|| {
        let (cid, _tree, chunks) = setup_disputed_commitment(4, 100u64);

        let bogus_proof: BoundedVec<[u8; 32], ConstU32<MAX_PROOF_DEPTH>> =
            BoundedVec::try_from(vec![[0x00u8; 32]]).unwrap();

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                100u64,
                bounded_chunk(chunks[0].clone()),
                bogus_proof,
            ),
            Error::<Runtime>::ChunkIndexOutOfBounds
        );
    });
}

// --- 31. State Mutability Safety on Rejection ---

#[test]
fn counter_dispute_failed_call_does_not_mutate_storage() {
    new_test_ext().execute_with(|| {
        let (cid, _tree, chunks) = setup_disputed_commitment(4, 100u64);

        let bogus_proof: BoundedVec<[u8; 32], ConstU32<MAX_PROOF_DEPTH>> =
            BoundedVec::try_from(vec![[0x00u8; 32]]).unwrap();
        let _ = VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            0u64,
            bounded_chunk(chunks[0].clone()),
            bogus_proof,
        );

        let commitment = VectorDb::vector_commitment(cid).expect("commitment must still exist");
        assert_eq!(
            commitment.status,
            CommitmentStatus::Disputed,
            "status must remain Disputed after a failed counter_dispute"
        );

        let dispute = VectorDb::dispute_record(cid).expect("DisputeRecord must still exist");
        assert_eq!(
            dispute.verdict, None,
            "verdict must remain unset after a failed counter_dispute"
        );

        assert_eq!(
            VectorDb::active_commitment_count(),
            1,
            "active count must remain unchanged after a failed counter_dispute"
        );
    });
}

// --- 32. Larger Tree Boundary Verification (Non-Power-of-Two) ---

#[test]
fn counter_dispute_succeeds_against_non_power_of_two_leaf_tree() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(7, 100u64);
        let index = 6usize;

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            index as ChunkIndex,
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));
    });
}

// --- 33. Multi-Dispute Independence Verification ---

#[test]
fn counter_dispute_multiple_commitments_are_independent() {
    new_test_ext().execute_with(|| {
        let p = test_did(1);
        let c1 = test_did(2);
        let c2 = test_did(3);
        register_test_agent(p, 1, true);
        register_test_agent(c1, 2, true);
        register_test_agent(c2, 3, true);

        let chunks1 = build_chunks(4);
        let chunks2 = build_chunks(4);
        let (root1, tree1) = build_tree(&chunks1);
        let chunks2: Vec<Vec<u8>> = chunks2
            .iter()
            .map(|c| c.iter().map(|b| b.wrapping_add(1)).collect())
            .collect();
        let (root2, _tree2) = build_tree(&chunks2);
        let block = System::block_number();

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c1,
            root1,
            4u64,
            metadata(),
            100u64,
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
            [0xEEu8; 32],
            4u64,
        ));

        assert_ok!(VectorDb::register_commitment(
            RuntimeOrigin::signed(1),
            p,
            c2,
            root2,
            4u64,
            metadata(),
            100u64,
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
            [0xEEu8; 32],
            4u64,
        ));

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid1,
            p,
            0u64,
            bounded_chunk(chunks1[0].clone()),
            proof_for(&tree1, 0),
        ));

        let stored2 = VectorDb::vector_commitment(cid2).unwrap();
        assert_eq!(stored2.status, CommitmentStatus::Disputed);
        assert_eq!(VectorDb::dispute_record(cid2).unwrap().verdict, None);

        let stored1 = VectorDb::vector_commitment(cid1).unwrap();
        assert_eq!(stored1.status, CommitmentStatus::DisputeResolved);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(3),
                cid2,
                c2,
                0u64,
                bounded_chunk(chunks1[0].clone()),
                proof_for(&tree1, 0),
            ),
            Error::<Runtime>::NotProvider
        );
    });
}
