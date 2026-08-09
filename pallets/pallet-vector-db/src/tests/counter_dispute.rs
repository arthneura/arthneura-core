//! Standard test suite verifying invariants of the `counter_dispute` extrinsic.
//!
//! `counter_dispute` no longer accepts a caller-supplied `chunk_index` — it
//! reads `disputed_chunk_index` from the `DisputeRecord` set by
//! `raise_dispute`, and verifies the submitted proof against that exact
//! index. This closes a soundness gap where a provider could previously
//! refute a dispute by proving any convenient chunk instead of the one
//! actually in question.
//!
//! Two tests from the previous revision no longer apply and were removed
//! rather than kept as dead weight:
//! - `deadline_check_precedes_chunk_index_check` — there is no longer a
//!   caller-supplied chunk index for the deadline check to precede.
//! - `chunk_index_check_precedes_proof_verification` — same reason; the
//!   chunk-index bound is now enforced at `raise_dispute` time, not here.
//! The two `ChunkIndexOutOfBounds` rejection tests moved to
//! `raise_dispute.rs`, where that bound is now actually enforced.

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

/// Sets up a complete disputed commitment state backed by a real `n`-leaf
/// Merkle tree, with the dispute bound to `disputed_chunk_index`.
fn setup_disputed_commitment_at(
    n: u8,
    expires_in_blocks: u64,
    disputed_chunk_index: ChunkIndex,
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
        disputed_chunk_index,
        [0xEEu8; 32],
        n as u64,
    ));

    (cid, tree, chunks)
}

/// Convenience wrapper: dispute bound to index 0 — the common case for
/// tests that don't care which specific index is in dispute.
fn setup_disputed_commitment(
    n: u8,
    expires_in_blocks: u64,
) -> ([u8; 32], MerkleTree<Blake2bHasher>, Vec<Vec<u8>>) {
    setup_disputed_commitment_at(n, expires_in_blocks, 0u64)
}

// --- 1. Happy-Path Integration: Real Proof Verification ---

#[test]
fn counter_dispute_happy_path_succeeds_with_valid_proof() {
    new_test_ext().execute_with(|| {
        let index = 3usize;
        let (cid, tree, chunks) = setup_disputed_commitment_at(8, 100u64, index as ChunkIndex);

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));
    });
}

// --- 2. Storage & Verdict Fields Integrity Check ---

#[test]
fn counter_dispute_stores_correct_fields() {
    new_test_ext().execute_with(|| {
        let index = 5usize;
        let (cid, tree, chunks) = setup_disputed_commitment_at(8, 100u64, index as ChunkIndex);

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
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
        assert_eq!(
            dispute.disputed_chunk_index, index as ChunkIndex,
            "disputed_chunk_index must remain unchanged by counter_dispute"
        );
    });
}

// --- 3. Event Emission Verification ---

#[test]
fn counter_dispute_emits_correct_event() {
    new_test_ext().execute_with(|| {
        let index = 0usize;
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
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
        let index = 1usize;
        let (cid, tree, chunks) = setup_disputed_commitment_at(4, 100u64, index as ChunkIndex);
        System::reset_events();

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
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
        let index = 2usize;
        let (cid, tree, chunks) = setup_disputed_commitment_at(4, 100u64, index as ChunkIndex);
        assert_eq!(VectorDb::active_commitment_count(), 1);

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
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
        let index = 0usize;
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::none(),
                cid,
                test_did(1),
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
        let index = 0usize;
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::root(),
                cid,
                test_did(1),
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
        let index = 0usize;
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
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
        let index = 2usize;
        let (cid, _tree, chunks) = setup_disputed_commitment_at(8, 100u64, index as ChunkIndex);

        let bogus_proof: BoundedVec<[u8; 32], ConstU32<MAX_PROOF_DEPTH>> =
            BoundedVec::try_from(vec![[0x99u8; 32], [0x88u8; 32], [0x77u8; 32]]).unwrap();

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
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
        let index = 4usize;
        let (cid, tree, _chunks) = setup_disputed_commitment_at(8, 100u64, index as ChunkIndex);
        let tampered_data = vec![0xFFu8; 64];

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                bounded_chunk(tampered_data),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::InvalidMerkleProof
        );
    });
}

// --- 14. Proof Verification: Chunk/Proof Mismatched Against the Disputed Index ---
//
// Redesigned for the binding fix: there is no longer a caller-supplied
// `chunk_index` to mismatch against the dispute. Instead, this proves the
// pallet correctly rejects a chunk+proof pair for a DIFFERENT chunk than
// the one actually recorded as disputed — the provider cannot dodge the
// real complaint by presenting proof of some other, unrelated chunk.

#[test]
fn counter_dispute_rejects_proof_for_a_different_chunk_than_disputed() {
    new_test_ext().execute_with(|| {
        let disputed_index = 1usize;
        let (cid, tree, chunks) =
            setup_disputed_commitment_at(8, 100u64, disputed_index as ChunkIndex);

        // Provider submits chunk 6's data + a valid proof FOR chunk 6 —
        // real data, real proof, just for the wrong (undisputed) chunk.
        let wrong_index = 6usize;

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                bounded_chunk(chunks[wrong_index].clone()),
                proof_for(&tree, wrong_index),
            ),
            Error::<Runtime>::InvalidMerkleProof
        );
    });
}

// --- 15. Edge Case: Last Valid Chunk Index Acceptance ---

#[test]
fn counter_dispute_accepts_last_valid_chunk_index() {
    new_test_ext().execute_with(|| {
        let index = 3usize; // last valid index for n=4
        let (cid, tree, chunks) = setup_disputed_commitment_at(4, 100u64, index as ChunkIndex);

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));
    });
}

// --- 16. Edge Case: Single Leaf Tree Acceptance ---

#[test]
fn counter_dispute_accepts_single_leaf_tree_with_empty_proof() {
    new_test_ext().execute_with(|| {
        let (cid, tree, chunks) = setup_disputed_commitment(1, 100u64);

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            bounded_chunk(chunks[0].clone()),
            proof_for(&tree, 0),
        ));
    });
}

// --- 17. Temporal Deadline: Inclusive Boundary Acceptance ---

#[test]
fn counter_dispute_accepts_at_exact_deadline_block_inclusive() {
    new_test_ext().execute_with(|| {
        let index = 0usize;
        let (cid, tree, chunks) = setup_disputed_commitment(4, 1000u64);

        System::set_block_number(11);
        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));
    });
}

// --- 18. Temporal Deadline: Exclusive Boundary Rejection ---

#[test]
fn counter_dispute_rejects_one_block_past_deadline() {
    new_test_ext().execute_with(|| {
        let index = 0usize;
        let (cid, tree, chunks) = setup_disputed_commitment(4, 1000u64);

        System::set_block_number(12);
        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::DisputeWindowExpired
        );
    });
}

// --- 19. Temporal Deadline: Out of Bounds Rejection ---

#[test]
fn counter_dispute_rejects_long_after_deadline() {
    new_test_ext().execute_with(|| {
        let index = 0usize;
        let (cid, tree, chunks) = setup_disputed_commitment(4, 1000u64);

        System::set_block_number(5000);
        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::DisputeWindowExpired
        );
    });
}

// --- 20. Origin Check: Provider Identity Mismatch ---

#[test]
fn counter_dispute_rejects_wrong_provider_did() {
    new_test_ext().execute_with(|| {
        let index = 0usize;
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);

        let impostor_did = test_did(50);
        register_test_agent(impostor_did, 1, true);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                impostor_did,
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::NotProvider
        );
    });
}

// --- 21. Origin Check: Consumer Hijack Rejection ---

#[test]
fn counter_dispute_consumer_cannot_counter_as_provider() {
    new_test_ext().execute_with(|| {
        let index = 0usize;
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(2),
                cid,
                test_did(2),
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::NotProvider
        );
    });
}

// --- 22. Origin Check: Controller Authority Rejection ---

#[test]
fn counter_dispute_rejects_wrong_controller() {
    new_test_ext().execute_with(|| {
        let index = 0usize;
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(99),
                cid,
                test_did(1),
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::NotProvider
        );
    });
}

// --- 23. Origin Check: Attacker Isolation ---

#[test]
fn counter_dispute_registered_attacker_cannot_counter_for_others() {
    new_test_ext().execute_with(|| {
        let index = 0usize;
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);

        let attacker_did = test_did(66);
        register_test_agent(attacker_did, 66, true);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(66),
                cid,
                attacker_did,
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::NotProvider
        );
    });
}

// --- 24. Precondition Check: Late-Suspension Rejection ---

#[test]
fn counter_dispute_rejects_provider_suspended_before_countering() {
    new_test_ext().execute_with(|| {
        let index = 0usize;
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);

        register_test_agent(test_did(1), 1, false);

        assert_noop!(
            VectorDb::counter_dispute(
                RuntimeOrigin::signed(1),
                cid,
                test_did(1),
                bounded_chunk(chunks[index].clone()),
                proof_for(&tree, index),
            ),
            Error::<Runtime>::ProviderNotEligible
        );
    });
}

// --- 25. Guard Priority: NotDisputed precedes Provider DID check ---

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
                bounded_chunk(chunks[0].clone()),
                proof_for(&tree, 0),
            ),
            Error::<Runtime>::NotDisputed
        );
    });
}

// --- 26. Guard Priority: Provider DID check precedes Controller lookup ---

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
                bounded_chunk(chunks[0].clone()),
                proof_for(&tree, 0),
            ),
            Error::<Runtime>::NotProvider
        );
    });
}

// --- 27. State Mutability Safety on Rejection ---

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

// --- 28. Larger Tree Boundary Verification (Non-Power-of-Two) ---

#[test]
fn counter_dispute_succeeds_against_non_power_of_two_leaf_tree() {
    new_test_ext().execute_with(|| {
        let index = 6usize; // last valid index for n=7
        let (cid, tree, chunks) = setup_disputed_commitment_at(7, 100u64, index as ChunkIndex);

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));
    });
}

// --- 29b. Reputation Consequence: False Disputer Penalized ---

#[test]
fn counter_dispute_penalizes_the_false_disputer() {
    new_test_ext().execute_with(|| {
        let index = 0usize;
        let (cid, tree, chunks) = setup_disputed_commitment(4, 100u64);
        let consumer_did = test_did(2); // matches setup_valid_pair's fixed DID

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            bounded_chunk(chunks[index].clone()),
            proof_for(&tree, index),
        ));

        assert_eq!(
            crate::mock::reputation_calls(),
            vec![(consumer_did, "false_disputer")],
            "counter_dispute must call ReputationHandler::penalize_false_disputer \
             exactly once, on the consumer's DID -- not the provider's"
        );
    });
}

// --- 29c. Reputation Consequence: No Penalty on Failed Counter ---

#[test]
fn counter_dispute_does_not_penalize_on_invalid_proof() {
    new_test_ext().execute_with(|| {
        let index = 2usize;
        let (cid, _tree, chunks) = setup_disputed_commitment_at(8, 100u64, index as ChunkIndex);

        let bogus_proof: BoundedVec<[u8; 32], ConstU32<MAX_PROOF_DEPTH>> =
            BoundedVec::try_from(vec![[0x99u8; 32], [0x88u8; 32], [0x77u8; 32]]).unwrap();

        let _ = VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid,
            test_did(1),
            bounded_chunk(chunks[index].clone()),
            bogus_proof,
        );

        assert!(
            crate::mock::reputation_calls().is_empty(),
            "a rejected counter_dispute (invalid proof) must not trigger any \
             reputation penalty"
        );
    });
}

// --- 29. Multi-Dispute Independence Verification ---

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
            0u64,
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
            0u64,
            [0xEEu8; 32],
            4u64,
        ));

        assert_ok!(VectorDb::counter_dispute(
            RuntimeOrigin::signed(1),
            cid1,
            p,
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
                bounded_chunk(chunks1[0].clone()),
                proof_for(&tree1, 0),
            ),
            Error::<Runtime>::NotProvider
        );
    });
}
