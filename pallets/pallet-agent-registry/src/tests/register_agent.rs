use super::*;

#[test]
fn register_agent_works() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let caps = CAP_DATA_PROVIDER | CAP_INFERENCE_ENGINE;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        let did = derive_did(&pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            signed_at_block,
            caps,
            metadata(),
            label(),
        ));

        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.controller, controller);
        assert_eq!(profile.capabilities, caps);
        assert_eq!(profile.reputation_score, 0);
        assert_eq!(profile.status, AgentStatus::Active);
        assert!(profile.is_verified);
        assert_eq!(profile.quantum_scheme, QuantumScheme::MlDsa65);

        let dids = AgentRegistry::controller_agents(controller);
        assert_eq!(dids.len(), 1);
        assert_eq!(dids[0], did);

        assert_eq!(AgentRegistry::active_agent_count(), 1);

        System::assert_last_event(Event::AgentRegistered { did, controller }.into());
    });
}

#[test]
fn register_agent_duplicate_did_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey.clone(),
            signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        // Same pubkey, fresh signature over the same challenge shape.
        let (_pubkey2, signature2) = {
            let did = derive_did(&pubkey);
            let genesis_hash = System::block_hash(0u64);
            let signed_at_hash = System::block_hash(signed_at_block);
            let challenge = build_challenge(
                genesis_hash,
                did,
                controller,
                signed_at_block,
                signed_at_hash,
            );
            let keypair = generate_keypair(1);
            let sig = sign_challenge(&keypair.signing_key, &challenge);
            (pubkey.clone(), sig)
        };

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                signature2,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::DidAlreadyRegistered
        );
    });
}

#[test]
fn register_agent_unsigned_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::none(),
                pubkey,
                signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn register_agent_too_many_agents_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();

        for i in 0..64u64 {
            let (pubkey, signature) = valid_register_params(i, controller, signed_at_block);
            assert_ok!(AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ));
        }

        let (pubkey, signature) = valid_register_params(64, controller, signed_at_block);
        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::TooManyAgentsForController
        );
    });
}

#[test]
fn register_agent_bit_flipped_signature_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, mut signature) = valid_register_params(1, controller, signed_at_block);

        let mid = signature.len() / 2;
        signature[mid] ^= 0x01;

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidQuantumProof
        );
    });
}

#[test]
fn register_agent_signature_from_different_keypair_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();

        let alice_keypair = generate_keypair(1);
        let alice_pubkey = pubkey_bytes(&alice_keypair.verifying_key);
        let alice_did = derive_did(&alice_pubkey);

        let genesis_hash = System::block_hash(0u64);
        let signed_at_hash = System::block_hash(signed_at_block);
        let challenge = build_challenge(
            genesis_hash,
            alice_did,
            controller,
            signed_at_block,
            signed_at_hash,
        );

        let bob_keypair = generate_keypair(2);
        let forged_signature = sign_challenge(&bob_keypair.signing_key, &challenge);

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                alice_pubkey,
                forged_signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidQuantumProof
        );
    });
}

#[test]
fn register_agent_pubkey_too_short_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);

        let mut short_bytes = pubkey.into_inner();
        short_bytes.pop();
        let short_pubkey =
            BoundedVec::<u8, frame_support::traits::ConstU32<1952>>::try_from(short_bytes)
                .expect("len - 1 is still within the bound");

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                short_pubkey,
                signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidPubkeyLength
        );
    });
}

#[test]
fn register_agent_signature_too_short_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);

        let mut short_bytes = signature.into_inner();
        short_bytes.pop();
        let short_signature =
            BoundedVec::<u8, frame_support::traits::ConstU32<3309>>::try_from(short_bytes)
                .expect("len - 1 is still within the bound");

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                short_signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidSignatureLength
        );
    });
}

#[test]
fn register_agent_empty_pubkey_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (_pubkey, signature) = valid_register_params(1, controller, signed_at_block);

        let empty_pubkey =
            BoundedVec::<u8, frame_support::traits::ConstU32<1952>>::try_from(Vec::new())
                .expect("empty vec is within any bound");

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                empty_pubkey,
                signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidPubkeyLength
        );
    });
}

#[test]
fn register_agent_empty_signature_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, _signature) = valid_register_params(1, controller, signed_at_block);

        let empty_signature =
            BoundedVec::<u8, frame_support::traits::ConstU32<3309>>::try_from(Vec::new())
                .expect("empty vec is within any bound");

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                empty_signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidSignatureLength
        );
    });
}

#[test]
fn register_agent_signature_over_wrong_message_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let keypair = generate_keypair(1);
        let pubkey = pubkey_bytes(&keypair.verifying_key);

        let wrong_message = b"this is not the challenge you are looking for".to_vec();
        let forged_signature = sign_challenge(&keypair.signing_key, &wrong_message);

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                forged_signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidQuantumProof
        );
    });
}

#[test]
fn register_agent_all_zero_pubkey_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (_pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        let zero_pubkey =
            BoundedVec::<u8, frame_support::traits::ConstU32<1952>>::try_from(vec![0u8; 1952])
                .expect("exactly MAX_PUBKEY_LEN zero bytes fits the bound");

        // Decodes into a structurally well-formed VerifyingKey; rejected
        // at verification, not at decode.
        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                zero_pubkey,
                signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidQuantumProof
        );
    });
}

#[test]
fn register_agent_all_zero_signature_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, _signature) = valid_register_params(1, controller, signed_at_block);
        let zero_signature =
            BoundedVec::<u8, frame_support::traits::ConstU32<3309>>::try_from(vec![0u8; 3309])
                .expect("exactly MAX_SIG_LEN zero bytes fits the bound");

        // Rejected at decode: signature encoding has structural
        // constraints an all-zero buffer violates.
        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                zero_signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidSignatureLength
        );
    });
}

#[test]
fn register_agent_exact_resubmission_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey.clone(),
            signature.clone(),
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::DidAlreadyRegistered
        );
    });
}

#[test]
fn register_agent_cross_controller_signature_fails() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let signed_at_block = System::block_number();

        // Signed for alice; submitted under bob.
        let (alice_pubkey, alice_signature) = valid_register_params(1, alice, signed_at_block);

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(bob),
                alice_pubkey,
                alice_signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidQuantumProof
        );
    });
}

#[test]
fn register_agent_off_by_one_signed_at_block_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        System::set_block_number(10);
        let actually_signed_block = System::block_number();
        let claimed_block = actually_signed_block - 1;

        // Signed for `actually_signed_block`; submitted claiming
        // `actually_signed_block - 1`. Both are within the replay
        // window, so this is caught by signature verification, not the
        // window check.
        let (pubkey, signature) = valid_register_params(1, controller, actually_signed_block);

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                signature,
                claimed_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidQuantumProof
        );
    });
}

#[test]
fn register_agent_random_garbage_pubkey_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (_pubkey, signature) = valid_register_params(1, controller, signed_at_block);

        let garbage: Vec<u8> = (0u32..1952u32).map(|i| (i % 251) as u8 + 1).collect();
        let garbage_pubkey =
            BoundedVec::<u8, frame_support::traits::ConstU32<1952>>::try_from(garbage)
                .expect("exactly MAX_PUBKEY_LEN bytes fits the bound");

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                garbage_pubkey,
                signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidQuantumProof
        );
    });
}

#[test]
fn register_agent_random_garbage_signature_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, _signature) = valid_register_params(1, controller, signed_at_block);

        let garbage: Vec<u8> = (0u32..3309u32).map(|i| (i % 251) as u8 + 1).collect();
        let garbage_signature =
            BoundedVec::<u8, frame_support::traits::ConstU32<3309>>::try_from(garbage)
                .expect("exactly MAX_SIG_LEN bytes fits the bound");

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                garbage_signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidSignatureLength
        );
    });
}

#[test]
fn register_agent_cross_genesis_signature_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let keypair = generate_keypair(1);
        let pubkey = pubkey_bytes(&keypair.verifying_key);
        let did = derive_did(&pubkey);

        let forged_genesis_hash = sp_core::H256::repeat_byte(0xAB);
        let real_signed_at_hash = System::block_hash(signed_at_block);
        let forged_challenge = build_challenge(
            forged_genesis_hash,
            did,
            controller,
            signed_at_block,
            real_signed_at_hash,
        );
        let forged_signature = sign_challenge(&keypair.signing_key, &forged_challenge);

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                forged_signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidQuantumProof
        );
    });
}

#[test]
fn register_agent_wrong_signed_at_hash_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let keypair = generate_keypair(1);
        let pubkey = pubkey_bytes(&keypair.verifying_key);
        let did = derive_did(&pubkey);

        let genesis_hash = System::block_hash(0u64);
        let forged_signed_at_hash = sp_core::H256::repeat_byte(0xCD);
        let forged_challenge = build_challenge(
            genesis_hash,
            did,
            controller,
            signed_at_block,
            forged_signed_at_hash,
        );
        let forged_signature = sign_challenge(&keypair.signing_key, &forged_challenge);

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                forged_signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidQuantumProof
        );
    });
}

#[test]
fn register_agent_did_pubkey_mismatch_in_challenge_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let keypair = generate_keypair(1);
        let pubkey = pubkey_bytes(&keypair.verifying_key);

        let other_keypair = generate_keypair(999);
        let other_pubkey = pubkey_bytes(&other_keypair.verifying_key);
        let mismatched_did = derive_did(&other_pubkey);

        let genesis_hash = System::block_hash(0u64);
        let signed_at_hash = System::block_hash(signed_at_block);
        let challenge = build_challenge(
            genesis_hash,
            mismatched_did,
            controller,
            signed_at_block,
            signed_at_hash,
        );
        let signature = sign_challenge(&keypair.signing_key, &challenge);

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidQuantumProof
        );
    });
}

#[test]
fn register_agent_future_signed_at_block_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let current_block = System::block_number();
        let future_block = current_block + 1;

        let (pubkey, signature) = valid_register_params(1, controller, future_block);

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                signature,
                future_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::InvalidChallengeBlock
        );
    });
}

#[test]
fn register_agent_expired_challenge_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        System::set_block_number(200);
        let stale_block = 1u64;

        let (pubkey, signature) = valid_register_params(1, controller, stale_block);

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                signature,
                stale_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::ChallengeExpired
        );
    });
}

#[test]
fn register_agent_signed_at_block_exactly_at_window_boundary_works() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;

        // REPLAY_WINDOW is 64; the boundary check is `<=`, so exactly
        // 64 blocks back must still succeed.
        System::set_block_number(100);
        let current_block = System::block_number();
        let boundary_block = current_block - 64;

        let (pubkey, signature) = valid_register_params(1, controller, boundary_block);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            boundary_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));
    });
}

#[test]
fn register_agent_signed_at_block_one_past_window_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        System::set_block_number(100);
        let current_block = System::block_number();
        let one_past_boundary_block = current_block - 65;

        let (pubkey, signature) = valid_register_params(1, controller, one_past_boundary_block);

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                pubkey,
                signature,
                one_past_boundary_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::ChallengeExpired
        );
    });
}

#[test]
fn register_agent_same_pubkey_different_controller_fails() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let signed_at_block = System::block_number();

        let keypair = generate_keypair(1);
        let pubkey = pubkey_bytes(&keypair.verifying_key);
        let did = derive_did(&pubkey);

        let genesis_hash = System::block_hash(0u64);
        let signed_at_hash = System::block_hash(signed_at_block);

        let alice_challenge =
            build_challenge(genesis_hash, did, alice, signed_at_block, signed_at_hash);
        let alice_signature = sign_challenge(&keypair.signing_key, &alice_challenge);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            pubkey.clone(),
            alice_signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        // DID is derived from the pubkey alone, so it's the same DID
        // regardless of which controller signs for it. Bob signs his
        // own correctly-bound challenge for this pubkey, but the DID
        // already exists.
        let bob_challenge =
            build_challenge(genesis_hash, did, bob, signed_at_block, signed_at_hash);
        let bob_signature = sign_challenge(&keypair.signing_key, &bob_challenge);

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(bob),
                pubkey,
                bob_signature,
                signed_at_block,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::DidAlreadyRegistered
        );
    });
}

#[test]
fn register_agent_pubkey_one_byte_over_bound_cannot_be_constructed() {
    let oversized: Vec<u8> = vec![0u8; 1953];
    let result = BoundedVec::<u8, frame_support::traits::ConstU32<1952>>::try_from(oversized);
    assert!(
        result.is_err(),
        "BoundedVec must reject a buffer one byte over MAX_PUBKEY_LEN"
    );
}

#[test]
fn register_agent_signature_one_byte_over_bound_cannot_be_constructed() {
    let oversized: Vec<u8> = vec![0u8; 3310];
    let result = BoundedVec::<u8, frame_support::traits::ConstU32<3309>>::try_from(oversized);
    assert!(
        result.is_err(),
        "BoundedVec must reject a buffer one byte over MAX_SIG_LEN"
    );
}
