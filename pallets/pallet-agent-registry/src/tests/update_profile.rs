use super::*;

#[test]
fn update_profile_works() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        let did = derive_did(&pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        let new_caps: CapabilityBitmap = CAP_INFERENCE_ENGINE;

        assert_ok!(AgentRegistry::update_profile(
            RuntimeOrigin::signed(controller),
            did,
            new_caps,
            metadata(),
            label(),
        ));

        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.capabilities, new_caps);

        System::assert_last_event(Event::AgentProfileUpdated { did }.into());
    });
}

#[test]
fn update_profile_not_controller_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let attacker = 2u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        let did = derive_did(&pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_noop!(
            AgentRegistry::update_profile(
                RuntimeOrigin::signed(attacker),
                did,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::NotController
        );
    });
}

#[test]
fn update_profile_did_not_found_fails() {
    new_test_ext().execute_with(|| {
        let never_registered_did = derive_did(&pubkey_bytes(&generate_keypair(999).verifying_key));

        assert_noop!(
            AgentRegistry::update_profile(
                RuntimeOrigin::signed(1u64),
                never_registered_did,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::DidNotFound
        );
    });
}

#[test]
fn update_profile_revoked_agent_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        let did = derive_did(&pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Revoked,
        ));

        assert_noop!(
            AgentRegistry::update_profile(
                RuntimeOrigin::signed(controller),
                did,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::AgentRevoked
        );
    });
}

#[test]
fn update_profile_unsigned_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        let did = derive_did(&pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_noop!(
            AgentRegistry::update_profile(
                RuntimeOrigin::none(),
                did,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn update_profile_overwrites_metadata_and_label() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        let did = derive_did(&pubkey);

        let old_metadata: BoundedVec<u8, frame_support::traits::ConstU32<MAX_METADATA_LEN>> =
            BoundedVec::try_from(b"old metadata".to_vec()).unwrap();
        let old_label: BoundedVec<u8, frame_support::traits::ConstU32<MAX_LABEL_LEN>> =
            BoundedVec::try_from(b"old label".to_vec()).unwrap();

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            old_metadata,
            old_label,
        ));

        let new_metadata: BoundedVec<u8, frame_support::traits::ConstU32<MAX_METADATA_LEN>> =
            BoundedVec::try_from(b"new metadata".to_vec()).unwrap();
        let new_label: BoundedVec<u8, frame_support::traits::ConstU32<MAX_LABEL_LEN>> =
            BoundedVec::try_from(b"new label".to_vec()).unwrap();

        assert_ok!(AgentRegistry::update_profile(
            RuntimeOrigin::signed(controller),
            did,
            CAP_DATA_PROVIDER,
            new_metadata.clone(),
            new_label.clone(),
        ));

        // Full replacement, not a merge: the old values must be gone.
        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.metadata, new_metadata);
        assert_eq!(profile.label, new_label);
    });
}

#[test]
fn update_profile_suspended_agent_still_works() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        let did = derive_did(&pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Suspended,
        ));

        // Only Revoked is blocked; Suspended is not.
        let new_caps: CapabilityBitmap = CAP_INFERENCE_ENGINE;
        assert_ok!(AgentRegistry::update_profile(
            RuntimeOrigin::signed(controller),
            did,
            new_caps,
            metadata(),
            label(),
        ));

        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.capabilities, new_caps);
        assert_eq!(profile.status, AgentStatus::Suspended);
    });
}

#[test]
fn update_profile_registered_attacker_cannot_update_others_profile() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let signed_at_block = System::block_number();

        let (alice_pubkey, alice_sig) = valid_register_params(1, alice, signed_at_block);
        let alice_did = derive_did(&alice_pubkey);

        let (bob_pubkey, bob_sig) = valid_register_params(2, bob, signed_at_block);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_pubkey,
            alice_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));
        // Bob has his own valid, registered profile — he is not an
        // outsider, just not the controller of Alice's DID.
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(bob),
            bob_pubkey,
            bob_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_noop!(
            AgentRegistry::update_profile(
                RuntimeOrigin::signed(bob),
                alice_did,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::NotController
        );
    });
}

#[test]
fn update_profile_controller_check_precedes_revoked_check() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let attacker = 2u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        let did = derive_did(&pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Revoked,
        ));

        // The DID is both revoked AND not owned by the attacker. The
        // controller check runs first in the pallet body, so this must
        // surface NotController, not AgentRevoked.
        assert_noop!(
            AgentRegistry::update_profile(
                RuntimeOrigin::signed(attacker),
                did,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::NotController
        );
    });
}

#[test]
fn update_profile_all_fields_overwritten_simultaneously() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        let did = derive_did(&pubkey);

        let old_metadata: BoundedVec<u8, frame_support::traits::ConstU32<MAX_METADATA_LEN>> =
            BoundedVec::try_from(b"old metadata".to_vec()).unwrap();
        let old_label: BoundedVec<u8, frame_support::traits::ConstU32<MAX_LABEL_LEN>> =
            BoundedVec::try_from(b"old label".to_vec()).unwrap();

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            old_metadata,
            old_label,
        ));

        let new_metadata: BoundedVec<u8, frame_support::traits::ConstU32<MAX_METADATA_LEN>> =
            BoundedVec::try_from(b"new metadata".to_vec()).unwrap();
        let new_label: BoundedVec<u8, frame_support::traits::ConstU32<MAX_LABEL_LEN>> =
            BoundedVec::try_from(b"new label".to_vec()).unwrap();

        assert_ok!(AgentRegistry::update_profile(
            RuntimeOrigin::signed(controller),
            did,
            CAP_INFERENCE_ENGINE,
            new_metadata.clone(),
            new_label.clone(),
        ));

        // All three mutable fields replaced in a single call; none retain old value.
        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.capabilities, CAP_INFERENCE_ENGINE);
        assert_eq!(profile.metadata, new_metadata);
        assert_eq!(profile.label, new_label);
    });
}

#[test]
fn update_profile_noop_resubmit_succeeds_and_emits_event() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        let did = derive_did(&pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        // Identical values resubmitted — pallet has no noop guard, must succeed.
        assert_ok!(AgentRegistry::update_profile(
            RuntimeOrigin::signed(controller),
            did,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        // Event emitted unconditionally; no silent short-circuit exists.
        System::assert_last_event(Event::AgentProfileUpdated { did }.into());
    });
}

#[test]
fn update_profile_zero_capabilities_allowed() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        let did = derive_did(&pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        // Zero bitmap: no validation rejects it; capability content is
        // caller-defined, not a protocol invariant.
        assert_ok!(AgentRegistry::update_profile(
            RuntimeOrigin::signed(controller),
            did,
            0u64,
            metadata(),
            label(),
        ));

        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.capabilities, 0u64);
    });
}

#[test]
fn update_profile_immutable_fields_unchanged_after_update() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        let did = derive_did(&pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_ok!(AgentRegistry::update_profile(
            RuntimeOrigin::signed(controller),
            did,
            CAP_INFERENCE_ENGINE,
            metadata(),
            label(),
        ));

        // update_profile exposes no mechanism to mutate these fields;
        // confirm storage reflects that invariant explicitly.
        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.controller, controller);
        assert_eq!(profile.status, AgentStatus::Active);
        assert!(profile.is_verified);
        assert_eq!(profile.quantum_scheme, QuantumScheme::MlDsa65);
    });
}

#[test]
fn update_profile_did_not_found_precedes_controller_check() {
    new_test_ext().execute_with(|| {
        // Non-existent DID + wrong caller: storage lookup (step 2) fires
        // before controller check (step 3), so DidNotFound wins.
        let never_registered_did = derive_did(&pubkey_bytes(&generate_keypair(999).verifying_key));

        assert_noop!(
            AgentRegistry::update_profile(
                RuntimeOrigin::signed(2u64),
                never_registered_did,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::DidNotFound
        );
    });
}
