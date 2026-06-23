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
