use super::*;

#[test]
fn set_agent_status_suspend_works() {
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

        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.status, AgentStatus::Suspended);
        assert_eq!(AgentRegistry::active_agent_count(), 1);

        System::assert_last_event(
            Event::AgentStatusChanged {
                did,
                new_status: AgentStatus::Suspended,
            }
            .into(),
        );
    });
}

#[test]
fn set_agent_status_revoke_decrements_counter() {
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

        assert_eq!(AgentRegistry::active_agent_count(), 1);

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Revoked,
        ));

        assert_eq!(AgentRegistry::active_agent_count(), 0);
    });
}

#[test]
fn set_agent_status_revoked_terminal_fails() {
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
            AgentRegistry::set_agent_status(
                RuntimeOrigin::signed(controller),
                did,
                AgentStatus::Active,
            ),
            Error::<Runtime>::AgentRevoked
        );
    });
}

#[test]
fn set_agent_status_not_controller_fails() {
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
            AgentRegistry::set_agent_status(
                RuntimeOrigin::signed(attacker),
                did,
                AgentStatus::Suspended,
            ),
            Error::<Runtime>::NotController
        );
    });
}
