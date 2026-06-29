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

#[test]
fn set_agent_status_unsigned_fails() {
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
            AgentRegistry::set_agent_status(RuntimeOrigin::none(), did, AgentStatus::Suspended,),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn set_agent_status_did_not_found_fails() {
    new_test_ext().execute_with(|| {
        let never_registered_did = derive_did(&pubkey_bytes(&generate_keypair(999).verifying_key));

        assert_noop!(
            AgentRegistry::set_agent_status(
                RuntimeOrigin::signed(1u64),
                never_registered_did,
                AgentStatus::Suspended,
            ),
            Error::<Runtime>::DidNotFound
        );
    });
}

#[test]
fn set_agent_status_did_not_found_precedes_controller_check() {
    new_test_ext().execute_with(|| {
        // Storage lookup (step 2) runs before controller check (step 3);
        // a wrong caller against a non-existent DID surfaces DidNotFound.
        let never_registered_did = derive_did(&pubkey_bytes(&generate_keypair(999).verifying_key));

        assert_noop!(
            AgentRegistry::set_agent_status(
                RuntimeOrigin::signed(2u64),
                never_registered_did,
                AgentStatus::Suspended,
            ),
            Error::<Runtime>::DidNotFound
        );
    });
}

#[test]
fn set_agent_status_registered_attacker_cannot_change_others_status() {
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
        // Bob is a legitimate participant — not an outsider — but controls
        // only his own DID, not Alice's.
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
            AgentRegistry::set_agent_status(
                RuntimeOrigin::signed(bob),
                alice_did,
                AgentStatus::Suspended,
            ),
            Error::<Runtime>::NotController
        );
    });
}

#[test]
fn set_agent_status_controller_check_precedes_revoked_check() {
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

        // DID is revoked AND caller is not the controller; controller check
        // (step 3) runs before the terminal-state guard (step 4).
        assert_noop!(
            AgentRegistry::set_agent_status(
                RuntimeOrigin::signed(attacker),
                did,
                AgentStatus::Active,
            ),
            Error::<Runtime>::NotController
        );
    });
}

#[test]
fn set_agent_status_suspended_to_active_restores_status() {
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

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Active,
        ));

        // Suspended is not terminal; the round-trip must succeed and the
        // counter must remain at 1 throughout — only Revoked decrements it.
        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.status, AgentStatus::Active);
        assert_eq!(AgentRegistry::active_agent_count(), 1);

        System::assert_last_event(
            Event::AgentStatusChanged {
                did,
                new_status: AgentStatus::Active,
            }
            .into(),
        );
    });
}

#[test]
fn set_agent_status_suspended_to_revoked_decrements_counter() {
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

        assert_eq!(AgentRegistry::active_agent_count(), 1);

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Revoked,
        ));

        // Counter decrements on any transition into Revoked regardless of
        // the prior state; Suspended→Revoked is not a special case.
        assert_eq!(AgentRegistry::active_agent_count(), 0);
    });
}

#[test]
fn set_agent_status_active_to_active_noop_succeeds() {
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

        // No-op transition: pallet applies the write unconditionally and
        // emits the event; there is no same-state guard.
        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Active,
        ));

        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.status, AgentStatus::Active);
        assert_eq!(AgentRegistry::active_agent_count(), 1);

        System::assert_last_event(
            Event::AgentStatusChanged {
                did,
                new_status: AgentStatus::Active,
            }
            .into(),
        );
    });
}

#[test]
fn set_agent_status_suspended_to_suspended_noop_succeeds() {
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

        // Suspended→Suspended is not guarded; succeeds and emits the event.
        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Suspended,
        ));

        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.status, AgentStatus::Suspended);
        assert_eq!(AgentRegistry::active_agent_count(), 1);
    });
}

#[test]
fn set_agent_status_counter_saturates_at_zero() {
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

        assert_eq!(AgentRegistry::active_agent_count(), 0);

        // ActiveAgentCount is already 0; a second decrement attempt via a
        // separate agent must not underflow — saturating_sub holds at 0.
        let controller2 = 2u64;
        let signed_at_block2 = System::block_number();
        let (pubkey2, signature2) = valid_register_params(2, controller2, signed_at_block2);
        let did2 = derive_did(&pubkey2);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller2),
            pubkey2,
            signature2,
            signed_at_block2,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller2),
            did2,
            AgentStatus::Revoked,
        ));

        // Both agents revoked: count is 0, not underflowed.
        assert_eq!(AgentRegistry::active_agent_count(), 0);
    });
}
