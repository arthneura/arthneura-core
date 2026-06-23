use super::*;

#[test]
fn give_star_works() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let signed_at_block = System::block_number();
        let (alice_pubkey, alice_sig) = valid_register_params(1, alice, signed_at_block);
        let (bob_pubkey, bob_sig) = valid_register_params(2, bob, signed_at_block);
        let alice_did = derive_did(&alice_pubkey);
        let bob_did = derive_did(&bob_pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_pubkey,
            alice_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(bob),
            bob_pubkey,
            bob_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        let profile = AgentRegistry::agent_profile(bob_did).unwrap();
        assert_eq!(profile.reputation_score, 1);

        System::assert_last_event(
            Event::StarGiven {
                giver: alice_did,
                receiver: bob_did,
            }
            .into(),
        );
    });
}

#[test]
fn give_star_cannot_star_self() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let signed_at_block = System::block_number();
        let (alice_pubkey, alice_sig) = valid_register_params(1, alice, signed_at_block);
        let alice_did = derive_did(&alice_pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_pubkey,
            alice_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(alice), alice_did),
            Error::<Runtime>::CannotStarSelf
        );
    });
}

#[test]
fn give_star_cooldown_enforced() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let signed_at_block = System::block_number();
        let (alice_pubkey, alice_sig) = valid_register_params(1, alice, signed_at_block);
        let (bob_pubkey, bob_sig) = valid_register_params(2, bob, signed_at_block);
        let bob_did = derive_did(&bob_pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_pubkey,
            alice_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(bob),
            bob_pubkey,
            bob_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did
        ));

        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(alice), bob_did),
            Error::<Runtime>::CooldownNotExpired
        );
    });
}

#[test]
fn give_star_after_cooldown_works() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let signed_at_block = System::block_number();
        let (alice_pubkey, alice_sig) = valid_register_params(1, alice, signed_at_block);
        let (bob_pubkey, bob_sig) = valid_register_params(2, bob, signed_at_block);
        let bob_did = derive_did(&bob_pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_pubkey,
            alice_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(bob),
            bob_pubkey,
            bob_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did
        ));

        System::set_block_number(12);

        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did
        ));

        let profile = AgentRegistry::agent_profile(bob_did).unwrap();
        assert_eq!(profile.reputation_score, 2);
    });
}
