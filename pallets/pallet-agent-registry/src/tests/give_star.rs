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

#[test]
fn give_star_unsigned_fails() {
    new_test_ext().execute_with(|| {
        let bob = 2u64;
        let signed_at_block = System::block_number();
        let (bob_pubkey, bob_sig) = valid_register_params(2, bob, signed_at_block);
        let bob_did = derive_did(&bob_pubkey);

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
            AgentRegistry::give_star(RuntimeOrigin::none(), bob_did),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn give_star_giver_has_no_did_fails() {
    new_test_ext().execute_with(|| {
        let bob = 2u64;
        let signed_at_block = System::block_number();
        let (bob_pubkey, bob_sig) = valid_register_params(2, bob, signed_at_block);
        let bob_did = derive_did(&bob_pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(bob),
            bob_pubkey,
            bob_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        // Account 99 has no registered agent.
        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(99u64), bob_did),
            Error::<Runtime>::DidNotFound
        );
    });
}

#[test]
fn give_star_receiver_not_found_fails() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let signed_at_block = System::block_number();
        let (alice_pubkey, alice_sig) = valid_register_params(1, alice, signed_at_block);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_pubkey,
            alice_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        let ghost_did = derive_did(&pubkey_bytes(&generate_keypair(999).verifying_key));

        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(alice), ghost_did),
            Error::<Runtime>::DidNotFound
        );
    });
}

#[test]
fn give_star_receiver_revoked_fails() {
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

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(bob),
            bob_did,
            AgentStatus::Revoked,
        ));

        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(alice), bob_did),
            Error::<Runtime>::AgentRevoked
        );
    });
}

#[test]
fn give_star_receiver_suspended_succeeds() {
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

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(bob),
            bob_did,
            AgentStatus::Suspended,
        ));

        // Only Revoked blocks receiving a star.
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        let profile = AgentRegistry::agent_profile(bob_did).unwrap();
        assert_eq!(profile.reputation_score, 1);
    });
}

#[test]
fn give_star_cooldown_boundary_one_block_early_fails() {
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

        System::set_block_number(1);
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        // last_star = 1, cooldown = 10, expiry = 11. Block 10 is one short.
        System::set_block_number(10);
        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(alice), bob_did),
            Error::<Runtime>::CooldownNotExpired
        );
    });
}

#[test]
fn give_star_cooldown_boundary_exact_passes() {
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

        System::set_block_number(1);
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        // last_star = 1, cooldown = 10, expiry = 11. Exact boundary passes.
        System::set_block_number(11);
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        let profile = AgentRegistry::agent_profile(bob_did).unwrap();
        assert_eq!(profile.reputation_score, 2);
    });
}

#[test]
fn give_star_cooldown_boundary_one_block_after_passes() {
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

        System::set_block_number(1);
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        // last_star = 1, cooldown = 10, expiry = 11. Block 12 is past expiry.
        System::set_block_number(12);
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        let profile = AgentRegistry::agent_profile(bob_did).unwrap();
        assert_eq!(profile.reputation_score, 2);
    });
}

#[test]
fn give_star_controller_with_multiple_dids_uses_first() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let signed_at_block = System::block_number();

        let (alice_pubkey1, alice_sig1) = valid_register_params(1, alice, signed_at_block);
        let alice_did1 = derive_did(&alice_pubkey1);

        let (alice_pubkey2, alice_sig2) = valid_register_params(3, alice, signed_at_block);
        let alice_did2 = derive_did(&alice_pubkey2);

        let (bob_pubkey, bob_sig) = valid_register_params(2, bob, signed_at_block);
        let bob_did = derive_did(&bob_pubkey);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_pubkey1,
            alice_sig1,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_pubkey2,
            alice_sig2,
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

        // The first-registered DID under this controller is the giver.
        System::assert_last_event(
            Event::StarGiven {
                giver: alice_did1,
                receiver: bob_did,
            }
            .into(),
        );

        assert_eq!(AgentRegistry::star_givers(alice_did2, bob_did), 0u64);
    });
}

#[test]
fn give_star_multiple_givers_accumulate_score() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let charlie = 3u64;
        let signed_at_block = System::block_number();

        let (alice_pubkey, alice_sig) = valid_register_params(1, alice, signed_at_block);
        let (bob_pubkey, bob_sig) = valid_register_params(2, bob, signed_at_block);
        let (charlie_pubkey, charlie_sig) = valid_register_params(3, charlie, signed_at_block);
        let charlie_did = derive_did(&charlie_pubkey);

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
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(charlie),
            charlie_pubkey,
            charlie_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            charlie_did,
        ));
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(bob),
            charlie_did,
        ));

        let profile = AgentRegistry::agent_profile(charlie_did).unwrap();
        assert_eq!(profile.reputation_score, 2);
    });
}

#[test]
fn give_star_cooldown_is_per_pair_not_global() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let charlie = 3u64;
        let signed_at_block = System::block_number();

        let (alice_pubkey, alice_sig) = valid_register_params(1, alice, signed_at_block);
        let (bob_pubkey, bob_sig) = valid_register_params(2, bob, signed_at_block);
        let (charlie_pubkey, charlie_sig) = valid_register_params(3, charlie, signed_at_block);
        let bob_did = derive_did(&bob_pubkey);
        let charlie_did = derive_did(&charlie_pubkey);

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
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(charlie),
            charlie_pubkey,
            charlie_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            charlie_did,
        ));

        let bob_profile = AgentRegistry::agent_profile(bob_did).unwrap();
        let charlie_profile = AgentRegistry::agent_profile(charlie_did).unwrap();
        assert_eq!(bob_profile.reputation_score, 1);
        assert_eq!(charlie_profile.reputation_score, 1);
    });
}

#[test]
fn give_star_no_did_check_precedes_self_star_check() {
    new_test_ext().execute_with(|| {
        let ghost_did = derive_did(&pubkey_bytes(&generate_keypair(99).verifying_key));

        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(99u64), ghost_did),
            Error::<Runtime>::DidNotFound
        );
    });
}

#[test]
fn give_star_receiver_revoked_check_precedes_cooldown() {
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
            bob_did,
        ));

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(bob),
            bob_did,
            AgentStatus::Revoked,
        ));

        // Both the revoked-receiver check and the still-active cooldown
        // would independently reject this call; AgentRevoked wins.
        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(alice), bob_did),
            Error::<Runtime>::AgentRevoked
        );
    });
}

#[test]
fn give_star_reputation_score_saturates_at_max() {
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

        crate::pallet::AgentProfiles::<Runtime>::mutate(bob_did, |maybe_profile| {
            if let Some(profile) = maybe_profile {
                profile.reputation_score = u32::MAX;
            }
        });

        assert_eq!(
            AgentRegistry::agent_profile(bob_did)
                .unwrap()
                .reputation_score,
            u32::MAX
        );

        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        let profile = AgentRegistry::agent_profile(bob_did).unwrap();
        assert_eq!(profile.reputation_score, u32::MAX);
    });
}
