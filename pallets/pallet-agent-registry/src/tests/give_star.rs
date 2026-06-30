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
            alice_did,
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
            AgentRegistry::give_star(RuntimeOrigin::signed(alice), alice_did, alice_did,),
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
        let alice_did = derive_did(&alice_pubkey);
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
            alice_did,
            bob_did,
        ));

        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(alice), alice_did, bob_did,),
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
        let alice_did = derive_did(&alice_pubkey);
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
            alice_did,
            bob_did,
        ));

        System::set_block_number(12);

        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            alice_did,
            bob_did,
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
            AgentRegistry::give_star(RuntimeOrigin::none(), Did::default(), bob_did,),
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

        // Account 99 has no registered agent. ControllerAgents::get(&99)
        // returns an empty vec, so .contains(&Did::default()) is false —
        // the new ownership check rejects via NotController before any
        // DID-existence lookup runs.
        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(99u64), Did::default(), bob_did,),
            Error::<Runtime>::NotController
        );
    });
}

#[test]
fn give_star_receiver_not_found_fails() {
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

        let ghost_did = derive_did(&pubkey_bytes(&generate_keypair(999).verifying_key));

        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(alice), alice_did, ghost_did,),
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
        let alice_did = derive_did(&alice_pubkey);
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
            AgentRegistry::give_star(RuntimeOrigin::signed(alice), alice_did, bob_did,),
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
        let alice_did = derive_did(&alice_pubkey);
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
            alice_did,
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
        let alice_did = derive_did(&alice_pubkey);
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
            alice_did,
            bob_did,
        ));

        // last_star = 1, cooldown = 10, expiry = 11. Block 10 is one short.
        System::set_block_number(10);
        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(alice), alice_did, bob_did,),
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
        let alice_did = derive_did(&alice_pubkey);
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
            alice_did,
            bob_did,
        ));

        // last_star = 1, cooldown = 10, expiry = 11. Exact boundary passes.
        System::set_block_number(11);
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            alice_did,
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
        let alice_did = derive_did(&alice_pubkey);
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
            alice_did,
            bob_did,
        ));

        // last_star = 1, cooldown = 10, expiry = 11. Block 12 is past expiry.
        System::set_block_number(12);
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            alice_did,
            bob_did,
        ));

        let profile = AgentRegistry::agent_profile(bob_did).unwrap();
        assert_eq!(profile.reputation_score, 2);
    });
}

#[test]
fn give_star_controller_can_act_as_any_owned_did() {
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

        // Alice explicitly acts as her SECOND registered DID — previously
        // impossible, since the old .first()-based lookup always forced
        // alice_did1 regardless of caller intent.
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            alice_did2,
            bob_did,
        ));

        // The star ledger and event must reflect alice_did2 as giver, not
        // alice_did1 — proving the explicit parameter is actually used.
        System::assert_last_event(
            Event::StarGiven {
                giver: alice_did2,
                receiver: bob_did,
            }
            .into(),
        );

        // alice_did2's cooldown ledger entry is now set...
        assert_eq!(
            AgentRegistry::star_givers(alice_did2, bob_did),
            System::block_number()
        );
        // ...while alice_did1, which never acted, remains untouched.
        assert_eq!(AgentRegistry::star_givers(alice_did1, bob_did), 0u64);
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
        let alice_did = derive_did(&alice_pubkey);
        let (bob_pubkey, bob_sig) = valid_register_params(2, bob, signed_at_block);
        let bob_did = derive_did(&bob_pubkey);
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
            alice_did,
            charlie_did,
        ));
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(bob),
            bob_did,
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
        let alice_did = derive_did(&alice_pubkey);
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
            alice_did,
            bob_did,
        ));

        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            alice_did,
            charlie_did,
        ));

        let bob_profile = AgentRegistry::agent_profile(bob_did).unwrap();
        let charlie_profile = AgentRegistry::agent_profile(charlie_did).unwrap();
        assert_eq!(bob_profile.reputation_score, 1);
        assert_eq!(charlie_profile.reputation_score, 1);
    });
}

#[test]
fn give_star_not_controller_check_precedes_self_star_check() {
    new_test_ext().execute_with(|| {
        // Caller passes the SAME did for both giver_did and receiver
        // (which would trigger CannotStarSelf if ownership were verified),
        // but caller 99 owns no DIDs at all. Ownership verification (step 2)
        // must run before the self-star guard (step 3), so NotController
        // wins even though the self-star condition is also true.
        let ghost_did = derive_did(&pubkey_bytes(&generate_keypair(99).verifying_key));

        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(99u64), ghost_did, ghost_did,),
            Error::<Runtime>::NotController
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
        let alice_did = derive_did(&alice_pubkey);
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
            alice_did,
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
            AgentRegistry::give_star(RuntimeOrigin::signed(alice), alice_did, bob_did,),
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
        let alice_did = derive_did(&alice_pubkey);
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
            alice_did,
            bob_did,
        ));

        let profile = AgentRegistry::agent_profile(bob_did).unwrap();
        assert_eq!(profile.reputation_score, u32::MAX);
    });
}

#[test]
fn give_star_spoofed_giver_did_fails() {
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

        // Alice (signed origin) tries to act as Charlie's DID, which she
        // does not control. Must be rejected even though charlie_did is a
        // real, registered DID — ownership, not mere existence, is checked.
        assert_noop!(
            AgentRegistry::give_star(RuntimeOrigin::signed(alice), charlie_did, bob_did),
            Error::<Runtime>::NotController
        );
    });
}
