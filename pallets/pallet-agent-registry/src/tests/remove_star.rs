use super::*;

#[test]
fn remove_star_works() {
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
            bob_did
        ));
        assert_eq!(
            AgentRegistry::agent_profile(bob_did)
                .unwrap()
                .reputation_score,
            1
        );

        assert_ok!(AgentRegistry::remove_star(
            RuntimeOrigin::signed(alice),
            bob_did
        ));
        assert_eq!(
            AgentRegistry::agent_profile(bob_did)
                .unwrap()
                .reputation_score,
            0
        );

        System::assert_last_event(
            Event::StarRemoved {
                giver: alice_did,
                receiver: bob_did,
            }
            .into(),
        );
    });
}

#[test]
fn remove_star_not_starred_fails() {
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

        assert_noop!(
            AgentRegistry::remove_star(RuntimeOrigin::signed(alice), bob_did),
            Error::<Runtime>::NotStarred
        );
    });
}

#[test]
fn remove_star_resets_cooldown() {
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

        assert_ok!(AgentRegistry::remove_star(
            RuntimeOrigin::signed(alice),
            bob_did
        ));

        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did
        ));

        let profile = AgentRegistry::agent_profile(bob_did).unwrap();
        assert_eq!(profile.reputation_score, 1);
    });
}

#[test]
fn remove_star_unsigned_fails() {
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

        assert_noop!(
            AgentRegistry::remove_star(RuntimeOrigin::none(), bob_did),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn remove_star_giver_has_no_did_fails() {
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

        // Account 99 has never registered an agent; ControllerAgents returns
        // an empty vec, so .first() is None → DidNotFound.
        assert_noop!(
            AgentRegistry::remove_star(RuntimeOrigin::signed(99u64), bob_did),
            Error::<Runtime>::DidNotFound
        );
    });
}

#[test]
fn remove_star_no_did_check_precedes_not_starred_check() {
    new_test_ext().execute_with(|| {
        // Giver has no DID and has never starred the receiver. Step 2
        // (ControllerAgents lookup) fires before step 3 (StarGivers check),
        // so DidNotFound wins over NotStarred.
        let ghost_did = derive_did(&pubkey_bytes(&generate_keypair(999).verifying_key));

        assert_noop!(
            AgentRegistry::remove_star(RuntimeOrigin::signed(99u64), ghost_did),
            Error::<Runtime>::DidNotFound
        );
    });
}

#[test]
fn remove_star_double_remove_fails() {
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
        assert_ok!(AgentRegistry::remove_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        // Ledger entry reset to 0 (sentinel); a second remove must surface
        // NotStarred, not succeed silently.
        assert_noop!(
            AgentRegistry::remove_star(RuntimeOrigin::signed(alice), bob_did),
            Error::<Runtime>::NotStarred
        );
    });
}

#[test]
fn remove_star_reputation_score_saturates_at_zero() {
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

        // Force reputation_score to 0 directly; the star ledger still shows
        // a valid star so remove_star can proceed.
        crate::pallet::AgentProfiles::<Runtime>::mutate(bob_did, |maybe_profile| {
            if let Some(profile) = maybe_profile {
                profile.reputation_score = 0;
            }
        });

        assert_ok!(AgentRegistry::remove_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        // saturating_sub must not underflow; score stays at 0.
        let profile = AgentRegistry::agent_profile(bob_did).unwrap();
        assert_eq!(profile.reputation_score, 0);
    });
}

#[test]
fn remove_star_registered_attacker_cannot_remove_others_star() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let eve = 3u64;
        let signed_at_block = System::block_number();

        let (alice_pubkey, alice_sig) = valid_register_params(1, alice, signed_at_block);
        let (bob_pubkey, bob_sig) = valid_register_params(2, bob, signed_at_block);
        let (eve_pubkey, eve_sig) = valid_register_params(3, eve, signed_at_block);
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
        // Eve is a legitimate participant with her own registered DID —
        // not an outsider — but she never starred Bob.
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(eve),
            eve_pubkey,
            eve_sig,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        // Eve's ledger entry for (eve_did→bob_did) is zero; she never
        // starred Bob, so the call surfaces NotStarred, not a controller error.
        assert_noop!(
            AgentRegistry::remove_star(RuntimeOrigin::signed(eve), bob_did),
            Error::<Runtime>::NotStarred
        );
    });
}

#[test]
fn remove_star_controller_with_multiple_dids_uses_first() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let signed_at_block = System::block_number();

        // Alice registers two agents under the same controller account.
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

        // Star recorded under alice_did1 (first() of ControllerAgents).
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        assert_ok!(AgentRegistry::remove_star(
            RuntimeOrigin::signed(alice),
            bob_did,
        ));

        // Event must name alice_did1 as giver, not alice_did2.
        System::assert_last_event(
            Event::StarRemoved {
                giver: alice_did1,
                receiver: bob_did,
            }
            .into(),
        );

        // alice_did2 ledger entry must remain untouched (still zero).
        assert_eq!(AgentRegistry::star_givers(alice_did2, bob_did), 0u64);
    });
}
