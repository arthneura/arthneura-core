use super::*;
use crate::pallet::AgentProfiles;

// -- Local helper -------------------------------------------------------------
// Registers one agent from `seed` + `controller` and returns its DID.
fn register(seed: u64, controller: u64) -> Did {
    let signed_at_block = System::block_number();
    let (pubkey, signature) = valid_register_params(seed, controller, signed_at_block);
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
    did
}

// -- Happy paths --------------------------------------------------------------

#[test]
fn deregister_agent_works() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        assert!(AgentRegistry::agent_profile(did).is_none()); // slot gone, not tombstoned
        assert!(!AgentRegistry::controller_agents(controller).contains(&did)); // reverse-index pruned
        assert_eq!(AgentRegistry::active_agent_count(), 0); // counter at zero
        System::assert_last_event(
            Event::AgentDeregistered { did, controller }.into(),
        );
    });
}

#[test]
fn deregister_agent_suspended_works() {
    // Suspended is not terminal — voluntary exit must succeed.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Suspended,
        ));

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        assert!(AgentRegistry::agent_profile(did).is_none());
        assert_eq!(AgentRegistry::active_agent_count(), 0);
    });
}

#[test]
fn deregister_agent_deposit_returned_to_controller() {
    // RegistrationDeposit moves from reserved back to free in full.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        let free_after_register = Balances::free_balance(controller);
        assert_eq!(Balances::reserved_balance(controller), 100u64); // deposit locked

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        assert_eq!(Balances::reserved_balance(controller), 0u64);
        assert_eq!(Balances::free_balance(controller), free_after_register + 100u64);
    });
}

#[test]
fn deregister_agent_profile_slot_fully_removed() {
    // AgentProfiles::remove is used — contains_key returns false after deregistration.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        assert!(!AgentProfiles::<Runtime>::contains_key(did));
    });
}

#[test]
fn deregister_agent_removes_did_from_controller_index() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert!(AgentRegistry::controller_agents(controller).contains(&did));

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        assert!(!AgentRegistry::controller_agents(controller).contains(&did));
    });
}

#[test]
fn deregister_agent_decrements_active_count() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);
        assert_eq!(AgentRegistry::active_agent_count(), 1);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        assert_eq!(AgentRegistry::active_agent_count(), 0);
    });
}

#[test]
fn deregister_agent_emits_correct_event() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        System::assert_last_event(
            Event::AgentDeregistered { did, controller }.into(),
        );
    });
}

#[test]
fn deregister_agent_sibling_did_unaffected() {
    // Deregistering one DID leaves sibling DIDs intact in both indexes.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did1 = register(1, controller);
        let did2 = register(2, controller);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did1,
        ));

        assert!(AgentRegistry::agent_profile(did1).is_none());
        assert!(!AgentRegistry::controller_agents(controller).contains(&did1));
        assert!(AgentRegistry::agent_profile(did2).is_some()); // did2 intact
        assert!(AgentRegistry::controller_agents(controller).contains(&did2));
        assert_eq!(AgentRegistry::active_agent_count(), 1); // decremented once
    });
}

#[test]
fn deregister_agent_sibling_did_deposit_independent() {
    // Each deposit is independent — deregistering one DID unreserves exactly one deposit.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        register(1, controller);
        let did2 = register(2, controller);

        assert_eq!(Balances::reserved_balance(controller), 200u64); // both deposits locked

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did2,
        ));

        assert_eq!(Balances::reserved_balance(controller), 100u64); // sibling still locked
    });
}

#[test]
fn deregister_agent_allows_reregistration_of_same_did() {
    // Slot removal allows immediate re-registration of the same DID.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        let signed_at_block = System::block_number();
        let (pubkey, signature) = valid_register_params(1, controller, signed_at_block);
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            pubkey,
            signature,
            signed_at_block,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert!(AgentRegistry::agent_profile(did).is_some());
        assert_eq!(AgentRegistry::active_agent_count(), 1);
    });
}

#[test]
fn deregister_agent_count_with_multiple_agents_decrements_per_call() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did1 = register(1, controller);
        let did2 = register(2, controller);
        let did3 = register(3, controller);
        assert_eq!(AgentRegistry::active_agent_count(), 3);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did1,
        ));
        assert_eq!(AgentRegistry::active_agent_count(), 2);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did2,
        ));
        assert_eq!(AgentRegistry::active_agent_count(), 1);

        assert!(AgentRegistry::agent_profile(did3).is_some()); // did3 untouched
    });
}

#[test]
fn deregister_agent_suspended_deposit_returned() {
    // Suspended agents receive a full deposit refund on voluntary exit.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Suspended,
        ));

        assert_eq!(Balances::reserved_balance(controller), 100u64);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        assert_eq!(Balances::reserved_balance(controller), 0u64);
    });
}

// -- Error paths --------------------------------------------------------------

#[test]
fn deregister_agent_unsigned_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert_noop!(
            AgentRegistry::deregister_agent(RuntimeOrigin::none(), did),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn deregister_agent_did_not_found_fails() {
    new_test_ext().execute_with(|| {
        let never_registered = derive_did(&pubkey_bytes(&generate_keypair(999).verifying_key));

        assert_noop!(
            AgentRegistry::deregister_agent(
                RuntimeOrigin::signed(1u64),
                never_registered,
            ),
            Error::<Runtime>::DidNotFound
        );
    });
}

#[test]
fn deregister_agent_not_controller_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let attacker = 2u64;
        let did = register(1, controller);

        assert_noop!(
            AgentRegistry::deregister_agent(
                RuntimeOrigin::signed(attacker),
                did,
            ),
            Error::<Runtime>::NotController
        );

        assert!(AgentRegistry::agent_profile(did).is_some()); // profile untouched
        assert_eq!(AgentRegistry::active_agent_count(), 1);
    });
}

#[test]
fn deregister_agent_revoked_fails() {
    // Revoked is terminal — deregistration rejected, AgentAlreadyRevoked returned.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Revoked,
        ));

        assert_noop!(
            AgentRegistry::deregister_agent(
                RuntimeOrigin::signed(controller),
                did,
            ),
            Error::<Runtime>::AgentAlreadyRevoked
        );
    });
}

#[test]
fn deregister_agent_revoked_profile_retained_on_chain() {
    // Failed deregister on a Revoked agent must not disturb the audit trail.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Revoked,
        ));

        let _ = AgentRegistry::deregister_agent(RuntimeOrigin::signed(controller), did);

        assert!(AgentRegistry::agent_profile(did).is_some());
        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.status, AgentStatus::Revoked);
    });
}

#[test]
fn deregister_agent_revoked_deposit_not_returned() {
    // No partial unreserve on the error path — deposit stays locked for Revoked agents.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        let reserved_before = Balances::reserved_balance(controller);

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Revoked,
        ));

        let _ = AgentRegistry::deregister_agent(RuntimeOrigin::signed(controller), did);

        assert_eq!(Balances::reserved_balance(controller), reserved_before);
    });
}

#[test]
fn deregister_agent_suspend_then_revoke_cannot_deregister() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Suspended,
        ));
        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Revoked,
        ));

        assert_noop!(
            AgentRegistry::deregister_agent(
                RuntimeOrigin::signed(controller),
                did,
            ),
            Error::<Runtime>::AgentAlreadyRevoked
        );
    });
}

// -- Error ordering -----------------------------------------------------------

#[test]
fn deregister_agent_did_not_found_precedes_not_controller_check() {
    // Step ordering: DidNotFound (step 2) surfaces before NotController (step 3).
    new_test_ext().execute_with(|| {
        let attacker = 2u64;
        let never_registered = derive_did(&pubkey_bytes(&generate_keypair(999).verifying_key));

        assert_noop!(
            AgentRegistry::deregister_agent(
                RuntimeOrigin::signed(attacker),
                never_registered,
            ),
            Error::<Runtime>::DidNotFound
        );
    });
}

#[test]
fn deregister_agent_not_controller_precedes_revoked_check() {
    // Step ordering: NotController (step 3) surfaces before AgentAlreadyRevoked (step 4).
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let attacker = 2u64;
        let did = register(1, controller);

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Revoked,
        ));

        assert_noop!(
            AgentRegistry::deregister_agent(
                RuntimeOrigin::signed(attacker),
                did,
            ),
            Error::<Runtime>::NotController
        );
    });
}

// -- Double call / idempotency ------------------------------------------------

#[test]
fn deregister_agent_double_deregister_fails_with_did_not_found() {
    // Second call on the same DID hits DidNotFound — slot is gone after first deregister.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        assert_noop!(
            AgentRegistry::deregister_agent(
                RuntimeOrigin::signed(controller),
                did,
            ),
            Error::<Runtime>::DidNotFound
        );
    });
}

// -- Attacker scenarios -------------------------------------------------------

#[test]
fn deregister_agent_registered_attacker_cannot_deregister_others() {
    // Registered attacker cannot deregister a foreign DID.
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let alice_did = register(1, alice);
        register(2, bob);

        assert_noop!(
            AgentRegistry::deregister_agent(
                RuntimeOrigin::signed(bob),
                alice_did,
            ),
            Error::<Runtime>::NotController
        );

        assert!(AgentRegistry::agent_profile(alice_did).is_some());
        assert_eq!(AgentRegistry::active_agent_count(), 2);
    });
}

#[test]
fn deregister_agent_controller_cannot_use_wrong_did_to_deregister_sibling() {
    // Owning other DIDs does not grant rights over a foreign DID.
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let alice_did = register(1, alice);
        register(2, alice); // alice controls two DIDs

        let bob_did = register(3, bob);

        assert_noop!(
            AgentRegistry::deregister_agent(
                RuntimeOrigin::signed(alice),
                bob_did,
            ),
            Error::<Runtime>::NotController
        );

        assert!(AgentRegistry::agent_profile(bob_did).is_some());
        assert!(AgentRegistry::agent_profile(alice_did).is_some());
        assert_eq!(AgentRegistry::active_agent_count(), 3);
    });
}

// -- Balance precision --------------------------------------------------------

#[test]
fn deregister_agent_exact_balance_accounting() {
    // Full balance lifecycle: initial → post-register → post-deregister.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let initial_free = Balances::free_balance(controller);
        let initial_reserved = Balances::reserved_balance(controller);
        assert_eq!(initial_reserved, 0u64);

        let did = register(1, controller);

        assert_eq!(Balances::reserved_balance(controller), 100u64); // deposit locked
        assert_eq!(Balances::free_balance(controller), initial_free - 100u64);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        assert_eq!(Balances::free_balance(controller), initial_free); // fully restored
        assert_eq!(Balances::reserved_balance(controller), 0u64);
    });
}

#[test]
fn deregister_agent_multi_agent_deposit_accounting() {
    // Each deregister unreserves exactly one deposit; two removed → one deposit remains.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let initial_free = Balances::free_balance(controller);

        let did1 = register(1, controller);
        let did2 = register(2, controller);
        let _did3 = register(3, controller);

        assert_eq!(Balances::reserved_balance(controller), 300u64);
        assert_eq!(Balances::free_balance(controller), initial_free - 300u64);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did1,
        ));
        assert_eq!(Balances::reserved_balance(controller), 200u64);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did2,
        ));
        assert_eq!(Balances::reserved_balance(controller), 100u64);
        assert_eq!(Balances::free_balance(controller), initial_free - 100u64);
    });
}

// -- Storage invariants -------------------------------------------------------

#[test]
fn deregister_agent_controller_index_empty_after_last_did_removed() {
    // ControllerAgents vec is empty after the last DID is removed.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        assert!(AgentRegistry::controller_agents(controller).is_empty());
    });
}

#[test]
fn deregister_agent_all_fields_cleared() {
    // No partial stub left in the primary index after deregistration.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        let profile_before = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile_before.controller, controller);
        assert!(profile_before.is_verified);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        assert!(AgentRegistry::agent_profile(did).is_none());
    });
}

#[test]
fn deregister_agent_active_count_not_below_zero() {
    // ActiveAgentCount saturating_sub cannot underflow to u32::MAX.
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = register(1, controller);

        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(controller),
            did,
        ));

        assert_eq!(AgentRegistry::active_agent_count(), 0u32);
        assert_ne!(AgentRegistry::active_agent_count(), u32::MAX);
    });
}
