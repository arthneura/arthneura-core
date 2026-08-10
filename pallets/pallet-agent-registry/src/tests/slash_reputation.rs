//! Unit tests for `Pallet::slash_reputation` — a non-extrinsic,
//! internal-only function invoked by trusted protocol-level callers
//! (currently: pallet-vector-db's dispute resolution, via the
//! `ReputationHandler` hook wired in the runtime). Unlike every other
//! test in this suite, these calls never go through `RuntimeOrigin` —
//! there is no origin to check, since the caller is meant to be the
//! trusted runtime itself, not an end user.

use super::*;

/// Registers a single agent (controller = account 1) and returns its DID.
fn register_test_agent() -> Did {
    let alice = 1u64;
    let signed_at_block = System::block_number();
    let (pubkey, sig) = valid_register_params(1, alice, signed_at_block);
    let did = derive_did(&pubkey);

    assert_ok!(AgentRegistry::register_agent(
        RuntimeOrigin::signed(alice),
        pubkey,
        sig,
        signed_at_block,
        CAP_DATA_PROVIDER,
        metadata(),
        label(),
    ));

    did
}

// --- 1. Happy Path: Decrements Reputation ---

#[test]
fn slash_reputation_decrements_score() {
    new_test_ext().execute_with(|| {
        let did = register_test_agent();

        crate::pallet::AgentProfiles::<Runtime>::mutate(did, |maybe_profile| {
            if let Some(profile) = maybe_profile {
                profile.reputation_score = 10;
            }
        });

        AgentRegistry::slash_reputation(&did, 3);

        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.reputation_score, 7);
    });
}

// --- 2. Saturating: Never Underflows Below Zero ---

#[test]
fn slash_reputation_saturates_at_zero() {
    new_test_ext().execute_with(|| {
        let did = register_test_agent();

        crate::pallet::AgentProfiles::<Runtime>::mutate(did, |maybe_profile| {
            if let Some(profile) = maybe_profile {
                profile.reputation_score = 1;
            }
        });

        AgentRegistry::slash_reputation(&did, 5);

        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(
            profile.reputation_score, 0,
            "slash_reputation must saturate at zero, never underflow/wrap a u32"
        );
    });
}

// --- 3. Event Emission on Success ---

#[test]
fn slash_reputation_emits_correct_event() {
    new_test_ext().execute_with(|| {
        let did = register_test_agent();

        crate::pallet::AgentProfiles::<Runtime>::mutate(did, |maybe_profile| {
            if let Some(profile) = maybe_profile {
                profile.reputation_score = 10;
            }
        });

        AgentRegistry::slash_reputation(&did, 4);

        System::assert_last_event(
            Event::ReputationSlashed {
                did,
                amount: 4,
                new_score: 6,
            }
            .into(),
        );
    });
}

// --- 4. Fail-Safe: Silent No-Op on Unregistered DID ---

#[test]
fn slash_reputation_noop_on_unregistered_did() {
    new_test_ext().execute_with(|| {
        let ghost_did = derive_did(&pubkey_bytes(&generate_keypair(999).verifying_key));
        System::reset_events();

        // Must not panic. Must not emit any event, since there was no
        // profile to slash — the whole point is that a caller (like a
        // permissionless finalize_dispute) can never be blocked by this.
        AgentRegistry::slash_reputation(&ghost_did, 5);

        assert_eq!(
            System::events().len(),
            0,
            "slash_reputation on an unregistered DID must emit no event"
        );
    });
}

// --- 5. Zero-Amount Slash Is a Valid No-Op (Still Emits Event) ---

#[test]
fn slash_reputation_zero_amount_leaves_score_unchanged_but_still_emits() {
    new_test_ext().execute_with(|| {
        let did = register_test_agent();

        crate::pallet::AgentProfiles::<Runtime>::mutate(did, |maybe_profile| {
            if let Some(profile) = maybe_profile {
                profile.reputation_score = 3;
            }
        });

        AgentRegistry::slash_reputation(&did, 0);

        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.reputation_score, 3);

        System::assert_last_event(
            Event::ReputationSlashed {
                did,
                amount: 0,
                new_score: 3,
            }
            .into(),
        );
    });
}

// --- 6. Does Not Touch Unrelated Agents ---

#[test]
fn slash_reputation_only_affects_the_targeted_did() {
    new_test_ext().execute_with(|| {
        let alice_did = register_test_agent();

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

        crate::pallet::AgentProfiles::<Runtime>::mutate(alice_did, |p| {
            if let Some(profile) = p {
                profile.reputation_score = 10;
            }
        });
        crate::pallet::AgentProfiles::<Runtime>::mutate(bob_did, |p| {
            if let Some(profile) = p {
                profile.reputation_score = 10;
            }
        });

        AgentRegistry::slash_reputation(&alice_did, 5);

        assert_eq!(
            AgentRegistry::agent_profile(alice_did).unwrap().reputation_score,
            5
        );
        assert_eq!(
            AgentRegistry::agent_profile(bob_did).unwrap().reputation_score,
            10,
            "slashing alice's DID must not touch bob's untouched profile"
        );
    });
}
