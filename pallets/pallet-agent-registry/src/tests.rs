//! Unit tests for pallet-agent-registry.

use crate::mock::*;
use crate::pallet::{
    AgentStatus, CapabilityBitmap, Error, Event, CAP_DATA_PROVIDER, CAP_INFERENCE_ENGINE,
    MAX_LABEL_LEN, MAX_METADATA_LEN,
};
use frame_support::{assert_noop, assert_ok, BoundedVec};
use sp_runtime::DispatchError;

// -- Helpers ------------------------------------------------------------------

fn did(seed: u8) -> [u8; 32] {
    [seed; 32]
}

fn metadata() -> BoundedVec<u8, frame_support::traits::ConstU32<MAX_METADATA_LEN>> {
    BoundedVec::default()
}

fn label() -> BoundedVec<u8, frame_support::traits::ConstU32<MAX_LABEL_LEN>> {
    BoundedVec::default()
}

// -- register_agent -----------------------------------------------------------

#[test]
fn register_agent_works() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = did(1);
        let caps = CAP_DATA_PROVIDER | CAP_INFERENCE_ENGINE;

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            did,
            caps,
            metadata(),
            label(),
        ));

        // Profile stored correctly
        let profile = AgentRegistry::agent_profile(did).unwrap();
        assert_eq!(profile.controller, controller);
        assert_eq!(profile.capabilities, caps);
        assert_eq!(profile.reputation_score, 0);
        assert_eq!(profile.status, AgentStatus::Active);

        // Reverse index updated
        let dids = AgentRegistry::controller_agents(controller);
        assert_eq!(dids.len(), 1);
        assert_eq!(dids[0], did);

        // Counter incremented
        assert_eq!(AgentRegistry::active_agent_count(), 1);

        // Event emitted
        System::assert_last_event(Event::AgentRegistered { did, controller }.into());
    });
}

#[test]
fn register_agent_duplicate_did_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = did(1);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            did,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                did,
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::DidAlreadyRegistered
        );
    });
}

#[test]
fn register_agent_unsigned_fails() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::none(),
                did(1),
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            DispatchError::BadOrigin
        );
    });
}

#[test]
fn register_agent_too_many_agents_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;

        // Register 64 agents
        for i in 0..64u8 {
            assert_ok!(AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                did(i),
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ));
        }

        // 65th must fail
        assert_noop!(
            AgentRegistry::register_agent(
                RuntimeOrigin::signed(controller),
                did(64),
                CAP_DATA_PROVIDER,
                metadata(),
                label(),
            ),
            Error::<Runtime>::TooManyAgentsForController
        );
    });
}

// -- update_profile -----------------------------------------------------------

#[test]
fn update_profile_works() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = did(1);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            did,
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
        let did = did(1);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            did,
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
        assert_noop!(
            AgentRegistry::update_profile(
                RuntimeOrigin::signed(1u64),
                did(99),
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
        let did = did(1);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            did,
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

// -- set_agent_status ---------------------------------------------------------

#[test]
fn set_agent_status_suspend_works() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = did(1);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            did,
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

        // Counter should NOT decrement on suspend
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
        let did = did(1);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            did,
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

        // Counter must decrement on revoke
        assert_eq!(AgentRegistry::active_agent_count(), 0);
    });
}

#[test]
fn set_agent_status_revoked_terminal_fails() {
    new_test_ext().execute_with(|| {
        let controller = 1u64;
        let did = did(1);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            did,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(controller),
            did,
            AgentStatus::Revoked,
        ));

        // Cannot transition out of Revoked
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
        let did = did(1);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(controller),
            did,
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

// -- give_star / remove_star --------------------------------------------------

#[test]
fn give_star_works() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let alice_did = did(1);
        let bob_did = did(2);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_did,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(bob),
            bob_did,
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
        let alice_did = did(1);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_did,
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
        let alice_did = did(1);
        let bob_did = did(2);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_did,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(bob),
            bob_did,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        // First star — ok
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did
        ));

        // Immediate re-star — cooldown not expired
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
        let alice_did = did(1);
        let bob_did = did(2);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_did,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(bob),
            bob_did,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        // Star at block 1
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did
        ));

        // Advance past cooldown (10 blocks in mock)
        System::set_block_number(12);

        // Re-star after cooldown — ok
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did
        ));

        let profile = AgentRegistry::agent_profile(bob_did).unwrap();
        assert_eq!(profile.reputation_score, 2);
    });
}

#[test]
fn remove_star_works() {
    new_test_ext().execute_with(|| {
        let alice = 1u64;
        let bob = 2u64;
        let alice_did = did(1);
        let bob_did = did(2);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_did,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(bob),
            bob_did,
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
        let alice_did = did(1);
        let bob_did = did(2);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_did,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(bob),
            bob_did,
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
        let alice_did = did(1);
        let bob_did = did(2);

        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(alice),
            alice_did,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(bob),
            bob_did,
            CAP_DATA_PROVIDER,
            metadata(),
            label(),
        ));

        // Give star
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did
        ));

        // Remove star — resets to zero
        assert_ok!(AgentRegistry::remove_star(
            RuntimeOrigin::signed(alice),
            bob_did
        ));

        // Re-star immediately — should succeed since zero means never starred
        assert_ok!(AgentRegistry::give_star(
            RuntimeOrigin::signed(alice),
            bob_did
        ));

        let profile = AgentRegistry::agent_profile(bob_did).unwrap();
        assert_eq!(profile.reputation_score, 1);
    });
}
