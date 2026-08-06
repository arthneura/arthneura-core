//! Brutal, live end-to-end lifecycle test suite for `pallet_agent_registry`.
//! Runs against a real `--dev` node (`ws://127.0.0.1:9944`) — not a mock,
//! not `#[test]` unit logic. Every scenario submits a real signed
//! extrinsic and asserts on the real pallet-level error/success outcome.
//!
//! Deliberately a single sequential test function rather than many
//! `#[tokio::test]` functions: parallel tests sharing dev accounts would
//! race on account nonces. Each section is numbered and independently
//! readable; a failure at section N pinpoints exactly which
//! extrinsic/scenario broke.
//!
//! Known gap: `DidAlreadyRegistered` is not directly testable through the
//! public `register_agent()` client as-is, since every call generates a
//! fresh random keypair (and therefore a fresh DID) — there is no way to
//! force the same DID twice without a lower-level test hook exposing key
//! generation separately from submission. Not exercised here.

use offchain_agent_registry::{
    deregister_agent, give_star, register_agent, remove_star, set_agent_status, update_profile,
    AgentStatus, Did,
};
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::dev;

/// Asserts that a `Result`'s error `Display` output contains the expected
/// on-chain pallet error variant name. Substring match (not exact) because
/// the client wraps errors opaquely as `subxt::Error` -- we don't decode
/// into a typed `Error<T>` enum client-side.
fn assert_pallet_error<T: std::fmt::Debug>(result: Result<T, impl std::fmt::Display>, expected_variant: &str) {
    match result {
        Ok(v) => panic!("expected pallet error '{expected_variant}', got success: {v:?}"),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains(expected_variant),
                "expected error containing '{expected_variant}', got: '{msg}'"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn brutal_lifecycle_suite() {
    let client = OnlineClient::<PolkadotConfig>::from_url("ws://127.0.0.1:9944")
        .await
        .expect("failed to connect to live dev node -- is `docker run ... --dev` up on :9944?");

    let alice = dev::alice();
    let bob = dev::bob();

    // A nonexistent DID -- never registered, used across all DidNotFound checks.
    let unregistered_did: Did = [0xEE; 32];

    // ---------------------------------------------------------------
    // Section 0: Register four agents.
    //   0.1 alice_agent   -- controller alice
    //   0.2 bob_agent     -- controller bob
    //   0.3 alice_agent2  -- controller alice (SAME controller as 0.1,
    //                        needed for CannotStarSameController)
    //   0.4 bob_agent2    -- controller bob, dedicated Revoked-terminal
    //                        target so bob_agent stays untouched
    // ---------------------------------------------------------------
    let alice_agent = register_agent(&client, &alice, 0b1, b"alice profile".to_vec(), b"alice-agent".to_vec())
        .await
        .expect("Section 0.1: alice_agent registration must succeed");
    let alice_agent_did = alice_agent.did;
    println!("Section 0.1 OK: alice_agent_did=0x{}", hex::encode(alice_agent_did));

    let bob_agent = register_agent(&client, &bob, 0b1, b"bob profile".to_vec(), b"bob-agent".to_vec())
        .await
        .expect("Section 0.2: bob_agent registration must succeed");
    let bob_agent_did = bob_agent.did;
    println!("Section 0.2 OK: bob_agent_did=0x{}", hex::encode(bob_agent_did));

    let alice_agent2 = register_agent(&client, &alice, 0b10, b"alice second profile".to_vec(), b"alice-agent-2".to_vec())
        .await
        .expect("Section 0.3: alice_agent2 registration must succeed");
    let alice_agent2_did = alice_agent2.did;
    println!("Section 0.3 OK: alice_agent2_did=0x{}", hex::encode(alice_agent2_did));

    let bob_agent2 = register_agent(&client, &bob, 0b10, b"bob second profile".to_vec(), b"bob-agent-2".to_vec())
        .await
        .expect("Section 0.4: bob_agent2 registration must succeed");
    let bob_agent2_did = bob_agent2.did;
    println!("Section 0.4 OK: bob_agent2_did=0x{}", hex::encode(bob_agent2_did));

    // ---------------------------------------------------------------
    // Section 1 (error): update_profile by a non-controller
    // ---------------------------------------------------------------
    let non_controller_update = update_profile(&client, &bob, alice_agent_did, 0b1, b"hijacked".to_vec(), b"hijacked".to_vec()).await;
    assert_pallet_error(non_controller_update, "NotController");
    println!("Section 1 OK: update_profile by non-controller rejected as expected");

    // ---------------------------------------------------------------
    // Section 2 (error): update_profile on a nonexistent DID
    // ---------------------------------------------------------------
    let ghost_update = update_profile(&client, &alice, unregistered_did, 0b1, b"ghost".to_vec(), b"ghost".to_vec()).await;
    assert_pallet_error(ghost_update, "DidNotFound");
    println!("Section 2 OK: update_profile on nonexistent DID rejected as expected");

    // ---------------------------------------------------------------
    // Section 3 (happy): update_profile by the real controller
    // ---------------------------------------------------------------
    update_profile(&client, &alice, alice_agent_did, 0b11, b"alice updated profile".to_vec(), b"alice-agent-v2".to_vec())
        .await
        .expect("Section 3: update_profile by real controller must succeed");
    println!("Section 3 OK: update_profile by real controller succeeded");

    // ---------------------------------------------------------------
    // Section 4 (happy): set_agent_status -> Suspended
    // ---------------------------------------------------------------
    set_agent_status(&client, &alice, alice_agent_did, AgentStatus::Suspended)
        .await
        .expect("Section 4: set_agent_status to Suspended must succeed");
    println!("Section 4 OK: alice_agent suspended");

    // ---------------------------------------------------------------
    // Section 5 (happy): set_agent_status -> Active (back)
    // ---------------------------------------------------------------
    set_agent_status(&client, &alice, alice_agent_did, AgentStatus::Active)
        .await
        .expect("Section 5: set_agent_status back to Active must succeed");
    println!("Section 5 OK: alice_agent reactivated");

    // ---------------------------------------------------------------
    // Section 6 (error): set_agent_status on a nonexistent DID
    // ---------------------------------------------------------------
    let ghost_status = set_agent_status(&client, &alice, unregistered_did, AgentStatus::Suspended).await;
    assert_pallet_error(ghost_status, "DidNotFound");
    println!("Section 6 OK: set_agent_status on nonexistent DID rejected as expected");

    // ---------------------------------------------------------------
    // Section 7 (error): set_agent_status by a non-controller
    // ---------------------------------------------------------------
    let non_controller_status = set_agent_status(&client, &bob, alice_agent_did, AgentStatus::Suspended).await;
    assert_pallet_error(non_controller_status, "NotController");
    println!("Section 7 OK: set_agent_status by non-controller rejected as expected");

    // ---------------------------------------------------------------
    // Section 8 (happy): give_star alice_agent -> bob_agent (cross-controller)
    // ---------------------------------------------------------------
    give_star(&client, &alice, alice_agent_did, bob_agent_did)
        .await
        .expect("Section 8: give_star cross-controller must succeed");
    println!("Section 8 OK: star given alice_agent -> bob_agent");

    // ---------------------------------------------------------------
    // Section 9 (error): give_star immediate repeat, same pair -- CooldownNotExpired
    // ---------------------------------------------------------------
    let cooldown_result = give_star(&client, &alice, alice_agent_did, bob_agent_did).await;
    assert_pallet_error(cooldown_result, "CooldownNotExpired");
    println!("Section 9 OK: immediate re-star rejected as expected (cooldown)");

    // ---------------------------------------------------------------
    // Section 10 (error): give_star self-star
    // ---------------------------------------------------------------
    let self_star = give_star(&client, &alice, alice_agent_did, alice_agent_did).await;
    assert_pallet_error(self_star, "CannotStarSelf");
    println!("Section 10 OK: self-star rejected as expected");

    // ---------------------------------------------------------------
    // Section 11 (error): give_star to a nonexistent receiver
    // ---------------------------------------------------------------
    let ghost_receiver_star = give_star(&client, &alice, alice_agent_did, unregistered_did).await;
    assert_pallet_error(ghost_receiver_star, "DidNotFound");
    println!("Section 11 OK: give_star to nonexistent receiver rejected as expected");

    // ---------------------------------------------------------------
    // Section 12 (error): give_star same-controller -- alice_agent -> alice_agent2
    // ---------------------------------------------------------------
    let same_controller_star = give_star(&client, &alice, alice_agent_did, alice_agent2_did).await;
    assert_pallet_error(same_controller_star, "CannotStarSameController");
    println!("Section 12 OK: same-controller star rejected as expected");

    // ---------------------------------------------------------------
    // Section 13 (error): give_star by a non-controller claiming someone else's DID
    // ---------------------------------------------------------------
    let non_controller_star = give_star(&client, &bob, alice_agent_did, bob_agent_did).await;
    assert_pallet_error(non_controller_star, "NotController");
    println!("Section 13 OK: give_star with unowned giver_did rejected as expected");

    // ---------------------------------------------------------------
    // Section 14 (happy): remove_star -- removes the star from Section 8
    // ---------------------------------------------------------------
    remove_star(&client, &alice, alice_agent_did, bob_agent_did)
        .await
        .expect("Section 14: remove_star on an existing star must succeed");
    println!("Section 14 OK: star removed alice_agent -> bob_agent");

    // ---------------------------------------------------------------
    // Section 15 (error): remove_star again -- no star exists now
    // ---------------------------------------------------------------
    let no_star = remove_star(&client, &alice, alice_agent_did, bob_agent_did).await;
    assert_pallet_error(no_star, "NotStarred");
    println!("Section 15 OK: remove_star with no existing star rejected as expected");

    // ---------------------------------------------------------------
    // Section 16 (error): remove_star by a non-controller
    // ---------------------------------------------------------------
    let non_controller_remove = remove_star(&client, &bob, alice_agent_did, bob_agent_did).await;
    assert_pallet_error(non_controller_remove, "NotController");
    println!("Section 16 OK: remove_star with unowned giver_did rejected as expected");

    // ---------------------------------------------------------------
    // Section 17 (happy): give_star again immediately after remove_star --
    // confirms remove_star resets the cooldown record to zero.
    // ---------------------------------------------------------------
    give_star(&client, &alice, alice_agent_did, bob_agent_did)
        .await
        .expect("Section 17: give_star immediately after remove_star must succeed (cooldown reset)");
    println!("Section 17 OK: re-star immediately after removal succeeded (cooldown reset confirmed)");

    // ---------------------------------------------------------------
    // Section 18: Revoked-terminal chain, isolated on bob_agent2
    // ---------------------------------------------------------------
    set_agent_status(&client, &bob, bob_agent2_did, AgentStatus::Revoked)
        .await
        .expect("Section 18.1: set_agent_status to Revoked must succeed");
    println!("Section 18.1 OK: bob_agent2 revoked");

    let revoked_status_again = set_agent_status(&client, &bob, bob_agent2_did, AgentStatus::Active).await;
    assert_pallet_error(revoked_status_again, "AgentRevoked");
    println!("Section 18.2 OK: set_agent_status on Revoked profile rejected as expected");

    let revoked_update = update_profile(&client, &bob, bob_agent2_did, 0b1, b"cant touch this".to_vec(), b"nope".to_vec()).await;
    assert_pallet_error(revoked_update, "AgentRevoked");
    println!("Section 18.3 OK: update_profile on Revoked profile rejected as expected");

    let revoked_deregister = deregister_agent(&client, &bob, bob_agent2_did).await;
    assert_pallet_error(revoked_deregister, "AgentAlreadyRevoked");
    println!("Section 18.4 OK: deregister_agent on Revoked profile rejected as expected");

    // ---------------------------------------------------------------
    // Section 19 (error): deregister_agent on a nonexistent DID
    // ---------------------------------------------------------------
    let ghost_deregister = deregister_agent(&client, &alice, unregistered_did).await;
    assert_pallet_error(ghost_deregister, "DidNotFound");
    println!("Section 19 OK: deregister_agent on nonexistent DID rejected as expected");

    // ---------------------------------------------------------------
    // Section 20 (error): deregister_agent by a non-controller
    // ---------------------------------------------------------------
    let non_controller_deregister = deregister_agent(&client, &bob, alice_agent_did).await;
    assert_pallet_error(non_controller_deregister, "NotController");
    println!("Section 20 OK: deregister_agent by non-controller rejected as expected");

    // ---------------------------------------------------------------
    // Section 21 (happy): deregister_agent on a still-Active profile
    // ---------------------------------------------------------------
    deregister_agent(&client, &alice, alice_agent_did)
        .await
        .expect("Section 21: deregister_agent on an Active profile must succeed");
    println!("Section 21 OK: alice_agent deregistered -- deposit unreserved");

    println!("\n=== BRUTAL LIFECYCLE SUITE: ALL 22 SECTIONS PASSED ===");
}
