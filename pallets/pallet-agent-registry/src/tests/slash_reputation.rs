//! Tests for `slash_reputation` and `slash_reputation_for_guilty_delivery`.
//!
//! Both are non-extrinsic `pub fn` methods on `Pallet<T>` — no signed
//! origin, no `DispatchResult`. They are fire-and-forget: they never
//! panic or propagate errors to their caller. Every behavioral guarantee
//! documented in lib.rs is verified here.
//!
//! Mock constants (from mock.rs):
//!   StrikeThreshold       = 3
//!   DepositSlashPerStrike = 20  (burned, not routed to treasury)
//!   RegistrationDeposit   = 100
//!
//! Deposit drain schedule across full cycles:
//!   cycle 1 → 100-20 = 80
//!   cycle 2 →  80-20 = 60
//!   cycle 3 →  60-20 = 40
//!   cycle 4 →  40-20 = 20
//!   cycle 5 →  20-20 =  0
//!   cycle 6 →   0-0  =  0  (amount = 0 in DepositSlashed)

use super::*;

// ── Helpers ──────────────────────────────────────────────────────────────────

/// Register an agent from `seed` under `controller` at block 1.
/// Returns the DID.
fn register(seed: u64, controller: u64) -> Did {
    let (pubkey, sig) = valid_register_params(seed, controller, 1);
    assert_ok!(AgentRegistry::register_agent(
        RuntimeOrigin::signed(controller),
        pubkey.clone(),
        sig,
        1,
        0,
        metadata(),
        label(),
    ));
    derive_did(&pubkey)
}

/// Current `reputation_score` for `did`. Panics if DID not registered.
fn reputation(did: Did) -> u32 {
    AgentRegistry::agent_profile(did)
        .expect("DID not registered")
        .reputation_score
}

/// Current dispute-strike count for `did` (ValueQuery — 0 if never set).
fn strikes(did: Did) -> u32 {
    AgentRegistry::dispute_strikes(did)
}

/// Reserved balance for `account`.
fn reserved(account: u64) -> u64 {
    Balances::reserved_balance(account)
}

/// All events emitted since the last `System::reset_events()`.
fn emitted() -> Vec<RuntimeEvent> {
    System::events().into_iter().map(|r| r.event).collect()
}

/// Assert `ReputationSlashed { did, amount, new_score }` is in the event log.
macro_rules! assert_reputation_slashed {
    ($did:expr, $amount:expr, $new_score:expr) => {
        assert!(
            emitted().contains(&RuntimeEvent::AgentRegistry(Event::ReputationSlashed {
                did: $did,
                amount: $amount,
                new_score: $new_score,
            })),
            "expected ReputationSlashed {{ amount: {}, new_score: {} }}",
            $amount,
            $new_score,
        );
    };
}

/// Assert `DepositSlashed { did, controller, amount, strikes_at_slash }` is
/// in the event log.
macro_rules! assert_deposit_slashed {
    ($did:expr, $controller:expr, $amount:expr, $strikes:expr) => {
        assert!(
            emitted().contains(&RuntimeEvent::AgentRegistry(Event::DepositSlashed {
                did: $did,
                controller: $controller,
                amount: $amount,
                strikes_at_slash: $strikes,
            })),
            "expected DepositSlashed {{ amount: {}, strikes_at_slash: {} }}",
            $amount,
            $strikes,
        );
    };
}

/// Assert no `DepositSlashed` was emitted.
macro_rules! assert_no_deposit_slashed {
    () => {
        for ev in emitted() {
            if let RuntimeEvent::AgentRegistry(Event::DepositSlashed { .. }) = ev {
                panic!("unexpected DepositSlashed event");
            }
        }
    };
}

/// Assert no AgentRegistry event was emitted at all.
macro_rules! assert_no_registry_event {
    () => {
        for ev in emitted() {
            if let RuntimeEvent::AgentRegistry(_) = ev {
                panic!("unexpected AgentRegistry event: {:?}", ev);
            }
        }
    };
}

/// Run `n` full strike cycles (each cycle = StrikeThreshold calls) on `did`.
fn run_cycles(did: &Did, n: u32) {
    for _ in 0..n * 3 {
        AgentRegistry::slash_reputation_for_guilty_delivery(did, 1);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// slash_reputation  (plain — no strike tracking, no deposit impact)
// ═══════════════════════════════════════════════════════════════════════════

/// Basic slash: score decreases and ReputationSlashed fires.
#[test]
fn slash_reputation_works() {
    new_test_ext().execute_with(|| {
        let did_a = register(1, 1);
        let did_b = register(2, 2);

        // Build reputation = 5 via 5 give_star calls (each past cooldown).
        for i in 0..5u64 {
            System::set_block_number(1 + i * 11);
            assert_ok!(AgentRegistry::give_star(
                RuntimeOrigin::signed(2),
                did_b,
                did_a,
            ));
        }
        assert_eq!(reputation(did_a), 5);
        System::reset_events();

        AgentRegistry::slash_reputation(&did_a, 3);

        assert_eq!(reputation(did_a), 2);
        assert_reputation_slashed!(did_a, 3, 2);
    });
}

/// Unknown DID: completely silent — no event, no panic, nothing.
#[test]
fn slash_reputation_did_not_found_is_silent_noop() {
    new_test_ext().execute_with(|| {
        let ghost: Did = [0xde; 32];

        AgentRegistry::slash_reputation(&ghost, 50);

        assert_no_registry_event!();
    });
}

/// Slash larger than current score: saturates at zero, does not underflow.
#[test]
fn slash_reputation_saturates_at_zero() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1); // reputation = 0
        System::reset_events();

        AgentRegistry::slash_reputation(&did, u32::MAX);

        assert_eq!(reputation(did), 0);
        assert_reputation_slashed!(did, u32::MAX, 0);
    });
}

/// Event `amount` field is the *requested* amount, not the actual delta.
/// When score=0 and we request 100, amount=100 (not 0) in the event.
#[test]
fn slash_reputation_event_amount_is_requested_not_actual_delta() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1); // reputation = 0
        System::reset_events();

        AgentRegistry::slash_reputation(&did, 100);

        assert_reputation_slashed!(did, 100, 0);
    });
}

/// Slash exactly equal to current score: lands at exactly zero.
#[test]
fn slash_reputation_exact_to_zero() {
    new_test_ext().execute_with(|| {
        let did_a = register(1, 1);
        let did_b = register(2, 2);

        // Build reputation = 3
        for i in 0..3u64 {
            System::set_block_number(1 + i * 11);
            assert_ok!(AgentRegistry::give_star(
                RuntimeOrigin::signed(2),
                did_b,
                did_a,
            ));
        }
        assert_eq!(reputation(did_a), 3);
        System::reset_events();

        AgentRegistry::slash_reputation(&did_a, 3);

        assert_eq!(reputation(did_a), 0);
        assert_reputation_slashed!(did_a, 3, 0);
    });
}

/// Amount = 0: event still fires and score is unchanged.
/// No special-case guard for zero-amount slashes.
#[test]
fn slash_reputation_zero_amount_emits_event_score_unchanged() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);
        System::reset_events();

        AgentRegistry::slash_reputation(&did, 0);

        assert_eq!(reputation(did), 0);
        assert_reputation_slashed!(did, 0, 0);
    });
}

/// Multiple calls accumulate correctly with correct event per call.
#[test]
fn slash_reputation_accumulates_across_calls() {
    new_test_ext().execute_with(|| {
        let did_a = register(1, 1);
        let did_b = register(2, 2);

        // Build reputation = 10
        for i in 0..10u64 {
            System::set_block_number(1 + i * 11);
            assert_ok!(AgentRegistry::give_star(
                RuntimeOrigin::signed(2),
                did_b,
                did_a,
            ));
        }
        assert_eq!(reputation(did_a), 10);

        AgentRegistry::slash_reputation(&did_a, 3);
        assert_eq!(reputation(did_a), 7);

        AgentRegistry::slash_reputation(&did_a, 3);
        assert_eq!(reputation(did_a), 4);

        AgentRegistry::slash_reputation(&did_a, 3);
        assert_eq!(reputation(did_a), 1);

        // Saturates — does not underflow
        AgentRegistry::slash_reputation(&did_a, 10);
        assert_eq!(reputation(did_a), 0);
    });
}

/// Revoked agent still gets slashed — slash_reputation has no status guard.
/// The profile is kept on-chain after revocation (audit trail), so the
/// slash must reach it.
#[test]
fn slash_reputation_revoked_agent_is_still_slashed() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);
        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(1),
            did,
            AgentStatus::Revoked,
        ));
        System::reset_events();

        AgentRegistry::slash_reputation(&did, 5);

        assert_reputation_slashed!(did, 5, 0);
    });
}

/// Suspended agent still gets slashed — same reasoning as Revoked.
#[test]
fn slash_reputation_suspended_agent_is_still_slashed() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);
        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(1),
            did,
            AgentStatus::Suspended,
        ));
        System::reset_events();

        AgentRegistry::slash_reputation(&did, 5);

        assert_reputation_slashed!(did, 5, 0);
    });
}

/// slash_reputation must never touch DisputeStrikes — that is exclusively
/// the domain of slash_reputation_for_guilty_delivery.
#[test]
fn slash_reputation_never_touches_dispute_strikes() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);

        for _ in 0..100 {
            AgentRegistry::slash_reputation(&did, 1);
        }

        assert_eq!(strikes(did), 0);
    });
}

/// slash_reputation must never touch the registration deposit, even after
/// hundreds of calls.
#[test]
fn slash_reputation_never_touches_deposit() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);
        assert_eq!(reserved(1), 100);
        System::reset_events();

        for _ in 0..100 {
            AgentRegistry::slash_reputation(&did, 1);
        }

        assert_eq!(reserved(1), 100);
        assert_no_deposit_slashed!();
    });
}

// ═══════════════════════════════════════════════════════════════════════════
// slash_reputation_for_guilty_delivery  (strike tracking + deposit slash)
// ═══════════════════════════════════════════════════════════════════════════

/// Basic path: reputation slashed and strike counter incremented, but no
/// deposit slash below threshold.
#[test]
fn slash_reputation_for_guilty_delivery_works_below_threshold() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);
        System::reset_events();

        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 5);

        assert_eq!(strikes(did), 1);
        assert_reputation_slashed!(did, 5, 0);
        assert_no_deposit_slashed!();
    });
}

/// Unknown DID: completely silent — no event, no strike, no panic.
#[test]
fn slash_reputation_for_guilty_delivery_did_not_found_is_silent_noop() {
    new_test_ext().execute_with(|| {
        let ghost: Did = [0xab; 32];

        AgentRegistry::slash_reputation_for_guilty_delivery(&ghost, 10);

        assert_no_registry_event!();
        assert_eq!(strikes(ghost), 0);
    });
}

/// Each call increments the strike counter by exactly 1.
#[test]
fn slash_reputation_for_guilty_delivery_increments_strike_counter_each_call() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);

        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);
        assert_eq!(strikes(did), 1);

        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);
        assert_eq!(strikes(did), 2);
    });
}

/// Two calls (threshold - 1): no deposit slash, deposit fully intact.
#[test]
fn slash_reputation_for_guilty_delivery_below_threshold_no_deposit_slash() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);
        System::reset_events();

        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);
        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);

        assert_eq!(strikes(did), 2);
        assert_eq!(reserved(1), 100); // deposit untouched
        assert_no_deposit_slashed!();
    });
}

/// Third call (exactly at threshold): DepositSlashed fires, deposit reduced.
#[test]
fn slash_reputation_for_guilty_delivery_exactly_at_threshold_fires_deposit_slash() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);

        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);
        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);
        System::reset_events();

        // Exactly at threshold (call 3)
        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);

        assert_deposit_slashed!(did, 1, 20, 3);
        assert_eq!(reserved(1), 80); // 100 - 20
    });
}

/// At threshold: both ReputationSlashed AND DepositSlashed fire in the
/// same call — in that order (slash_reputation is called first internally).
#[test]
fn slash_reputation_for_guilty_delivery_both_events_fire_at_threshold() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);

        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);
        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);
        System::reset_events();

        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);

        let evs = emitted();
        assert!(
            evs.contains(&RuntimeEvent::AgentRegistry(Event::ReputationSlashed {
                did,
                amount: 1,
                new_score: 0,
            })),
            "ReputationSlashed must fire at threshold"
        );
        assert!(
            evs.contains(&RuntimeEvent::AgentRegistry(Event::DepositSlashed {
                did,
                controller: 1,
                amount: 20,
                strikes_at_slash: 3,
            })),
            "DepositSlashed must fire at threshold"
        );
    });
}

/// After the threshold fires, the strike counter resets to 0 so the next
/// cycle requires a full fresh run of StrikeThreshold offenses.
#[test]
fn slash_reputation_for_guilty_delivery_strike_counter_resets_after_threshold() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);

        run_cycles(&did, 1); // 3 calls — threshold fires

        assert_eq!(strikes(did), 0);
    });
}

/// Deposit is actually decremented by DepositSlashPerStrike (20) on threshold.
#[test]
fn slash_reputation_for_guilty_delivery_deposit_decremented_by_slash_amount() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);
        assert_eq!(reserved(1), 100);

        run_cycles(&did, 1);

        assert_eq!(reserved(1), 80);
    });
}

/// After reset, 3 more calls fire the deposit slash again.
#[test]
fn slash_reputation_for_guilty_delivery_second_cycle_fires_again() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);

        run_cycles(&did, 1);
        assert_eq!(reserved(1), 80);
        assert_eq!(strikes(did), 0);

        System::reset_events();
        run_cycles(&did, 1);

        assert_eq!(reserved(1), 60);
        assert_deposit_slashed!(did, 1, 20, 3);
        assert_eq!(strikes(did), 0);
    });
}

/// Five full cycles drain the 100-unit deposit to exactly zero.
/// Strike counter resets cleanly after each cycle.
#[test]
fn slash_reputation_for_guilty_delivery_five_cycles_drain_deposit_to_zero() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);

        for cycle in 1..=5u64 {
            run_cycles(&did, 1);
            let expected = 100u64.saturating_sub(cycle * 20);
            assert_eq!(reserved(1), expected, "after cycle {cycle}");
            assert_eq!(strikes(did), 0, "strikes must reset after cycle {cycle}");
        }

        assert_eq!(reserved(1), 0);
    });
}

/// When deposit is fully depleted, the 6th cycle still fires DepositSlashed
/// but with amount = 0 (slash_reserved returns the full requested amount as
/// unslashable deficit).
#[test]
fn slash_reputation_for_guilty_delivery_deposit_fully_depleted_amount_is_zero_in_event() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);

        // 5 cycles drain the deposit completely
        run_cycles(&did, 5);
        assert_eq!(reserved(1), 0);

        System::reset_events();

        // 6th cycle: threshold fires but nothing to slash
        run_cycles(&did, 1);

        assert_deposit_slashed!(did, 1, 0, 3);
        assert_eq!(reserved(1), 0);
    });
}

/// Strikes are tracked per-DID. Two agents' counters are fully independent.
#[test]
fn slash_reputation_for_guilty_delivery_strikes_isolated_per_did() {
    new_test_ext().execute_with(|| {
        let did_a = register(1, 1);
        let did_b = register(2, 2);

        AgentRegistry::slash_reputation_for_guilty_delivery(&did_a, 1);
        AgentRegistry::slash_reputation_for_guilty_delivery(&did_a, 1);

        assert_eq!(strikes(did_a), 2);
        assert_eq!(strikes(did_b), 0); // B must be completely unaffected
    });
}

/// Plain slash_reputation calls must never count toward the strike threshold,
/// regardless of how many are made. Only slash_reputation_for_guilty_delivery
/// increments strikes.
#[test]
fn slash_reputation_plain_calls_do_not_count_toward_strikes() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);

        // 100 plain reputation slashes — strikes stay at 0, deposit untouched
        for _ in 0..100 {
            AgentRegistry::slash_reputation(&did, 1);
        }
        assert_eq!(strikes(did), 0);
        assert_eq!(reserved(1), 100);

        // Now 2 guilty-delivery slashes — strikes = 2 only
        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);
        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);
        assert_eq!(strikes(did), 2);

        // 3rd guilty-delivery hits threshold — deposit slashed
        System::reset_events();
        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);

        assert_eq!(strikes(did), 0);
        assert_eq!(reserved(1), 80);
        assert_deposit_slashed!(did, 1, 20, 3);
    });
}

/// Revoked agent: no status guard in either slash function.
/// The profile is retained on-chain after revocation, so both the reputation
/// slash and strike tracking must reach it.
#[test]
fn slash_reputation_for_guilty_delivery_revoked_agent_still_slashed() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);
        assert_ok!(AgentRegistry::set_agent_status(
            RuntimeOrigin::signed(1),
            did,
            AgentStatus::Revoked,
        ));
        System::reset_events();

        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 5);

        assert_eq!(strikes(did), 1);
        assert_reputation_slashed!(did, 5, 0);
    });
}

/// Two agents under different controllers: slashing A must not touch B's
/// deposit, reputation, or strikes.
#[test]
fn slash_reputation_for_guilty_delivery_sibling_agent_unaffected() {
    new_test_ext().execute_with(|| {
        let did_a = register(1, 1);
        let did_b = register(2, 2);

        // Hit threshold for A
        run_cycles(&did_a, 1);

        assert_eq!(reserved(1), 80); // A's controller slashed
        assert_eq!(reserved(2), 100); // B's controller untouched
        assert_eq!(strikes(did_b), 0);
        assert_eq!(reputation(did_b), 0);
    });
}

/// Dispute strikes persist through deregister and re-registration of the
/// same DID. deregister_agent does NOT clear DisputeStrikes. This means an
/// agent that re-registers inherits its penalty history.
#[test]
fn slash_reputation_for_guilty_delivery_strikes_carry_over_after_deregister_reregister() {
    new_test_ext().execute_with(|| {
        let (pubkey, sig) = valid_register_params(1, 1, 1);
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(1),
            pubkey.clone(),
            sig,
            1,
            0,
            metadata(),
            label(),
        ));
        let did = derive_did(&pubkey);

        // 2 strikes — one before threshold
        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);
        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);
        assert_eq!(strikes(did), 2);

        // Voluntarily exit — deposit returned, but strikes are NOT cleared
        assert_ok!(AgentRegistry::deregister_agent(
            RuntimeOrigin::signed(1),
            did,
        ));
        assert_eq!(strikes(did), 2); // still 2

        // Re-register with the same DID (same keypair, same block is fine
        // because block_hash(1) is deterministic in the mock)
        let (pubkey2, sig2) = valid_register_params(1, 1, 1);
        assert_ok!(AgentRegistry::register_agent(
            RuntimeOrigin::signed(1),
            pubkey2,
            sig2,
            1,
            0,
            metadata(),
            label(),
        ));

        // Inherited strikes = 2 — one more call triggers threshold immediately
        assert_eq!(strikes(did), 2);
        System::reset_events();

        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 1);

        assert_eq!(strikes(did), 0); // reset
        assert_deposit_slashed!(did, 1, 20, 3); // deposit slashed
    });
}

/// Multiple agents under the same controller: slashing one DID must not
/// affect the strikes or reputation of the other DIDs owned by that
/// controller.
#[test]
fn slash_reputation_for_guilty_delivery_same_controller_two_dids_isolated() {
    new_test_ext().execute_with(|| {
        let did_a = register(1, 1); // controller 1, agent A
        let did_b = register(2, 1); // controller 1, agent B — different seed

        // Hammer A close to threshold
        AgentRegistry::slash_reputation_for_guilty_delivery(&did_a, 1);
        AgentRegistry::slash_reputation_for_guilty_delivery(&did_a, 1);

        assert_eq!(strikes(did_a), 2);
        assert_eq!(strikes(did_b), 0); // B isolated even though same controller
    });
}

/// Zero amount: event fires (ReputationSlashed with amount=0) and strike
/// is still incremented. Threshold can still be reached.
#[test]
fn slash_reputation_for_guilty_delivery_zero_amount_still_tracks_strikes() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);

        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 0);
        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 0);
        System::reset_events();

        // Third zero-amount call still hits threshold
        AgentRegistry::slash_reputation_for_guilty_delivery(&did, 0);

        assert_eq!(strikes(did), 0); // reset
        assert_deposit_slashed!(did, 1, 20, 3);
    });
}

/// strikes_at_slash in DepositSlashed is always exactly StrikeThreshold (3)
/// because the counter is incremented to threshold before the event fires.
#[test]
fn slash_reputation_for_guilty_delivery_strikes_at_slash_is_always_threshold() {
    new_test_ext().execute_with(|| {
        let did = register(1, 1);

        // Multiple cycles — every DepositSlashed must report strikes_at_slash = 3
        for _ in 0..3 {
            run_cycles(&did, 1);
        }

        for ev in emitted() {
            if let RuntimeEvent::AgentRegistry(Event::DepositSlashed {
                strikes_at_slash, ..
            }) = ev
            {
                assert_eq!(
                    strikes_at_slash, 3,
                    "strikes_at_slash must always equal StrikeThreshold"
                );
            }
        }
    });
}
