//! Unit tests for `pallet-escrow`.
//!
//! These call `lock`/`release`/`refund` directly as plain Rust
//! functions -- there is no extrinsic, no signed origin, matching how
//! a real caller (e.g. `pallet-vector-db`) will invoke this pallet.

use crate::mock::*;
use crate::pallet::{Error, Event};
use frame_support::assert_noop;

const ESCROW_A: [u8; 32] = [0xAAu8; 32];
const ESCROW_B: [u8; 32] = [0xBBu8; 32];

// --- 1. lock: happy path ---

#[test]
fn lock_reserves_funds_and_creates_record() {
    new_test_ext().execute_with(|| {
        assert_eq!(Balances::free_balance(1), 1_000_000);
        assert_eq!(Balances::reserved_balance(1), 0);

        assert_eq!(Escrow::lock(ESCROW_A, 1, 2, 500), Ok(()));

        assert_eq!(Balances::free_balance(1), 999_500);
        assert_eq!(Balances::reserved_balance(1), 500);

        let record = Escrow::escrow(ESCROW_A).expect("escrow record must exist");
        assert_eq!(record.payer, 1);
        assert_eq!(record.payee, 2);
        assert_eq!(record.amount, 500);
        assert_eq!(record.status, crate::pallet::EscrowStatus::Locked);
    });
}

#[test]
fn lock_emits_correct_event() {
    new_test_ext().execute_with(|| {
        assert_eq!(Escrow::lock(ESCROW_A, 1, 2, 500), Ok(()));

        System::assert_last_event(
            Event::FundsLocked {
                escrow_id: ESCROW_A,
                payer: 1,
                payee: 2,
                amount: 500,
            }
            .into(),
        );
    });
}

// --- 2. lock: error paths ---

#[test]
fn lock_fails_on_insufficient_balance() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Escrow::lock(ESCROW_A, 1, 2, 10_000_000),
            Error::<Runtime>::InsufficientBalanceForEscrow
        );

        // Nothing should have moved on a failed lock.
        assert_eq!(Balances::reserved_balance(1), 0);
        assert!(Escrow::escrow(ESCROW_A).is_none());
    });
}

#[test]
fn lock_fails_on_duplicate_escrow_id() {
    new_test_ext().execute_with(|| {
        assert_eq!(Escrow::lock(ESCROW_A, 1, 2, 500), Ok(()));

        assert_noop!(
            Escrow::lock(ESCROW_A, 1, 3, 200),
            Error::<Runtime>::EscrowAlreadyExists
        );

        // The original record must be untouched by the failed second call.
        let record = Escrow::escrow(ESCROW_A).unwrap();
        assert_eq!(record.payee, 2);
        assert_eq!(record.amount, 500);
    });
}

// --- 3. release: happy path ---

#[test]
fn release_moves_funds_to_payee() {
    new_test_ext().execute_with(|| {
        assert_eq!(Escrow::lock(ESCROW_A, 1, 2, 500), Ok(()));
        assert_eq!(Balances::free_balance(2), 1_000_000);

        assert_eq!(Escrow::release(ESCROW_A), Ok(()));

        assert_eq!(Balances::free_balance(1), 999_500, "payer's free balance stays debited");
        assert_eq!(Balances::reserved_balance(1), 0, "reserve is fully cleared");
        assert_eq!(Balances::free_balance(2), 1_000_500, "payee receives the funds");

        let record = Escrow::escrow(ESCROW_A).unwrap();
        assert_eq!(record.status, crate::pallet::EscrowStatus::Released);
    });
}

#[test]
fn release_emits_correct_event() {
    new_test_ext().execute_with(|| {
        assert_eq!(Escrow::lock(ESCROW_A, 1, 2, 500), Ok(()));
        assert_eq!(Escrow::release(ESCROW_A), Ok(()));

        System::assert_last_event(
            Event::FundsReleased {
                escrow_id: ESCROW_A,
                payer: 1,
                payee: 2,
                amount: 500,
            }
            .into(),
        );
    });
}

// --- 4. release: error paths ---

#[test]
fn release_fails_on_nonexistent_escrow() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Escrow::release(ESCROW_A),
            Error::<Runtime>::EscrowNotFound
        );
    });
}

#[test]
fn release_fails_when_already_released() {
    new_test_ext().execute_with(|| {
        assert_eq!(Escrow::lock(ESCROW_A, 1, 2, 500), Ok(()));
        assert_eq!(Escrow::release(ESCROW_A), Ok(()));

        assert_noop!(
            Escrow::release(ESCROW_A),
            Error::<Runtime>::EscrowNotLocked
        );

        // Balance must not move a second time.
        assert_eq!(Balances::free_balance(2), 1_000_500);
    });
}

#[test]
fn release_fails_when_already_refunded() {
    new_test_ext().execute_with(|| {
        assert_eq!(Escrow::lock(ESCROW_A, 1, 2, 500), Ok(()));
        assert_eq!(Escrow::refund(ESCROW_A), Ok(()));

        assert_noop!(
            Escrow::release(ESCROW_A),
            Error::<Runtime>::EscrowNotLocked
        );
    });
}

// --- 5. refund: happy path ---

#[test]
fn refund_returns_funds_to_payer() {
    new_test_ext().execute_with(|| {
        assert_eq!(Escrow::lock(ESCROW_A, 1, 2, 500), Ok(()));

        assert_eq!(Escrow::refund(ESCROW_A), Ok(()));

        assert_eq!(Balances::free_balance(1), 1_000_000, "payer made whole again");
        assert_eq!(Balances::reserved_balance(1), 0);
        assert_eq!(Balances::free_balance(2), 1_000_000, "payee never received anything");

        let record = Escrow::escrow(ESCROW_A).unwrap();
        assert_eq!(record.status, crate::pallet::EscrowStatus::Refunded);
    });
}

#[test]
fn refund_emits_correct_event() {
    new_test_ext().execute_with(|| {
        assert_eq!(Escrow::lock(ESCROW_A, 1, 2, 500), Ok(()));
        assert_eq!(Escrow::refund(ESCROW_A), Ok(()));

        System::assert_last_event(
            Event::FundsRefunded {
                escrow_id: ESCROW_A,
                payer: 1,
                amount: 500,
            }
            .into(),
        );
    });
}

// --- 6. refund: error paths ---

#[test]
fn refund_fails_on_nonexistent_escrow() {
    new_test_ext().execute_with(|| {
        assert_noop!(
            Escrow::refund(ESCROW_A),
            Error::<Runtime>::EscrowNotFound
        );
    });
}

#[test]
fn refund_fails_when_already_refunded() {
    new_test_ext().execute_with(|| {
        assert_eq!(Escrow::lock(ESCROW_A, 1, 2, 500), Ok(()));
        assert_eq!(Escrow::refund(ESCROW_A), Ok(()));

        assert_noop!(
            Escrow::refund(ESCROW_A),
            Error::<Runtime>::EscrowNotLocked
        );

        // Payer must not be credited a second time.
        assert_eq!(Balances::free_balance(1), 1_000_000);
    });
}

#[test]
fn refund_fails_when_already_released() {
    new_test_ext().execute_with(|| {
        assert_eq!(Escrow::lock(ESCROW_A, 1, 2, 500), Ok(()));
        assert_eq!(Escrow::release(ESCROW_A), Ok(()));

        assert_noop!(
            Escrow::refund(ESCROW_A),
            Error::<Runtime>::EscrowNotLocked
        );
    });
}

// --- 7. Multi-escrow independence ---

#[test]
fn multiple_escrows_are_independent() {
    new_test_ext().execute_with(|| {
        assert_eq!(Escrow::lock(ESCROW_A, 1, 2, 500), Ok(()));
        assert_eq!(Escrow::lock(ESCROW_B, 1, 3, 300), Ok(()));

        assert_eq!(Balances::reserved_balance(1), 800);

        assert_eq!(Escrow::release(ESCROW_A), Ok(()));

        // Releasing A must not touch B.
        let record_b = Escrow::escrow(ESCROW_B).unwrap();
        assert_eq!(record_b.status, crate::pallet::EscrowStatus::Locked);
        assert_eq!(Balances::reserved_balance(1), 300, "only B's amount remains reserved");

        assert_eq!(Escrow::refund(ESCROW_B), Ok(()));
        assert_eq!(Balances::reserved_balance(1), 0);
        assert_eq!(Balances::free_balance(2), 1_000_500, "A's payee kept its release");
        assert_eq!(Balances::free_balance(3), 1_000_000, "B's payee received nothing, correctly");
    });
}
