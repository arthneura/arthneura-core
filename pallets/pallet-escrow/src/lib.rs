//! # pallet-escrow
//!
//! Generic, reusable escrow for locking, releasing, and refunding funds
//! tied to any commitment-style deal.
//!
//! This pallet knows nothing about commitments, disputes, or data
//! delivery -- it only knows how to hold a payer's funds against an
//! `EscrowId` and, later, either move them to a payee or return them to
//! the payer. Any pallet with a deal that needs money held in the
//! middle (data delivery today; compute jobs, task bounties, or
//! anything else tomorrow) calls into this one rather than
//! implementing its own reserve/release logic.
//!
//! Deliberately NOT extrinsics. Every entry point here is a plain
//! internal function, callable only from trusted runtime code -- there
//! is no signed origin for a caller to spoof, and no direct path for an
//! end user to lock, release, or refund funds without going through the
//! pallet that owns the underlying deal (e.g. `pallet-vector-db`).
//!
//! Unlike `pallet-agent-registry`'s `slash_reputation`, these functions
//! are NOT fire-and-forget. A reputation penalty can silently no-op --
//! it's a punishment, and a punishment failing to land doesn't corrupt
//! anything. Money is different: if a lock fails, the caller's own
//! extrinsic must fail too, or funds could appear to move when they
//! didn't. All three entry points return a `Result`.

#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[cfg(test)]
mod mock;

#[cfg(test)]
mod tests;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::{
        pallet_prelude::*,
        traits::{Currency, ReservableCurrency},
    };
    use frame_system::pallet_prelude::*;

    // -- Types ------------------------------------------------------------

    /// Identifies one escrow record. Callers reuse an ID they already
    /// have (e.g. `pallet-vector-db`'s `commitment_id`) rather than this
    /// pallet minting its own -- there is exactly one escrow per deal,
    /// so no separate ID-generation scheme is needed.
    pub type EscrowId = [u8; 32];

    /// Balance type for `Config::Currency`.
    pub type BalanceOf<T> =
        <<T as Config>::Currency as Currency<<T as frame_system::Config>::AccountId>>::Balance;

    // -- EscrowStatus -------------------------------------------------------

    /// Lifecycle of a single escrow record. `Released` and `Refunded`
    /// are both terminal -- once funds have moved, this record is history,
    /// not a live balance.
    #[derive(
        Clone,
        Copy,
        PartialEq,
        Eq,
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        MaxEncodedLen,
        RuntimeDebug,
    )]
    pub enum EscrowStatus {
        /// Funds are reserved from `payer`, not yet moved.
        Locked,
        /// Funds moved from `payer` to `payee`.
        Released,
        /// Funds returned to `payer`.
        Refunded,
    }

    // -- EscrowRecord ---------------------------------------------------------

    #[derive(
        Clone,
        PartialEq,
        Eq,
        Encode,
        Decode,
        DecodeWithMemTracking,
        TypeInfo,
        MaxEncodedLen,
        RuntimeDebug,
    )]
    #[scale_info(skip_type_params(T))]
    pub struct EscrowRecord<T: Config> {
        pub payer: T::AccountId,
        pub payee: T::AccountId,
        pub amount: BalanceOf<T>,
        pub status: EscrowStatus,
        pub locked_at: BlockNumberFor<T>,
    }

    // -- Config ---------------------------------------------------------------

    #[pallet::config]
    pub trait Config: frame_system::Config {
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
        /// Currency locked/released/refunded by this pallet. Requires
        /// `ReservableCurrency` for `reserve`/`unreserve`/
        /// `repatriate_reserved` -- the same reserve-based pattern
        /// `pallet-agent-registry` uses for its registration deposit.
        type Currency: ReservableCurrency<Self::AccountId>;
    }

    // -- Pallet ---------------------------------------------------------------

    const STORAGE_VERSION: frame_support::traits::StorageVersion =
        frame_support::traits::StorageVersion::new(0);

    #[pallet::pallet]
    #[pallet::storage_version(STORAGE_VERSION)]
    pub struct Pallet<T>(_);

    // -- Storage --------------------------------------------------------------

    /// One record per active or historical escrow. Never pruned on
    /// release/refund -- the terminal record is the audit trail proving
    /// where the funds went.
    #[pallet::storage]
    #[pallet::getter(fn escrow)]
    pub type Escrows<T: Config> =
        StorageMap<_, Blake2_128Concat, EscrowId, EscrowRecord<T>, OptionQuery>;

    // -- Events ---------------------------------------------------------------

    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Funds reserved from `payer` against `escrow_id`.
        FundsLocked {
            escrow_id: EscrowId,
            payer: T::AccountId,
            payee: T::AccountId,
            amount: BalanceOf<T>,
        },
        /// Locked funds moved from `payer` to `payee`.
        FundsReleased {
            escrow_id: EscrowId,
            payer: T::AccountId,
            payee: T::AccountId,
            amount: BalanceOf<T>,
        },
        /// Locked funds returned to `payer`.
        FundsRefunded {
            escrow_id: EscrowId,
            payer: T::AccountId,
            amount: BalanceOf<T>,
        },
    }

    // -- Errors ---------------------------------------------------------------

    #[pallet::error]
    pub enum Error<T> {
        /// An escrow already exists for this `EscrowId`. Each ID is
        /// one-shot -- callers must not reuse an ID across deals.
        EscrowAlreadyExists,
        /// No escrow record exists for this `EscrowId`.
        EscrowNotFound,
        /// The escrow is not in `Locked` state -- already released or
        /// refunded. Both `release` and `refund` require `Locked`.
        EscrowNotLocked,
        /// `payer`'s free balance is below `amount` at lock time.
        InsufficientBalanceForEscrow,
    }

    // -- Internal, non-extrinsic entry points ---------------------------------

    impl<T: Config> Pallet<T> {
        /// Reserves `amount` from `payer` and creates a new `Locked`
        /// escrow record under `escrow_id`. Fails if an escrow already
        /// exists for this ID, or if `payer` can't cover `amount`.
        ///
        /// Callable only from trusted runtime code -- there is no
        /// extrinsic wrapping this, and therefore no origin to spoof.
        pub fn lock(
            escrow_id: EscrowId,
            payer: T::AccountId,
            payee: T::AccountId,
            amount: BalanceOf<T>,
        ) -> DispatchResult {
            ensure!(
                !Escrows::<T>::contains_key(escrow_id),
                Error::<T>::EscrowAlreadyExists
            );

            T::Currency::reserve(&payer, amount)
                .map_err(|_| Error::<T>::InsufficientBalanceForEscrow)?;

            let current_block = <frame_system::Pallet<T>>::block_number();
            Escrows::<T>::insert(
                escrow_id,
                EscrowRecord::<T> {
                    payer: payer.clone(),
                    payee: payee.clone(),
                    amount,
                    status: EscrowStatus::Locked,
                    locked_at: current_block,
                },
            );

            Self::deposit_event(Event::FundsLocked {
                escrow_id,
                payer,
                payee,
                amount,
            });

            Ok(())
        }

        /// Moves the locked funds from `payer` to `payee` via
        /// `repatriate_reserved`, and marks the escrow `Released`.
        /// Requires the escrow to currently be `Locked`.
        pub fn release(escrow_id: EscrowId) -> DispatchResult {
            let mut record = Escrows::<T>::get(escrow_id).ok_or(Error::<T>::EscrowNotFound)?;
            ensure!(
                record.status == EscrowStatus::Locked,
                Error::<T>::EscrowNotLocked
            );

            T::Currency::repatriate_reserved(
                &record.payer,
                &record.payee,
                record.amount,
                frame_support::traits::BalanceStatus::Free,
            )?;

            record.status = EscrowStatus::Released;
            let (payer, payee, amount) =
                (record.payer.clone(), record.payee.clone(), record.amount);
            Escrows::<T>::insert(escrow_id, record);

            Self::deposit_event(Event::FundsReleased {
                escrow_id,
                payer,
                payee,
                amount,
            });

            Ok(())
        }

        /// Returns the locked funds to `payer` via `unreserve`, and
        /// marks the escrow `Refunded`. Requires the escrow to
        /// currently be `Locked`.
        pub fn refund(escrow_id: EscrowId) -> DispatchResult {
            let mut record = Escrows::<T>::get(escrow_id).ok_or(Error::<T>::EscrowNotFound)?;
            ensure!(
                record.status == EscrowStatus::Locked,
                Error::<T>::EscrowNotLocked
            );

            T::Currency::unreserve(&record.payer, record.amount);

            record.status = EscrowStatus::Refunded;
            let (payer, amount) = (record.payer.clone(), record.amount);
            Escrows::<T>::insert(escrow_id, record);

            Self::deposit_event(Event::FundsRefunded {
                escrow_id,
                payer,
                amount,
            });

            Ok(())
        }
    }
}
