#![cfg_attr(not(feature = "std"), no_std)]

pub use pallet::*;

#[frame_support::pallet]
pub mod pallet {
    use frame_support::pallet_prelude::*;
    use frame_system::pallet_prelude::*;

    // -- Config Trait ---------------------------------------------------------
    #[pallet::config]
    pub trait Config: frame_system::Config {
        /// Event type definition
        type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;
    }

    #[pallet::pallet]
    pub struct Pallet<T>(_);

    // -- Storage Placeholder --------------------------------------------------
    #[pallet::storage]
    pub type DummyStorage<T: Config> = StorageValue<_, u32, ValueQuery>;

    // -- Events ---------------------------------------------------------------
    #[pallet::event]
    #[pallet::generate_deposit(pub(super) fn deposit_event)]
    pub enum Event<T: Config> {
        /// Dummy event to verify transactions
        DummyEvent { value: u32, who: T::AccountId },
    }

    // -- Errors ---------------------------------------------------------------
    #[pallet::error]
    pub enum Error<T> {
        NoneValue,
    }

    // -- Dispatchables (Calls) ------------------------------------------------
    #[pallet::call]
    impl<T: Config> Pallet<T> {
        /// A basic dummy transaction to check pallet registration
        #[pallet::call_index(0)]
        #[pallet::weight(Weight::default())]
        pub fn do_nothing(origin: OriginFor<T>, value: u32) -> DispatchResult {
            let who = ensure_signed(origin)?;
            
            // Storage mein value update karega
            DummyStorage::<T>::put(value);
            
            // Event emit karega
            Self::deposit_event(Event::DummyEvent { value, who });
            
            Ok(())
        }
    }
}