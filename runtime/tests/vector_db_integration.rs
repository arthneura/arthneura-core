//! Runtime-level integration tests for `pallet-vector-db`.
//!
//! Verifies integration between `pallet-vector-db` and `pallet-agent-registry`
//! using the concrete `Runtime` configuration types.

use frame_support::{assert_err, assert_ok, traits::ConstU32, BoundedVec};
use pallet_agent_registry::pallet::{AgentProfile, AgentProfiles, AgentStatus, QuantumScheme};
use pallet_vector_db::pallet::{Error as VectorDbError, Event as VectorDbEvent, MAX_METADATA_LEN};
use solochain_template_runtime::{AccountId, Runtime, RuntimeEvent, RuntimeOrigin, System, VectorDb};
use sp_keyring::Sr25519Keyring;
use sp_runtime::BuildStorage;

// --- Shared Test Harness ---

/// Builds `TestExternalities` for the concrete `Runtime`, initialized at block 1.
fn new_test_ext() -> sp_io::TestExternalities {
    let storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .expect("frame_system genesis storage should build");
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

/// Generates a deterministic DID for index `n` (first byte set to `n`, remaining zeroed).
fn test_did(n: u8) -> [u8; 32] {
    let mut did = [0u8; 32];
    did[0] = n;
    did
}

/// Generates a deterministic, non-zero Merkle root for index `n` to clear zero-checks.
fn test_merkle_root(n: u8) -> [u8; 32] {
    sp_io::hashing::blake2_256(&[n; 64])
}

fn test_metadata() -> BoundedVec<u8, ConstU32<MAX_METADATA_LEN>> {
    BoundedVec::try_from(b"test-schema-v1".to_vec()).unwrap()
}

/// Constructs a full `AgentProfile<Runtime>` for direct storage seeding.
fn seed_agent(
    did: [u8; 32],
    controller: AccountId,
    status: AgentStatus,
    is_verified: bool,
) -> AgentProfile<Runtime> {
    AgentProfile {
        did,
        controller,
        capabilities: 0,
        reputation_score: 0,
        status,
        registered_at: System::block_number(),
        is_verified,
        quantum_scheme: QuantumScheme::MlDsa65,
        metadata: BoundedVec::default(),
        label: BoundedVec::default(),
    }
}

/// Seeds an active, verified provider-consumer identity pair directly into runtime storage.
fn seed_eligible_pair(provider_idx: u8, consumer_idx: u8) -> ([u8; 32], AccountId, [u8; 32]) {
    let provider_did = test_did(provider_idx);
    let consumer_did = test_did(consumer_idx);
    let provider_account = Sr25519Keyring::Alice.to_account_id();
    let consumer_account = Sr25519Keyring::Bob.to_account_id();

    AgentProfiles::<Runtime>::insert(
        provider_did,
        seed_agent(provider_did, provider_account.clone(), AgentStatus::Active, true),
    );
    AgentProfiles::<Runtime>::insert(
        consumer_did,
        seed_agent(consumer_did, consumer_account, AgentStatus::Active, true),
    );

    (provider_did, provider_account, consumer_did)
}

// --- Happy Path ---

mod happy_path {
    use super::*;

    #[test]
    fn succeeds_and_emits_event() {
        new_test_ext().execute_with(|| {
            let (provider_did, provider_account, consumer_did) = seed_eligible_pair(1, 2);
            let merkle_root = test_merkle_root(1);

            assert_ok!(VectorDb::register_commitment(
                RuntimeOrigin::signed(provider_account),
                provider_did,
                consumer_did,
                merkle_root,
                10,
                test_metadata(),
                100,
            ));

            let emitted = System::events().into_iter().any(|record| {
                matches!(
                    record.event,
                    RuntimeEvent::VectorDb(VectorDbEvent::CommitmentRegistered {
                        provider,
                        consumer,
                        merkle_root: emitted_root,
                        total_chunks: 10,
                        ..
                    }) if provider == provider_did
                        && consumer == consumer_did
                        && emitted_root == merkle_root
                )
            });
            assert!(emitted, "expected a CommitmentRegistered event matching the call");
        });
    }
}

// --- Input Validation ---

mod input_validation {
    use super::*;

    #[test]
    fn fails_on_self_trade() {
        new_test_ext().execute_with(|| {
            let did = test_did(1);
            let caller = Sr25519Keyring::Alice.to_account_id();

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(caller),
                    did,
                    did,
                    test_merkle_root(1),
                    10,
                    test_metadata(),
                    100,
                ),
                VectorDbError::<Runtime>::SelfTrade
            );
        });
    }

    #[test]
    fn fails_on_zero_total_chunks() {
        new_test_ext().execute_with(|| {
            let (provider_did, provider_account, consumer_did) = seed_eligible_pair(1, 2);

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(provider_account),
                    provider_did,
                    consumer_did,
                    test_merkle_root(1),
                    0,
                    test_metadata(),
                    100,
                ),
                VectorDbError::<Runtime>::TotalChunksMustBePositive
            );
        });
    }

    #[test]
    fn fails_on_zero_merkle_root() {
        new_test_ext().execute_with(|| {
            let (provider_did, provider_account, consumer_did) = seed_eligible_pair(1, 2);

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(provider_account),
                    provider_did,
                    consumer_did,
                    [0u8; 32],
                    10,
                    test_metadata(),
                    100,
                ),
                VectorDbError::<Runtime>::InvalidMerkleRoot
            );
        });
    }
}

// --- Provider Eligibility ---

mod provider_eligibility {
    use super::*;

    #[test]
    fn fails_when_provider_unregistered() {
        new_test_ext().execute_with(|| {
            let unregistered_provider_did = test_did(99); 
            let consumer_did = test_did(2);
            let consumer_account = Sr25519Keyring::Bob.to_account_id();

            AgentProfiles::<Runtime>::insert(
                consumer_did,
                seed_agent(consumer_did, consumer_account, AgentStatus::Active, true),
            );

            let caller = Sr25519Keyring::Alice.to_account_id();

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(caller),
                    unregistered_provider_did,
                    consumer_did,
                    test_merkle_root(2),
                    10,
                    test_metadata(),
                    100,
                ),
                VectorDbError::<Runtime>::ProviderNotEligible
            );
        });
    }

    #[test]
    fn fails_when_caller_is_not_provider_controller() {
        new_test_ext().execute_with(|| {
            let (provider_did, _provider_account, consumer_did) = seed_eligible_pair(1, 2);
            let impostor = Sr25519Keyring::Charlie.to_account_id();

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(impostor),
                    provider_did,
                    consumer_did,
                    test_merkle_root(1),
                    10,
                    test_metadata(),
                    100,
                ),
                VectorDbError::<Runtime>::NotProvider
            );
        });
    }

    #[test]
    fn fails_when_provider_suspended() {
        new_test_ext().execute_with(|| {
            let provider_did = test_did(3);
            let consumer_did = test_did(4);
            let provider_account = Sr25519Keyring::Alice.to_account_id();
            let consumer_account = Sr25519Keyring::Bob.to_account_id();

            AgentProfiles::<Runtime>::insert(
                provider_did,
                seed_agent(provider_did, provider_account.clone(), AgentStatus::Suspended, true),
            );
            AgentProfiles::<Runtime>::insert(
                consumer_did,
                seed_agent(consumer_did, consumer_account, AgentStatus::Active, true),
            );

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(provider_account),
                    provider_did,
                    consumer_did,
                    test_merkle_root(3),
                    10,
                    test_metadata(),
                    100,
                ),
                VectorDbError::<Runtime>::ProviderNotEligible
            );
        });
    }

    #[test]
    fn fails_when_provider_revoked() {
        new_test_ext().execute_with(|| {
            let provider_did = test_did(5);
            let consumer_did = test_did(6);
            let provider_account = Sr25519Keyring::Alice.to_account_id();
            let consumer_account = Sr25519Keyring::Bob.to_account_id();

            AgentProfiles::<Runtime>::insert(
                provider_did,
                seed_agent(provider_did, provider_account.clone(), AgentStatus::Revoked, true),
            );
            AgentProfiles::<Runtime>::insert(
                consumer_did,
                seed_agent(consumer_did, consumer_account, AgentStatus::Active, true),
            );

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(provider_account),
                    provider_did,
                    consumer_did,
                    test_merkle_root(4),
                    10,
                    test_metadata(),
                    100,
                ),
                VectorDbError::<Runtime>::ProviderNotEligible
            );
        });
    }

    #[test]
    fn fails_when_provider_unverified() {
        new_test_ext().execute_with(|| {
            let provider_did = test_did(7);
            let consumer_did = test_did(8);
            let provider_account = Sr25519Keyring::Alice.to_account_id();
            let consumer_account = Sr25519Keyring::Bob.to_account_id();

            AgentProfiles::<Runtime>::insert(
                provider_did,
                seed_agent(provider_did, provider_account.clone(), AgentStatus::Active, false),
            );
            AgentProfiles::<Runtime>::insert(
                consumer_did,
                seed_agent(consumer_did, consumer_account, AgentStatus::Active, true),
            );

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(provider_account),
                    provider_did,
                    consumer_did,
                    test_merkle_root(5),
                    10,
                    test_metadata(),
                    100,
                ),
                VectorDbError::<Runtime>::ProviderNotEligible
            );
        });
    }
}

// --- Consumer Eligibility ---

mod consumer_eligibility {
    use super::*;

    #[test]
    fn fails_when_consumer_unregistered() {
        new_test_ext().execute_with(|| {
            let provider_did = test_did(1);
            let unregistered_consumer_did = test_did(98); 
            let provider_account = Sr25519Keyring::Alice.to_account_id();

            AgentProfiles::<Runtime>::insert(
                provider_did,
                seed_agent(provider_did, provider_account.clone(), AgentStatus::Active, true),
            );

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(provider_account),
                    provider_did,
                    unregistered_consumer_did,
                    test_merkle_root(6),
                    10,
                    test_metadata(),
                    100,
                ),
                VectorDbError::<Runtime>::ConsumerNotEligible
            );
        });
    }

    #[test]
    fn fails_when_consumer_suspended() {
        new_test_ext().execute_with(|| {
            let provider_did = test_did(9);
            let consumer_did = test_did(10);
            let provider_account = Sr25519Keyring::Alice.to_account_id();
            let consumer_account = Sr25519Keyring::Bob.to_account_id();

            AgentProfiles::<Runtime>::insert(
                provider_did,
                seed_agent(provider_did, provider_account.clone(), AgentStatus::Active, true),
            );
            AgentProfiles::<Runtime>::insert(
                consumer_did,
                seed_agent(consumer_did, consumer_account, AgentStatus::Suspended, true),
            );

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(provider_account),
                    provider_did,
                    consumer_did,
                    test_merkle_root(7),
                    10,
                    test_metadata(),
                    100,
                ),
                VectorDbError::<Runtime>::ConsumerNotEligible
            );
        });
    }

    #[test]
    fn fails_when_consumer_revoked() {
        new_test_ext().execute_with(|| {
            let provider_did = test_did(11);
            let consumer_did = test_did(12);
            let provider_account = Sr25519Keyring::Alice.to_account_id();
            let consumer_account = Sr25519Keyring::Bob.to_account_id();

            AgentProfiles::<Runtime>::insert(
                provider_did,
                seed_agent(provider_did, provider_account.clone(), AgentStatus::Active, true),
            );
            AgentProfiles::<Runtime>::insert(
                consumer_did,
                seed_agent(consumer_did, consumer_account, AgentStatus::Revoked, true),
            );

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(provider_account),
                    provider_did,
                    consumer_did,
                    test_merkle_root(8),
                    10,
                    test_metadata(),
                    100,
                ),
                VectorDbError::<Runtime>::ConsumerNotEligible
            );
        });
    }

    #[test]
    fn fails_when_consumer_unverified() {
        new_test_ext().execute_with(|| {
            let provider_did = test_did(13);
            let consumer_did = test_did(14);
            let provider_account = Sr25519Keyring::Alice.to_account_id();
            let consumer_account = Sr25519Keyring::Bob.to_account_id();

            AgentProfiles::<Runtime>::insert(
                provider_did,
                seed_agent(provider_did, provider_account.clone(), AgentStatus::Active, true),
            );
            AgentProfiles::<Runtime>::insert(
                consumer_did,
                seed_agent(consumer_did, consumer_account, AgentStatus::Active, false),
            );

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(provider_account),
                    provider_did,
                    consumer_did,
                    test_merkle_root(9),
                    10,
                    test_metadata(),
                    100,
                ),
                VectorDbError::<Runtime>::ConsumerNotEligible
            );
        });
    }
}

// --- Expiry Bounds ---

mod expiry_bounds {
    use super::*;
    use frame_support::traits::Get;

    #[test]
    fn fails_when_expiry_is_zero() {
        new_test_ext().execute_with(|| {
            let (provider_did, provider_account, consumer_did) = seed_eligible_pair(1, 2);

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(provider_account),
                    provider_did,
                    consumer_did,
                    test_merkle_root(1),
                    10,
                    test_metadata(),
                    0,
                ),
                VectorDbError::<Runtime>::ExpiryMustBePositive
            );
        });
    }

    #[test]
    fn fails_when_expiry_exceeds_max_lifetime() {
        new_test_ext().execute_with(|| {
            let (provider_did, provider_account, consumer_did) = seed_eligible_pair(1, 2);
            let max_lifetime: u32 =
                <Runtime as pallet_vector_db::Config>::MaxCommitmentLifetime::get();

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(provider_account),
                    provider_did,
                    consumer_did,
                    test_merkle_root(1),
                    10,
                    test_metadata(),
                    max_lifetime + 1,
                ),
                VectorDbError::<Runtime>::ExpiryTooFar
            );
        });
    }

    #[test]
    fn succeeds_when_expiry_equals_max_lifetime() {
        new_test_ext().execute_with(|| {
            let (provider_did, provider_account, consumer_did) = seed_eligible_pair(1, 2);
            let max_lifetime: u32 =
                <Runtime as pallet_vector_db::Config>::MaxCommitmentLifetime::get();

            assert_ok!(VectorDb::register_commitment(
                RuntimeOrigin::signed(provider_account),
                provider_did,
                consumer_did,
                test_merkle_root(1),
                10,
                test_metadata(),
                max_lifetime,
            ));
        });
    }
}

// --- Idempotency / Duplicate Detection ---

mod idempotency {
    use super::*;

    #[test]
    fn fails_on_duplicate_commitment_in_same_block() {
        new_test_ext().execute_with(|| {
            let (provider_did, provider_account, consumer_did) = seed_eligible_pair(1, 2);
            let merkle_root = test_merkle_root(1);

            assert_ok!(VectorDb::register_commitment(
                RuntimeOrigin::signed(provider_account.clone()),
                provider_did,
                consumer_did,
                merkle_root,
                10,
                test_metadata(),
                100,
            ));

            assert_err!(
                VectorDb::register_commitment(
                    RuntimeOrigin::signed(provider_account),
                    provider_did,
                    consumer_did,
                    merkle_root,
                    10,
                    test_metadata(),
                    100,
                ),
                VectorDbError::<Runtime>::CommitmentAlreadyExists
            );
        });
    }
}