//! Mock runtime and test environment for `pallet-vector-db`.
//!
//! Decouples identity validation by mocking `AgentLookup` with a thread-local
//! registry, removing compile-time dependencies on `pallet-agent-registry`.

use crate as pallet_vector_db;
use crate::pallet::{CommitmentId, VectorHash, MAX_METADATA_LEN, MAX_PREIMAGE_LEN};
use codec::Encode;
use frame_support::{derive_impl, parameter_types, BoundedVec};
use sp_runtime::BuildStorage;
use std::cell::RefCell;
use std::collections::HashMap;

// ── Mock Runtime Configuration ────────────────────────────────────────────────

type Block = frame_system::mocking::MockBlock<Runtime>;

frame_support::construct_runtime!(
    pub enum Runtime {
        System:   frame_system,
        VectorDb: pallet_vector_db,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Runtime {
    type Block = Block;
}

// ── Thread-Local Mock Agent Registry ─────────────────────────────────────────

// Thread-local state: DID -> (Controller u64, is_active_verified bool).
// Isolated per test thread to prevent parallel execution state leaks.
thread_local! {
    static AGENTS: RefCell<HashMap<[u8; 32], (u64, bool)>> = RefCell::new(HashMap::new());
}

pub struct MockRegistry;

impl crate::AgentLookup<u64> for MockRegistry {
    fn controller_of(did: &[u8; 32]) -> Option<u64> {
        AGENTS.with(|a| a.borrow().get(did).map(|(c, _)| *c))
    }
    fn is_active_verified(did: &[u8; 32]) -> bool {
        AGENTS.with(|a| a.borrow().get(did).map(|(_, v)| *v).unwrap_or(false))
    }
}

/// Registers a test identity in the thread-local mock storage.
/// Set `active_verified` to `false` to simulate suspended, revoked, or unverified states.
pub fn register_test_agent(did: [u8; 32], controller: u64, active_verified: bool) {
    AGENTS.with(|a| {
        a.borrow_mut().insert(did, (controller, active_verified));
    });
}

// Resets the mock registry state before each test run.
fn clear_agents() {
    AGENTS.with(|a| a.borrow_mut().clear());
}

// ── Pallet Configuration ─────────────────────────────────────────────────────

parameter_types! {
    /// Provider dispute response window (10 blocks).
    pub const DisputeWindow: u64 = 10;
    /// Hard ceiling on commitment lifetimes (1,000 blocks).
    pub const MaxCommitmentLifetime: u64 = 1_000;
}

impl pallet_vector_db::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type AgentRegistry = MockRegistry;
    type DisputeWindow = DisputeWindow;
    type MaxCommitmentLifetime = MaxCommitmentLifetime;
}

// ── Test Externalities Builder ───────────────────────────────────────────────

/// Builds `TestExternalities` initialized at block height 1 with a clean registry.
/// Block 1 ensures that events are deposited and queryable (events are ignored at block 0).
pub fn new_test_ext() -> sp_io::TestExternalities {
    clear_agents();
    let storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .unwrap();
    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

// ── Test Helpers ─────────────────────────────────────────────────────────────

/// Generates a deterministic DID for index `n` (first byte set to `n`, remaining zeroed).
pub fn test_did(n: u8) -> [u8; 32] {
    let mut did = [0u8; 32];
    did[0] = n;
    did
}

/// Generates a deterministic `VectorHash` for index `n` via `blake2_256([n; 64])`.
pub fn test_vector_hash(n: u8) -> VectorHash {
    sp_io::hashing::blake2_256(&[n; 64])
}

/// Generates a 64-byte preimage satisfying `blake2_256(preimage) == test_vector_hash(n)`.
pub fn test_preimage(n: u8) -> BoundedVec<u8, frame_support::traits::ConstU32<MAX_PREIMAGE_LEN>> {
    BoundedVec::try_from([n; 64].to_vec()).expect("64 bytes is within MAX_PREIMAGE_LEN (4096)")
}

/// Generates a static dummy metadata vector for testing bounds.
pub fn metadata() -> BoundedVec<u8, frame_support::traits::ConstU32<MAX_METADATA_LEN>> {
    BoundedVec::try_from(b"test-schema-v1".to_vec()).unwrap()
}

/// Deterministically derives a `CommitmentId` mirroring the on-chain logic.
pub fn derive_commitment_id(
    provider: [u8; 32],
    consumer: [u8; 32],
    vector_hash: VectorHash,
    created_at_block: u64,
) -> CommitmentId {
    let mut preimage = b"ArthNeura-Vector-v1".to_vec();
    preimage.extend_from_slice(&provider);
    preimage.extend_from_slice(&consumer);
    preimage.extend_from_slice(&vector_hash);
    preimage.extend_from_slice(&created_at_block.encode());
    sp_io::hashing::blake2_256(&preimage)
}
