//! Mock runtime and test environment for `pallet-vector-db`.
//!
//! Decouples identity validation by mocking `AgentLookup` with a thread-local
//! registry, removing compile-time dependencies on `pallet-agent-registry`.

use crate as pallet_vector_db;
use crate::pallet::{CommitmentId, MerkleRoot, MAX_METADATA_LEN};
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
        Balances: pallet_balances,
        VectorDb: pallet_vector_db,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Runtime {
    type Block = Block;
    type AccountData = pallet_balances::AccountData<u64>;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Runtime {
    type AccountStore = System;
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

thread_local! {
    static REPUTATION_CALLS: RefCell<Vec<([u8; 32], &'static str)>> = RefCell::new(Vec::new());
}

pub struct MockReputationHandler;

impl crate::ReputationHandler for MockReputationHandler {
    fn penalize_provider(did: &[u8; 32]) {
        REPUTATION_CALLS.with(|c| c.borrow_mut().push((*did, "provider")));
    }
    fn penalize_false_disputer(did: &[u8; 32]) {
        REPUTATION_CALLS.with(|c| c.borrow_mut().push((*did, "false_disputer")));
    }
}

pub fn reputation_calls() -> Vec<([u8; 32], &'static str)> {
    REPUTATION_CALLS.with(|c| c.borrow().clone())
}

fn clear_reputation_calls() {
    REPUTATION_CALLS.with(|c| c.borrow_mut().clear());
}

// ── Mock Escrow Handler ──────────────────────────────────────────────────────

// Records every EscrowHandler call, in order, so tests can assert exactly
// which operation fired with which arguments -- without a real
// pallet-escrow dependency in this crate's test build.
#[derive(Clone, Debug, PartialEq)]
pub enum EscrowCall {
    Lock { escrow_id: [u8; 32], payer: u64, payee: u64, amount: u64 },
    Release { escrow_id: [u8; 32] },
    Refund { escrow_id: [u8; 32] },
}

thread_local! {
    static ESCROW_CALLS: RefCell<Vec<EscrowCall>> = RefCell::new(Vec::new());
    // Controls whether the next `lock` call succeeds -- lets tests
    // simulate an insufficient-balance rejection without needing a
    // real Currency implementation behind this mock.
    static ESCROW_LOCK_SHOULD_FAIL: RefCell<bool> = RefCell::new(false);
}

pub struct MockEscrowHandler;

impl crate::EscrowHandler<u64, u64> for MockEscrowHandler {
    fn lock(escrow_id: [u8; 32], payer: u64, payee: u64, amount: u64) -> sp_runtime::DispatchResult {
        if ESCROW_LOCK_SHOULD_FAIL.with(|f| *f.borrow()) {
            return Err(sp_runtime::DispatchError::Other("mock escrow lock failure"));
        }
        ESCROW_CALLS.with(|c| c.borrow_mut().push(EscrowCall::Lock { escrow_id, payer, payee, amount }));
        Ok(())
    }
    fn release(escrow_id: [u8; 32]) -> sp_runtime::DispatchResult {
        ESCROW_CALLS.with(|c| c.borrow_mut().push(EscrowCall::Release { escrow_id }));
        Ok(())
    }
    fn refund(escrow_id: [u8; 32]) -> sp_runtime::DispatchResult {
        ESCROW_CALLS.with(|c| c.borrow_mut().push(EscrowCall::Refund { escrow_id }));
        Ok(())
    }
}

/// Returns every `EscrowHandler` call recorded so far, in order.
pub fn escrow_calls() -> Vec<EscrowCall> {
    ESCROW_CALLS.with(|c| c.borrow().clone())
}

/// Makes the next `EscrowHandler::lock` call fail, simulating a
/// consumer who can't cover the commitment's price.
pub fn set_escrow_lock_should_fail(should_fail: bool) {
    ESCROW_LOCK_SHOULD_FAIL.with(|f| *f.borrow_mut() = should_fail);
}

fn clear_escrow_calls() {
    ESCROW_CALLS.with(|c| c.borrow_mut().clear());
    ESCROW_LOCK_SHOULD_FAIL.with(|f| *f.borrow_mut() = false);
}

// ── Pallet Configuration ─────────────────────────────────────────────────────

parameter_types! {
    /// Provider dispute response window (10 blocks).
    pub const DisputeWindow: u64 = 10;
    /// Hard ceiling on commitment lifetimes (1,000 blocks).
    pub const MaxCommitmentLifetime: u64 = 1_000;
    pub const ProviderGuiltySlash: u32 = 5;
    pub const FalseDisputeSlash: u32 = 2;
}

impl pallet_vector_db::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type AgentRegistry = MockRegistry;
    type DisputeWindow = DisputeWindow;
    type MaxCommitmentLifetime = MaxCommitmentLifetime;
    type ReputationHandler = MockReputationHandler;
    type ProviderGuiltySlash = ProviderGuiltySlash;
    type FalseDisputeSlash = FalseDisputeSlash;
    type Currency = Balances;
    type EscrowHandler = MockEscrowHandler;
}

// ── Test Externalities Builder ───────────────────────────────────────────────

/// Builds `TestExternalities` initialized at block height 1 with a clean registry.
/// Block 1 ensures that events are deposited and queryable (events are ignored at block 0).
pub fn new_test_ext() -> sp_io::TestExternalities {
    clear_agents();
    clear_reputation_calls();
    clear_escrow_calls();
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .unwrap();
    pallet_balances::GenesisConfig::<Runtime> {
        balances: vec![(1, 1_000_000), (2, 1_000_000), (3, 1_000_000)],
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
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

/// Generates a deterministic `MerkleRoot` for index `n` via `blake2_256([n; 64])`.
pub fn test_vector_hash(n: u8) -> MerkleRoot {
    sp_io::hashing::blake2_256(&[n; 64])
}

/// Generates a static dummy metadata vector for testing bounds.
pub fn metadata() -> BoundedVec<u8, frame_support::traits::ConstU32<MAX_METADATA_LEN>> {
    BoundedVec::try_from(b"test-schema-v1".to_vec()).unwrap()
}

/// Deterministically derives a `CommitmentId` mirroring the on-chain logic.
pub fn derive_commitment_id(
    provider: [u8; 32],
    consumer: [u8; 32],
    vector_hash: MerkleRoot,
    created_at_block: u64,
) -> CommitmentId {
    let mut preimage = b"ArthNeura-Vector-v1".to_vec();
    preimage.extend_from_slice(&provider);
    preimage.extend_from_slice(&consumer);
    preimage.extend_from_slice(&vector_hash);
    preimage.extend_from_slice(&created_at_block.encode());
    sp_io::hashing::blake2_256(&preimage)
}
