//! Test runtime for pallet-agent-registry.

use crate as pallet_agent_registry;
use crate::pallet::{Did, MAX_PUBKEY_LEN, MAX_SIG_LEN};
use codec::Encode;
use frame_support::{derive_impl, traits::ConstU32, BoundedVec};
use ml_dsa::{EncodedSignature, EncodedVerifyingKey, Keypair, MlDsa65, SigningKey, VerifyingKey};
use sp_runtime::BuildStorage;

type Block = frame_system::mocking::MockBlock<Runtime>;

frame_support::construct_runtime!(
    pub enum Runtime {
        System: frame_system,
        Balances: pallet_balances,
        AgentRegistry: pallet_agent_registry,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Runtime {
    type AccountData = pallet_balances::AccountData<u64>;
    type Block = Block;
}

#[derive_impl(pallet_balances::config_preludes::TestDefaultConfig)]
impl pallet_balances::Config for Runtime {
    type AccountStore = System;
}

impl pallet_agent_registry::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type StarCooldown = frame_support::traits::ConstU64<10>;
    type Currency = Balances;
    type RegistrationDeposit = frame_support::traits::ConstU64<100>;
    type StrikeThreshold = frame_support::traits::ConstU32<3>;
    type DepositSlashPerStrike = frame_support::traits::ConstU64<20>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut storage = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .unwrap();

    // Endow every account id used across this pallet's test suite with
    // a balance well above any RegistrationDeposit total a single test
    // can reserve (the largest case, register_agent_too_many_agents_fails,
    // reserves 64 x RegistrationDeposit from one controller).
    pallet_balances::GenesisConfig::<Runtime> {
        balances: (1u64..=20u64).map(|acc| (acc, 1_000_000u64)).collect(),
        ..Default::default()
    }
    .assimilate_storage(&mut storage)
    .unwrap();

    let mut ext: sp_io::TestExternalities = storage.into();
    ext.execute_with(|| System::set_block_number(1));
    ext
}

// -- ML-DSA test infrastructure ------------------------------------------
//
// Everything below is test-only (never compiled into production code —
// this whole module is `#[cfg(test)]` via lib.rs's `mod mock;`). It exists
// to let tests generate real, valid ML-DSA-65 keypairs and signatures
// deterministically, so the same test always produces the same bytes on
// every run (no flaky CI from OS-randomness).
//
// Signing uses `SigningKey::sign_deterministic` — FIPS 204 Algorithm 2's
// optional deterministic variant. This is a real, spec-compliant ML-DSA
// signing mode (not a test-only hack); it simply takes no RNG argument,
// which means tests need no custom RNG plumbing at all.

/// A deterministic ML-DSA-65 keypair generated from a `u64` seed.
/// Same seed always produces the same keypair, across every test run.
pub struct TestKeypair {
    pub signing_key: SigningKey<MlDsa65>,
    pub verifying_key: VerifyingKey<MlDsa65>,
}

/// Generate a deterministic ML-DSA-65 keypair from a `u64` seed.
///
/// The seed is expanded to a 32-byte ML-DSA seed via a simple,
/// non-cryptographic mixing function — this only needs to be
/// deterministic and distinct per distinct input seed, which is all
/// tests require. (No RNG is involved; `from_seed` itself is the
/// deterministic FIPS 204 KeyGen algorithm.)
pub fn generate_keypair(seed: u64) -> TestKeypair {
    let mut seed_bytes = [0u8; 32];
    for (i, chunk) in seed_bytes.chunks_mut(8).enumerate() {
        // Mix the seed with its chunk index so the 4 chunks of the
        // 32-byte buffer aren't just 4 repeats of the same 8 bytes.
        let mixed = seed.wrapping_add(i as u64).wrapping_mul(0x9E3779B97F4A7C15);
        chunk.copy_from_slice(&mixed.to_le_bytes());
    }

    let ml_dsa_seed = ml_dsa::B32::from(seed_bytes);
    let signing_key = SigningKey::<MlDsa65>::from_seed(&ml_dsa_seed);
    let verifying_key = signing_key.verifying_key();

    TestKeypair {
        signing_key,
        verifying_key,
    }
}

/// Encode a `VerifyingKey` to the raw bytes `register_agent` expects as
/// its `pubkey` argument, as a `BoundedVec<u8, ConstU32<MAX_PUBKEY_LEN>>`.
pub fn pubkey_bytes(vk: &VerifyingKey<MlDsa65>) -> BoundedVec<u8, ConstU32<MAX_PUBKEY_LEN>> {
    let encoded: EncodedVerifyingKey<MlDsa65> = vk.encode();
    BoundedVec::try_from(encoded.to_vec()).expect("ML-DSA-65 pubkey is exactly MAX_PUBKEY_LEN")
}

/// Build the exact challenge bytes `register_agent` verifies against:
/// `(genesis_hash, did, controller, signed_at_block, signed_at_hash).encode()`.
/// Tests use this so the challenge construction can never silently drift
/// from the pallet's actual logic — if the pallet's tuple shape changes,
/// this helper (and every test using it) will fail to compile or fail
/// the resulting signature check, not pass silently with stale bytes.
pub fn build_challenge(
    genesis_hash: <Runtime as frame_system::Config>::Hash,
    did: Did,
    controller: u64,
    signed_at_block: u64,
    signed_at_hash: <Runtime as frame_system::Config>::Hash,
) -> Vec<u8> {
    (
        genesis_hash,
        did,
        controller,
        signed_at_block,
        signed_at_hash,
    )
        .encode()
}

/// Sign `challenge` with `signing_key`, using ML-DSA's deterministic
/// signing variant (no RNG, no per-call randomness — same key + same
/// challenge always produces the same signature bytes). Returns the raw
/// signature bytes as a `BoundedVec<u8, ConstU32<MAX_SIG_LEN>>`, ready
/// for `register_agent`.
pub fn sign_challenge(
    signing_key: &SigningKey<MlDsa65>,
    challenge: &[u8],
) -> BoundedVec<u8, ConstU32<MAX_SIG_LEN>> {
    let signature = signing_key
        .expanded_key()
        .sign_deterministic(challenge, &[])
        .expect("signing with a valid key over an empty context cannot fail");
    let encoded: EncodedSignature<MlDsa65> = signature.encode();
    BoundedVec::try_from(encoded.to_vec()).expect("ML-DSA-65 signature is exactly MAX_SIG_LEN")
}

/// Derive a DID exactly the way `register_agent` does:
/// `blake2_256("ArthNeura-DID-v1" ++ pubkey)`. Exposed standalone so
/// tests can predict a DID *before* calling register_agent — e.g. to
/// assert on it, or to construct a deliberately-mismatched challenge
/// for adversarial tests. If the pallet's derivation ever changes, this
/// must change too, or signature checks will start failing for the
/// right reason (drift caught immediately) rather than the wrong one.
pub fn derive_did(pubkey: &[u8]) -> Did {
    let mut preimage = b"ArthNeura-DID-v1".to_vec();
    preimage.extend_from_slice(pubkey);
    sp_io::hashing::blake2_256(&preimage)
}

/// One-call helper: generates a keypair from `seed`, derives its DID,
/// builds the exact on-chain challenge for `controller` and
/// `signed_at_block`, and signs it. Returns `(pubkey, signature)` ready
/// to pass straight into `register_agent`.
///
/// MUST be called from inside `execute_with(|| { ... })` — it reads
/// on-chain block hashes via `System::block_hash`, which only exist
/// inside a runtime/storage context.
///
/// `signed_at_block` is a parameter, not hardcoded to the current
/// block, specifically so adversarial tests can pass an expired,
/// future, or otherwise out-of-window block number while still reusing
/// every other piece of this helper (keypair generation, pubkey
/// encoding, challenge construction, signing) unchanged.
pub fn valid_register_params(
    seed: u64,
    controller: u64,
    signed_at_block: u64,
) -> (
    BoundedVec<u8, ConstU32<MAX_PUBKEY_LEN>>,
    BoundedVec<u8, ConstU32<MAX_SIG_LEN>>,
) {
    let keypair = generate_keypair(seed);
    let pubkey = pubkey_bytes(&keypair.verifying_key);
    let did = derive_did(&pubkey);

    let genesis_hash = System::block_hash(0u64);
    let signed_at_hash = System::block_hash(signed_at_block);

    let challenge = build_challenge(
        genesis_hash,
        did,
        controller,
        signed_at_block,
        signed_at_hash,
    );
    let signature = sign_challenge(&keypair.signing_key, &challenge);

    (pubkey, signature)
}
