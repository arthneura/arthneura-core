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
        AgentRegistry: pallet_agent_registry,
    }
);

#[derive_impl(frame_system::config_preludes::TestDefaultConfig)]
impl frame_system::Config for Runtime {
    type Block = Block;
}

impl pallet_agent_registry::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type StarCooldown = frame_support::traits::ConstU64<10>;
}

pub fn new_test_ext() -> sp_io::TestExternalities {
    let mut ext: sp_io::TestExternalities = frame_system::GenesisConfig::<Runtime>::default()
        .build_storage()
        .unwrap()
        .into();
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
