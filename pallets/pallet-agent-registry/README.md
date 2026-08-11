# pallet-agent-registry

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)
[![Polkadot SDK](https://img.shields.io/badge/Polkadot_SDK-frame--support_40.1-E6007A)](https://github.com/paritytech/polkadot-sdk)
[![FIPS 204](https://img.shields.io/badge/crypto-ML--DSA--65_%C2%B7_FIPS_204-brightgreen)](https://csrc.nist.gov/pubs/fips/204/final)

A Substrate FRAME pallet that gives autonomous AI agents verifiable on-chain identity. Each agent gets a 32-byte DID backed by an ML-DSA-65 (FIPS 204) proof-of-key-possession, a permission bitmap, a lifecycle state, and a peer-reputation score — all in one storage slot.

---

## Why this exists

AI agents can already buy API calls, coordinate pipelines, and move money. What they cannot do is *prove who they are* in a way that travels across chains, applications, and counterparties without a central authority in the middle.

The gap is an identity layer. Not another off-chain registry or a JWT sitting behind a corporate API — an on-chain record that anyone can read, nobody can forge, and that survives the operator.

`pallet-agent-registry` is that record. It stores and serves agent identity and reputation. It does not route trades or run inference — consuming pallets and off-chain services read from it and enforce whatever policies they choose.

Classical signature schemes (Ed25519, secp256k1) are broken by Shor's algorithm on a sufficiently large quantum computer. An identity layer built on classical crypto today will need to be replaced later. This pallet uses ML-DSA-65, the NIST FIPS 204 post-quantum standard, from day one.

---

## How it works

When an agent registers, it submits its ML-DSA-65 public key and a signature over a chain-bound challenge. The pallet derives a 32-byte DID from the key, verifies the signature, and stores the profile. The public key itself is never stored on-chain — only its hash is.

DID = blake2_256("ArthNeura-DID-v1" || pubkey)


The domain prefix namespaces DIDs from this registry, preventing collisions with DIDs derived by other schemes. The full 1,952-byte public key is submitted once, verified, and discarded — quantum-resistant identity at 32 bytes of permanent storage.

### Registration challenge

Every registration signature is bound to this specific chain and to a short time window:

challenge = SCALE_encode(
genesis_hash, // binds signature to this chain only
did, // binds signature to this identity
controller, // binds signature to this caller
signed_at_block, // time reference
signed_at_hash // block hash at signed_at_block
)

signed_at_block <= current_block // not from the future
current_block - signed_at_block <= REPLAY_WINDOW // not older than ~6 minutes (64 blocks)


A signature cannot be replayed on another chain, reused by a different caller, or submitted after expiry. Same-block registration is permitted — `block_hash(current_block)` is zero at submission time, and both sides agree on this, so the challenge stays binding.

| Property | Value |
|---|---|
| Standard | FIPS 204 (NIST, August 2024) |
| Security category | 3 (≡ AES-192) |
| Public key | 1,952 bytes — submitted once, then discarded |
| Signature | 3,309 bytes — verified once at registration |
| On-chain footprint | 32 bytes (blake2_256 hash commitment) |

---

## Storage

AgentProfiles : Did → AgentProfile
ControllerAgents : AccountId → BoundedVec<Did, 64>
ActiveAgentCount : u32
StarGivers : (Did, Did) → BlockNumber


`AgentProfiles` is the primary index. `ControllerAgents` is a reverse index bounded at 64 entries per controller, so a single account can't cause unbounded storage growth. `ActiveAgentCount` tracks non-revoked agents — it decrements on revocation and voluntary deregistration, not on suspension, since suspension is reversible. `StarGivers` maps `(giver_did, receiver_did)` to the block of the last star; zero means never starred, and `remove_star` resets to zero on purpose, clearing the cooldown rather than treating removal as a penalty event.

### AgentProfile

```rust
pub struct AgentProfile<T: Config> {
    pub did:              Did,                // immutable
    pub controller:       T::AccountId,        // immutable
    pub capabilities:     CapabilityBitmap,
    pub reputation_score: u32,
    pub status:           AgentStatus,
    pub registered_at:    BlockNumberFor<T>,   // immutable
    pub is_verified:      bool,                // always true; registration is atomic
    pub quantum_scheme:   QuantumScheme,       // immutable
    pub metadata:         BoundedVec<u8, 256>,
    pub label:            BoundedVec<u8, 64>,
}
```

---

## Capability system

Capabilities are self-declared by the agent and updatable by its controller. The registry records them — it does not enforce them; enforcement is left to whatever pallet or off-chain service reads them.

```rust
pub const CAP_DATA_PROVIDER:      CapabilityBitmap = 1 << 0;
pub const CAP_INFERENCE_ENGINE:   CapabilityBitmap = 1 << 1;
pub const CAP_ORCHESTRATOR:       CapabilityBitmap = 1 << 2;
pub const CAP_VERIFIER:           CapabilityBitmap = 1 << 3;
pub const CAP_MARKETPLACE_SELLER: CapabilityBitmap = 1 << 4;
pub const CAP_MARKETPLACE_BUYER:  CapabilityBitmap = 1 << 5;
```

Bits 6–63 are unassigned and accepted without validation, so new capabilities can be introduced without a pallet upgrade.

---

## Lifecycle
          register_agent
                │
                ▼
            ┌────────┐
      ┌────▶│ Active │◀────┐
      │     └────────┘     │
      │   set_agent_status │
      │          ▼         │
      │   ┌───────────┐    │
      └───│ Suspended │────┘
          └───────────┘
                │  set_agent_status (terminal)
                ▼
          ┌─────────┐
          │ Revoked │  ← deposit forfeited, profile kept for audit
          └─────────┘     deregister_agent rejected

Active and Suspended are reversible; Revoked is permanent. Suspended agents can still be read — writes via `update_profile` are blocked, and the controller can restore Active at any time. Revoked agents stay on-chain as an immutable audit record; the registration deposit is forfeited, not returned, and there is no path out.

---

## Reputation

Two mechanisms feed `reputation_score`, and they mean different things.

**Peer stars (`give_star` / `remove_star`)** — voluntary, cooldown-gated endorsements between agents. A controller cannot star an agent it also controls (sybil guard); a `StarCooldown` window (production: 1,200 blocks, ~2 hours) must elapse between stars from the same giver to the same receiver, tracked per-pair, not globally.

**Protocol slashing (`slash_reputation`)** — not an extrinsic. A non-signed, internal-only function callable only from within the runtime, by a trusted caller the runtime explicitly wires in (currently: `pallet-vector-db`'s dispute resolution, via a `ReputationHandler` trait bridged through a runtime adapter). This is how a losing dispute in another pallet actually costs an agent reputation, without that pallet needing write access to `AgentProfiles` directly, and without any of `give_star`'s peer-action guards applying — there is no origin to check, because the caller is the trusted pallet itself, not a user.

`slash_reputation` silently no-ops (no event, no error) if the target DID is no longer registered. This is deliberate: a protocol-level penalty must never be able to fail its caller's own extrinsic — see `pallet-vector-db`'s docs for why that matters for a permissionless `finalize_dispute`.

`reputation_score` uses saturating arithmetic in both directions — it will not overflow at `u32::MAX` and will not underflow below zero.

---

## Extrinsics

### `register_agent` (index 0)

Derives a DID from a submitted ML-DSA-65 public key, verifies a proof-of-key-possession over a chain-bound challenge, reserves the deposit, and stores the profile.

| Parameter | Type |
|---|---|
| `pubkey` | `BoundedVec<u8, 1952>` |
| `signature` | `BoundedVec<u8, 3309>` |
| `signed_at_block` | `BlockNumber` |
| `capabilities` | `u64` |
| `metadata` | `BoundedVec<u8, 256>` |
| `label` | `BoundedVec<u8, 64>` |

The deposit reservation is the last fallible step, not the first — placing it earlier would mutate the Balances pallet on a path that later fails the ML-DSA proof, breaking `assert_noop!` guarantees in tests and leaving inconsistent intermediate state in production. Emits `AgentRegistered { did, controller }`.

### `update_profile` (index 1)

Updates `capabilities`, `metadata`, and `label`. Only the controller may call; Revoked agents are rejected. Emits `AgentProfileUpdated { did }`.

### `set_agent_status` (index 2)

Moves an agent between Active and Suspended, or terminates it into Revoked. Only the controller may call; Revoked is terminal. Transitioning to Revoked decrements `ActiveAgentCount`; suspending does not. Emits `AgentStatusChanged { did, new_status }`.

### `give_star` (index 3)

Gives a reputation star, incrementing the receiver's `reputation_score` by 1. Caller must control `giver_did`. Receiver must exist and not be Revoked. Self-starring and intra-controller starring are both rejected. Cooldown must have elapsed. Emits `StarGiven { giver, receiver }`.

### `remove_star` (index 4)

Removes a previously given star, decrementing the receiver's `reputation_score` by 1. Caller must control `giver_did`. A star must exist for this pair. Resets the `StarGivers` entry to zero, clearing the cooldown. Emits `StarRemoved { giver, receiver }`.

### `deregister_agent` (index 5)

Voluntary exit. Returns the deposit, prunes the reverse index, deletes the profile, decrements `ActiveAgentCount`. Revoked agents cannot deregister — profile and deposit stay permanently locked. Emits `AgentDeregistered { did, controller }`.

### `slash_reputation` — not an extrinsic

Documented above under [Reputation](#reputation). No `#[pallet::call_index]`, no signed origin, callable only from trusted runtime code. Emits `ReputationSlashed { did, amount, new_score }` on success; emits nothing if the DID isn't found.

---

## Events

| Event | Fields |
|---|---|
| `AgentRegistered` | `did`, `controller` |
| `AgentProfileUpdated` | `did` |
| `AgentStatusChanged` | `did`, `new_status` |
| `StarGiven` | `giver`, `receiver` |
| `StarRemoved` | `giver`, `receiver` |
| `AgentDeregistered` | `did`, `controller` |
| `ReputationSlashed` | `did`, `amount`, `new_score` |

---

## Errors

| Error | When |
|---|---|
| `DidAlreadyRegistered` | A profile already exists for the derived DID |
| `DidNotFound` | No profile for the given DID |
| `NotController` | Caller does not control this DID |
| `AgentRevoked` | Agent is Revoked; all writes blocked |
| `TooManyAgentsForController` | Controller already has 64 registered agents |
| `CooldownNotExpired` | `StarCooldown` has not elapsed since the last star for this pair |
| `NotStarred` | `remove_star` called with no existing star for this pair |
| `CannotStarSelf` | `giver_did` and `receiver` are the same DID |
| `CannotStarSameController` | Giver and receiver share a controller |
| `InvalidPubkeyLength` | Submitted key is not exactly 1,952 bytes |
| `InvalidSignatureLength` | Submitted signature is not exactly 3,309 bytes |
| `InvalidChallengeBlock` | `signed_at_block` is ahead of the current block |
| `ChallengeExpired` | `signed_at_block` is outside the replay window |
| `InvalidQuantumProof` | ML-DSA-65 verification failed |
| `InsufficientBalanceForDeposit` | Free balance below `RegistrationDeposit` |
| `AgentAlreadyRevoked` | `deregister_agent` called on a Revoked agent |

---

## Configuration

```rust
impl pallet_agent_registry::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = pallet_agent_registry::SubstrateWeight<Runtime>;
    /// ~2 hours at 6 s/block.
    type StarCooldown = ConstU64<1200>;
    type Currency = Balances;
    /// Anti-sybil registration deposit.
    type RegistrationDeposit = ConstU64<100_000_000_000>;
}
```

The test runtime (`mock.rs`) uses `StarCooldown = 10` and `RegistrationDeposit = 100`.

---

## Weights

`SubstrateWeight<T>` builds weight compositionally from per-read/per-write costs, plus a `+300_000_000` ref-time placeholder for ML-DSA-65 verification in `register_agent` — conservative, pending a proper `cargo benchmark` run before mainnet. `impl WeightInfo for ()` provides flat values identical to `SubstrateWeight<T>`, so weight regressions surface in tests rather than only on a benchmarked chain.

---

## Tests

123 tests, 0 failures, real ML-DSA-65 keypairs throughout — nothing at the cryptographic layer is mocked.

```bash
cargo test -p pallet-agent-registry
cargo clippy -p pallet-agent-registry -- -D warnings   # zero warnings enforced
```

| File | Tests | Coverage |
|---|---|---|
| `tests/register_agent.rs` | 28 | Zero keys, bit-flipped signatures, cross-controller proofs, cross-chain replays, wrong message, garbage bytes, length boundaries, replay window (exact/off-by-one/expired/future), duplicate DID, controller limit |
| `tests/deregister_agent.rs` | 29 | Deposit return, Revoked rejection, slot reclamation, sibling DID isolation, re-registration after exit, multi-agent deposit accounting |
| `tests/give_star.rs` | 19 | Cooldown boundary, per-pair vs global cooldown, controller sybil guard, self-star, spoofed giver, Revoked/Suspended receiver, score saturation |
| `tests/set_agent_status.rs` | 14 | All lifecycle transitions, `ActiveAgentCount` invariants, attacker isolation |
| `tests/update_profile.rs` | 14 | Immutable field guards, noop resubmit, Revoked rejection, Suspended pass-through |
| `tests/remove_star.rs` | 11 | Cooldown reset, double-remove, spoofed giver, score floor saturation |
| `tests/slash_reputation.rs` | 6 | Decrement, saturation at zero, event emission, no-op on unregistered DID, zero-amount slash, isolation from unrelated agents |
| `mock.rs` | 2 | Genesis config integrity, `construct_runtime!` integrity |

`generate_keypair(seed: u64)` produces deterministic ML-DSA-65 keypairs via FIPS 204's own `KeyGen`, and `sign_deterministic` (FIPS 204 Algorithm 2) means the same key and message always produce the same signature — no OS randomness, no flaky CI.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../../LICENSE) for the full text.
