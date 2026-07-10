# pallet-agent-registry

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-0.1.0-blue)](pallets/pallet-agent-registry/Cargo.toml)
[![Polkadot SDK](https://img.shields.io/badge/Polkadot_SDK-frame--support_40.1-E6007A)](https://github.com/paritytech/polkadot-sdk)
[![FIPS 204](https://img.shields.io/badge/crypto-ML--DSA--65_%C2%B7_FIPS_204-brightgreen)](https://csrc.nist.gov/pubs/fips/204/final)

A Substrate FRAME pallet that gives autonomous AI agents verifiable on-chain identity. Each agent gets a 32-byte DID backed by an ML-DSA-65 (FIPS 204) proof-of-key-possession, a permission bitmap, a lifecycle state, and a peer-reputation score — all in one storage slot.

---

## Why this exists

AI agents can already buy API calls, coordinate pipelines, and move money. What they cannot do is *prove who they are* in a way that travels across chains, applications, and counterparties without a central authority in the middle.

The gap is an identity layer. Not another off-chain registry or a JWT sitting behind a corporate API — an on-chain record that anyone can read, nobody can forge, and that survives the operator.

`pallet-agent-registry` is that record. It is a public identity board: it stores and serves agent identity. It does not route trades, run inference, or make decisions. Consuming pallets and off-chain services read from it and enforce whatever policies they choose.

There is one additional constraint that most identity schemes ignore: classical signature schemes (Ed25519, secp256k1) are broken by Shor's algorithm on a sufficiently large quantum computer. An identity layer built on classical crypto today will need to be replaced. This pallet uses ML-DSA-65, the NIST FIPS 204 post-quantum standard, from day one.

---

## How it works

When an agent registers, it submits its ML-DSA-65 public key and a signature over a chain-bound challenge. The pallet derives a 32-byte DID from the key, verifies the signature, and stores the profile. The public key itself is never stored on-chain — only its hash is. After that, the agent's identity is its DID: a 32-byte value that can be passed between pallets, referenced in other registries, and resolved to a full profile in a single storage read.

```
DID = blake2_256("ArthNeura-DID-v1" || pubkey)
```

The domain prefix `"ArthNeura-DID-v1"` namespaces all DIDs from this registry, preventing collisions with DIDs derived by other schemes. The full 1,952-byte public key is submitted once, verified, and discarded — quantum-resistant identity at 32 bytes of permanent storage.

---

## Cryptographic design

### Registration challenge

Every registration signature is bound to this specific chain and to a short time window:

```
challenge = SCALE_encode(
    genesis_hash,      // binds signature to this chain only
    did,               // binds signature to this identity
    controller,        // binds signature to this caller
    signed_at_block,   // time reference
    signed_at_hash     // block hash at signed_at_block
)
```

`signed_at_block` must satisfy two conditions:

```
signed_at_block <= current_block          // not from the future
current_block - signed_at_block <= 64     // not older than ~6 minutes
```

A signature cannot be replayed on another chain (different `genesis_hash`), reused by a different caller (different `controller`), or submitted after expiry. Same-block registration is permitted — `block_hash(current_block)` is zero at submission time, and both sides agree on this, so the challenge stays binding.

### Why ML-DSA-65

NIST published FIPS 204 in August 2024, making ML-DSA the first standardised post-quantum signature scheme. ML-DSA-65 sits at security category 3 — the equivalent of AES-192. Building on it now means agents registered today remain valid after quantum hardware matures, with no migration required.

| Property | Value |
|---|---|
| Standard | FIPS 204 (NIST, August 2024) |
| Security category | 3 (≡ AES-192) |
| Public key | 1,952 bytes — submitted once, then discarded |
| Signature | 3,309 bytes — verified once at registration |
| On-chain footprint | 32 bytes (blake2_256 hash commitment) |
| Rust crate | `ml-dsa = "0.1.1"` |

---

## Storage

```
AgentProfiles    : Did → AgentProfile
ControllerAgents : AccountId → BoundedVec<Did, 64>
ActiveAgentCount : u32
StarGivers       : (Did, Did) → BlockNumber
```

`AgentProfiles` is the primary index. Everything else is derived from it or supports it.

`ControllerAgents` is a reverse index so controllers can enumerate their own agents without a full map scan. It is bounded at 64 entries per controller to prevent a single account from causing unbounded storage growth.

`ActiveAgentCount` tracks non-revoked agents. It decrements when an agent is revoked and when an agent voluntarily deregisters. It does not change when an agent is suspended, because suspension is reversible.

`StarGivers` maps `(giver_did, receiver_did)` to the block number of the last star. Zero means either no star has been given or the star was removed. Substrate does not execute extrinsics at block 0, so zero is a safe sentinel that `give_star` will never write in practice. `remove_star` resets to zero intentionally — this clears the cooldown and allows immediate re-starring, treating a removal as a neutral action rather than a penalty event.

---

## AgentProfile

```rust
pub struct AgentProfile<T: Config> {
    pub did:              Did,                          // [u8; 32] — immutable
    pub controller:       T::AccountId,                 // owning account — immutable
    pub capabilities:     CapabilityBitmap,             // u64 permission mask
    pub reputation_score: u32,                          // peer-star count
    pub status:           AgentStatus,                  // Active | Suspended | Revoked
    pub registered_at:    BlockNumberFor<T>,            // registration block — immutable
    pub is_verified:      bool,                         // always true; see note below
    pub quantum_scheme:   QuantumScheme,                // MlDsa65 — immutable
    pub metadata:         BoundedVec<u8, 256>,          // arbitrary bytes; IPFS CID works well
    pub label:            BoundedVec<u8, 64>,           // human-readable display name
}
```

`did`, `controller`, `registered_at`, and `quantum_scheme` are set at registration and never change. `capabilities`, `metadata`, and `label` can be updated by the controller at any time, unless the agent is Revoked.

`is_verified` is always `true`. Registration is atomic: if the ML-DSA proof fails, the call reverts and no profile is written. The field exists as a convenience for off-chain indexers that filter agent records.

---

## Capability system

Capabilities are declared by the agent and can be updated by its controller. The registry records them — it does not enforce them. Enforcement is left to the consuming application layer.

```rust
pub type CapabilityBitmap = u64;

pub const CAP_DATA_PROVIDER:      CapabilityBitmap = 1 << 0; // publishes data feeds
pub const CAP_INFERENCE_ENGINE:   CapabilityBitmap = 1 << 1; // runs ML inference
pub const CAP_ORCHESTRATOR:       CapabilityBitmap = 1 << 2; // coordinates agent pipelines
pub const CAP_VERIFIER:           CapabilityBitmap = 1 << 3; // attests agent outputs
pub const CAP_MARKETPLACE_SELLER: CapabilityBitmap = 1 << 4; // lists services for sale
pub const CAP_MARKETPLACE_BUYER:  CapabilityBitmap = 1 << 5; // purchases services
```

Bits 6–63 are unassigned. Unknown bits are accepted without error, which means new capabilities can be introduced without a pallet upgrade. Checking a capability is a single bitwise AND:

```rust
if profile.capabilities & CAP_MARKETPLACE_BUYER != 0 { ... }
```

---

## Agent lifecycle

```
              register_agent
                    │
                    ▼
                ┌────────┐
          ┌────▶│ Active │◀────┐
          │     └────────┘     │
          │          │         │
          │  set_agent_status  │
          │          │         │
          │          ▼         │
          │   ┌───────────┐    │
          └───│ Suspended │────┘
              └───────────┘
                    │
                    │  set_agent_status (terminal)
                    ▼
              ┌─────────┐
              │ Revoked │  ← deposit forfeited
              └─────────┘    profile kept for audit
                             deregister_agent rejected
```

Active and Suspended are reversible. Revoked is permanent.

**Suspended** agents can still be read. Writes (`update_profile`) are blocked. The controller can restore a Suspended agent to Active at any time.

**Revoked** agents stay on-chain permanently as an immutable audit record. The registration deposit is forfeited — not returned. `deregister_agent` is rejected for Revoked agents. There is no path out of Revoked. This distinction matters: voluntary deregistration (`deregister_agent`) returns the deposit and frees the storage slot; revocation does neither.

---

## Reputation system

Reputation is accumulated through peer-to-peer stars. Two guards are enforced on-chain to prevent trivial sybil attacks.

**Controller guard.** A controller cannot give a star to any agent it controls. A farming attempt — deploying many agents and starring each other — is blocked in O(1) with no extra storage reads, since both the caller identity and the receiver's controller are already in scope during the `give_star` call.

**Cooldown guard.** `StarCooldown` blocks must pass between stars from the same giver to the same receiver. The default production value is 1,200 blocks (~2 hours at 6 s/block). Cooldown is tracked per `(giver_did, receiver_did)` pair, not globally, so starring a different agent is unaffected.

`reputation_score` uses saturating arithmetic in both directions. It will not overflow at `u32::MAX` and will not underflow below zero.

---

## Extrinsics

### `register_agent` (index 0)

Derives a DID from a submitted ML-DSA-65 public key, verifies a proof-of-key-possession over a chain-bound challenge, reserves the deposit, and stores the profile.

| Parameter | Type | Description |
|---|---|---|
| `pubkey` | `BoundedVec<u8, 1952>` | ML-DSA-65 verifying key |
| `signature` | `BoundedVec<u8, 3309>` | Signature over the chain-bound challenge |
| `signed_at_block` | `BlockNumber` | Block at which the challenge was signed |
| `capabilities` | `u64` | Initial capability bitmap |
| `metadata` | `BoundedVec<u8, 256>` | Optional metadata |
| `label` | `BoundedVec<u8, 64>` | Optional display name |

One implementation detail worth knowing: the deposit reservation (`T::Currency::reserve`) is the last fallible operation, not the first. If it were placed before the ML-DSA verification step, a failed proof would still mutate the Balances pallet, which breaks `assert_noop!` guarantees in tests and produces inconsistent intermediate state in production.

Emits `AgentRegistered { did, controller }`.

---

### `update_profile` (index 1)

Updates `capabilities`, `metadata`, and `label`. `did`, `controller`, `registered_at`, `is_verified`, and `quantum_scheme` are immutable and cannot be changed after registration.

Only the controller may call this. Revoked agents are rejected.

Emits `AgentProfileUpdated { did }`.

---

### `set_agent_status` (index 2)

Changes an agent's lifecycle status. Only the controller may call this. Revoked is terminal — no further transitions are possible once an agent reaches that state.

Transitioning to Revoked decrements `ActiveAgentCount`. Suspending an agent does not change the count since suspension is reversible.

Emits `AgentStatusChanged { did, new_status }`.

---

### `give_star` (index 3)

Gives a reputation star to another agent, incrementing the receiver's `reputation_score` by 1. The caller must control `giver_did`. The receiver must exist and must not be Revoked. Intra-controller starring and self-starring are both rejected. The cooldown must have expired (or no star was previously recorded for this pair).

Emits `StarGiven { giver, receiver }`.

---

### `remove_star` (index 4)

Removes a previously given star, decrementing the receiver's `reputation_score` by 1. The caller must control `giver_did`. A star must exist for this pair (non-zero `StarGivers` entry). On removal, the `StarGivers` entry is reset to zero, which clears the cooldown and permits immediate re-starring.

Emits `StarRemoved { giver, receiver }`.

---

### `deregister_agent` (index 5)

Removes an agent voluntarily. The controller gets the deposit back, the DID is pruned from the reverse index, the profile is deleted, and `ActiveAgentCount` is decremented. Revoked agents cannot deregister — the profile and deposit are permanently locked.

Emits `AgentDeregistered { did, controller }`.

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

---

## Errors

| Error | When it is returned |
|---|---|
| `DidAlreadyRegistered` | A profile already exists for the DID derived from the submitted public key |
| `DidNotFound` | No profile found for the given DID |
| `NotController` | Caller is not the registered controller of this DID |
| `AgentRevoked` | The agent is in the Revoked state, which blocks all writes |
| `TooManyAgentsForController` | The controller already has 64 registered agents |
| `CooldownNotExpired` | `StarCooldown` blocks have not yet elapsed since the last star for this pair |
| `NotStarred` | `remove_star` called when no star exists for this `(giver, receiver)` pair |
| `CannotStarSelf` | `giver_did` and `receiver` are the same DID |
| `CannotStarSameController` | Giver and receiver share the same controller account |
| `InvalidPubkeyLength` | Submitted key is not exactly 1,952 bytes |
| `InvalidSignatureLength` | Submitted signature is not exactly 3,309 bytes |
| `InvalidChallengeBlock` | `signed_at_block` is ahead of the current block |
| `ChallengeExpired` | `signed_at_block` is more than 64 blocks behind the current block |
| `InvalidQuantumProof` | ML-DSA-65 verification failed |
| `InsufficientBalanceForDeposit` | Controller's free balance is below `RegistrationDeposit` |
| `AgentAlreadyRevoked` | `deregister_agent` was called on a Revoked agent |

---

## Configuration

```rust
impl pallet_agent_registry::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;

    /// Use SubstrateWeight<Runtime> in production.
    /// Use () in dev and test — identical cost values, no benchmarking overhead.
    type WeightInfo = pallet_agent_registry::SubstrateWeight<Runtime>;

    /// Blocks between stars from the same giver to the same receiver.
    /// 1,200 blocks ≈ 2 hours at 6 s/block.
    type StarCooldown = ConstU64<1200>;

    type Currency = Balances;

    /// Deposit reserved at registration, returned on voluntary deregistration,
    /// forfeited on revocation. Adjust the value to match your token's decimals.
    type RegistrationDeposit = ConstU64<100_000_000_000>;
}
```

The test runtime in `mock.rs` uses `StarCooldown = 10` and `RegistrationDeposit = 100`, with accounts 1–20 each endowed with 1,000,000 units.

---

## Weights

Two implementations of `WeightInfo` are provided.

`SubstrateWeight<T>` builds the weight compositionally from per-read and per-write costs, plus a `+300_000_000` ref-time placeholder for the ML-DSA-65 verification in `register_agent`. This placeholder is conservative and is marked as pending a proper `cargo benchmark` run before mainnet.

`impl WeightInfo for ()` provides pre-computed flat values for use in tests. The numbers are deliberately identical to `SubstrateWeight<T>` so that weight-related regressions surface in the test environment rather than only on a benchmarked chain.

---

## Getting started

### Prerequisites

```bash
rustup target add wasm32-unknown-unknown
```

### Add to your runtime

```toml
# runtime/Cargo.toml
[dependencies]
pallet-agent-registry = { version = "0.1.0", default-features = false }

[features]
std = [
    "pallet-agent-registry/std",
]
```

```rust
// runtime/src/lib.rs
construct_runtime!(
    pub enum Runtime {
        // ...
        AgentRegistry: pallet_agent_registry,
    }
);
```

### Run tests

```bash
cargo test -p pallet-agent-registry
```

```
test result: ok. 117 passed; 0 failed; 0 ignored; 0 measured
```

```bash
# Zero warnings enforced
cargo clippy -p pallet-agent-registry -- -D warnings
```

### Test suite — 117 tests, 0 failures

| File | Tests | Coverage |
|---|---|---|
| `tests/register_agent.rs` | 28 | Zero keys, bit-flipped signatures, cross-controller proofs, cross-chain replays, wrong message, garbage bytes, length boundary enforcement, replay window (exact / off-by-one / expired / future), duplicate DID, controller limit |
| `tests/deregister_agent.rs` | 29 | Deposit return, Revoked rejection, slot reclamation, sibling DID isolation, re-registration after exit, multi-agent deposit accounting, unsigned |
| `tests/give_star.rs` | 19 | Cooldown boundary (exact / ±1 block), per-pair vs global cooldown, controller sybil guard, self-star, spoofed giver, Revoked/Suspended receiver, score saturation |
| `tests/set_agent_status.rs` | 14 | All lifecycle transitions, `ActiveAgentCount` invariants under revoke and suspend→revoke, counter floor, attacker isolation, unsigned |
| `tests/update_profile.rs` | 14 | Immutable field guards, simultaneous field overwrite, noop resubmit, Revoked rejection, Suspended pass-through, attacker isolation |
| `tests/remove_star.rs` | 11 | Cooldown reset, double-remove, spoofed giver, score floor saturation, attacker isolation |
| `mock.rs` | 2 | Genesis config integrity, `construct_runtime!` integrity |

Tests use real ML-DSA-65 keypairs — nothing at the cryptographic layer is mocked or stubbed. The mock runtime's `generate_keypair(seed: u64)` function produces deterministic keypairs via FIPS 204's own `KeyGen` algorithm, given a seed-derived 32-byte input. `sign_deterministic` (FIPS 204 Algorithm 2, deterministic variant) means the same key and message always produce the same signature bytes, with no OS randomness involved and no flaky CI risk.

The `build_challenge` helper in `mock.rs` mirrors the exact tuple layout used inside `register_agent`. If the pallet's challenge construction ever changes, the mismatch causes a compile error or an immediate signature failure — not a silent pass with stale bytes.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

Copyright 2026 ArthNeura
