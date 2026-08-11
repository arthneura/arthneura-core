# pallet-vector-db

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](../../LICENSE)
[![Polkadot SDK](https://img.shields.io/badge/Polkadot_SDK-frame--support_40.1-E6007A)](https://github.com/paritytech/polkadot-sdk)

A Substrate FRAME pallet that anchors Merkle-root commitments for off-chain data delivery between AI agents, and adjudicates delivery disputes on-chain using cryptographic proof rather than a human arbitrator.

---

## Why this exists

Two agents that don't know each other need a way to trade data without trusting each other or a third party. One agent commits to delivering a payload; the other needs a way to check, after the fact, whether what arrived actually matches what was promised — without re-transmitting the whole payload on-chain, which would defeat the point of a blockchain being cheap to write to.

`pallet-vector-db` anchors a Merkle root of the payload's chunks on-chain at commitment time. If the consumer later disputes a specific chunk, the provider proves inclusion of the correct chunk against that root with a Merkle proof — a few hundred bytes, checkable in milliseconds, regardless of how large the original payload was.

This pallet only records and adjudicates commitments. It does not store the actual data (that's the off-chain client's job — see `offchain-vector-db`), and as of this writing it does not move payment on settlement — see [What this pallet doesn't do yet](#what-this-pallet-doesnt-do-yet).

---

## How it works

### Cross-pallet identity check

`pallet-vector-db` never imports `pallet-agent-registry` directly. It declares a trait, `AgentLookup`, for whatever it needs to know about a DID:

```rust
pub trait AgentLookup<AccountId> {
    fn controller_of(did: &[u8; 32]) -> Option<AccountId>;
    fn is_active_verified(did: &[u8; 32]) -> bool;
}
```

The runtime supplies a small adapter (`runtime/src/adapters/agent_registry.rs`) that answers this trait against `pallet-agent-registry`'s real storage. Neither pallet's crate depends on the other's — the coupling exists only in the runtime, in one small, auditable file.

### Custom Merkle hasher

The chain runs in `no_std` WASM, where the standard `rs_merkle` crate's hashing utilities aren't available. `Blake2bHasher` implements `rs_merkle::Hasher` directly on top of `sp_io::hashing::blake2_256`, so proof verification runs natively in the runtime with no heap allocation in the sibling-hash reconstruction path.

### Commitment lifecycle

register_commitment
│
▼
┌─────────┐ acknowledge_commitment ┌────────┐
│ Pending │ ─────────────────────────▶│ Active │
└─────────┘ └────────┘
│ │
close_commitment raise_dispute
│ │
▼ ▼
┌─────────┐ ┌──────────┐
│ Settled │ │ Disputed │
└─────────┘ └──────────┘
│ │
finalize_dispute│ │counter_dispute
(timeout) │ │(valid proof)
▼ ▼
┌──────────────────┐
│ DisputeResolved │
└──────────────────┘


`Pending` and `Active` commitments past their expiry can also be swept by `expire_commitment`, transitioning to a removed record rather than a stored `Expired` state.

---

## The dispute-binding design

This is the part of the pallet worth understanding precisely, because an earlier version of it had a real soundness gap.

When a consumer raises a dispute, it must name a specific `disputed_chunk_index` — not just submit a hash and hope. That index is written into the on-chain `DisputeRecord`. When the provider later calls `counter_dispute`, it no longer supplies its own chunk index — the pallet reads `disputed_chunk_index` back out of the stored `DisputeRecord` and requires the Merkle proof to verify against exactly that index.

The earlier design let the provider choose which chunk to prove at counter-time. That meant a provider could "win" any dispute by proving some unrelated, genuinely-correct chunk from the same tree, regardless of whether the chunk the consumer actually complained about was corrupted. Binding the index at dispute-raise time, and re-reading it (not re-accepting it) at counter-time, closes that gap — the provider has to defend the specific claim, not a claim of its own choosing.

---

## Reputation consequence

A resolved dispute has a real, automatic cost on both sides, via a second cross-pallet trait:

```rust
pub trait ReputationHandler {
    fn penalize_provider(did: &Did);
    fn penalize_false_disputer(did: &Did);
}
```

`finalize_dispute` (provider never countered in time) calls `penalize_provider`. `counter_dispute` (provider proved the exact disputed chunk was fine) calls `penalize_false_disputer` on the consumer who raised it. Both are wired to `pallet-agent-registry::slash_reputation` through a runtime adapter — the same decoupling pattern as `AgentLookup`.

This is deliberately two-sided. If only a guilty provider could be penalized, a consumer could raise disputes for free — spam every delivery on the chance of a payout, since losing costs nothing. `penalize_false_disputer` gives a baseless dispute a real, smaller cost, so raising one has to be a decision made in good faith.

Both hook calls are fire-and-forget: no `Result`, nothing that can fail the caller's own extrinsic. This matters most for `finalize_dispute`, which is permissionless — anyone can call it once the window lapses, and it must always succeed if its own preconditions are met, regardless of what state the losing party's identity is in by then.

---

## What this pallet doesn't do yet

**It does not move money.** `close_commitment`, `finalize_dispute`, and `counter_dispute` all resolve to a verified *record* — a settled delivery, a guilty-provider verdict, or a baseless-dispute verdict — not a balance change. There is no price on a commitment today, and no escrow. That is the immediate next piece of work: a generic, reusable escrow pallet that this pallet (and future commitment types beyond data delivery) will settle payment through, rather than implementing payment logic inline.

---

## Extrinsics

### `register_commitment` (index 0)

Provider anchors a Merkle root, chunk count, metadata, and expiry for a delivery to a named consumer. Both DIDs must be active and verified; self-trades are rejected.

| Parameter | Type |
|---|---|
| `provider_did` | `Did` |
| `consumer_did` | `Did` |
| `merkle_root` | `[u8; 32]` |
| `total_chunks` | `u64` |
| `metadata` | `BoundedVec<u8, 256>` |
| `expires_in_blocks` | `BlockNumber` |

`commitment_id` is derived on-chain: `blake2_256("ArthNeura-Vector-v1" ++ provider ++ consumer ++ merkle_root ++ current_block)` — it depends on the block the extrinsic lands in, so a client cannot predict it before submission. Emits `CommitmentRegistered`.

### `acknowledge_commitment` (index 1)

Consumer accepts a `Pending` commitment, moving it to `Active`. Must be called by the consumer's controller before expiry. Emits `CommitmentAcknowledged`.

### `close_commitment` (index 2)

Consumer confirms the delivered stream hash matches the committed Merkle root, moving `Active` to `Settled`. A mismatch is rejected, not silently accepted. Emits `CommitmentSettled`.

### `raise_dispute` (index 3)

Consumer flags `disputed_chunk_index` as corrupted, supplying the hash it actually received for that chunk. Opens the provider's response window (`DisputeWindow`, production: 14,400 blocks ≈ 1 day). The index must be within `total_chunks` — checked here, not at counter-time. Emits `DisputeRaised`.

### `counter_dispute` (index 4)

Provider submits the raw chunk data and a Merkle proof for `disputed_chunk_index` — the index is read from the stored `DisputeRecord`, not supplied by the caller. A valid proof resolves the dispute as `ClaimantUnsubstantiated` and penalizes the consumer's reputation. Emits `DisputeCountered`.

### `finalize_dispute` (index 5)

Permissionless. Once `counter_deadline` has passed without a successful counter, resolves the dispute as `ProviderGuilty` and penalizes the provider's reputation. Emits `DisputeFinalized`.

### `expire_commitment` (index 6)

Permissionless cleanup for a `Pending` or `Active` commitment that lapsed without settlement or dispute. Removes the record entirely. Emits `CommitmentExpired`.

---

## Events

| Event | Fields |
|---|---|
| `CommitmentRegistered` | `commitment_id`, `provider`, `consumer`, `merkle_root`, `total_chunks`, `expires_at` |
| `CommitmentAcknowledged` | `commitment_id`, `acknowledged_at` |
| `CommitmentSettled` | `commitment_id`, `final_stream_hash`, `chunk_count` |
| `DisputeRaised` | `commitment_id`, `merkle_root`, `disputed_chunk_index`, `received_chunk_hash`, `counter_deadline` |
| `DisputeCountered` | `commitment_id`, `verdict` |
| `DisputeFinalized` | `commitment_id`, `verdict`, `provider`, `consumer` |
| `CommitmentExpired` | `commitment_id` |

---

## Errors

| Error | When |
|---|---|
| `CommitmentAlreadyExists` | Derived `commitment_id` collides (block-dependent; effectively unreachable in practice) |
| `CommitmentNotFound` | No commitment for the given ID |
| `NotProvider` / `NotConsumer` | Caller does not control the claimed provider/consumer DID |
| `ProviderNotEligible` / `ConsumerNotEligible` | DID unregistered, inactive, or unverified |
| `SelfTrade` | `provider_did == consumer_did` |
| `ExpiryMustBePositive` / `ExpiryTooFar` | `expires_in_blocks` is zero, or exceeds `MaxCommitmentLifetime` |
| `CommitmentExpiredError` | Action attempted after `expires_at` |
| `NotPending` / `NotActive` / `NotDisputed` | Status guard failed for the extrinsic called |
| `AlreadyFinalized` | `expire_commitment` called on a terminal-state commitment |
| `StreamHashMismatch` | `close_commitment`'s hash doesn't match the committed root |
| `InvalidMerkleProof` | `counter_dispute`'s proof fails verification |
| `DisputeAlreadyRaised` | A `DisputeRecord` already exists for this commitment |
| `DisputeWindowStillOpen` / `DisputeWindowExpired` | Temporal guard on `finalize_dispute` / `counter_dispute` |
| `NotYetExpired` | `expire_commitment` called before `expires_at` |
| `TotalChunksMustBePositive` | `total_chunks == 0` |
| `InvalidMerkleRoot` | `merkle_root == [0u8; 32]` |
| `ChunkIndexOutOfBounds` | `disputed_chunk_index >= total_chunks` |

---

## Configuration

```rust
impl pallet_vector_db::Config for Runtime {
    type RuntimeEvent = RuntimeEvent;
    type WeightInfo = ();
    type AgentRegistry = AgentRegistryAdapter;
    /// ~1 day at 6 s/block.
    type DisputeWindow = ConstU32<14_400>;
    /// ~7 days at 6 s/block.
    type MaxCommitmentLifetime = ConstU32<100_800>;
    type ReputationHandler = ReputationHandlerAdapter;
    type ProviderGuiltySlash = ConstU32<5>;
    type FalseDisputeSlash = ConstU32<2>;
}
```

`DisputeWindow` is kept a full order of magnitude smaller than `MaxCommitmentLifetime` so a dispute raised at any point in a commitment's life always gets its full response window. `ProviderGuiltySlash` is set higher than `FalseDisputeSlash` — failing to deliver (or defend) is treated as a more severe protocol violation than a mistaken dispute. Both slash amounts, and the window/lifetime constants, are hardcoded pending a governance pallet.

---

## Tests

198 tests, 0 failures, against a mock runtime with a thread-local `AgentLookup`/`ReputationHandler` double (`mock.rs`) that decouples this pallet's test suite from needing `pallet-agent-registry` compiled in.

```bash
cargo test -p pallet-vector-db
```

Coverage spans the full lifecycle per extrinsic (happy path, every documented error, guard-ordering regression tests where two errors could plausibly fire on the same call), real `rs_merkle` trees and proofs (not stubbed), and explicit assertions that the `ReputationHandler` hook fires exactly once, with the correct DID, on each verdict path — and does not fire at all on a rejected call.

Beyond unit tests, `offchain-vector-db`'s `live_lifecycle.rs` runs a 12-section, sequential, end-to-end suite against a real `--dev` node — every extrinsic, real signed transactions, real finalized blocks.

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](../../LICENSE) for the full text.
