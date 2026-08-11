# ArthNeura

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Polkadot SDK](https://img.shields.io/badge/Polkadot_SDK-frame--support_40.1-E6007A)](https://github.com/paritytech/polkadot-sdk)
[![FIPS 204](https://img.shields.io/badge/crypto-ML--DSA--65_%C2%B7_FIPS_204-brightgreen)](https://csrc.nist.gov/pubs/fips/204/final)
[![Status](https://img.shields.io/badge/status-pre--testnet-orange)]()

A sovereign settlement layer for autonomous AI agents — identity, escrow, and dispute arbitration, built as a Substrate L1.

---

## The problem

AI agents can already talk to each other. Protocols like MCP and A2A give them a shared language for calling tools and passing messages. What none of them give an agent is a way to *transact* with a stranger and be sure the deal will be honored — without a company sitting in the middle, holding the money, and deciding who was right.

That middle layer is usually a platform: a company's API, a company's escrow account, a company's terms of service. It works, but it means every agent-to-agent interaction ultimately depends on a human-run business being solvent, honest, and available. For a handful of agents doing occasional work, that's tolerable. For an economy where autonomous agents transact with each other continuously, at machine speed, in numbers no support team can individually review, it isn't.

ArthNeura is an attempt to build that missing layer as infrastructure rather than as a platform: identity, money, and dispute resolution that live in code an agent can verify for itself, rather than in a database it has to trust.

---

## Architecture: what's on-chain, what isn't

Not everything about ArthNeura needs to be decentralized — only the parts where trust actually matters.

**On-chain, decentralized** — anything that is a promise: an agent's identity, its reputation, and its money. These live in Substrate pallets. No operator can alter a balance, forge an identity, or overturn a cryptographically-verified dispute outcome. This is the part that has to be trustless, because it's the part being trusted with something.

**Off-chain, centralized** — anything that is convenience: discovery/search interfaces, an indexer that makes chain data queryable fast, a fiat on/off-ramp (a regulated banking activity by law, not something a blockchain can do), SDKs, and documentation. None of this custodies funds or identity — it sits in front of the chain, it doesn't replace it.

The split is an engineering and trust decision, not something an agent or developer needs to think about day to day — from the outside, it's one product.

---

## What's built today

Two pallets, both live-tested against a real node, not just mocked.

### `pallet-agent-registry` — identity and reputation

Gives every autonomous agent a 32-byte decentralized identifier backed by an ML-DSA-65 (FIPS 204) post-quantum signature — not a classical scheme (Ed25519, secp256k1) that Shor's algorithm eventually breaks. Registration works like this: an agent submits its ML-DSA-65 public key and a signature over a chain-bound, time-windowed challenge; the pallet verifies the proof, derives `did = blake2_256("ArthNeura-DID-v1" || pubkey)`, and stores the profile. The 1,952-byte public key is checked once and discarded — only its 32-byte hash lives on-chain permanently.

What it actually does, extrinsic by extrinsic:

- **`register_agent`** — verifies the ML-DSA-65 proof, reserves an anti-sybil deposit, writes the profile
- **`update_profile`** — lets the controller change capabilities, metadata, and display label; identity fields (`did`, `controller`, `registered_at`) are immutable for life
- **`set_agent_status`** — moves an agent between Active and Suspended freely; Revoked is a one-way door — the profile stays on-chain as a permanent audit record, and the deposit is forfeited, not returned
- **`give_star` / `remove_star`** — peer-to-peer reputation, gated by a per-pair cooldown and a same-controller sybil guard, so one operator can't farm reputation across agents it secretly controls
- **`deregister_agent`** — voluntary exit; returns the deposit, prunes the record, frees the storage slot (Revoked agents cannot take this path)
- **`slash_reputation`** — not an extrinsic at all. A non-signed, protocol-internal function that only a trusted caller inside the runtime can invoke (see below) — this is how a losing dispute in the other pallet actually costs an agent something

Full cryptographic design, storage layout, and error reference: [`pallets/pallet-agent-registry`](pallets/pallet-agent-registry).

### `pallet-vector-db` — verifiable data commitments and dispute arbitration

Lets one agent commit to delivering a payload to another, anchored on-chain by a Merkle root, so the delivery is cryptographically checkable rather than trust-based. This is the pallet that gives ArthNeura an actual mechanism for resolving "did the provider actually deliver what they promised" without a human arbitrator.

The commitment lifecycle:

- **`register_commitment`** — provider anchors a Merkle root, chunk count, and expiry for a data delivery to a specific consumer; both parties must be active, verified agents
- **`acknowledge_commitment`** — consumer accepts, moving the commitment from Pending to Active
- **`close_commitment`** — consumer confirms the delivered stream hash matches what was committed; happy path, no dispute
- **`raise_dispute`** — consumer flags a specific chunk index as corrupted, opening a fixed response window for the provider
- **`counter_dispute`** — provider must produce a Merkle inclusion proof for *that exact disputed chunk index*, not just any correct chunk from the tree. This binding is deliberate: an earlier version of this pallet let a provider "win" a dispute by proving an unrelated piece of data was fine, which is a real soundness gap we found and closed before attaching any real consequence to a verdict.
- **`finalize_dispute`** — permissionless; if the provider never counters within the window, the dispute resolves against them
- **`expire_commitment`** — permissionless cleanup for a commitment nobody ever acted on

Every dispute resolves to one of two verdicts, and both sides face a real consequence through the `ReputationHandler` hook into `pallet-agent-registry`: a provider caught delivering bad data loses more reputation than a consumer caught raising a baseless dispute — but both lose something, so disputing has to be a decision made in good faith, not a free option to spam.

**What this pallet does not do yet: move money.** A commitment today is a verified record of delivery, not a transfer of value — closing or losing a dispute changes reputation, not a balance. That's the next thing being built (see below).

### Cross-pallet design

`pallet-vector-db` and `pallet-agent-registry` don't depend on each other directly — each declares a trait (`AgentLookup`, `ReputationHandler`) it needs answered, and the runtime wires a small adapter between them (`runtime/src/adapters/`). Neither pallet knows the other's crate exists. This is the same pattern the next pallet (escrow) will plug into, rather than either existing pallet growing payment logic bolted onto its own storage.

### Off-chain clients

Rust libraries (`offchain-agent-registry`, `offchain-vector-db`) that wrap every extrinsic above: keypair generation, ML-DSA signing, chunk-splitting and Merkle-proof construction, dynamic `subxt` calls against a live node. `offchain-agent-registry` includes an encrypted local keystore (ChaCha20Poly1305, Argon2id-derived key) so an agent's identity survives a process restart instead of being regenerated — and lost — every run.

### Testing

327 unit tests across the workspace (123 in `pallet-agent-registry`, 198 in `pallet-vector-db`, 6 elsewhere) against mock runtimes, plus brutal, sequential, end-to-end lifecycle suites for both pallets that run against a real `--dev` Substrate node — every extrinsic, every documented error path, and the cross-pallet reputation-slash path triggered live through an actual dispute.

cargo test --workspace --lib


---

## Next

**Escrow.** Neither pallet moves ART tokens today — a settled commitment is a verified record, not a payment. A generic, reusable escrow pallet is next: lock funds when a commitment is accepted, release them on clean settlement, refund or redirect them based on a dispute verdict. Built generic from the start, the same way `AgentLookup` and `ReputationHandler` were, so every future commitment type (not just data delivery) can use it without rewriting payment logic.

---

## Repository layout

pallets/pallet-agent-registry/ identity + reputation pallet
pallets/pallet-vector-db/ verifiable data-commitment pallet
runtime/ Substrate runtime, pallet wiring, cross-pallet adapters
node/ solochain node binary
offchain-agent-registry/ Rust client for pallet-agent-registry, encrypted keystore
offchain-vector-db/ Rust client for pallet-vector-db, chunking + Merkle proofs
docs/ setup notes


---

## Running locally

```bash
rustup target add wasm32-unknown-unknown
docker build -t arthneura-node:latest .
docker run -d --name arthneura-dev-node \
  -p 9933:9933 -p 9944:9944 -p 30333:30333 \
  arthneura-node:latest \
  --dev --rpc-external --rpc-cors=all --rpc-methods=unsafe
```

```bash
cargo test --workspace --lib                                    # unit tests, mock runtime
cargo test -p offchain-agent-registry --test live_lifecycle -- --nocapture   # live node, 22 scenarios
cargo test -p offchain-vector-db --test live_lifecycle -- --nocapture        # live node, 12 scenarios
```

---

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE) for the full text.

Copyright 2026 ArthNeura
