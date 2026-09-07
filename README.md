# arthneura-core

<p>
  <img src="https://img.shields.io/badge/license-Apache--2.0-blue" alt="Apache-2.0" />
  <img src="https://img.shields.io/badge/stack-Substrate-E6007A" alt="Substrate" />
  <img src="https://img.shields.io/badge/Polkadot_SDK-frame--support-e6007a" alt="Polkadot SDK" />
  <img src="https://img.shields.io/badge/lang-Rust-orange" alt="Rust" />
  <img src="https://img.shields.io/badge/crypto-ML--DSA--65_FIPS_204-2ea44f" alt="ML-DSA-65" />
  <img src="https://img.shields.io/badge/status-pre--testnet-e65100" alt="pre-testnet" />
</p>

This is the chain.

If two agents who have never met need to lock money, hand over bytes, and fight about one bad chunk, that fight happens here. Not in a company's ticket queue.

Talking is already solved by other protocols. Settlement is not. That is the only job of this repo.

The marketplace is a different repo: [arthneura-market](https://github.com/arthneura/arthneura-market). It can list work and pass URLs around. It cannot hold keys, cannot hold funds, and cannot decide a dispute. If a PR in that repo starts submitting extrinsics or touching balances, it is the wrong PR.

Pre-testnet. Local `--dev` node. Do not treat this as a public network.

## Clone

```
git clone https://github.com/arthneura/arthneura-core.git
cd arthneura-core
```

You need:

- `git`
- Rust via [rustup](https://rustup.rs)
- Docker

First time on a machine:

```
rustup toolchain install stable
rustup target add wasm32-unknown-unknown
```

macOS / Linux assumed below. Windows notes: [#17](https://github.com/arthneura/arthneura-core/issues/17).

## Run a local node

```
docker build -t arthneura-node:latest .
docker run -d --name arthneura-dev-node \
  -p 9933:9933 -p 9944:9944 -p 30333:30333 \
  arthneura-node:latest \
  --dev --rpc-external --rpc-cors=all --rpc-methods=unsafe
```

If the name is already taken:

```
docker start arthneura-dev-node
```

RPC: `ws://127.0.0.1:9944`

Stop later:

```
docker stop arthneura-dev-node
```

## Tests

Node does not need to be up for mock tests:

```
cargo test --workspace --lib
```

Live suites need the container running:

```
cargo test -p offchain-agent-registry --test live_lifecycle -- --nocapture
cargo test -p offchain-vector-db --test live_lifecycle -- --nocapture
```

If those hang, the node is down.

## What you can do on this chain

1. An agent registers with an ML-DSA-65 key and gets a 32-byte DID.
2. Two agents open a commitment: Merkle root, chunk count, expiry.
3. Payment can sit in escrow while that commitment is live.
4. The consumer closes if the payload matches, or names a chunk index and starts a dispute.
5. The provider has to prove *that* chunk. A proof of some other leaf does not count. That hole existed once. It is closed.
6. Reputation moves through a runtime hook. Nobody calls `slash_reputation` from a wallet.

A single 15-minute path for a stranger (register → lock → deliver → settle) is [#16](https://github.com/arthneura/arthneura-core/issues/16). Not in this file yet on purpose.

## The three pallets

They do not import each other. The runtime wires them in `runtime/src/adapters/`. If you feel like importing the registry crate into vector-db, stop. Add a trait and an adapter.

### pallet-agent-registry

```
did = blake2_256("ArthNeura-DID-v1" || pubkey)
```

The 1,952-byte public key is checked at register and dropped. Storage keeps the hash.

| call | what it does |
| --- | --- |
| `register_agent` | proof of key + deposit + profile |
| `update_profile` | label / capabilities. identity fields stay put |
| `set_agent_status` | Active or Suspended. Revoked is one way. deposit is lost |
| `give_star` / `remove_star` | peer score, cooldown + same-controller check |
| `deregister_agent` | leave and take the deposit, unless Revoked |
| `slash_reputation` | runtime only. not a public extrinsic |

More: `pallets/pallet-agent-registry/README.md`

### pallet-vector-db

The deal object.

| call | what it does |
| --- | --- |
| `register_commitment` | provider anchors the root |
| `acknowledge_commitment` | consumer accepts |
| `close_commitment` | consumer says it matched |
| `raise_dispute` | consumer points at one chunk index |
| `counter_dispute` | provider proves that index |
| `finalize_dispute` | anyone, if the window died |
| `expire_commitment` | leftover cleanup |

More: `pallets/pallet-vector-db/README.md`

### pallet-escrow

Lock, release, refund. Generic, so the next commitment type does not invent a second money pallet.

Wired so a closed or disputed commitment can move value, not only a reputation integer.

Code: `pallets/pallet-escrow/`

## Off-chain Rust

`offchain-agent-registry` — keygen, register, status. Encrypted keystore on disk (ChaCha20Poly1305, Argon2id) so a process restart does not mint a new DID.

`offchain-vector-db` — split payload, build tree, talk to the node.

Local env files live under `env-setup/`. Those are machine secrets, not protocol.

## Repo map

```
pallets/           court
runtime/           wiring only
node/              binary inside the docker image
offchain-*/        clients
docs/              extra setup notes
env-setup/         local env, not committed secrets if you can help it
```

## If you want to help

Read open issues before writing code.

- [#16](https://github.com/arthneura/arthneura-core/issues/16) — 15-minute demo path
- [#17](https://github.com/arthneura/arthneura-core/issues/17) — Windows / PowerShell env

Docs-only PRs are fine. Runtime changes need a test that fails without the patch.

In the PR say: which pallet or client, mock tests or live tests.

Do not add a fourth pallet in a drive-by.

## What this repo is not

Not a chat protocol.  
Not a hosted escrow company.  
Not the marketplace.  
Not mainnet.

## License

Apache-2.0. See `LICENSE`.

Copyright 2026 ArthNeura
