# 15-minute local demo

Pre-testnet. Local --dev node only. Not a public network.

This is the map for a first run of arthneura-core.

Path the court is built for:

register two agents → lock (escrow) → deliver bytes → settle
or dispute one chunk index.

You do not need the market repo for this demo.

## 0. What you need

- git
- Docker Desktop running
- rustup (https://rustup.rs)
- 8 GB RAM better, first docker build is slow

macOS / Linux terminal. Windows: PowerShell notes in issue
https://github.com/arthneura/arthneura-core/issues/17
Do not paste export FOO=bar into cmd.exe.

## 1. Clone

    git clone https://github.com/arthneura/arthneura-core.git
    cd arthneura-core

## 2. Rust target

    rustup show
    rustup target add wasm32-unknown-unknown

The repo has rust-toolchain.toml. rustup will pick the pin.

## 3. Start the node

First time (slow — image build):

    docker build -t arthneura-node:latest .
    docker run -d --name arthneura-dev-node \
      -p 9933:9933 -p 9944:9944 -p 30333:30333 \
      arthneura-node:latest \
      --dev --rpc-external --rpc-cors=all --rpc-methods=unsafe

Later days:

    docker start arthneura-dev-node

If name already in use:

    docker start arthneura-dev-node

RPC:

    ws://127.0.0.1:9944

Wait ~20 seconds after start before tests.

## 4. Prove the machine works (no node)

    cargo test --workspace --lib

This hits mock runtimes. Fail here = toolchain / compile, not the chain.

## 5. Prove the court on the live node

Node must be up.

    cargo test -p offchain-agent-registry --test live_lifecycle -- --nocapture
    cargo test -p offchain-vector-db --test live_lifecycle -- --nocapture

Exit 0 = identity + commitment + dispute path actually talked to --dev.

What those suites walk:

1. Register agents (ML-DSA-65 DID, deposit, status).
2. Commit a Merkle root and chunk count to a consumer.
3. Acknowledge / close on the happy path.
4. Or raise a dispute on one chunk index. Provider must prove that index, not some other leaf.

Escrow (lock / release / refund) is in this repo and wired in the runtime.
Live client coverage for escrow is thinner than registry + vector-db — do not invent a fourth pallet in a first PR.

Offchain crates:

    offchain-agent-registry/
    offchain-vector-db/

Binaries that read stamp / env for register, acknowledge, close live in those crates (see recent commits). This file is the order. Those binaries are the buttons. Copy env names from the crate, not from memory.

## 6. Optional: bazaar after the court

https://github.com/arthneura/arthneura-market

Postgres + Go indexer + API. Listings and offers only. submit stays false.
Curl cookbook: https://github.com/arthneura/arthneura-market/issues/30

Skip this in the first 15 minutes.

## 7. Stop

    docker stop arthneura-dev-node

Do not docker rm unless you want a clean slate.

## 8. If it breaks

- wasm target missing → step 2
- rustc version weird → rust-toolchain.toml + rustup show
- port 9944 busy → stop the other node
- live tests hang → node not up or still booting
- Windows path / env → issue #17
- “how do I run one extrinsic” → open the matching offchain crate, do not guess flags

## 9. What this demo is not

Not testnet.
Not a token faucet.
Not “the market submitted the extrinsic.”
Not permission to add a fourth pallet in a drive-by PR.
