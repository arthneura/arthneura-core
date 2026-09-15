# Local court demo

Pre-testnet. Laptop and Docker. About fifteen minutes.

If two agents never met and still need to lock money, hand over bytes, and fight about one chunk, that fight is this repo.

The market repo is a bulletin board. It does not hold keys or funds. Do not send extrinsics from there.

## Window

Dev genesis sets the dispute window to 10 blocks (about a minute). The testnet preset keeps 14400. Refund scripts that sleep about 90 seconds only work on --dev. Do not quote the dev window as an SLA.

## Bring the node up

    docker build -t arthneura-node:latest .
    docker rm -f arthneura-dev-node
    docker run -d --name arthneura-dev-node -p 9944:9944 arthneura-node:latest --dev --rpc-external --rpc-cors=all --rpc-methods=unsafe

Wait until it is importing blocks. RPC is ws://127.0.0.1:9944.

## Four scripts, same node, repo root

Pay:

    ./scripts/stranger-settle.sh

You want RESULT=SETTLED. Two agents, one commitment, lock, close.

The window is not decoration:

    ./scripts/stranger-dispute.sh

You want RAISE=OK and finalize rejected with DisputeWindowStillOpen.

Nobody proved, so refund:

    ./scripts/stranger-refund.sh

You want RESULT=REFUNDED. Only honest on --dev.

Buyer raised a fake hash, seller still has the leaf on disk:

    ./scripts/stranger-counter.sh

You want COUNTER=OK and RESULT=COUNTERED.
Chunks come from /tmp/arthneura-offchain-store on this machine.
A second laptop cannot counter a raise it did not register.

## When it blows up

Node not up: run the docker lines above.
Connection refused on 9944: container still starting.
Refund too fast on a long window: you are not on --dev.
Counter cannot find chunks: register and counter must share that tmp store.

## Not in this file

Listings, offers, pull, CSV live in arthneura-market.
No public chain, no token, no UI.

Clone this repo, run the four scripts. That is the court demo.
