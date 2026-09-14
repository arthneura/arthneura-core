#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export CHAIN_WS="${CHAIN_WS:-ws://127.0.0.1:9944}"
PRICE="${PRICE:-1000}"
BAD_HASH="0000000000000000000000000000000000000000000000000000000000000001"

echo "=== 0. node ==="
if ! docker ps --format '{{.Names}}' | grep -q '^arthneura-dev-node$'; then
  echo "ERROR node nahi chal raha."
  exit 1
fi

echo "=== 1. provider ==="
PROVIDER_LINE="$(SIGNER=alice LABEL=provider cargo run -q -p offchain-agent-registry)"
echo "$PROVIDER_LINE"
PROVIDER_DID="$(echo "$PROVIDER_LINE" | sed -n 's/^DID=//p' | tail -n 1)"

echo "=== 2. consumer ==="
CONSUMER_LINE="$(SIGNER=bob LABEL=consumer cargo run -q -p offchain-agent-registry)"
echo "$CONSUMER_LINE"
CONSUMER_DID="$(echo "$CONSUMER_LINE" | sed -n 's/^DID=//p' | tail -n 1)"

echo "=== 3. register ==="
REG_OUT="$(ACTION=register SIGNER=alice PROVIDER_DID="$PROVIDER_DID" CONSUMER_DID="$CONSUMER_DID" PRICE="$PRICE" PAYLOAD="hello arthneura" cargo run -q -p offchain-vector-db)"
echo "$REG_OUT"
COMMITMENT_ID="$(echo "$REG_OUT" | sed -n 's/^COMMITMENT_ID=//p' | tail -n 1)"
TOTAL_CHUNKS="$(echo "$REG_OUT" | sed -n 's/^TOTAL_CHUNKS=//p' | tail -n 1)"

echo "=== 4. lock ==="
ACTION=acknowledge SIGNER=bob COMMITMENT_ID="$COMMITMENT_ID" CONSUMER_DID="$CONSUMER_DID" cargo run -q -p offchain-vector-db

echo "=== 5. balances AFTER LOCK ==="
SIGNER=bob ACTION=balance cargo run -q -p offchain-vector-db

echo "=== 6. raise dispute (galat chunk hash) ==="
ACTION=raise SIGNER=bob \
COMMITMENT_ID="$COMMITMENT_ID" \
CONSUMER_DID="$CONSUMER_DID" \
CHUNK_INDEX=0 \
TOTAL_CHUNKS="$TOTAL_CHUNKS" \
RECEIVED_CHUNK_HASH="$BAD_HASH" \
cargo run -q -p offchain-vector-db

echo "=== 7. finalize abhi (window 14400 — fail expected) ==="
set +e
ACTION=finalize SIGNER=bob COMMITMENT_ID="$COMMITMENT_ID" cargo run -q -p offchain-vector-db
FIN_OK=$?
set -e

echo
echo "PROVIDER_DID=$PROVIDER_DID"
echo "CONSUMER_DID=$CONSUMER_DID"
echo "COMMITMENT_ID=$COMMITMENT_ID"
echo "FINALIZE_EXIT=$FIN_OK"
echo "RESULT=DISPUTED"
