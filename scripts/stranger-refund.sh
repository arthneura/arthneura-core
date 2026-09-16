#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
export CHAIN_WS="${CHAIN_WS:-ws://127.0.0.1:9944}"
PRICE="${PRICE:-1000}"
BAD_HASH="0000000000000000000000000000000000000000000000000000000000000001"

echo "=== 0. node ==="
code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:9944 || true)
if [ "$code" = "000" ] || [ -z "$code" ]; then
  echo "ERROR node is not reachable on 9944"
  exit 1
fi

echo "=== 1-2. agents ==="
PROVIDER_LINE="$(SIGNER=alice LABEL=provider cargo run -q -p offchain-agent-registry)"
CONSUMER_LINE="$(SIGNER=bob LABEL=consumer cargo run -q -p offchain-agent-registry)"
echo "$PROVIDER_LINE"
echo "$CONSUMER_LINE"
PROVIDER_DID="$(echo "$PROVIDER_LINE" | sed -n 's/^DID=//p' | tail -n 1)"
CONSUMER_DID="$(echo "$CONSUMER_LINE" | sed -n 's/^DID=//p' | tail -n 1)"

echo "=== 3. register + lock ==="
REG_OUT="$(ACTION=register SIGNER=alice PROVIDER_DID="$PROVIDER_DID" CONSUMER_DID="$CONSUMER_DID" PRICE="$PRICE" PAYLOAD="hello arthneura" cargo run -q -p offchain-vector-db)"
echo "$REG_OUT"
COMMITMENT_ID="$(echo "$REG_OUT" | sed -n 's/^COMMITMENT_ID=//p' | tail -n 1)"
TOTAL_CHUNKS="$(echo "$REG_OUT" | sed -n 's/^TOTAL_CHUNKS=//p' | tail -n 1)"
ACTION=acknowledge SIGNER=bob COMMITMENT_ID="$COMMITMENT_ID" CONSUMER_DID="$CONSUMER_DID" cargo run -q -p offchain-vector-db

echo "=== 4. balances AFTER LOCK ==="
SIGNER=bob ACTION=balance cargo run -q -p offchain-vector-db

echo "=== 5. raise ==="
ACTION=raise SIGNER=bob COMMITMENT_ID="$COMMITMENT_ID" CONSUMER_DID="$CONSUMER_DID" CHUNK_INDEX=0 TOTAL_CHUNKS="$TOTAL_CHUNKS" RECEIVED_CHUNK_HASH="$BAD_HASH" cargo run -q -p offchain-vector-db

echo "=== 6. wait ~15 blocks (dev window=10) ==="
sleep 90

echo "=== 7. finalize ==="
ACTION=finalize SIGNER=bob COMMITMENT_ID="$COMMITMENT_ID" cargo run -q -p offchain-vector-db

echo "=== 8. balances AFTER REFUND ==="
SIGNER=alice ACTION=balance cargo run -q -p offchain-vector-db
SIGNER=bob ACTION=balance cargo run -q -p offchain-vector-db

echo
echo "COMMITMENT_ID=$COMMITMENT_ID"
echo "RESULT=REFUNDED"
