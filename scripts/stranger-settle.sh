#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"
CHAIN_WS="${CHAIN_WS:-ws://127.0.0.1:9944}"
PRICE="${PRICE:-1000}"
export CHAIN_WS
echo "=== 0. node ==="
code=$(curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:9944 || true)
if [ "$code" = "000" ] || [ -z "$code" ]; then
  echo "ERROR node is not reachable on 9944"
  exit 1
fi
echo "=== 1. provider agent (Alice) ==="
PROVIDER_LINE="$(SIGNER=alice LABEL=provider cargo run -q -p offchain-agent-registry)"
echo "$PROVIDER_LINE"
PROVIDER_DID="$(echo "$PROVIDER_LINE" | sed -n 's/^DID=//p' | tail -n 1)"
[ -n "$PROVIDER_DID" ] || { echo "ERROR missing provider DID"; exit 1; }
echo "=== 2. consumer agent (Bob) ==="
CONSUMER_LINE="$(SIGNER=bob LABEL=consumer cargo run -q -p offchain-agent-registry)"
echo "$CONSUMER_LINE"
CONSUMER_DID="$(echo "$CONSUMER_LINE" | sed -n 's/^DID=//p' | tail -n 1)"
[ -n "$CONSUMER_DID" ] || { echo "ERROR missing consumer DID"; exit 1; }
echo "=== 3. balances BEFORE ==="
SIGNER=alice ACTION=balance cargo run -q -p offchain-vector-db
SIGNER=bob ACTION=balance cargo run -q -p offchain-vector-db
echo "=== 4. register commitment ==="
REG_OUT="$(ACTION=register SIGNER=alice PROVIDER_DID="$PROVIDER_DID" CONSUMER_DID="$CONSUMER_DID" PRICE="$PRICE" PAYLOAD="hello arthneura" cargo run -q -p offchain-vector-db)"
echo "$REG_OUT"
COMMITMENT_ID="$(echo "$REG_OUT" | sed -n 's/^COMMITMENT_ID=//p' | tail -n 1)"
MERKLE_ROOT="$(echo "$REG_OUT" | sed -n 's/^MERKLE_ROOT=//p' | tail -n 1)"
TOTAL_CHUNKS="$(echo "$REG_OUT" | sed -n 's/^TOTAL_CHUNKS=//p' | tail -n 1)"
[ -n "$COMMITMENT_ID" ] && [ -n "$MERKLE_ROOT" ] || { echo "ERROR register fail"; exit 1; }
echo "=== 5. acknowledge = lock ==="
ACTION=acknowledge SIGNER=bob COMMITMENT_ID="$COMMITMENT_ID" CONSUMER_DID="$CONSUMER_DID" cargo run -q -p offchain-vector-db
echo "=== 6. balances AFTER LOCK ==="
SIGNER=alice ACTION=balance cargo run -q -p offchain-vector-db
SIGNER=bob ACTION=balance cargo run -q -p offchain-vector-db
echo "=== 7. close = release ==="
ACTION=close SIGNER=bob COMMITMENT_ID="$COMMITMENT_ID" CONSUMER_DID="$CONSUMER_DID" MERKLE_ROOT="$MERKLE_ROOT" TOTAL_CHUNKS="$TOTAL_CHUNKS" cargo run -q -p offchain-vector-db
echo "=== 8. balances AFTER SETTLE ==="
SIGNER=alice ACTION=balance cargo run -q -p offchain-vector-db
SIGNER=bob ACTION=balance cargo run -q -p offchain-vector-db
echo
echo "PROVIDER_DID=$PROVIDER_DID"
echo "CONSUMER_DID=$CONSUMER_DID"
echo "COMMITMENT_ID=$COMMITMENT_ID"
echo "MERKLE_ROOT=$MERKLE_ROOT"
echo "TOTAL_CHUNKS=$TOTAL_CHUNKS"
echo "PRICE=$PRICE"
echo "RESULT=SETTLED"
