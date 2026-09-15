#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
curl -sf -o /dev/null http://127.0.0.1:9944 || true
P="$(SIGNER=alice LABEL=provider cargo run -q -p offchain-agent-registry)"
C="$(SIGNER=bob LABEL=consumer cargo run -q -p offchain-agent-registry)"
echo "$P"
echo "$C"
PROVIDER_DID="$(echo "$P" | sed -n "s/^DID=//p" | tail -n 1)"
CONSUMER_DID="$(echo "$C" | sed -n "s/^DID=//p" | tail -n 1)"
REG="$(ACTION=register SIGNER=alice PROVIDER_DID="$PROVIDER_DID" CONSUMER_DID="$CONSUMER_DID" PRICE=1000 PAYLOAD="hello arthneura" cargo run -q -p offchain-vector-db)"
echo "$REG"
COMMITMENT_ID="$(echo "$REG" | sed -n "s/^COMMITMENT_ID=//p" | tail -n 1)"
TOTAL_CHUNKS="$(echo "$REG" | sed -n "s/^TOTAL_CHUNKS=//p" | tail -n 1)"
ACTION=acknowledge SIGNER=bob COMMITMENT_ID="$COMMITMENT_ID" CONSUMER_DID="$CONSUMER_DID" cargo run -q -p offchain-vector-db
ACTION=raise SIGNER=bob COMMITMENT_ID="$COMMITMENT_ID" CONSUMER_DID="$CONSUMER_DID" CHUNK_INDEX=0 TOTAL_CHUNKS="$TOTAL_CHUNKS" RECEIVED_CHUNK_HASH=0000000000000000000000000000000000000000000000000000000000000001 cargo run -q -p offchain-vector-db
echo "=== counter (Alice proves leaf 0 from local store) ==="
ACTION=counter SIGNER=alice COMMITMENT_ID="$COMMITMENT_ID" PROVIDER_DID="$PROVIDER_DID" CHUNK_INDEX=0 TOTAL_CHUNKS="$TOTAL_CHUNKS" cargo run -q -p offchain-vector-db
echo "COMMITMENT_ID=$COMMITMENT_ID"
echo "RESULT=COUNTERED"
