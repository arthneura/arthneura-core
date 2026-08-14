//! Brutal, live end-to-end lifecycle test suite for `pallet_vector_db`.
//! Runs against a real `--dev` node (`ws://127.0.0.1:9944`) — not a mock,
//! not `#[test]` unit logic. Every scenario submits a real signed
//! extrinsic and asserts on the real pallet-level error/success outcome.
//!
//! Deliberately a single sequential test function rather than many
//! `#[tokio::test]` functions: parallel tests sharing dev accounts would
//! race on account nonces and on shared on-chain commitment state. Each
//! section is numbered and independently readable; a failure at section N
//! pinpoints exactly which extrinsic/scenario broke.

use offchain_agent_registry::register_agent;
use offchain_vector_db::{
    acknowledge_commitment, close_commitment, counter_dispute, expire_commitment, finalize_dispute,
    raise_dispute, register_commitment, FsChunkStore,
};
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::dev;

/// Asserts that a `Result`'s error `Display` output contains the expected
/// on-chain pallet error variant name. Substring match (not exact) because
/// the client wraps errors opaquely as `subxt::Error` -- we don't decode
/// into a typed `Error<T>` enum client-side, matching the pattern already
/// used throughout the client (errors surface via `subxt::Error`, not
/// re-modeled).
fn assert_pallet_error<T: std::fmt::Debug>(result: Result<T, impl std::fmt::Display>, expected_variant: &str) {
    match result {
        Ok(v) => panic!("expected pallet error '{expected_variant}', got success: {v:?}"),
        Err(e) => {
            let msg = e.to_string();
            assert!(
                msg.contains(expected_variant),
                "expected error containing '{expected_variant}', got: '{msg}'"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn brutal_lifecycle_suite() {
    let client = OnlineClient::<PolkadotConfig>::from_url("ws://127.0.0.1:9944")
        .await
        .expect("failed to connect to live dev node -- is `docker run ... --dev` up on :9944?");

    let alice = dev::alice(); // provider controller
    let bob = dev::bob(); // consumer controller
    
    // ---------------------------------------------------------------
    // Section 0: Register two eligible agents (provider, consumer)
    // ---------------------------------------------------------------
    let provider_agent = register_agent(&client, &alice, 0b1, b"provider".to_vec(), b"provider-agent".to_vec())
        .await
        .expect("Section 0: provider registration must succeed");
    let consumer_agent = register_agent(&client, &bob, 0b1, b"consumer".to_vec(), b"consumer-agent".to_vec())
        .await
        .expect("Section 0: consumer registration must succeed");

    let provider_did = provider_agent.did;
    let consumer_did = consumer_agent.did;
    println!("Section 0 OK: provider_did=0x{} consumer_did=0x{}", hex::encode(provider_did), hex::encode(consumer_did));

    let store = FsChunkStore::new("/tmp/arthneura-brutal-test-store");

    // ---------------------------------------------------------------
    // Section 1 (error): SelfTrade -- provider_did == consumer_did
    // ---------------------------------------------------------------
    let self_trade_result = register_commitment(
        &client,
        &alice,
        &store,
        provider_did,
        provider_did,
        b"self trade payload".to_vec().as_slice(),
        b"meta".to_vec(),
        1000, 500u128)
    .await;
    assert_pallet_error(self_trade_result, "SelfTrade");
    println!("Section 1 OK: SelfTrade rejected as expected");

    // ---------------------------------------------------------------
    // Section 2 (error): ProviderNotEligible -- unregistered DID
    // ---------------------------------------------------------------
    let unregistered_did: [u8; 32] = [0xEE; 32];
    let ineligible_result = register_commitment(
        &client,
        &alice,
        &store,
        unregistered_did,
        consumer_did,
        b"ineligible payload".to_vec().as_slice(),
        b"meta".to_vec(),
        1000, 500u128)
    .await;
    assert_pallet_error(ineligible_result, "ProviderNotEligible");
    println!("Section 2 OK: ProviderNotEligible rejected as expected");

    // ---------------------------------------------------------------
    // Section 3 (happy path A): register -> acknowledge -> close
    // ---------------------------------------------------------------
    let payload_a = b"happy path A payload -- settled cleanly".to_vec();
    let commit_a = register_commitment(&client, &alice, &store, provider_did, consumer_did, &payload_a, b"meta-a".to_vec(), 1000, 500u128)
        .await
        .expect("Section 3: register_commitment must succeed with eligible DIDs");
    println!("Section 3.1 OK: registered commitment_id=0x{}", hex::encode(commit_a.commitment_id));

    // Section 4 (error): wrong caller acknowledges -- Charlie is not consumer's controller
    let wrong_ack = acknowledge_commitment(&client, &alice, commit_a.commitment_id, consumer_did).await;
    assert_pallet_error(wrong_ack, "NotConsumer");
    println!("Section 4 OK: wrong-caller acknowledge_commitment rejected as expected");

    // Section 3.2: correct caller acknowledges
    acknowledge_commitment(&client, &bob, commit_a.commitment_id, consumer_did)
        .await
        .expect("Section 3.2: acknowledge_commitment must succeed for the real consumer controller");
    println!("Section 3.2 OK: acknowledged");

    // Section 5 (error): double-acknowledge on an already-Active commitment
    let double_ack = acknowledge_commitment(&client, &bob, commit_a.commitment_id, consumer_did).await;
    assert_pallet_error(double_ack, "NotPending");
    println!("Section 5 OK: double-acknowledge rejected as expected");

    // Section 6 (error): close_commitment with a wrong final_stream_hash
    let wrong_hash: [u8; 32] = [0x11; 32];
    let bad_close = close_commitment(&client, &bob, commit_a.commitment_id, consumer_did, wrong_hash, commit_a.total_chunks).await;
    assert_pallet_error(bad_close, "StreamHashMismatch");
    println!("Section 6 OK: StreamHashMismatch rejected as expected");

    // Section 3.3: correct close_commitment
    close_commitment(&client, &bob, commit_a.commitment_id, consumer_did, commit_a.merkle_root, commit_a.total_chunks)
        .await
        .expect("Section 3.3: close_commitment must succeed with the correct stream hash");
    println!("Section 3.3 OK: closed -- happy path A complete");

    // ---------------------------------------------------------------
    // Section 7 (error): close_commitment on a still-Pending commitment
    // (register a fresh one, do NOT acknowledge, try to close directly)
    // ---------------------------------------------------------------
    let payload_pending = b"pending, never acknowledged".to_vec();
    let commit_pending = register_commitment(&client, &alice, &store, provider_did, consumer_did, &payload_pending, b"meta-p".to_vec(), 1000, 500u128)
        .await
        .expect("Section 7 setup: register_commitment must succeed");
    let close_while_pending = close_commitment(&client, &bob, commit_pending.commitment_id, consumer_did, commit_pending.merkle_root, commit_pending.total_chunks).await;
    assert_pallet_error(close_while_pending, "NotActive");
    println!("Section 7 OK: close_commitment on Pending commitment rejected as expected");

    // ---------------------------------------------------------------
    // Section 8 (error): expire_commitment before expiry has passed
    // ---------------------------------------------------------------
    let too_early_expire = expire_commitment(&client, &alice, commit_pending.commitment_id).await;
    assert_pallet_error(too_early_expire, "NotYetExpired");
    println!("Section 8 OK: premature expire_commitment rejected as expected");

    // ---------------------------------------------------------------
    // Section 9 (happy path B): register -> acknowledge -> raise_dispute
    //                            -> counter_dispute (provider wins)
    // ---------------------------------------------------------------
    let payload_b = b"happy path B payload -- disputed then refuted".to_vec();
    let commit_b = register_commitment(&client, &alice, &store, provider_did, consumer_did, &payload_b, b"meta-b".to_vec(), 1000, 500u128)
        .await
        .expect("Section 9.1: register_commitment must succeed");
    acknowledge_commitment(&client, &bob, commit_b.commitment_id, consumer_did)
        .await
        .expect("Section 9.2: acknowledge_commitment must succeed");
    println!("Section 9.1-9.2 OK: registered + acknowledged commit_b=0x{}", hex::encode(commit_b.commitment_id));

    let bogus_received_hash: [u8; 32] = [0x22; 32];
    raise_dispute(&client, &bob, commit_b.commitment_id, consumer_did, 0u64, bogus_received_hash, commit_b.total_chunks)
        .await
        .expect("Section 9.3: raise_dispute must succeed on an Active commitment");
    println!("Section 9.3 OK: dispute raised");

    // Section 10 (error): raising a second dispute on the same commitment
    let double_dispute = raise_dispute(&client, &bob, commit_b.commitment_id, consumer_did, 0u64, bogus_received_hash, commit_b.total_chunks).await;
    assert_pallet_error(double_dispute, "NotActive"); // corrected: raise_dispute flips status Active->Disputed, so a second attempt fails the status guard, not a dedicated "already raised" check
    println!("Section 10 OK: double-dispute rejected as expected");

    // Section 11 (error): finalize_dispute before the counter_deadline lapses
    let too_early_finalize = finalize_dispute(&client, &alice, commit_b.commitment_id).await;
    assert_pallet_error(too_early_finalize, "DisputeWindowStillOpen");
    println!("Section 11 OK: premature finalize_dispute rejected as expected");

    // Section 9.4: provider counters the dispute with a valid proof
    counter_dispute(&client, &alice, &store, commit_b.commitment_id, provider_did, 0, commit_b.total_chunks)
        .await
        .expect("Section 9.4: counter_dispute must succeed with a valid Merkle proof");
    println!("Section 9.4 OK: dispute countered -- happy path B complete");

    // Section 12 (error): counter_dispute on a commitment with no open dispute
    let no_dispute = counter_dispute(&client, &alice, &store, commit_a.commitment_id, provider_did, 0, commit_a.total_chunks).await;
    assert_pallet_error(no_dispute, "NotDisputed");
    println!("Section 12 OK: counter_dispute without an open dispute rejected as expected");

    println!("\n=== BRUTAL LIFECYCLE SUITE: ALL 12 SECTIONS PASSED ===");
}
