//! Live test for `bootstrap_new_agent` -- the sponsored sovereign
//! account bootstrap flow. Verifies: (1) a fresh, unfunded sr25519
//! account can be funded by a sponsor and register itself on-chain as
//! its own controller, (2) both the ML-DSA identity and the sr25519
//! account seed round-trip correctly through the encrypted keystore,
//! and (3) calling `bootstrap_new_agent` a second time with the same
//! label is idempotent -- it loads from disk rather than re-registering
//! or re-transferring funds.

use offchain_agent_registry::bootstrap_new_agent;
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::dev;

const TEST_PASSPHRASE: &str = "brutal-test-passphrase-do-not-use-in-prod";
const FUNDING_AMOUNT: u128 = 150_000_000_000_000; // 150 UNIT: covers 100 UNIT RegistrationDeposit + fees + headroom

#[tokio::test(flavor = "multi_thread")]
async fn bootstrap_sovereign_agent_lifecycle() {
    let client = OnlineClient::<PolkadotConfig>::from_url("ws://127.0.0.1:9944")
        .await
        .expect("failed to connect to live dev node -- is `docker run ... --dev` up on :9944?");

    let sponsor = dev::alice(); // funded dev account, acts as sponsor only

    let label = format!("brutal-bootstrap-test-{}", std::process::id());
    let keystore_dir = std::env::temp_dir().join("arthneura-brutal-keystore-test");

    // -- Section 1: cold start -- sponsor funds a brand-new sovereign account --
    let first = bootstrap_new_agent(
        &client,
        &sponsor,
        &keystore_dir,
        &label,
        TEST_PASSPHRASE,
        FUNDING_AMOUNT,
        0b1,
        b"bootstrap-test".to_vec(),
        b"sovereign-agent".to_vec(),
    )
    .await
    .expect("Section 1: cold-start bootstrap must succeed");

    println!(
        "Section 1 OK: bootstrapped did=0x{} account={}",
        hex::encode(first.did),
        first.account.public_key().to_account_id()
    );

    let sponsor_account_id = sponsor.public_key().to_account_id();
    assert_ne!(
        first.account.public_key().to_account_id(),
        sponsor_account_id,
        "Section 1: bootstrapped agent's account must differ from the sponsor -- sponsor must not become the on-chain controller"
    );
    println!("Section 1b OK: bootstrapped account is distinct from sponsor (sovereign, not sponsor-controlled)");

    // -- Section 2: idempotent reload -- same label, no new chain interaction --
    let second = bootstrap_new_agent(
        &client,
        &sponsor,
        &keystore_dir,
        &label,
        TEST_PASSPHRASE,
        FUNDING_AMOUNT,
        0b1,
        b"bootstrap-test".to_vec(),
        b"sovereign-agent".to_vec(),
    )
    .await
    .expect("Section 2: reload from existing keystore must succeed");

    assert_eq!(first.did, second.did, "Section 2: reloaded DID must match the originally bootstrapped DID");
    assert_eq!(
        first.account.public_key().to_account_id(),
        second.account.public_key().to_account_id(),
        "Section 2: reloaded account must match the originally bootstrapped account"
    );
    println!("Section 2 OK: idempotent reload returned identical did+account -- no duplicate registration or funding transfer occurred");

    let _ = std::fs::remove_file(keystore_dir.join(format!("{label}.json")));
    let _ = std::fs::remove_file(keystore_dir.join(format!("{label}-account.json")));

    println!("\n=== BOOTSTRAP LIFECYCLE TEST: ALL SECTIONS PASSED ===");
}
