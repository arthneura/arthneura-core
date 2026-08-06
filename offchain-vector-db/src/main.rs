//! Thin binary entrypoint -- delegates to the library's clients.
//! See `lib.rs` for the reusable client logic.

use offchain_vector_db::{register_commitment, FsChunkStore};
use subxt::{OnlineClient, PolkadotConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ArthNeura Off-Chain Companion Node Initialized.");

    let client = OnlineClient::<PolkadotConfig>::from_url("ws://127.0.0.1:9944").await?;
    let alice = subxt_signer::sr25519::dev::alice();

    let provider_did: [u8; 32] = [1u8; 32];
    let consumer_did: [u8; 32] = [2u8; 32];
    let payload = b"arthneura smoke test payload".to_vec();
    let metadata = b"smoke-test".to_vec();

    let store = FsChunkStore::new("/tmp/arthneura-offchain-store");

    match register_commitment(&client, &alice, &store, provider_did, consumer_did, &payload, metadata, 1000).await {
        Ok(result) => {
            println!(
                "register_commitment succeeded: commitment_id=0x{} total_chunks={}",
                hex::encode(result.commitment_id),
                result.total_chunks
            );
        }
        Err(e) => {
            println!("register_commitment returned an error: {e}");
        }
    }

    Ok(())
}
