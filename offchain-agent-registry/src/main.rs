//! Thin binary entrypoint -- delegates to the library's `register_agent`.
//! See `lib.rs` for the reusable client logic.

use offchain_agent_registry::register_agent;
use subxt::{OnlineClient, PolkadotConfig};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ArthNeura Off-Chain Agent Registry Client Initialized.");

    let client = OnlineClient::<PolkadotConfig>::from_url("ws://127.0.0.1:9944").await?;
    let alice = subxt_signer::sr25519::dev::alice();

    match register_agent(&client, &alice, 0b1, b"smoke-test-agent".to_vec(), b"alice-agent".to_vec()).await {
        Ok(agent) => println!("register_agent succeeded: did=0x{}", hex::encode(agent.did)),
        Err(e) => println!("register_agent returned an error: {e}"),
    }

    Ok(())
}
