//! Thin binary entrypoint -- delegates to the library's `register_agent`.
//! See `lib.rs` for the reusable client logic.

use offchain_agent_registry::register_agent;
use subxt::{OnlineClient, PolkadotConfig};

fn signer_from_env() -> subxt_signer::sr25519::Keypair {
    match std::env::var("SIGNER").unwrap_or_else(|_| "alice".into()).as_str() {
        "bob" => subxt_signer::sr25519::dev::bob(),
        _ => subxt_signer::sr25519::dev::alice(),
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("ArthNeura Off-Chain Agent Registry Client Initialized.");

    let ws = std::env::var("CHAIN_WS").unwrap_or_else(|_| "ws://127.0.0.1:9944".into());
    let client = OnlineClient::<PolkadotConfig>::from_url(&ws).await?;
    let signer = signer_from_env();
    let label = std::env::var("LABEL").unwrap_or_else(|_| "alice-agent".into());

    match register_agent(
        &client,
        &signer,
        0b1,
        b"smoke-test-agent".to_vec(),
        label.into_bytes(),
    )
    .await
    {
        Ok(agent) => {
            println!("register_agent succeeded: did=0x{}", hex::encode(agent.did));
            println!("DID=0x{}", hex::encode(agent.did));
        }
        Err(e) => {
            eprintln!("register_agent returned an error: {e}");
            std::process::exit(1);
        }
    }

    Ok(())
}
