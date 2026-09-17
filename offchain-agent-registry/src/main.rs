//! Thin binary. Uses register_or_load_agent so a DID survives restarts.

use std::path::PathBuf;

use offchain_agent_registry::{keystore, register_or_load_agent};
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
    let who = std::env::var("SIGNER").unwrap_or_else(|_| "alice".into());
    let key_label = std::env::var("KEY_LABEL").unwrap_or(who);
    let label = std::env::var("LABEL").unwrap_or_else(|_| format!("{key_label}-agent"));
    let passphrase = std::env::var("KEYSTORE_PASS").unwrap_or_else(|_| "dev-passphrase".into());
    let keystore_dir: PathBuf = match std::env::var("KEYSTORE_DIR") {
        Ok(s) => PathBuf::from(s),
        Err(_) => keystore::default_keystore_dir()?,
    };

    let existed = keystore::identity_exists(&keystore_dir, &key_label);
    match register_or_load_agent(
        &client,
        &signer,
        &keystore_dir,
        &key_label,
        &passphrase,
        0b1,
        b"smoke-test-agent".to_vec(),
        label.into_bytes(),
    )
    .await
    {
        Ok(agent) => {
            println!("DID=0x{}", hex::encode(agent.did));
            println!("IDENTITY={}", if existed { "loaded" } else { "registered" });
            println!("KEYSTORE={}", keystore_dir.join(format!("{key_label}.json")).display());
        }
        Err(e) => {
            eprintln!("register_or_load_agent failed: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
}
