//! Thin binary. ACTION=register (default) or ACTION=acknowledge.
//! Keys stay in this process. Market never sees them.

use offchain_vector_db::{acknowledge_commitment, register_commitment, FsChunkStore};
use subxt::{OnlineClient, PolkadotConfig};

fn hex32(name: &str) -> Result<[u8; 32], Box<dyn std::error::Error>> {
    let raw = std::env::var(name)?;
    let b = hex::decode(raw.trim())?;
    if b.len() != 32 {
        return Err(format!("{name} must be 32-byte hex").into());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&b);
    Ok(out)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ws = std::env::var("CHAIN_WS").unwrap_or_else(|_| "ws://127.0.0.1:9944".into());
    let action = std::env::var("ACTION").unwrap_or_else(|_| "register".into());
    let client = OnlineClient::<PolkadotConfig>::from_url(&ws).await?;

    if action == "acknowledge" {
        let commitment_id = hex32("COMMITMENT_ID")?;
        let consumer_did = hex32("CONSUMER_DID")?;
        let who = std::env::var("SIGNER").unwrap_or_else(|_| "bob".into());
        let signer = match who.as_str() {
            "alice" => subxt_signer::sr25519::dev::alice(),
            _ => subxt_signer::sr25519::dev::bob(),
        };
        match acknowledge_commitment(&client, &signer, commitment_id, consumer_did).await {
            Ok(()) => {
                println!(
                    "acknowledge_commitment succeeded: commitment_id=0x{}",
                    hex::encode(commitment_id)
                );
            }
            Err(e) => {
                eprintln!("acknowledge_commitment returned an error: {e}");
                std::process::exit(1);
            }
        }
        return Ok(());
    }

    let provider_did = hex32("PROVIDER_DID")?;
    let consumer_did = hex32("CONSUMER_DID")?;
    let expires: u32 = std::env::var("EXPIRES_IN_BLOCKS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);
    let price: u128 = std::env::var("PRICE")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(75);
    let payload = match std::env::var("PAYLOAD") {
        Ok(s) if !s.is_empty() => s.into_bytes(),
        _ => b"arthneura stamp payload".to_vec(),
    };
    let alice = subxt_signer::sr25519::dev::alice();
    let store = FsChunkStore::new("/tmp/arthneura-offchain-store");
    match register_commitment(
        &client,
        &alice,
        &store,
        provider_did,
        consumer_did,
        &payload,
        b"from-stamp".to_vec(),
        expires,
        price,
    )
    .await
    {
        Ok(result) => {
            println!(
                "register_commitment succeeded: commitment_id=0x{} merkle_root=0x{} total_chunks={}",
                hex::encode(result.commitment_id),
                hex::encode(result.merkle_root),
                result.total_chunks
            );
        }
        Err(e) => {
            eprintln!("register_commitment returned an error: {e}");
            std::process::exit(1);
        }
    }
    Ok(())
}
