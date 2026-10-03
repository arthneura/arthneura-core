//! Local door. Alice pays the fee. The stranger keeps the key.
//! Bind 127.0.0.1 only. Do not put this on 0.0.0.0.

use std::io::{Read, Write};
use std::net::TcpListener;

use offchain_agent_registry::submit_signed_registration;
use serde_json::json;
use subxt::{OnlineClient, PolkadotConfig};

fn signer() -> subxt_signer::sr25519::Keypair {
    subxt_signer::sr25519::dev::alice()
}

fn respond(mut stream: impl Write, status: &str, body: &str) {
    let msg = format!(
        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
        body.len()
    );
    let _ = stream.write_all(msg.as_bytes());
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let ws = std::env::var("CHAIN_WS").unwrap_or_else(|_| "ws://127.0.0.1:9944".into());
    let client = OnlineClient::<PolkadotConfig>::from_url(&ws).await?;
    let listener = TcpListener::bind("127.0.0.1:8790")?;
    println!("REGISTER_DOOR=127.0.0.1:8790");
    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut buf = Vec::new();
        let mut tmp = [0u8; 1024];
        loop {
            let n = stream.read(&mut tmp).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if buf.windows(4).any(|w| w == b"\r\n\r\n") || buf.len() > 8192 {
                break;
            }
        }
        if buf.is_empty() {
            continue;
        }
        let req = String::from_utf8_lossy(&buf);
        let line = req.lines().next().unwrap_or("");
        if line.starts_with("GET /v1/register/challenge") {
            let block = client.blocks().at_latest().await?;
            let body = json!({
                "genesis": hex::encode(client.genesis_hash().0),
                "controller": hex::encode(signer().public_key().0),
                "block": block.number(),
                "hash": hex::encode(block.hash().0),
            })
            .to_string();
            respond(&mut stream, "200 OK", &body);
            continue;
        }
        if line.starts_with("POST /v1/register") {
            let raw = req.split("\r\n\r\n").nth(1).unwrap_or("");
            let v: serde_json::Value = match serde_json::from_str(raw) {
                Ok(v) => v,
                Err(_) => {
                    respond(&mut stream, "400 Bad Request", r#"{"error":"bad json"}"#);
                    continue;
                }
            };
            let pubkey = hex::decode(v["pubkey"].as_str().unwrap_or("").trim_start_matches("0x")).unwrap_or_default();
            let signature = hex::decode(v["signature"].as_str().unwrap_or("").trim_start_matches("0x")).unwrap_or_default();
            let signed_at_block = v["signed_at_block"].as_u64().unwrap_or(0) as u32;
            let label = v["label"].as_str().unwrap_or("").as_bytes().to_vec();
            if pubkey.is_empty() || signature.is_empty() || signed_at_block == 0 {
                respond(&mut stream, "400 Bad Request", r#"{"error":"pubkey, signature, signed_at_block required"}"#);
                continue;
            }
            match submit_signed_registration(
                &client,
                &signer(),
                pubkey,
                signature,
                signed_at_block,
                1,
                b"door".to_vec(),
                label,
            )
            .await
            {
                Ok(did) => {
                    let body = json!({"did": hex::encode(did), "status": "submitted"}).to_string();
                    respond(&mut stream, "200 OK", &body);
                }
                Err(e) => {
                    let body = json!({"error": e.to_string()}).to_string();
                    respond(&mut stream, "400 Bad Request", &body);
                }
            }
            continue;
        }
        respond(&mut stream, "404 Not Found", r#"{"error":"not found"}"#);
    }
    Ok(())
}
