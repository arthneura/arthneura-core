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
    let rpc = subxt::backend::rpc::RpcClient::from_url(&ws).await?;
    let listener = TcpListener::bind("127.0.0.1:8790")?;
    println!("REGISTER_DOOR=127.0.0.1:8790");
    let mut pending = std::collections::HashMap::<String, subxt::tx::PartialExtrinsic<PolkadotConfig, OnlineClient<PolkadotConfig>>>::new();
    for incoming in listener.incoming() {
        let mut stream = match incoming {
            Ok(s) => s,
            Err(_) => continue,
        };
        let mut buf = Vec::new();
        let mut tmp = [0u8; 4096];
        loop {
            let n = stream.read(&mut tmp).unwrap_or(0);
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&tmp[..n]);
            if let Some(i) = buf.windows(4).position(|w| w == b"\r\n\r\n") {
                let head = String::from_utf8_lossy(&buf[..i]).to_ascii_lowercase();
                let need = head.lines().find_map(|l| l.strip_prefix("content-length:"))
                    .and_then(|n| n.trim().parse::<usize>().ok())
                    .unwrap_or(0);
                if buf.len() >= i + 4 + need || buf.len() > 65536 {
                    break;
                }
            }
            if buf.len() > 65536 {
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
            let q = line.split('?').nth(1).unwrap_or("").split(' ').next().unwrap_or("");
            let controller = q.split('&').find_map(|p| p.strip_prefix("account=")).unwrap_or("");
            let controller = if controller.len() == 64 { controller.to_string() } else { hex::encode(signer().public_key().0) };
            let body = json!({
                "genesis": hex::encode(client.genesis_hash().0),
                "controller": controller,
                "block": block.number(),
                "hash": hex::encode(block.hash().0),
            })
            .to_string();
            respond(&mut stream, "200 OK", &body);
            continue;
        }
        if line.starts_with("POST /v1/prepare") {
            let raw = req.split("\r\n\r\n").nth(1).unwrap_or("");
            let v: serde_json::Value = match serde_json::from_str(raw) {
                Ok(v) => v,
                Err(_) => { respond(&mut stream, "400 Bad Request", r#"{"error":"bad json"}"#); continue; }
            };
            let account = hex::decode(v["account"].as_str().unwrap_or("").trim_start_matches("0x")).unwrap_or_default();
            let pubkey = hex::decode(v["pubkey"].as_str().unwrap_or("").trim_start_matches("0x")).unwrap_or_default();
            let signature = hex::decode(v["signature"].as_str().unwrap_or("").trim_start_matches("0x")).unwrap_or_default();
            let signed_at_block = v["signed_at_block"].as_u64().unwrap_or(0);
            let label = v["label"].as_str().unwrap_or("").as_bytes().to_vec();
            if account.len() != 32 || pubkey.is_empty() || signature.is_empty() || signed_at_block == 0 {
                respond(&mut stream, "400 Bad Request", r#"{"error":"account, pubkey, signature, signed_at_block required"}"#);
                continue;
            }
            let tx = subxt::dynamic::tx(
                "AgentRegistry",
                "register_agent",
                vec![
                    subxt::dynamic::Value::from_bytes(pubkey),
                    subxt::dynamic::Value::from_bytes(signature),
                    subxt::dynamic::Value::u128(signed_at_block as u128),
                    subxt::dynamic::Value::u128(1),
                    subxt::dynamic::Value::from_bytes(b"door".to_vec()),
                    subxt::dynamic::Value::from_bytes(label),
                ],
            );
            let account_id = subxt::utils::AccountId32(account.try_into().unwrap());
            let partial = match client.tx().create_partial_signed(&tx, &account_id, Default::default()).await {
                Ok(p) => p,
                Err(e) => {
                    let body = json!({"error": e.to_string()}).to_string();
                    respond(&mut stream, "400 Bad Request", &body);
                    continue;
                }
            };
            let payload = hex::encode(partial.signer_payload());
            let token = format!("p{}", pending.len());
            pending.insert(token.clone(), partial);
            let body = json!({"token": token, "payload": payload}).to_string();
            respond(&mut stream, "200 OK", &body);
            continue;
        }
        if line.starts_with("POST /v1/finish") {
            let raw = req.split("\r\n\r\n").nth(1).unwrap_or("");
            let v: serde_json::Value = match serde_json::from_str(raw) {
                Ok(v) => v,
                Err(_) => { respond(&mut stream, "400 Bad Request", r#"{"error":"bad json"}"#); continue; }
            };
            let token = v["token"].as_str().unwrap_or("").to_string();
            let sigb = hex::decode(v["signature"].as_str().unwrap_or("").trim_start_matches("0x")).unwrap_or_default();
            let account = hex::decode(v["account"].as_str().unwrap_or("").trim_start_matches("0x")).unwrap_or_default();
            if sigb.len() != 64 || account.len() != 32 {
                respond(&mut stream, "400 Bad Request", r#"{"error":"account and 64-byte signature required"}"#);
                continue;
            }
            let Some(partial) = pending.remove(&token) else {
                respond(&mut stream, "400 Bad Request", r#"{"error":"unknown token"}"#);
                continue;
            };
            let mut sig = [0u8; 64];
            sig.copy_from_slice(&sigb);
            let address = subxt::utils::MultiAddress::Id(subxt::utils::AccountId32(account.try_into().unwrap()));
            let signature = subxt::utils::MultiSignature::Sr25519(sig);
            let submitted = partial.sign_with_address_and_signature(&address, &signature);
            match submitted.submit_and_watch().await {
                Ok(w) => match w.wait_for_finalized_success().await {
                    Ok(_) => respond(&mut stream, "200 OK", r#"{"status":"registered"}"#),
                    Err(e) => {
                        let body = json!({"error": e.to_string()}).to_string();
                        respond(&mut stream, "400 Bad Request", &body);
                    }
                },
                Err(e) => {
                    let body = json!({"error": e.to_string()}).to_string();
                    respond(&mut stream, "400 Bad Request", &body);
                }
            }
            continue;
        }
        if line.starts_with("POST /v1/fund") {
            let raw = req.split("\r\n\r\n").nth(1).unwrap_or("");
            let v: serde_json::Value = match serde_json::from_str(raw) {
                Ok(v) => v,
                Err(_) => {
                    respond(&mut stream, "400 Bad Request", r#"{"error":"bad json"}"#);
                    continue;
                }
            };
            let account = hex::decode(v["account"].as_str().unwrap_or("").trim_start_matches("0x")).unwrap_or_default();
            if account.len() != 32 {
                respond(&mut stream, "400 Bad Request", r#"{"error":"account must be 32-byte hex"}"#);
                continue;
            }
            let amount: u128 = std::env::var("FUND_AMOUNT").ok().and_then(|s| s.parse().ok()).unwrap_or(2_000_000_000_000);
            let dest = subxt::dynamic::Value::unnamed_variant(
                "Id",
                vec![subxt::dynamic::Value::from_bytes(account)],
            );
            let tx = subxt::dynamic::tx(
                "Balances",
                "transfer_keep_alive",
                vec![dest, subxt::dynamic::Value::u128(amount)],
            );
            match client
                .tx()
                .sign_and_submit_then_watch_default(&tx, &signer())
                .await
            {
                Ok(w) => match w.wait_for_finalized_success().await {
                    Ok(_) => respond(&mut stream, "200 OK", r#"{"status":"funded"}"#),
                    Err(e) => {
                        let body = json!({"error": e.to_string()}).to_string();
                        respond(&mut stream, "400 Bad Request", &body);
                    }
                },
                Err(e) => {
                    let body = json!({"error": e.to_string()}).to_string();
                    respond(&mut stream, "400 Bad Request", &body);
                }
            }
            continue;
        }
        if line.starts_with("POST /v1/submit") {
            let raw = req.split("\r\n\r\n").nth(1).unwrap_or("");
            let v: serde_json::Value = match serde_json::from_str(raw) {
                Ok(v) => v,
                Err(_) => {
                    respond(&mut stream, "400 Bad Request", r#"{"error":"bad json"}"#);
                    continue;
                }
            };
            let tx_hex = v["tx"].as_str().unwrap_or("").trim().trim_start_matches("0x");
            let bytes = hex::decode(tx_hex).unwrap_or_default();
            if bytes.is_empty() {
                respond(&mut stream, "400 Bad Request", r#"{"error":"tx hex required"}"#);
                continue;
            }
            let mut params = subxt::backend::rpc::rpc_params![format!("0x{tx_hex}")];
            let hash = match rpc.request::<String>("author_submitExtrinsic", params).await {
                Ok(h) => h,
                Err(e) => {
                    let body = json!({"error": e.to_string()}).to_string();
                    respond(&mut stream, "400 Bad Request", &body);
                    continue;
                }
            };
            let body = json!({"status":"submitted","hash": hash}).to_string();
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
