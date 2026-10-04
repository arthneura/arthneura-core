//! Make a key on this machine, sign the door challenge, ask Alice to pay.

use std::fs;
use std::path::PathBuf;

use ml_dsa::{Generate, KeyExport, Keypair, MlDsa65, Signer, SigningKey};
use serde_json::{json, Value};
use sp_core::blake2_256;

fn http(method: &str, path: &str, body: &str) -> String {
    let door = std::env::var("DOOR").unwrap_or_else(|_| "http://127.0.0.1:8790".into());
    let base = if door.starts_with("http://") || door.starts_with("https://") {
        door
    } else {
        format!("http://{door}")
    };
    let url = format!("{base}{path}");
    let mut cmd = std::process::Command::new("curl");
    cmd.args(["-sf", "-X", method, &url]);
    if !body.is_empty() {
        cmd.args(["-H", "content-type: application/json", "-d", body]);
    }
    let out = cmd.output().expect("curl missing");
    if !out.status.success() {
        panic!("door {method} {path}: {}", String::from_utf8_lossy(&out.stderr));
    }
    String::from_utf8(out.stdout).unwrap()
}

fn main() {
    let label = std::env::var("LABEL").unwrap_or_else(|_| "me".into());
    let dir = PathBuf::from(std::env::var("KEYSTORE_DIR").unwrap_or_else(|_| {
        let home = std::env::var("HOME").unwrap_or_else(|_| "/tmp".into());
        format!("{home}/agents/me")
    }));
    fs::create_dir_all(&dir).unwrap();

    let signing_key = SigningKey::<MlDsa65>::generate();
    let pubkey = signing_key.verifying_key().encode().to_vec();
    let did = {
        let mut pre = b"ArthNeura-DID-v1".to_vec();
        pre.extend_from_slice(&pubkey);
        blake2_256(&pre)
    };

    let ch: Value = serde_json::from_str(&http("GET", "/v1/register/challenge", "")).expect("bad challenge");
    let genesis = hex::decode(ch["genesis"].as_str().unwrap()).unwrap();
    let controller = hex::decode(ch["controller"].as_str().unwrap()).unwrap();
    let hash = hex::decode(ch["hash"].as_str().unwrap()).unwrap();
    let block = ch["block"].as_u64().unwrap() as u32;
    let mut g = [0u8; 32];
    let mut c = [0u8; 32];
    let mut h = [0u8; 32];
    g.copy_from_slice(&genesis);
    c.copy_from_slice(&controller);
    h.copy_from_slice(&hash);
    let challenge = codec::Encode::encode(&(g, did, c, block, h));
    let signature = signing_key.sign(&challenge).encode().to_vec();

    let body = json!({
        "pubkey": hex::encode(&pubkey),
        "signature": hex::encode(&signature),
        "signed_at_block": block,
        "label": label,
    })
    .to_string();
    let res = http("POST", "/v1/register", &body);
    let key_path = dir.join("me.json");
    fs::write(&key_path, hex::encode(signing_key.to_bytes().to_vec())).unwrap();
    println!("DID=0x{}", hex::encode(did));
    println!("KEY={key_path:?}");
    println!("{res}");
}
