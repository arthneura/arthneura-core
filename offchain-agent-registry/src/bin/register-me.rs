//! Make a key on this machine, sign the door challenge, ask Alice to pay.

use std::fs;
use std::path::PathBuf;

use ml_dsa::{Generate, KeyExport, Keypair, MlDsa65, Signer, SigningKey};
use serde_json::{json, Value};
use sp_core::blake2_256;

fn http(method: &str, path: &str, body: &str) -> String {
    let door = std::env::var("DOOR").or_else(|_| std::env::var("DOOR_URL")).unwrap_or_else(|_| "http://127.0.0.1:8790".into());
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
        panic!(
            "door {method} {path}: {}{}",
            String::from_utf8_lossy(&out.stderr),
            String::from_utf8_lossy(&out.stdout),
        );
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
    let pass = std::env::var("KEYSTORE_PASS").unwrap_or_else(|_| "dev-passphrase".into());
    let key_label = std::env::var("KEY_LABEL").unwrap_or_else(|_| "me".into());
    if std::env::var("OWN_CONTROLLER").ok().as_deref() == Some("1") {
        let account_seed: [u8; 32] = {
            let mut buf = [0u8; 32];
            getrandom::fill(&mut buf).expect("rng");
            buf
        };
        let account = subxt_signer::sr25519::Keypair::from_secret_key(account_seed).expect("account");
        let account_hex = hex::encode(account.public_key().0);
        println!("FUND={}", http("POST", "/v1/fund", &json!({"account": account_hex}).to_string()));
        let ch: Value = serde_json::from_str(&http("GET", &format!("/v1/register/challenge?account={account_hex}"), "")).expect("challenge");
        let block = ch["block"].as_u64().unwrap() as u32;
        let mut g = [0u8; 32];
        let mut c = [0u8; 32];
        let mut h = [0u8; 32];
        g.copy_from_slice(&hex::decode(ch["genesis"].as_str().unwrap()).unwrap());
        c.copy_from_slice(&hex::decode(ch["controller"].as_str().unwrap()).unwrap());
        h.copy_from_slice(&hex::decode(ch["hash"].as_str().unwrap()).unwrap());
        let challenge = codec::Encode::encode(&(g, did, c, block, h));
        let mldsa = signing_key.sign(&challenge).encode().to_vec();
        let prep: Value = serde_json::from_str(&http(
            "POST",
            "/v1/prepare",
            &json!({
                "account": account_hex,
                "pubkey": hex::encode(&pubkey),
                "signature": hex::encode(&mldsa),
                "signed_at_block": block,
                "label": label,
            }).to_string(),
        )).expect("prepare");
        if prep.get("error").is_some() {
            println!("PREPARE={prep}");
            return;
        }
        let payload = hex::decode(prep["payload"].as_str().unwrap()).unwrap();
        let msg: Vec<u8> = if payload.len() > 256 {
            sp_core::blake2_256(&payload).to_vec()
        } else {
            payload
        };
        let sig = account.sign(&msg);
        let done = http(
            "POST",
            "/v1/finish",
            &json!({"token": prep["token"], "account": account_hex, "signature": hex::encode(sig)}).to_string(),
        );
        offchain_agent_registry::keystore::save_identity(&dir, &key_label, did, &signing_key.to_bytes(), &pass).expect("id");
        offchain_agent_registry::keystore::save_identity(&dir, &format!("{key_label}-account"), did, &account_seed, &pass).expect("acct");
        let seed_path = dir.join("controller.seed");
        std::fs::write(&seed_path, hex::encode(account_seed)).expect("seed");
        println!("DID=0x{}", hex::encode(did));
        println!("CONTROLLER_SEED_FILE={seed_path:?}");
        println!("FINISH={done}");
        return;
    }
    let res = http("POST", "/v1/register", &body);
    offchain_agent_registry::keystore::save_identity(
        &dir,
        &key_label,
        did,
        &signing_key.to_bytes(),
        &pass,
    )
    .expect("keystore save");
    let key_path = dir.join(format!("{key_label}.json"));
    println!("DID=0x{}", hex::encode(did));
    println!("KEY={key_path:?}");
    println!("{res}");
}
