//! Off-chain client for `pallet_agent_registry::register_agent`.
//! Generates an ML-DSA65 keypair, derives the DID, signs the on-chain
//! replay-window challenge, and submits the registration extrinsic.

use ml_dsa::{Generate, KeyExport, Keypair, MlDsa65, Signer, SigningKey};
use sp_core::blake2_256;
use subxt::dynamic::Value;
use subxt::tx::Signer as SubxtSigner;
use subxt::{OnlineClient, PolkadotConfig};

const PALLET_NAME: &str = "AgentRegistry";
const DID_DOMAIN_TAG: &[u8] = b"ArthNeura-DID-v1";

pub type Did = [u8; 32];

#[derive(Debug, thiserror::Error)]
pub enum RegisterAgentError {
    #[error("subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("AgentRegistered event not found in finalized block")]
    EventMissing,
}

pub struct RegisteredAgent {
    pub did: Did,
    /// Raw ML-DSA65 signing key bytes. Caller is responsible for secure
    /// storage -- this client does not persist key material itself.
    pub signing_key_bytes: Vec<u8>,
}

/// Generates a fresh ML-DSA65 identity, derives its DID exactly as
/// `pallet_agent_registry::register_agent` does on-chain, signs the
/// chain-bound replay-window challenge, and submits registration.
///
/// `capabilities` type and exact bit layout are pallet-defined
/// (`CapabilityBitmap`) -- verify against `pallet-agent-registry`'s
/// actual type before relying on specific bit meanings.
pub async fn register_agent(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl SubxtSigner<PolkadotConfig> + Send + Sync),
    capabilities: u32,
    metadata: Vec<u8>,
    label: Vec<u8>,
) -> Result<RegisteredAgent, RegisterAgentError> {
    // -- 1. Generate ML-DSA65 keypair -----------------------------------
    let signing_key = SigningKey::<MlDsa65>::generate();
    let verifying_key = signing_key.verifying_key();
    let pubkey_bytes: Vec<u8> = verifying_key.encode().to_vec();
    let signing_key_bytes: Vec<u8> = signing_key.to_bytes().to_vec();

    // -- 2. Derive DID (must match pallet's domain-separated hash) ------
    let did: Did = {
        let mut preimage = DID_DOMAIN_TAG.to_vec();
        preimage.extend_from_slice(&pubkey_bytes);
        blake2_256(&preimage)
    };

    // -- 3. Fetch chain-bound challenge inputs from the live node --------
    let genesis_hash: [u8; 32] = client.genesis_hash().0;
    let latest_block = client.blocks().at_latest().await?;
    let signed_at_block: u32 = latest_block.number();
    let signed_at_hash: [u8; 32] = latest_block.hash().0;
    let controller: [u8; 32] = signer.account_id().0;

    // -- 4. Build and SCALE-encode the challenge tuple -------------------
    // Field order and types MUST match pallet_agent_registry::register_agent
    // exactly: (genesis_hash, did, controller, signed_at_block, signed_at_hash).
    // H256/AccountId32 SCALE-encode identically to raw [u8; 32] (no length
    // prefix), so using plain byte arrays here produces byte-identical
    // output to the pallet's typed tuple.
    let challenge = codec::Encode::encode(&(genesis_hash, did, controller, signed_at_block, signed_at_hash));

    // -- 5. Sign the challenge --------------------------------------------
    let signature = signing_key.sign(&challenge);
    let signature_bytes: Vec<u8> = signature.encode().to_vec();

    // -- 6. Submit register_agent ------------------------------------------
    let tx = subxt::dynamic::tx(
        PALLET_NAME,
        "register_agent",
        vec![
            Value::from_bytes(pubkey_bytes),
            Value::from_bytes(signature_bytes),
            Value::u128(signed_at_block as u128),
            Value::u128(capabilities as u128),
            Value::from_bytes(metadata),
            Value::from_bytes(label),
        ],
    );

    let events = client
        .tx()
        .sign_and_submit_then_watch_default(&tx, signer)
        .await?
        .wait_for_finalized_success()
        .await?;

    events
        .iter()
        .filter_map(|e| e.ok())
        .find(|e| e.pallet_name() == PALLET_NAME && e.variant_name() == "AgentRegistered")
        .ok_or(RegisterAgentError::EventMissing)?;

    Ok(RegisteredAgent { did, signing_key_bytes })
}

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
