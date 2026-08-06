//! Off-chain client library for `pallet_agent_registry::register_agent`.
//! Generates an ML-DSA65 keypair, derives the DID, signs the on-chain
//! replay-window challenge, and submits the registration extrinsic.

use ml_dsa::{Generate, KeyExport, Keypair, MlDsa65, Signer, SigningKey};
use sp_core::blake2_256;
use subxt::dynamic::Value;
use subxt::tx::Signer as SubxtSigner;
use subxt::{OnlineClient, PolkadotConfig};

pub const PALLET_NAME: &str = "AgentRegistry";
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
    /// Raw ML-DSA65 signing key seed bytes (32 bytes). Caller is
    /// responsible for secure storage -- this client does not persist
    /// key material itself.
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

// -----------------------------------------------------------------------
// update_profile client
// -----------------------------------------------------------------------

/// Pre-submission and transport errors only. On-chain `Error<T>` variants
/// (DidNotFound, NotController, AgentRevoked) surface via `subxt::Error`
/// from the dispatch result and are not re-modeled here.
#[derive(Debug, thiserror::Error)]
pub enum UpdateProfileError {
    #[error("subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("AgentProfileUpdated event not found in finalized block")]
    EventMissing,
}

/// Overwrites the mutable fields (`capabilities`, `metadata`, `label`) of
/// an existing profile. Caller must be the DID's registered controller;
/// `Revoked` profiles reject this call. Note this is a full overwrite, not
/// a merge -- omitted fields are not preserved, matching the pallet's
/// `update_profile` semantics exactly.
pub async fn update_profile(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl SubxtSigner<PolkadotConfig> + Send + Sync),
    did: Did,
    capabilities: u64,
    metadata: Vec<u8>,
    label: Vec<u8>,
) -> Result<(), UpdateProfileError> {
    let tx = subxt::dynamic::tx(
        PALLET_NAME,
        "update_profile",
        vec![
            Value::from_bytes(did),
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
        .find(|e| e.pallet_name() == PALLET_NAME && e.variant_name() == "AgentProfileUpdated")
        .ok_or(UpdateProfileError::EventMissing)?;

    Ok(())
}

// -----------------------------------------------------------------------
// set_agent_status client
// -----------------------------------------------------------------------

/// Mirrors on-chain `pallet_agent_registry::AgentStatus`. Variant names
/// MUST match exactly (case-sensitive) -- passed to `subxt::dynamic::Value`
/// as an unnamed-variant SCALE enum, resolved by name against live
/// metadata, not by discriminant index.
#[derive(Debug, Clone, Copy)]
pub enum AgentStatus {
    Active,
    Suspended,
    Revoked,
}

impl AgentStatus {
    fn variant_name(self) -> &'static str {
        match self {
            AgentStatus::Active => "Active",
            AgentStatus::Suspended => "Suspended",
            AgentStatus::Revoked => "Revoked",
        }
    }
}

/// Pre-submission and transport errors only. On-chain `Error<T>` variants
/// (DidNotFound, NotController, AgentRevoked) surface via `subxt::Error`
/// from the dispatch result and are not re-modeled here.
#[derive(Debug, thiserror::Error)]
pub enum SetAgentStatusError {
    #[error("subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("AgentStatusChanged event not found in finalized block")]
    EventMissing,
}

/// Changes an agent's lifecycle status. Caller must be the DID's
/// registered controller. `Revoked` is terminal on-chain -- once set, no
/// further transitions are possible for that DID (enforced by the pallet,
/// not re-validated here).
pub async fn set_agent_status(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl SubxtSigner<PolkadotConfig> + Send + Sync),
    did: Did,
    new_status: AgentStatus,
) -> Result<(), SetAgentStatusError> {
    let tx = subxt::dynamic::tx(
        PALLET_NAME,
        "set_agent_status",
        vec![
            Value::from_bytes(did),
            Value::unnamed_variant(new_status.variant_name(), vec![]),
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
        .find(|e| e.pallet_name() == PALLET_NAME && e.variant_name() == "AgentStatusChanged")
        .ok_or(SetAgentStatusError::EventMissing)?;

    Ok(())
}
