//! Off-chain client library for `pallet_agent_registry::register_agent`.
//! Generates an ML-DSA65 keypair, derives the DID, signs the on-chain
//! replay-window challenge, and submits the registration extrinsic.

use ml_dsa::{Generate, KeyExport, Keypair, MlDsa65, Signer, SigningKey};
use sp_core::blake2_256;
use subxt::dynamic::Value;
use subxt::tx::Signer as SubxtSigner;
use subxt::{OnlineClient, PolkadotConfig};

pub mod keystore;

use std::path::Path;

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

// -----------------------------------------------------------------------
// give_star client
// -----------------------------------------------------------------------

/// Pre-submission and transport errors only. On-chain `Error<T>` variants
/// (NotController, CannotStarSelf, DidNotFound, AgentRevoked,
/// CannotStarSameController, CooldownNotExpired) surface via
/// `subxt::Error` from the dispatch result and are not re-modeled here.
#[derive(Debug, thiserror::Error)]
pub enum GiveStarError {
    #[error("subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("StarGiven event not found in finalized block")]
    EventMissing,
}

/// Gives a reputation star from `giver_did` to `receiver`, incrementing
/// the receiver's `reputation_score` by 1. Caller must control
/// `giver_did`. Rejected on-chain for: self-starring, starring a DID
/// controlled by the same account (sybil-resistance), or calling again
/// before `Config::StarCooldown` blocks have elapsed since the last star
/// from this giver/receiver pair.
pub async fn give_star(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl SubxtSigner<PolkadotConfig> + Send + Sync),
    giver_did: Did,
    receiver: Did,
) -> Result<(), GiveStarError> {
    let tx = subxt::dynamic::tx(
        PALLET_NAME,
        "give_star",
        vec![Value::from_bytes(giver_did), Value::from_bytes(receiver)],
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
        .find(|e| e.pallet_name() == PALLET_NAME && e.variant_name() == "StarGiven")
        .ok_or(GiveStarError::EventMissing)?;

    Ok(())
}

// -----------------------------------------------------------------------
// remove_star client
// -----------------------------------------------------------------------

/// Pre-submission and transport errors only. On-chain `Error<T>` variants
/// (NotController, NotStarred) surface via `subxt::Error` from the
/// dispatch result and are not re-modeled here.
#[derive(Debug, thiserror::Error)]
pub enum RemoveStarError {
    #[error("subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("StarRemoved event not found in finalized block")]
    EventMissing,
}

/// Removes a previously given star, decrementing the receiver's
/// `reputation_score` by 1 (saturating -- never goes below zero). Caller
/// must control `giver_did`. Rejected on-chain if no star currently
/// exists from this giver/receiver pair. Resets the cooldown record to
/// zero, permitting an immediate re-star after removal.
pub async fn remove_star(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl SubxtSigner<PolkadotConfig> + Send + Sync),
    giver_did: Did,
    receiver: Did,
) -> Result<(), RemoveStarError> {
    let tx = subxt::dynamic::tx(
        PALLET_NAME,
        "remove_star",
        vec![Value::from_bytes(giver_did), Value::from_bytes(receiver)],
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
        .find(|e| e.pallet_name() == PALLET_NAME && e.variant_name() == "StarRemoved")
        .ok_or(RemoveStarError::EventMissing)?;

    Ok(())
}

// -----------------------------------------------------------------------
// deregister_agent client
// -----------------------------------------------------------------------

/// Pre-submission and transport errors only. On-chain `Error<T>` variants
/// (DidNotFound, NotController, AgentAlreadyRevoked) surface via
/// `subxt::Error` from the dispatch result and are not re-modeled here.
#[derive(Debug, thiserror::Error)]
pub enum DeregisterAgentError {
    #[error("subxt error: {0}")]
    Subxt(#[from] subxt::Error),
    #[error("AgentDeregistered event not found in finalized block")]
    EventMissing,
}

/// Voluntarily exits `did` from the registry: unreserves the full
/// registration deposit back to the controller, prunes the DID from the
/// controller's reverse index, and deletes the profile. Caller must be
/// the registered controller. `Revoked` profiles cannot deregister --
/// that status is terminal and forfeits the deposit permanently.
pub async fn deregister_agent(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl SubxtSigner<PolkadotConfig> + Send + Sync),
    did: Did,
) -> Result<(), DeregisterAgentError> {
    let tx = subxt::dynamic::tx(PALLET_NAME, "deregister_agent", vec![Value::from_bytes(did)]);

    let events = client
        .tx()
        .sign_and_submit_then_watch_default(&tx, signer)
        .await?
        .wait_for_finalized_success()
        .await?;

    events
        .iter()
        .filter_map(|e| e.ok())
        .find(|e| e.pallet_name() == PALLET_NAME && e.variant_name() == "AgentDeregistered")
        .ok_or(DeregisterAgentError::EventMissing)?;

    Ok(())
}

// -----------------------------------------------------------------------
// register_or_load_agent -- key-persistence wrapper
// -----------------------------------------------------------------------

#[derive(Debug, thiserror::Error)]
pub enum RegisterOrLoadError {
    #[error("on-chain registration failed: {0}")]
    Register(#[from] RegisterAgentError),
    #[error("keystore error: {0}")]
    KeyStore(#[from] keystore::KeyStoreError),
}

/// Idempotent identity bootstrap: if an encrypted identity already
/// exists on disk under `key_label` in `keystore_dir`, decrypts and
/// returns it WITHOUT touching the chain. Otherwise, registers a fresh
/// agent on-chain via [`register_agent`] and persists the resulting
/// keypair to disk before returning.
///
/// This is what makes an agent's identity survive a process restart --
/// without it, every `register_agent` call is a throwaway identity that
/// can never re-sign as itself again.
///
/// Known limitation: when loading an existing identity from disk, this
/// does NOT verify against the live chain that the DID is still
/// registered or that `signer` is still its controller (e.g. after a
/// `deregister_agent` call made from elsewhere). Deferred pending a
/// verified subxt dynamic-storage read.
pub async fn register_or_load_agent(
    client: &OnlineClient<PolkadotConfig>,
    signer: &(impl SubxtSigner<PolkadotConfig> + Send + Sync),
    keystore_dir: &Path,
    key_label: &str,
    passphrase: &str,
    capabilities: u32,
    metadata: Vec<u8>,
    display_label: Vec<u8>,
) -> Result<RegisteredAgent, RegisterOrLoadError> {
    if keystore::identity_exists(keystore_dir, key_label) {
        let stored = keystore::load_identity(keystore_dir, key_label, passphrase)?;
        return Ok(RegisteredAgent {
            did: stored.did,
            signing_key_bytes: stored.signing_key_bytes.to_vec(),
        });
    }

    let agent = register_agent(client, signer, capabilities, metadata, display_label).await?;
    keystore::save_identity(keystore_dir, key_label, agent.did, &agent.signing_key_bytes, passphrase)?;
    Ok(agent)
}
