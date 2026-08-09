//! ArthNeura Agent Economy Simulation.
//!
//! Bootstraps N fully sovereign, cryptographically independent agents
//! (each with its own persisted ML-DSA identity + funded sr25519
//! account -- see `offchain_agent_registry::bootstrap_new_agent`), pairs
//! them up, and runs their `vector-db` commitment lifecycles
//! CONCURRENTLY. This is the first test in this project that exercises
//! more than two agents and more than one in-flight transaction pipeline
//! at once -- it validates that the sovereign-account architecture
//! (distinct signer, distinct nonce sequence per agent) actually
//! delivers real parallelism, not just theoretical decentralization.
//!
//! Half the pairs settle happily (register -> acknowledge -> close);
//! half go through a full dispute cycle (register -> acknowledge ->
//! raise_dispute -> counter_dispute), so this doubles as a concurrent
//! stress test of the dispute-arbitration path specifically.

use offchain_agent_registry::bootstrap_new_agent;
use offchain_vector_db::{acknowledge_commitment, close_commitment, counter_dispute, raise_dispute, register_commitment, FsChunkStore};
use std::time::Instant;
use subxt::{OnlineClient, PolkadotConfig};
use subxt_signer::sr25519::dev;

/// Number of agents to bootstrap. Must be even (paired up 2-at-a-time).
/// Kept moderate: bootstrap is sequential per-agent (shared sponsor
/// nonce), so total bootstrap time scales linearly with N at roughly
/// one block (~6s) per agent for the funding transfer plus another for
/// registration.
const N_AGENTS: usize = 10;

/// Funding transferred to each fresh agent account. Must cover the
/// on-chain `RegistrationDeposit` (100 UNIT in this runtime) plus fees.
const FUNDING_AMOUNT: u128 = 150_000_000_000_000;

const KEYSTORE_PASSPHRASE: &str = "agent-economy-sim-ephemeral-passphrase";

struct PairResult {
    pair_id: usize,
    mode: &'static str,
    outcome: Result<(), String>,
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    assert!(N_AGENTS % 2 == 0, "N_AGENTS must be even -- agents are paired 2-at-a-time");

    println!("=== ArthNeura Agent Economy Simulation ===");
    println!("Bootstrapping {N_AGENTS} sovereign agents (sequential, sponsor-funded)...\n");

    let client = OnlineClient::<PolkadotConfig>::from_url("ws://127.0.0.1:9944").await?;
    let sponsor = dev::alice();

    let run_id = std::process::id();
    let keystore_dir = std::env::temp_dir().join(format!("arthneura-sim-keystore-{run_id}"));

    // -- Phase 1: sequential sovereign bootstrap -----------------------------
    let bootstrap_start = Instant::now();
    let mut agents = Vec::with_capacity(N_AGENTS);
    for i in 0..N_AGENTS {
        let label = format!("sim-agent-{i}-{run_id}");
        let agent = bootstrap_new_agent(
            &client,
            &sponsor,
            &keystore_dir,
            &label,
            KEYSTORE_PASSPHRASE,
            FUNDING_AMOUNT,
            0b1,
            format!("sim-agent-{i}").into_bytes(),
            format!("Agent-{i}").into_bytes(),
        )
        .await
        .map_err(|e| format!("bootstrap failed for agent {i}: {e}"))?;

        println!(
            "  Agent {i:2}: did=0x{}... account={}",
            &hex::encode(agent.did)[..16],
            agent.account.public_key().to_account_id()
        );
        agents.push(agent);
    }
    let bootstrap_elapsed = bootstrap_start.elapsed();
    println!("\nBootstrap complete: {N_AGENTS} agents in {:.1}s\n", bootstrap_elapsed.as_secs_f64());

    // -- Phase 2: pair up, run commitment lifecycles CONCURRENTLY -----------
    println!("Running {} concurrent pairs (mix of happy-path and dispute-path)...\n", N_AGENTS / 2);

    let mut pairs = Vec::new();
    let mut agents_iter = agents.into_iter();
    let mut pair_id = 0;
    while let (Some(provider), Some(consumer)) = (agents_iter.next(), agents_iter.next()) {
        pairs.push((pair_id, provider, consumer));
        pair_id += 1;
    }

    let exec_start = Instant::now();
    let mut handles = Vec::new();
    for (pair_id, provider, consumer) in pairs {
        let client = client.clone();
        let mode: &'static str = if pair_id % 2 == 0 { "happy" } else { "dispute" };

        handles.push(tokio::spawn(async move {
            let store = FsChunkStore::new(std::env::temp_dir().join(format!("arthneura-sim-chunks-{run_id}-{pair_id}")));
            let payload = format!("simulation payload for pair {pair_id}, mode={mode}").into_bytes();

            let result: Result<(), String> = async {
                let commit = register_commitment(
                    &client,
                    &provider.account,
                    &store,
                    provider.did,
                    consumer.did,
                    &payload,
                    b"sim-metadata".to_vec(),
                    1000,
                )
                .await
                .map_err(|e| format!("register_commitment: {e}"))?;

                acknowledge_commitment(&client, &consumer.account, commit.commitment_id, consumer.did)
                    .await
                    .map_err(|e| format!("acknowledge_commitment: {e}"))?;

                if mode == "happy" {
                    close_commitment(&client, &consumer.account, commit.commitment_id, consumer.did, commit.merkle_root, commit.total_chunks)
                        .await
                        .map_err(|e| format!("close_commitment: {e}"))?;
                } else {
                    let bogus_hash: [u8; 32] = [0xAB; 32];
                    raise_dispute(&client, &consumer.account, commit.commitment_id, consumer.did, bogus_hash, commit.total_chunks)
                        .await
                        .map_err(|e| format!("raise_dispute: {e}"))?;

                    counter_dispute(&client, &provider.account, &store, commit.commitment_id, provider.did, 0, commit.total_chunks)
                        .await
                        .map_err(|e| format!("counter_dispute: {e}"))?;
                }

                Ok(())
            }
            .await;

            PairResult { pair_id, mode, outcome: result }
        }));
    }

    let mut results = Vec::new();
    for handle in handles {
        results.push(handle.await.expect("task panicked"));
    }
    results.sort_by_key(|r| r.pair_id);
    let exec_elapsed = exec_start.elapsed();

    // -- Phase 3: report -------------------------------------------------
    println!("--- Results ---");
    let mut success_count = 0;
    for r in &results {
        match &r.outcome {
            Ok(()) => {
                success_count += 1;
                println!("  Pair {:2} [{:>7}] OK", r.pair_id, r.mode);
            }
            Err(e) => println!("  Pair {:2} [{:>7}] FAILED: {e}", r.pair_id, r.mode),
        }
    }

    println!(
        "\n{}/{} pairs succeeded. Concurrent execution: {:.1}s. Total wall time: {:.1}s.",
        success_count,
        results.len(),
        exec_elapsed.as_secs_f64(),
        (bootstrap_elapsed + exec_elapsed).as_secs_f64()
    );

    if success_count == results.len() {
        println!("\n=== SIMULATION PASSED: {N_AGENTS} sovereign agents, {} concurrent transaction pipelines, 100% success ===", results.len());
    } else {
        println!("\n=== SIMULATION INCOMPLETE: {}/{} pipelines failed ===", results.len() - success_count, results.len());
    }

    Ok(())
}
