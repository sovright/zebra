//! Reproduce a `[local_genesis]` chain's public network parameters.
//!
//! Prints a `[network.testnet_parameters]` TOML snippet consumable by an
//! UPSTREAM zfnd/zebra node (so external miners can join the chain over
//! P2P), plus the funded miner addresses and their P2PKH scripts.
//!
//! NEVER prints secret keys. The seed passed in IS secret material —
//! this tool exists so the seed itself never has to leave the operator.
//!
//! Usage:
//!   cargo run -p zebra-chain --features internal-miner \
//!     --example dump_local_genesis_params -- \
//!     <network_name> <seed_hex> <tip_time> <miner1,miner2,...>

use zebra_chain::local_genesis::{
    generate_local_testnet_with_funded_keys, LocalTestnetGenesisOptions,
};
use zebra_chain::parameters::{Network, NetworkUpgrade};

/// Map a [`NetworkUpgrade`] to the exact serde key name expected by upstream
/// zebrad's `[network.testnet_parameters.activation_heights]` deserializer
/// (`ConfiguredActivationHeights`). The `Debug` impl prints `Nu5`/`Nu6`/...,
/// but the config keys are `NU5`/`NU6`/`NU6.1`/`NU7`, so we cannot rely on
/// `{upgrade:?}` for those.
fn activation_height_key(upgrade: NetworkUpgrade) -> Option<&'static str> {
    use NetworkUpgrade::*;
    match upgrade {
        // Genesis/BeforeOverwinter are not configurable keys upstream.
        Genesis | BeforeOverwinter => None,
        Overwinter => Some("Overwinter"),
        Sapling => Some("Sapling"),
        Blossom => Some("Blossom"),
        Heartwood => Some("Heartwood"),
        Canopy => Some("Canopy"),
        Nu5 => Some("NU5"),
        Nu6 => Some("NU6"),
        Nu6_1 => Some("NU6.1"),
        Nu7 => Some("NU7"),
        #[cfg(zcash_unstable = "zfuture")]
        ZFuture => Some("ZFuture"),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() != 5 {
        eprintln!(
            "usage: {} <network_name> <seed_hex> <tip_time> <miner1,miner2,...>",
            args[0]
        );
        std::process::exit(2);
    }
    let network_name = args[1].clone();
    let seed: [u8; 32] = hex::decode(&args[2])?
        .try_into()
        .map_err(|_| "seed must be 32 bytes")?;
    let tip_time: i64 = args[3].parse()?;
    let miners: Vec<String> = args[4].split(',').map(String::from).collect();

    // MUST mirror LocalGenesisSection::to_options() in zebrad/src/config.rs
    // (target_spacing_secs = 1, latest = Nu6) and the live VM config
    // (maturity_padding_blocks = 0, disable_pow = false).
    let generated = generate_local_testnet_with_funded_keys(
        miners,
        LocalTestnetGenesisOptions {
            network_name,
            latest_network_upgrade: NetworkUpgrade::Nu6,
            disable_pow: false,
            target_spacing_secs: 1,
            seeded_tip_time: Some(tip_time),
            maturity_padding_blocks: 0,
            seed: Some(seed),
        },
    )?;

    let params = match &generated.network {
        Network::Testnet(params) => params,
        _ => return Err("expected a testnet network".into()),
    };

    println!("# --- paste into the miner-facing zebrad config ---");
    println!("[network.testnet_parameters]");
    println!("network_name = \"{}\"", params.network_name());
    println!("network_magic = {:?}", params.network_magic().0);
    println!("slow_start_interval = {}", params.slow_start_interval().0);
    println!(
        "target_difficulty_limit = \"{}\"",
        params.target_difficulty_limit()
    );
    println!("disable_pow = false");
    println!("genesis_hash = \"{}\"", params.genesis_hash());
    println!(
        "pre_blossom_halving_interval = {}",
        params.pre_blossom_halving_interval()
    );
    println!();
    println!("[network.testnet_parameters.activation_heights]");
    for (height, upgrade) in generated.network.full_activation_list() {
        if let Some(key) = activation_height_key(upgrade) {
            println!("{key} = {}", height.0);
        }
    }
    println!();
    println!("# --- informational (not config) ---");
    println!("# generated blocks: {}", generated.blocks.len());
    for (height, hash) in &generated.checkpoints {
        println!("# checkpoint {} {}", height.0, hash);
    }
    for key in &generated.funded_keys {
        // Addresses and scripts are public; secrets are NOT printed.
        println!("# funded miner '{}' address: {}", key.name, key.address);
        println!(
            "#   P2PKH script hex: {}",
            hex::encode(key.address.script().as_raw_bytes())
        );
    }
    Ok(())
}
