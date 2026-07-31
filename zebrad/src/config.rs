//! Zebrad Config
//!
//! See instructions in `commands.rs` to specify the path to your
//! application's configuration file and/or command-line options
//! for specifying it.

use std::{collections::HashMap, path::PathBuf};

use serde::{Deserialize, Serialize};
use zebra_rpc::config::mining::{default_miner_address, MinerAddressType};

use crate::components::With;

/// Centralized, case-insensitive suffix-based deny-list to ban setting config fields with
/// environment variables if those config field names end with any of these suffixes.
const DENY_CONFIG_KEY_SUFFIX_LIST: [&str; 5] = [
    "password",
    "secret",
    "token",
    // Block raw cookies only if a field is literally named "cookie".
    // (Paths like cookie_dir are not affected.)
    "cookie",
    // Only raw private keys; paths like *_private_key_path are not affected.
    "private_key",
];

/// Returns true if a leaf key name should be considered sensitive and blocked
/// from environment variable overrides.
fn is_sensitive_leaf_key(leaf_key: &str) -> bool {
    let key = leaf_key.to_ascii_lowercase();
    DENY_CONFIG_KEY_SUFFIX_LIST
        .iter()
        .any(|deny_suffix| key.ends_with(deny_suffix))
}

/// Configuration for `zebrad`.
///
/// The `zebrad` config is a TOML-encoded version of this structure. The meaning
/// of each field is described in the documentation, although it may be necessary
/// to click through to the sub-structures for each section.
///
/// The path to the configuration file can also be specified with the `--config` flag when running Zebra.
///
/// The default path to the `zebrad` config is platform dependent, based on
/// [`dirs::preference_dir`](https://docs.rs/dirs/latest/dirs/fn.preference_dir.html):
///
/// | Platform | Value                                 | Example                                        |
/// | -------- | ------------------------------------- | ---------------------------------------------- |
/// | Linux    | `$XDG_CONFIG_HOME` or `$HOME/.config` | `/home/alice/.config/zebrad.toml`              |
/// | macOS    | `$HOME/Library/Preferences`           | `/Users/Alice/Library/Preferences/zebrad.toml` |
/// | Windows  | `{FOLDERID_RoamingAppData}`           | `C:\Users\Alice\AppData\Local\zebrad.toml`     |
#[derive(Clone, Default, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields, default)]
pub struct ZebradConfig {
    /// Consensus configuration
    //
    // These configs use full paths to avoid a rustdoc link bug (#7048).
    pub consensus: zebra_consensus::config::Config,

    /// Metrics configuration
    pub metrics: crate::components::metrics::Config,

    /// Networking configuration
    pub network: zebra_network::config::Config,

    /// State configuration
    pub state: zebra_state::config::Config,

    /// Tracing configuration
    pub tracing: crate::components::tracing::Config,

    /// Sync configuration
    pub sync: crate::components::sync::Config,

    /// Mempool configuration
    pub mempool: crate::components::mempool::Config,

    /// Block notify configuration
    pub notify: crate::components::notify::Config,

    /// RPC configuration
    pub rpc: zebra_rpc::config::rpc::Config,

    /// Mining configuration
    pub mining: zebra_rpc::config::mining::Config,

    /// Health check HTTP server configuration.
    ///
    /// See the Zebra Book for details and examples:
    /// <https://zebra.zfnd.org/user/health.html>
    pub health: crate::components::health::Config,

    /// zcashd-compat mode configuration.
    pub zcashd_compat: crate::components::zcashd_compat::Config,

    /// Optional deterministic, isolated, single-node local testnet.
    ///
    /// When set, zebrad generates a brand-new chain from a fixed seed at startup
    /// (genesis + funded premine), uses it as the active network (ignoring
    /// `[network] network`), and commits the generated blocks to an empty state —
    /// no peers, no public network. See [`LocalGenesisConfig`].
    pub local_genesis: Option<LocalGenesisConfig>,
}

/// Configuration for a deterministic, isolated, single-node local testnet generated
/// from a fixed seed via [`zebra_chain::local_genesis`].
///
/// This runs a brand-new chain from its own genesis with no peers and no public
/// network. Network upgrades up to NU6 (Orchard + NU6) activate just after the
/// premine blocks, so the node serves Orchard `getblocktemplate` immediately.
#[derive(Clone, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct LocalGenesisConfig {
    /// Human-readable network name (alphanumeric + underscore, max 30 chars).
    pub network_name: String,

    /// Miner names to fund with a premine (one 10-ZEC coinbase block each).
    pub miners: Vec<String>,

    /// Hex-encoded 32-byte seed for deterministic key and chain generation.
    ///
    /// The same seed + miners + `tip_time` reproduce an identical genesis on every
    /// start, which is required for committing the same genesis to state across restarts.
    pub seed: String,

    /// Fixed UNIX timestamp (seconds) for the seeded tip block.
    ///
    /// Pinned (rather than wall-clock) so the generated chain is reproducible.
    pub tip_time: i64,

    /// Extra empty blocks appended after the premine blocks so coinbase outputs can mature.
    #[serde(default)]
    pub maturity_padding_blocks: u32,

    /// If true, skip Equihash proof-of-work validation. Default `false` (a genuinely mined chain).
    #[serde(default)]
    pub disable_pow: bool,
}

impl LocalGenesisConfig {
    /// Decode the configured 32-byte seed from a 64-character hex string.
    pub fn seed_bytes(&self) -> Result<[u8; 32], String> {
        let s = self.seed.trim();
        if s.len() != 64 {
            return Err(format!(
                "local_genesis.seed must be 64 hex chars (32 bytes), got {}",
                s.len()
            ));
        }
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let start = i * 2;
            *byte = u8::from_str_radix(&s[start..start + 2], 16)
                .map_err(|e| format!("local_genesis.seed is not valid hex: {e}"))?;
        }
        Ok(out)
    }

    /// Build the [`zebra_chain::local_genesis`] options for this config (capped at NU6).
    pub fn to_options(
        &self,
    ) -> Result<zebra_chain::local_genesis::LocalTestnetGenesisOptions, String> {
        Ok(zebra_chain::local_genesis::LocalTestnetGenesisOptions {
            network_name: self.network_name.clone(),
            latest_network_upgrade: zebra_chain::parameters::NetworkUpgrade::Nu6,
            disable_pow: self.disable_pow,
            target_spacing_secs: 1,
            seeded_tip_time: Some(self.tip_time),
            maturity_padding_blocks: self.maturity_padding_blocks,
            seed: Some(self.seed_bytes()?),
        })
    }
}

impl ZebradConfig {
    /// Loads the configuration from the conventional sources.
    ///
    /// Configuration is loaded from three sources, in order of precedence:
    /// 1. Environment variables with `ZEBRA_` prefix (highest precedence)
    /// 2. TOML configuration file (if provided)
    /// 3. Hard-coded defaults (lowest precedence)
    ///
    /// Environment variables use the format `ZEBRA_SECTION__KEY` where:
    /// - `SECTION` is the configuration section (e.g., `network`, `rpc`)
    /// - `KEY` is the configuration key within that section
    /// - Double underscores (`__`) separate nested keys
    ///
    /// # Security
    ///
    /// Environment variables whose leaf key names end with sensitive suffixes (case-insensitive)
    /// will cause configuration loading to fail with an error: `password`, `secret`, `token`, `cookie`, `private_key`.
    /// This prevents both silent misconfigurations and process table exposure of sensitive values.
    ///
    /// See [`DENY_CONFIG_KEY_SUFFIX_LIST`] and [`is_sensitive_leaf_key()`] above
    ///
    /// # Examples
    /// - `ZEBRA_NETWORK__NETWORK=Testnet` sets `network.network = "Testnet"`
    /// - `ZEBRA_RPC__LISTEN_ADDR=127.0.0.1:8232` sets `rpc.listen_addr = "127.0.0.1:8232"`
    pub fn load(config_path: Option<PathBuf>) -> Result<Self, config::ConfigError> {
        Self::load_with_env(config_path, "ZEBRA")
    }

    /// Loads configuration using a caller-provided environment variable prefix.
    ///
    /// This allows callers that need multiple configs in the same process (e.g.,
    /// the `copy-state` command) to keep overrides separate. For example:
    /// - Source/base config uses `ZEBRA_...` env vars (default prefix)
    /// - Target config uses `ZEBRA_TARGET_...` env vars
    ///
    /// The nested key separator remains `__`, e.g., `ZEBRA_TARGET_STATE__CACHE_DIR`.
    pub fn load_with_env(
        config_path: Option<PathBuf>,
        env_prefix: &str,
    ) -> Result<Self, config::ConfigError> {
        // 1. Start with an empty `config::Config` builder (no pre-populated values).
        // We merge sources, then deserialize into `ZebradConfig`, which uses
        // `ZebradConfig::default()` wherever keys are missing.
        let mut builder = config::Config::builder();

        // 2. Add TOML configuration file as a source if provided
        if let Some(path) = config_path {
            builder = builder.add_source(
                config::File::from(path)
                    .format(config::FileFormat::Toml)
                    .required(true),
            );
        }

        // 3. Load from environment variables (with a sensitive-leaf deny-list)
        // Use the provided prefix and `__` as separator for nested keys.
        // We filter the raw environment first, then let config-rs parse types via try_parsing(true).
        let mut filtered_env: HashMap<String, String> = HashMap::new();
        let required_prefix = format!("{}_", env_prefix);
        for (key, value) in std::env::vars() {
            if let Some(without_prefix) = key.strip_prefix(&required_prefix) {
                // Check for sensitive keys on the stripped key.
                let parts: Vec<&str> = without_prefix.split("__").collect();
                if let Some(leaf) = parts.last() {
                    if is_sensitive_leaf_key(leaf) {
                        return Err(config::ConfigError::Message(format!(
                            "Environment variable '{}' contains sensitive key '{}' which cannot be overridden via environment variables. \
                             Use the configuration file instead to prevent process table exposure.",
                            key, leaf
                        )));
                    }
                }

                // When providing a `source` map, the keys should not have the prefix.
                filtered_env.insert(without_prefix.to_string(), value);
            }
        }

        // When using `source`, we provide a map of already-filtered and processed
        // keys, so we use a default `Environment` without a prefix.
        builder = builder.add_source(
            config::Environment::default()
                .separator("__")
                .try_parsing(true)
                .source(Some(filtered_env)),
        );

        // Build the configuration
        let config = builder.build()?;
        // Deserialize into our struct, which will use defaults for any missing fields
        config.try_deserialize()
    }
}

impl With<MinerAddressType> for ZebradConfig {
    fn with(mut self, miner_address_type: MinerAddressType) -> Self {
        self.mining.miner_address = Some(
            default_miner_address(self.network.network.kind(), &miner_address_type)
                .parse()
                .expect("valid hard-coded address"),
        );

        self
    }
}
