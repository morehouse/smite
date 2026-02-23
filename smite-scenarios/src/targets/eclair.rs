//! Eclair target implementation.
//!
//! Eclair is written in Scala (JVM), so instrumentation is provided by a custom
//! Java bytecode agent that writes coverage directly to AFL shared memory via
//! JNI.

use std::fs;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;

use serde::Deserialize;
use smite::process::ManagedProcess;

use super::{Target, TargetError};

/// Number of blocks to generate at startup for coinbase maturity.
const INITIAL_BLOCKS: u64 = 101;

/// API password for Eclair's REST API.
const API_PASSWORD: &str = "fuzzpass";

/// Configuration for the Eclair target.
pub struct EclairConfig {
    /// Bitcoin RPC port (default: 18443 for regtest).
    pub bitcoind_rpc_port: u16,
    /// Bitcoin P2P port (default: 18444 for regtest).
    pub bitcoind_p2p_port: u16,
    /// Eclair P2P listen port (default: 9735).
    pub eclair_p2p_port: u16,
    /// Eclair REST API port (default: 8080).
    pub eclair_api_port: u16,
    /// ZMQ block notification port (default: 29000).
    pub zmq_block_port: u16,
    /// ZMQ transaction notification port (default: 29001).
    pub zmq_tx_port: u16,
}

impl Default for EclairConfig {
    fn default() -> Self {
        Self {
            bitcoind_rpc_port: 18443,
            bitcoind_p2p_port: 18444,
            eclair_p2p_port: 9735,
            eclair_api_port: 8080,
            zmq_block_port: 29000,
            zmq_tx_port: 29001,
        }
    }
}

/// Eclair Lightning node target.
///
/// Field order matters: `eclair` is declared before `bitcoind` so it drops first,
/// which allows Eclair to exit cleanly.
pub struct EclairTarget {
    eclair: ManagedProcess,
    #[allow(dead_code)] // bitcoind shuts down on drop
    bitcoind: ManagedProcess,
    pubkey: secp256k1::PublicKey,
    addr: SocketAddr,
    #[allow(dead_code)] // TempDir auto-cleans on drop
    temp_dir: Option<tempfile::TempDir>,
}

impl EclairTarget {
    /// Starts bitcoind and waits for it to be ready.
    fn start_bitcoind(
        config: &EclairConfig,
        data_dir: &Path,
    ) -> Result<ManagedProcess, TargetError> {
        log::info!("Starting bitcoind...");

        let bitcoind_dir = data_dir.join("bitcoind");
        fs::create_dir_all(&bitcoind_dir)?;

        // Eclair requires ZMQ for block and transaction notifications, and
        // bech32 address/change types for proper segwit wallet behavior.
        let mut cmd = Command::new("bitcoind");
        cmd.arg("-regtest")
            .arg(format!("-datadir={}", bitcoind_dir.display()))
            .arg(format!("-port={}", config.bitcoind_p2p_port))
            .arg(format!("-rpcport={}", config.bitcoind_rpc_port))
            .arg("-rpcuser=rpcuser")
            .arg("-rpcpassword=rpcpass")
            .arg("-fallbackfee=0.00001")
            .arg("-txindex=1")
            .arg("-server=1")
            .arg("-rest=1")
            .arg("-printtoconsole=0")
            .arg("-addresstype=bech32")
            .arg("-changetype=bech32")
            .arg(format!(
                "-zmqpubrawblock=tcp://127.0.0.1:{}",
                config.zmq_block_port
            ))
            .arg(format!(
                "-zmqpubrawtx=tcp://127.0.0.1:{}",
                config.zmq_tx_port
            ))
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let bitcoind = ManagedProcess::spawn(&mut cmd, "bitcoind")?;

        // Wait for bitcoind to be ready
        log::info!("Waiting for bitcoind to be ready...");
        for _ in 0..30 {
            let status = Command::new("bitcoin-cli")
                .arg("-regtest")
                .arg(format!("-datadir={}", bitcoind_dir.display()))
                .arg(format!("-rpcport={}", config.bitcoind_rpc_port))
                .arg("-rpcuser=rpcuser")
                .arg("-rpcpassword=rpcpass")
                .arg("getblockchaininfo")
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status();

            if status.is_ok_and(|s| s.success()) {
                log::info!("bitcoind is ready");
                return Self::setup_wallet(config, &bitcoind_dir, bitcoind);
            }

            std::thread::sleep(Duration::from_secs(1));
        }

        Err(TargetError::StartFailed(
            "bitcoind failed to become ready".into(),
        ))
    }

    /// Creates wallet and generates initial blocks.
    fn setup_wallet(
        config: &EclairConfig,
        bitcoind_dir: &Path,
        bitcoind: ManagedProcess,
    ) -> Result<ManagedProcess, TargetError> {
        // Create wallet (ignore error if already exists)
        let _ = Command::new("bitcoin-cli")
            .arg("-regtest")
            .arg(format!("-datadir={}", bitcoind_dir.display()))
            .arg(format!("-rpcport={}", config.bitcoind_rpc_port))
            .arg("-rpcuser=rpcuser")
            .arg("-rpcpassword=rpcpass")
            .arg("createwallet")
            .arg("default")
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status();

        // Generate 101 blocks for coinbase maturity
        let status = Command::new("bitcoin-cli")
            .arg("-regtest")
            .arg(format!("-datadir={}", bitcoind_dir.display()))
            .arg(format!("-rpcport={}", config.bitcoind_rpc_port))
            .arg("-rpcuser=rpcuser")
            .arg("-rpcpassword=rpcpass")
            .arg("-generate")
            .arg(INITIAL_BLOCKS.to_string())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()?;

        if !status.success() {
            return Err(TargetError::StartFailed(
                "failed to generate initial blocks".into(),
            ));
        }

        Ok(bitcoind)
    }

    /// Writes eclair.conf to the eclair data directory.
    fn write_config(config: &EclairConfig, eclair_dir: &Path) -> Result<(), TargetError> {
        let conf = format!(
            "eclair.chain=regtest\n\
             eclair.server.port={eclair_p2p_port}\n\
             eclair.api.enabled=true\n\
             eclair.api.port={eclair_api_port}\n\
             eclair.api.password={api_password}\n\
             eclair.bitcoind.rpcuser=rpcuser\n\
             eclair.bitcoind.rpcpassword=rpcpass\n\
             eclair.bitcoind.rpcport={bitcoind_rpc_port}\n\
             eclair.bitcoind.zmqblock=\"tcp://127.0.0.1:{zmq_block_port}\"\n\
             eclair.bitcoind.zmqtx=\"tcp://127.0.0.1:{zmq_tx_port}\"\n",
            eclair_p2p_port = config.eclair_p2p_port,
            eclair_api_port = config.eclair_api_port,
            api_password = API_PASSWORD,
            bitcoind_rpc_port = config.bitcoind_rpc_port,
            zmq_block_port = config.zmq_block_port,
            zmq_tx_port = config.zmq_tx_port,
        );
        fs::write(eclair_dir.join("eclair.conf"), conf)?;
        Ok(())
    }

    /// Starts Eclair and waits for it to be ready and synced.
    /// Returns the process and Eclair's identity pubkey.
    fn start_eclair(
        config: &EclairConfig,
        data_dir: &Path,
    ) -> Result<(ManagedProcess, secp256k1::PublicKey), TargetError> {
        log::info!("Starting eclair...");

        let eclair_dir = data_dir.join("eclair");
        fs::create_dir_all(&eclair_dir)?;

        Self::write_config(config, &eclair_dir)?;

        let mut cmd = Command::new("eclair-node.sh");
        cmd.arg(format!("-Declair.datadir={}", eclair_dir.display()))
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let eclair = ManagedProcess::spawn(&mut cmd, "eclair")?;

        // Wait for Eclair to be ready and fully synced. We poll the REST API
        // until blockHeight matches the initial blocks we generated.
        log::info!("Waiting for eclair to be ready and synced...");
        for _ in 0..120 {
            if let Ok((pubkey, blockheight)) = Self::query_info(config) {
                if blockheight >= INITIAL_BLOCKS {
                    log::info!("eclair synced (blockheight={blockheight})");
                    return Ok((eclair, pubkey));
                }
                log::debug!("eclair not yet synced (blockheight={blockheight})");
            }
            std::thread::sleep(Duration::from_secs(1));
        }

        Err(TargetError::StartFailed(
            "eclair failed to sync chain".into(),
        ))
    }

    /// Queries Eclair's identity public key and block height via the REST API.
    fn query_info(config: &EclairConfig) -> Result<(secp256k1::PublicKey, u64), TargetError> {
        #[derive(Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct GetInfoResponse {
            node_id: String,
            block_height: u64,
        }

        let output = Command::new("curl")
            .arg("-s")
            .arg("-X")
            .arg("POST")
            .arg("-u")
            .arg(format!(":{API_PASSWORD}"))
            .arg(format!(
                "http://127.0.0.1:{}/getinfo",
                config.eclair_api_port
            ))
            .output()?;

        if !output.status.success() || output.stdout.is_empty() {
            return Err(TargetError::StartFailed("curl getinfo failed".into()));
        }

        let info: GetInfoResponse = serde_json::from_slice(&output.stdout).map_err(|e| {
            TargetError::StartFailed(format!("failed to parse getinfo output: {e}"))
        })?;

        log::info!(
            "Eclair nodeId: {}, blockHeight: {}",
            info.node_id,
            info.block_height
        );

        let pubkey_bytes = hex::decode(&info.node_id)
            .map_err(|e| TargetError::StartFailed(format!("failed to decode pubkey hex: {e}")))?;

        let pubkey = secp256k1::PublicKey::from_slice(&pubkey_bytes)
            .map_err(|e| TargetError::StartFailed(format!("failed to parse pubkey: {e}")))?;

        Ok((pubkey, info.block_height))
    }
}

impl Target for EclairTarget {
    type Config = EclairConfig;

    fn start(config: Self::Config) -> Result<Self, TargetError> {
        // Check for SMITE_DATA_DIR to preserve data directory for debugging
        let (data_path, temp_dir) = if let Ok(dir) = std::env::var("SMITE_DATA_DIR") {
            let path = PathBuf::from(dir);
            fs::create_dir_all(&path)?;
            log::info!("Preserving data directory: {}", path.display());
            (path, None)
        } else {
            let temp = tempfile::tempdir()?;
            let path = temp.path().to_path_buf();
            (path, Some(temp))
        };

        let bitcoind = Self::start_bitcoind(&config, &data_path)?;
        let (eclair, pubkey) = Self::start_eclair(&config, &data_path)?;
        let addr = SocketAddr::from(([127, 0, 0, 1], config.eclair_p2p_port));

        log::info!("Both daemons are running, ready to fuzz");

        Ok(Self {
            eclair,
            bitcoind,
            pubkey,
            addr,
            temp_dir,
        })
    }

    fn pubkey(&self) -> &secp256k1::PublicKey {
        &self.pubkey
    }

    fn addr(&self) -> SocketAddr {
        self.addr
    }

    fn check_alive(&mut self) -> Result<(), TargetError> {
        if !self.eclair.is_running() {
            return Err(TargetError::Crashed);
        }
        Ok(())
    }
}
