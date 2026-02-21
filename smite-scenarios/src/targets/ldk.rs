//! LDK target implementation.
//!
//! Unlike LND, LDK is written in Rust so AFL instrumentation writes directly
//! to shared memory. No coverage pipes are needed.

use std::fs;
use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::Path;
use std::process::{Command, Stdio};

use smite::process::ManagedProcess;

use crate::bitcoind::{self, BitcoindConfig};

use super::{Target, TargetError};

/// Configuration for the LDK target.
pub struct LdkConfig {
    /// Bitcoin RPC port (default: 18443 for regtest).
    pub bitcoind_rpc_port: u16,
    /// Bitcoin P2P port (default: 18444 for regtest).
    pub bitcoind_p2p_port: u16,
    /// LDK P2P listen port (default: 9735).
    pub ldk_p2p_port: u16,
}

impl Default for LdkConfig {
    fn default() -> Self {
        Self {
            bitcoind_rpc_port: 18443,
            bitcoind_p2p_port: 18444,
            ldk_p2p_port: 9735,
        }
    }
}

impl LdkConfig {
    fn bitcoind_config(&self) -> BitcoindConfig {
        BitcoindConfig {
            rpc_port: self.bitcoind_rpc_port,
            p2p_port: self.bitcoind_p2p_port,
            zmq_block_port: None,
            zmq_tx_port: None,
        }
    }
}

/// LDK Lightning node target.
///
/// Field order matters: `ldk` is declared before `bitcoind` so it drops first,
/// which allows LDK to exit cleanly.
pub struct LdkTarget {
    ldk: ManagedProcess,
    #[allow(dead_code)] // bitcoind shuts down on drop
    bitcoind: ManagedProcess,
    pubkey: secp256k1::PublicKey,
    addr: SocketAddr,
    #[allow(dead_code)] // TempDir auto-cleans on drop
    temp_dir: Option<tempfile::TempDir>,
}

impl LdkTarget {
    /// Starts ldk-node-wrapper and waits for it to be ready.
    /// Returns the process and LDK's identity pubkey.
    fn start_ldk(
        config: &LdkConfig,
        data_dir: &Path,
    ) -> Result<(ManagedProcess, secp256k1::PublicKey), TargetError> {
        log::info!("Starting ldk-node-wrapper...");

        let ldk_dir = data_dir.join("ldk");
        fs::create_dir_all(&ldk_dir)?;

        let mut cmd = Command::new("ldk-node-wrapper");
        cmd.arg(ldk_dir.to_str().expect("valid UTF-8 path"))
            .arg(config.ldk_p2p_port.to_string())
            .arg(config.bitcoind_rpc_port.to_string())
            .stdout(Stdio::piped())
            .stderr(Stdio::null());

        let mut ldk = ManagedProcess::spawn(&mut cmd, "ldk-node-wrapper")?;

        // Parse pubkey from stdout. The wrapper prints:
        //   PUBKEY:<hex>
        //   READY
        let stdout = ldk.inner().stdout.take().ok_or_else(|| {
            TargetError::StartFailed("ldk-node-wrapper stdout not captured".into())
        })?;

        let reader = BufReader::new(stdout);
        let mut pubkey = None;

        for line in reader.lines() {
            let line = line.map_err(|e| TargetError::StartFailed(format!("read error: {e}")))?;

            if let Some(hex) = line.strip_prefix("PUBKEY:") {
                let bytes = hex::decode(hex).map_err(|e| {
                    TargetError::StartFailed(format!("failed to decode pubkey hex: {e}"))
                })?;
                pubkey = Some(secp256k1::PublicKey::from_slice(&bytes).map_err(|e| {
                    TargetError::StartFailed(format!("failed to parse pubkey: {e}"))
                })?);
                log::info!("LDK identity pubkey: {hex}");
            } else if line == "READY" {
                break;
            }
        }

        let pubkey =
            pubkey.ok_or_else(|| TargetError::StartFailed("no PUBKEY line received".into()))?;

        log::info!("ldk-node-wrapper is ready");
        Ok((ldk, pubkey))
    }
}

impl Target for LdkTarget {
    type Config = LdkConfig;

    fn start(config: Self::Config) -> Result<Self, TargetError> {
        let (data_path, temp_dir) = bitcoind::resolve_data_dir()?;

        let bitcoind = bitcoind::start(&config.bitcoind_config(), &data_path)?;
        let (ldk, pubkey) = Self::start_ldk(&config, &data_path)?;
        let addr = SocketAddr::from(([127, 0, 0, 1], config.ldk_p2p_port));

        log::info!("Both daemons are running, ready to fuzz");

        Ok(Self {
            ldk,
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
        // No coverage sync needed - Rust writes directly to AFL shm.
        // Just check that the process is still running.
        if !self.ldk.is_running() {
            return Err(TargetError::Crashed);
        }
        Ok(())
    }
}
