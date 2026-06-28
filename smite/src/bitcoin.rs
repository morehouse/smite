//! This module implements utilities for interacting with regtest
//! `bitcoind` instances via `bitcoin-cli`.

use std::cmp::Ordering;
use std::path::PathBuf;
use std::process::Command;
use std::str::FromStr;

use bitcoin::consensus::encode::serialize_hex;
use bitcoin::{Address, Amount, Network, OutPoint, ScriptBuf, Transaction, Txid};
use serde::{Deserialize, Serialize};

/// A spendable UTXO used as a transaction input.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Utxo {
    /// The value of the UTXO.
    pub amount: Amount,
    /// The transaction outpoint identifying the UTXO.
    pub outpoint: OutPoint,
    /// The script pubkey of the UTXO being spent.
    pub script_pubkey: ScriptBuf,
}

impl Ord for Utxo {
    fn cmp(&self, other: &Self) -> Ordering {
        // Sort in decreasing order of amount to support largest-first coin
        // selection (as used in `bdk_wallet`) and ensure deterministic ordering.
        other
            .amount
            .cmp(&self.amount)
            .then_with(|| other.script_pubkey.cmp(&self.script_pubkey))
            .then_with(|| other.outpoint.cmp(&self.outpoint))
    }
}

impl PartialOrd for Utxo {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

/// Connection info for invoking `bitcoin-cli` against the regtest `bitcoind`
/// started by a target.
#[derive(Debug, Clone)]
pub struct BitcoinCli {
    /// RPC port exposed by the regtest `bitcoind` instance.
    pub rpc_port: u16,
    /// Path passed to `bitcoin-cli -datadir`.
    pub bitcoind_dir: PathBuf,
}

impl BitcoinCli {
    /// Creates a `bitcoin-cli` command preconfigured with the connection
    /// arguments for this regtest node.
    #[must_use]
    pub fn run(&self) -> Command {
        let mut cmd = Command::new("bitcoin-cli");
        cmd.arg("-regtest")
            .arg(format!("-datadir={}", self.bitcoind_dir.display()))
            .arg(format!("-rpcport={}", self.rpc_port))
            .arg("-rpcuser=rpcuser")
            .arg("-rpcpassword=rpcpass");
        cmd
    }

    /// Mines the given number of blocks.
    ///
    /// # Panics
    ///
    /// If the `bitcoin-cli -generate` command fails to execute or returns
    /// a non-success exit status.
    pub fn mine_blocks(&self, num_blocks: u8) {
        let mine_out = self
            .run()
            .arg("-generate")
            .arg(num_blocks.to_string())
            .output()
            .expect("bitcoin-cli -generate should not fail");
        assert!(
            mine_out.status.success(),
            "bitcoin-cli -generate {} failed: {}",
            num_blocks,
            String::from_utf8_lossy(&mine_out.stderr)
        );
    }

    /// Returns the wallet's spendable UTXOs, sorted deterministically.
    ///
    /// # Panics
    ///
    /// - If `bitcoin-cli listunspent` fails to execute or exits non-zero.
    /// - If the output is not valid JSON, or any entry has an invalid amount,
    ///   txid, or hex scriptPubKey.
    #[must_use]
    pub fn get_utxos(&self) -> Vec<Utxo> {
        #[derive(Deserialize)]
        struct UnspentOutput {
            txid: String,
            vout: u32,
            amount: f64,
            #[serde(rename = "scriptPubKey")]
            script_pubkey: String,
            spendable: bool,
        }

        let utxo_out = self
            .run()
            .arg("listunspent")
            .output()
            .expect("bitcoin-cli listunspent should not fail");
        assert!(
            utxo_out.status.success(),
            "bitcoin-cli listunspent failed: {}",
            String::from_utf8_lossy(&utxo_out.stderr)
        );

        let utxos: Vec<UnspentOutput> =
            serde_json::from_slice(&utxo_out.stdout).expect("listunspent should return valid JSON");

        let mut spendable: Vec<Utxo> = utxos
            .into_iter()
            .filter(|u| u.spendable)
            .map(|u| Utxo {
                amount: Amount::from_btc(u.amount).expect("listunspent amount should be valid BTC"),
                outpoint: OutPoint::new(
                    Txid::from_str(&u.txid).expect("listunspent should return valid txid"),
                    u.vout,
                ),
                script_pubkey: ScriptBuf::from(
                    hex::decode(&u.script_pubkey)
                        .expect("listunspent should return valid hex scriptPubKey"),
                ),
            })
            .collect();
        // Sorted for determinism and to support largest-first coin selection
        // during transaction construction.
        spendable.sort();

        spendable
    }

    /// Returns the scriptPubKey for a newly generated wallet address.
    ///
    /// # Panics
    ///
    /// - If `bitcoin-cli getnewaddress` fails to execute or exits non-zero.
    /// - If the output is not valid UTF-8 or not a valid regtest address.
    #[must_use]
    pub fn get_new_address_script_pubkey(&self) -> ScriptBuf {
        let addr_out = self
            .run()
            .arg("getnewaddress")
            .output()
            .expect("bitcoin-cli getnewaddress should not fail");
        assert!(
            addr_out.status.success(),
            "bitcoin-cli getnewaddress failed: {}",
            String::from_utf8_lossy(&addr_out.stderr)
        );

        let addr_str = String::from_utf8(addr_out.stdout).expect("bitcoin address is valid UTF-8");
        Address::from_str(addr_str.trim())
            .and_then(|a| a.require_network(Network::Regtest))
            .expect("getnewaddress should return a valid address")
            .script_pubkey()
    }

    /// Signs and broadcasts a transaction.
    ///
    /// # Panics
    ///
    /// - If `bitcoin-cli signrawtransactionwithwallet` or `sendrawtransaction`
    ///   fails to execute or exits non-zero.
    /// - If the sign output is not valid JSON.
    /// - If signing returns `complete=false`.
    /// - If `sendrawtransaction` does not return a valid UTF-8 txid.
    /// - If the broadcasted txid does not match the given transaction's txid.
    pub fn sign_and_broadcast_tx(&self, tx: &Transaction) {
        #[derive(Deserialize)]
        struct SignRawTransactionResponse {
            hex: String,
            complete: bool,
        }

        let tx_hex = serialize_hex(tx);

        let signed_out = self
            .run()
            .arg("signrawtransactionwithwallet")
            .arg(&tx_hex)
            .output()
            .expect("bitcoin-cli signrawtransactionwithwallet should not fail");
        assert!(
            signed_out.status.success(),
            "bitcoin-cli signrawtransactionwithwallet failed: {}",
            String::from_utf8_lossy(&signed_out.stderr)
        );

        let signed_tx: SignRawTransactionResponse = serde_json::from_slice(&signed_out.stdout)
            .expect("signrawtransactionwithwallet should return valid JSON");
        assert!(
            signed_tx.complete,
            "signrawtransactionwithwallet returned complete=false"
        );

        let broadcast_out = self
            .run()
            .arg("sendrawtransaction")
            .arg(&signed_tx.hex)
            .output()
            .expect("bitcoin-cli sendrawtransaction should not fail");
        assert!(
            broadcast_out.status.success(),
            "bitcoin-cli sendrawtransaction failed: {}",
            String::from_utf8_lossy(&broadcast_out.stderr)
        );

        // Safe because bitcoind descriptor wallets currently default to native
        // SegWit, so signing does not alter the txid computed from the unsigned
        // Transaction.
        let broadcast_txid = String::from_utf8(broadcast_out.stdout)
            .expect("sendrawtransaction should return a valid UTF-8 txid");
        assert_eq!(
            broadcast_txid.trim(),
            tx.compute_txid().to_string(),
            "sendrawtransaction returned unexpected txid"
        );
    }

    /// Locks the given outpoints in the wallet so they are excluded from
    /// `listunspent` and automatic coin selection.
    ///
    /// Prevents independently built transactions from selecting the same UTXO.
    /// `listunspent` only excludes an output once its spending transaction
    /// reaches the mempool, so transactions built beforehand can share an input.
    /// The second transaction then either fails broadcast as a non-fee-bumping
    /// RBF replacement, or later fails signing because the prevout has left the
    /// UTXO set.
    ///
    /// # Panics
    ///
    /// If the `bitcoin-cli lockunspent` command fails to execute or exits
    /// non-zero.
    pub fn lock_utxos(&self, outpoints: &[OutPoint]) {
        #[derive(Serialize)]
        struct LockOutpoint {
            txid: String,
            vout: u32,
        }

        if outpoints.is_empty() {
            return;
        }

        let locks: Vec<LockOutpoint> = outpoints
            .iter()
            .map(|o| LockOutpoint {
                txid: o.txid.to_string(),
                vout: o.vout,
            })
            .collect();
        let locks_json = serde_json::to_string(&locks).expect("outpoints serialize to valid JSON");

        let lock_out = self
            .run()
            .arg("lockunspent")
            .arg("false")
            .arg(&locks_json)
            .output()
            .expect("bitcoin-cli lockunspent should not fail");
        assert!(
            lock_out.status.success(),
            "bitcoin-cli lockunspent failed: {}",
            String::from_utf8_lossy(&lock_out.stderr)
        );
    }

    /// Returns the number of confirmations for the transaction with the given
    /// txid, or `0` if it is unconfirmed (in the mempool) or unknown to the node
    /// (e.g. not broadcast yet).
    ///
    /// # Panics
    ///
    /// - If the `bitcoin-cli getrawtransaction` command fails to execute.
    /// - If the command succeeds but its output is not valid JSON.
    #[must_use]
    pub fn get_transaction_confirmations(&self, txid: Txid) -> u32 {
        #[derive(Deserialize)]
        struct GetRawTransactionResponse {
            // Omitted by `getrawtransaction` while the transaction is unconfirmed
            // (in the mempool), so default to zero confirmations.
            #[serde(default)]
            confirmations: u32,
        }

        let tx_out = self
            .run()
            .arg("getrawtransaction")
            .arg(txid.to_string())
            .arg("1")
            .output()
            .expect("bitcoin-cli getrawtransaction should not fail");

        // A non-zero exit means the transaction is unknown to the node, which is
        // expected before broadcast, so treat it as zero confirmations.
        if !tx_out.status.success() {
            return 0;
        }

        let tx_info: GetRawTransactionResponse = serde_json::from_slice(&tx_out.stdout)
            .expect("getrawtransaction should return valid JSON");

        tx_info.confirmations
    }
}
