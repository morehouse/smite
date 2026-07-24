//! Snapshot setup: procedural pre-snapshot state preparation for IR fuzzing.

use std::time::Duration;

use bitcoin::secp256k1::{PublicKey, Secp256k1, SecretKey};
use smite::bolt::{ChannelId, Init, InitTlvs, Message, OpenChannel, OpenChannelTlvs};
use smite::noise::NoiseConnection;
use smite::scenarios::ScenarioError;
use smite_ir::operation::ChannelTypeVariant;

use super::{handshake_with_target, ping_pong};
use crate::executor::ProgramContext;
use crate::targets::{EclairTarget, INITIAL_BLOCKS, Target};

/// Bitcoin regtest genesis hash (in BOLT 2 network byte order).
pub const REGTEST_CHAIN_HASH: [u8; 32] = [
    0x06, 0x22, 0x6e, 0x46, 0x11, 0x1a, 0x0b, 0x59, 0xca, 0xaf, 0x12, 0x60, 0x43, 0xeb, 0x5b, 0xbf,
    0x28, 0xc3, 0x4f, 0x3a, 0x5e, 0x33, 0x2a, 0x1f, 0xc7, 0xb2, 0xb7, 0x3c, 0xf1, 0x88, 0x91, 0x0f,
];

const TIMEOUT: Duration = Duration::from_secs(5);

/// Pre-snapshot setup that establishes a ready-to-use connection and produces
/// the [`ProgramContext`] an IR program will read at execution time. Called
/// once from `IrScenario::new()` before the Nyx snapshot is taken.
pub trait SnapshotSetup<T: Target> {
    /// Execute the setup and return the connection and context.
    ///
    /// # Errors
    ///
    /// Setup-specific; propagated to the scenario's `new()`.
    fn setup(target: &T) -> Result<(NoiseConnection, ProgramContext), ScenarioError>;
}

/// Clears a feature bit from a feature vector.
///
/// Feature vectors are encoded as big-endian byte arrays where bit N lives in
/// byte `features[len - 1 - N/8]` at position `N % 8`.
fn clear_feature_bit(features: &mut [u8], bit: usize) {
    let byte_index = features.len().checked_sub(1 + bit / 8);
    if let Some(i) = byte_index {
        features[i] &= !(1 << (bit % 8));
    }
}

/// Gossip-related feature bits (BOLT 9): `gossip_queries` (6/7),
/// `gossip_queries_ex` (10/11). Stripped so the target doesn't send
/// `gossip_timestamp_filter` or other gossip noise during execution.
const GOSSIP_FEATURE_BITS: &[usize] = &[6, 7, 10, 11];

/// Feature bits that force a dual-funded flow when both peers support them:
/// `option_dual_fund` (28/29). Eclair in particular will not allow
/// single-funded flows if either of these feature bits is set, so we strip them
/// when fuzzing the single-funded flow.
const DUAL_FUNDING_FEATURE_BITS: &[usize] = &[28, 29];

/// Peer storage feature bits: `option_provide_storage` (42/43). When enabled,
/// peers may send `peer_storage` and `peer_storage_retrieval` messages at
/// arbitrary times. Disabling these bits eliminates peer storage noise.
const PEER_STORAGE_FEATURE_BITS: &[usize] = &[42, 43];

/// Creates an `init` that echoes the received features with bits stripped that
/// would steer the target away from the single-funded `open_channel` flow.
fn init_for_single_funded(received: &Init) -> Init {
    let mut globalfeatures = received.globalfeatures.clone();
    let mut features = received.features.clone();
    for &bit in GOSSIP_FEATURE_BITS
        .iter()
        .chain(DUAL_FUNDING_FEATURE_BITS)
        .chain(PEER_STORAGE_FEATURE_BITS)
    {
        clear_feature_bit(&mut globalfeatures, bit);
        clear_feature_bit(&mut features, bit);
    }
    Init {
        globalfeatures,
        features,
        tlvs: InitTlvs::default(),
    }
}

/// Fixed feerate (sat/kW) for warmup `open_channel` messages. 2500 sat/kW
/// (~10 sat/vB) is comfortably inside every target's accepted range.
const WARMUP_FEERATE_PER_KW: u32 = 2500;

/// Fixed funding amount (sat) for warmup `open_channel` messages.
const WARMUP_FUNDING_SATOSHIS: u64 = 100_000;

/// Derives the six public keys an `open_channel` requires from fixed secrets.
fn warmup_channel_keys() -> [PublicKey; 6] {
    let secp = Secp256k1::new();
    let secrets: [[u8; 32]; 6] = [
        [0x21; 32], [0x22; 32], [0x23; 32], [0x24; 32], [0x25; 32], [0x26; 32],
    ];
    secrets.map(|s| {
        let sk = SecretKey::from_slice(&s).expect("valid warmup secret");
        PublicKey::from_secret_key(&secp, &sk)
    })
}

/// Builds a spec-valid single-funded `open_channel` for warmup traffic.
///
/// The parameters are fixed and known-good; only `temporary_channel_id` changes
/// per iteration. The `channel_type` is `Anchors`, the only type Eclair (the
/// sole JVM target, and thus the only one that runs warmup) accepts.
fn warmup_open_channel(
    chain_hash: [u8; 32],
    temporary_channel_id: ChannelId,
    keys: &[PublicKey; 6],
) -> OpenChannel {
    OpenChannel {
        chain_hash,
        temporary_channel_id,
        funding_satoshis: WARMUP_FUNDING_SATOSHIS,
        push_msat: 0,
        dust_limit_satoshis: 546,
        max_htlc_value_in_flight_msat: WARMUP_FUNDING_SATOSHIS * 1000,
        channel_reserve_satoshis: 1000,
        htlc_minimum_msat: 1,
        feerate_per_kw: WARMUP_FEERATE_PER_KW,
        to_self_delay: 144,
        max_accepted_htlcs: 483,
        funding_pubkey: keys[0],
        revocation_basepoint: keys[1],
        payment_basepoint: keys[2],
        delayed_payment_basepoint: keys[3],
        htlc_basepoint: keys[4],
        first_per_commitment_point: keys[5],
        channel_flags: 0x00,
        tlvs: OpenChannelTlvs {
            // Always send the TLV: a zero-length value is the BOLT 2 opt-out
            // signal when option_upfront_shutdown_script is negotiated (which
            // Eclair advertises and we echo). Omitting it is a protocol
            // violation that makes Eclair drop the connection.
            upfront_shutdown_script: Some(Vec::new()),
            channel_type: Some(ChannelTypeVariant::Anchors.encode()),
        },
    }
}

/// Derives a distinct, non-zero `temporary_channel_id` for warmup iteration
/// `seed`.
///
/// Each open within a connection needs a distinct id or Eclair rejects the
/// duplicate; `seed` provides that. The `0x01` fill also keeps every id
/// non-zero, avoiding the all-zero channel id BOLT 1 reserves for "fail all
/// channels".
fn warmup_temp_channel_id(seed: u64) -> ChannelId {
    let mut bytes = [0x01u8; 32];
    bytes[..8].copy_from_slice(&seed.to_be_bytes());
    ChannelId::new(bytes)
}

/// Number of `open_channel`s to send per throwaway warmup connection.
///
/// Eclair rate-limits pending (half-open) channels per peer (default 99). Opens
/// stay pending until the connection drops, so batches stay well under the limit
/// to keep Eclair accepting (and JIT-compiling) each one.
const WARMUP_OPENS_PER_CONNECTION: usize = 40;

/// Establishes a Noise connection and completes the `init` exchange for the
/// single-funded `open_channel` flow, returning a connection ready to carry
/// channel messages along with the target's `Init`.
fn establish_connection<T: Target>(target: &T) -> Result<(NoiseConnection, Init), ScenarioError> {
    let (mut conn, target_init) = handshake_with_target(target, TIMEOUT)?;

    // Echo features but strip the bits that would take us off the single-funded
    // `open_channel` path this setup is built for.
    let our_init = init_for_single_funded(&target_init);
    conn.send_message(&Message::Init(our_init).encode())?;

    // Drain any post-init noise so the caller starts from a clean connection.
    ping_pong(&mut conn)?;

    Ok((conn, target_init))
}

/// Drives `iterations` `open_channel` -> `accept_channel` exchanges to warm up a
/// JVM target before the snapshot, so `HotSpot` JIT-compiles the channel path.
///
/// Opens run on throwaway connections, never the snapshot connection: Eclair
/// rate-limits pending channels per peer, so each connection sends a batch
/// (<= [`WARMUP_OPENS_PER_CONNECTION`]) then drops, releasing the slots.
fn warmup<T: Target>(
    target: &T,
    chain_hash: [u8; 32],
    iterations: usize,
) -> Result<(), ScenarioError> {
    log::info!("Warming up target with {iterations} open_channel exchanges");
    let keys = warmup_channel_keys();
    for batch_start in (0..iterations).step_by(WARMUP_OPENS_PER_CONNECTION) {
        let (mut conn, _) = establish_connection(target)?;
        let batch_end = (batch_start + WARMUP_OPENS_PER_CONNECTION).min(iterations);
        for seed in batch_start..batch_end {
            let temp_id = warmup_temp_channel_id(seed as u64);
            let open = warmup_open_channel(chain_hash, temp_id, &keys);
            conn.send_message(&Message::OpenChannel(open).encode())?;
        }
        // Sync so Eclair processes (and JIT-compiles) the whole batch before conn
        // drops at the end of this iteration, releasing its pending-channel slots.
        ping_pong(&mut conn)?;
    }
    log::info!("Warmup complete");
    Ok(())
}

/// Setup that snapshots just after the Noise handshake and init exchange are
/// complete.
pub struct PostInitSetup;

impl<T: Target> SnapshotSetup<T> for PostInitSetup {
    fn setup(target: &T) -> Result<(NoiseConnection, ProgramContext), ScenarioError> {
        // Establish the pristine connection the fuzzer reuses across runs.
        let (conn, target_init) = establish_connection(target)?;

        let context = ProgramContext {
            target_pubkey: *target.pubkey(),
            chain_hash: REGTEST_CHAIN_HASH,
            // All targets gate startup on `INITIAL_BLOCKS` being mined, so
            // this is the floor. Dynamic per-target queries can replace it
            // later.
            block_height: u32::try_from(INITIAL_BLOCKS).expect("fits in u32"),
            target_features: target_init.features,
        };

        Ok((conn, context))
    }
}

/// Default number of warmup `open_channel` exchanges for [`EclairWarmupSetup`].
/// Worth ~25x on the open/accept path (cold ~73 ms `accept_channel` -> ~3 ms);
/// diminishing returns past ~2000, so 4000 sits on the plateau. Overridable at
/// runtime via `SMITE_WARMUP_ITERATIONS`.
const ECLAIR_WARMUP_ITERATIONS: usize = 4000;

/// [`PostInitSetup`] preceded by a JVM warmup pass; used for Eclair.
///
/// Before the snapshot it drives thousands of `open_channel` exchanges so
/// `HotSpot` JIT-compiles Eclair's channel path, then freezes the JIT, so every
/// restored VM starts hot with no compiler threads running during fuzzing.
pub struct EclairWarmupSetup;

impl SnapshotSetup<EclairTarget> for EclairWarmupSetup {
    fn setup(target: &EclairTarget) -> Result<(NoiseConnection, ProgramContext), ScenarioError> {
        // `SMITE_WARMUP_ITERATIONS` overrides the default without recompiling.
        let iterations = std::env::var("SMITE_WARMUP_ITERATIONS")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(ECLAIR_WARMUP_ITERATIONS);
        if iterations > 0 {
            warmup(target, REGTEST_CHAIN_HASH, iterations)?;
            target.freeze_jit()?;
        }

        // Reuse the generic post-init setup for the snapshot connection + context.
        PostInitSetup::setup(target)
    }
}
