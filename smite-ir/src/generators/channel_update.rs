//! Generator for `channel_update` gossip message.

use rand::Rng;

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Generates an unsolicited `channel_update` send.
///
/// Emits instructions to build and send a single signed `channel_update`. The
/// signing key, chain hash, and short channel id are drawn via
/// `pick_variable` so they can be shared with other gossip messages (e.g. a
/// preceding `channel_announcement`) when generators are composed.
#[derive(Clone, Copy)]
pub struct ChannelUpdateGenerator;

impl Generator for ChannelUpdateGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        let node_sk = builder.pick_variable(VariableType::PrivateKey, rng);
        let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);
        let short_channel_id = builder.pick_variable(VariableType::ShortChannelId, rng);
        let timestamp = builder.pick_variable(VariableType::Timestamp, rng);

        // message_flags and channel_flags are plain U8s so the mutator can flip
        // individual bits (e.g. must_be_one, direction, disable).
        let message_flags = builder.pick_variable(VariableType::U8, rng);
        let channel_flags = builder.pick_variable(VariableType::U8, rng);

        let cltv_expiry_delta = builder.pick_variable(VariableType::U16, rng);
        let htlc_minimum_msat = builder.pick_variable(VariableType::Amount, rng);
        let fee_base_msat = builder.pick_variable(VariableType::ForwardingFee, rng);
        let fee_proportional_millionths = builder.pick_variable(VariableType::ForwardingFee, rng);
        let htlc_maximum_msat = builder.pick_variable(VariableType::Amount, rng);

        let msg = builder.append(
            Operation::BuildChannelUpdate,
            &[
                node_sk,
                chain_hash,
                short_channel_id,
                timestamp,
                message_flags,
                channel_flags,
                cltv_expiry_delta,
                htlc_minimum_msat,
                fee_base_msat,
                fee_proportional_millionths,
                htlc_maximum_msat,
            ],
        );
        builder.append(Operation::SendMessage, &[msg]);
    }
}
