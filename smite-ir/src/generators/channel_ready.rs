//! Generator for `channel_ready` message flow.

use rand::{Rng, RngExt};

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Generates a `channel_ready` -> `channel_ready` flow.
///
/// Emits instructions to:
/// 1. Mine blocks to confirm the funding transaction.
/// 2. Build and send `channel_ready`
/// 3. Receive and parse counterparty's `channel_ready`
#[derive(Clone, Copy)]
pub struct ChannelReadyGenerator;

impl Generator for ChannelReadyGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        // Mine blocks to confirm the funding transaction.
        builder.append(Operation::MineBlocks(rng.random_range(1..=16)), &[]);

        // Channel parameters.
        let channel_id = builder.pick_variable(VariableType::ChannelId, rng);
        let second_per_commitment_point = builder.generate_fresh(VariableType::Point, rng);
        let short_channel_id = builder.generate_fresh(VariableType::ShortChannelId, rng);
        let include_alias = rng.random();

        // Build and send channel_ready.
        builder.append(
            Operation::SendChannelReady { include_alias },
            &[channel_id, second_per_commitment_point, short_channel_id],
        );

        // Receive channel_ready.
        builder.append(Operation::RecvChannelReady, &[]);
    }
}
