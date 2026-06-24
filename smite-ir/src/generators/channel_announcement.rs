//! Generator for `channel_announcement` gossip message.

use rand::Rng;

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Generates an unsolicited `channel_announcement` send.
#[derive(Clone, Copy)]
pub struct ChannelAnnouncementGenerator;

impl Generator for ChannelAnnouncementGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        let features = builder.pick_variable(VariableType::Features, rng);
        let chain_hash = builder.pick_variable(VariableType::ChainHash, rng);
        let scid = builder.pick_variable(VariableType::ShortChannelId, rng);

        // Use fresh private keys since channel_announcement validation
        // generally requires distinct keys.
        let node_sk_1 = builder.generate_fresh(VariableType::PrivateKey, rng);
        let node_sk_2 = builder.generate_fresh(VariableType::PrivateKey, rng);
        let bitcoin_sk_1 = builder.generate_fresh(VariableType::PrivateKey, rng);
        let bitcoin_sk_2 = builder.generate_fresh(VariableType::PrivateKey, rng);

        let msg = builder.append(
            Operation::BuildChannelAnnouncement,
            &[
                features,
                chain_hash,
                scid,
                node_sk_1,
                node_sk_2,
                bitcoin_sk_1,
                bitcoin_sk_2,
            ],
        );
        builder.append(Operation::SendMessage, &[msg]);
    }
}
