//! Generator for `node_announcement` gossip message.

use rand::{Rng, RngExt};

use super::Generator;
use crate::builder::ProgramBuilder;
use crate::{Operation, VariableType};

/// Generates an unsolicited `node_announcement` send.
#[derive(Clone, Copy)]
pub struct NodeAnnouncementGenerator;

impl Generator for NodeAnnouncementGenerator {
    fn generate(&self, builder: &mut ProgramBuilder, rng: &mut impl Rng) {
        let node_sk = builder.pick_variable(VariableType::PrivateKey, rng);
        let features = builder.pick_variable(VariableType::Features, rng);
        let timestamp = builder.pick_variable(VariableType::Timestamp, rng);
        let addresses = builder.pick_variable(VariableType::Bytes, rng);

        // rgb_color and alias are op-level params (not variable inputs) so the
        // mutator can flip bits inside them without changing their lengths.
        let rgb_color: [u8; 3] = rng.random();
        let mut alias = [0u8; 32];
        for b in &mut alias {
            // BOLT 7 requires alias to be valid UTF-8, which Eclair actually
            // enforces on decode.
            *b = rng.random_range(0x00..=0x7F);
        }

        let msg = builder.append(
            Operation::BuildNodeAnnouncement { rgb_color, alias },
            &[node_sk, features, timestamp, addresses],
        );
        builder.append(Operation::SendMessage, &[msg]);
    }
}
