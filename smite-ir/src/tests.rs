//! Tests for IR types.

use super::*;
use operation::AcceptChannelField;

/// Helper to build a private key with a single distinguishing byte.
fn key(byte: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[31] = byte;
    k
}

fn sample_context() -> ProgramContext {
    ProgramContext {
        target_pubkey: [0x02; 33],
        chain_hash: [0; 32],
        block_height: 800_000,
        target_features: vec![],
    }
}

#[test]
#[allow(clippy::too_many_lines)]
fn display_open_channel_program() {
    let instructions = vec![
        // 6 key pairs.
        Instruction {
            operation: Operation::LoadPrivateKey(key(1)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![0],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(2)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![2],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(3)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![4],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(4)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![6],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(5)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![8],
        },
        Instruction {
            operation: Operation::LoadPrivateKey(key(6)),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![10],
        },
        // Channel parameters.
        Instruction {
            operation: Operation::LoadChannelId([0; 32]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadChainHashFromContext,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(100_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(0),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(546),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(10_000_000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(1000),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadAmount(1),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeeratePerKw(2500),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU16(144),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU16(483),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadU8(1),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadBytes(vec![]),
            inputs: vec![],
        },
        Instruction {
            operation: Operation::LoadFeatures(vec![]),
            inputs: vec![],
        },
        // Build and send open_channel.
        Instruction {
            operation: Operation::BuildOpenChannel,
            inputs: vec![
                13, 12, 14, 15, 16, 17, 18, 19, 20, 21, 22, 1, 3, 5, 7, 9, 11, 23, 24, 25,
            ],
        },
        Instruction {
            operation: Operation::SendMessage,
            inputs: vec![26],
        },
        // Receive accept_channel and extract fields.
        Instruction {
            operation: Operation::RecvAcceptChannel,
            inputs: vec![],
        },
        Instruction {
            operation: Operation::ExtractAcceptChannel(AcceptChannelField::FundingPubkey),
            inputs: vec![28],
        },
        Instruction {
            operation: Operation::ExtractAcceptChannel(AcceptChannelField::FirstPerCommitmentPoint),
            inputs: vec![28],
        },
    ];

    let program = Program {
        instructions,
        context: sample_context(),
    };
    let text = program.to_string();
    let lines: Vec<&str> = text.lines().collect();

    let z31 = "00".repeat(31);
    let z32 = "00".repeat(32);

    #[rustfmt::skip]
    let expected: Vec<String> = vec![
        format!("v0 = LoadPrivateKey(0x{z31}01)"),
        "v1 = DerivePoint(v0)".into(),
        format!("v2 = LoadPrivateKey(0x{z31}02)"),
        "v3 = DerivePoint(v2)".into(),
        format!("v4 = LoadPrivateKey(0x{z31}03)"),
        "v5 = DerivePoint(v4)".into(),
        format!("v6 = LoadPrivateKey(0x{z31}04)"),
        "v7 = DerivePoint(v6)".into(),
        format!("v8 = LoadPrivateKey(0x{z31}05)"),
        "v9 = DerivePoint(v8)".into(),
        format!("v10 = LoadPrivateKey(0x{z31}06)"),
        "v11 = DerivePoint(v10)".into(),
        format!("v12 = LoadChannelId(0x{z32})"),
        "v13 = LoadChainHashFromContext()".into(),
        "v14 = LoadAmount(100000)".into(),
        "v15 = LoadAmount(0)".into(),
        "v16 = LoadAmount(546)".into(),
        "v17 = LoadAmount(10000000)".into(),
        "v18 = LoadAmount(1000)".into(),
        "v19 = LoadAmount(1)".into(),
        "v20 = LoadFeeratePerKw(2500)".into(),
        "v21 = LoadU16(144)".into(),
        "v22 = LoadU16(483)".into(),
        "v23 = LoadU8(1)".into(),
        "v24 = LoadBytes()".into(),
        "v25 = LoadFeatures()".into(),
        "v26 = BuildOpenChannel(v13, v12, v14, v15, v16, v17, v18, v19, v20, v21, v22, v1, v3, v5, v7, v9, v11, v23, v24, v25)".into(),
        "SendMessage(v26)".into(),
        "v28 = RecvAcceptChannel()".into(),
        "v29 = ExtractFundingPubkey(v28)".into(),
        "v30 = ExtractFirstPerCommitmentPoint(v28)".into(),
    ];

    assert_eq!(lines.len(), expected.len(), "line count mismatch");
    for (i, (got, want)) in lines.iter().zip(expected.iter()).enumerate() {
        assert_eq!(got, want, "line {i} mismatch");
    }
}

#[test]
fn postcard_roundtrip() {
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey(key(1)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::LoadChainHashFromContext,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadChannelId([0xab; 32]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(50_000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadFeatures(vec![0x01, 0x02]),
                inputs: vec![],
            },
        ],
        context: sample_context(),
    };

    let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
    let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
    assert_eq!(program, decoded);
}

// Ensure AcceptChannelField and AcceptChannelField::ALL stay in sync. The
// exhaustive match in this test will fail to compile if a variant is added
// without updating it, and the assertion will fail if the match is updated
// without updating AcceptChannelField::ALL.
#[test]
fn accept_channel_field_all_is_complete() {
    let variant_count = |f: AcceptChannelField| -> usize {
        match f {
            AcceptChannelField::TemporaryChannelId
            | AcceptChannelField::DustLimitSatoshis
            | AcceptChannelField::MaxHtlcValueInFlightMsat
            | AcceptChannelField::ChannelReserveSatoshis
            | AcceptChannelField::HtlcMinimumMsat
            | AcceptChannelField::MinimumDepth
            | AcceptChannelField::ToSelfDelay
            | AcceptChannelField::MaxAcceptedHtlcs
            | AcceptChannelField::FundingPubkey
            | AcceptChannelField::RevocationBasepoint
            | AcceptChannelField::PaymentBasepoint
            | AcceptChannelField::DelayedPaymentBasepoint
            | AcceptChannelField::HtlcBasepoint
            | AcceptChannelField::FirstPerCommitmentPoint
            | AcceptChannelField::UpfrontShutdownScript
            | AcceptChannelField::ChannelType => 16,
        }
    };
    assert_eq!(
        AcceptChannelField::ALL.len(),
        variant_count(AcceptChannelField::ALL[0]),
    );
}
