//! Tests for IR types.

use rand::SeedableRng;
use rand::rngs::SmallRng;
use smite::bolt::MAX_MESSAGE_SIZE;

use super::*;
use generators::OpenChannelGenerator;
use minimizers::{CommonSubexpressionEliminator, DeadCodeEliminator, Minimizer};
use mutators::{InputSwapMutator, OperationParamMutator};
use operation::AcceptChannelField;
use program::ValidateError;

/// Helper to build a private key with a single distinguishing byte.
fn key(byte: u8) -> [u8; 32] {
    let mut k = [0u8; 32];
    k[31] = byte;
    k
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

    let program = Program { instructions };
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

fn generate_program(seed: u64) -> Program {
    let mut rng = SmallRng::seed_from_u64(seed);
    let mut builder = ProgramBuilder::new();
    OpenChannelGenerator.generate(&mut builder, &mut rng);
    builder.build()
}

// If OpenChannelGenerator completes without panicking, every instruction has
// correct input types (enforced by ProgramBuilder::append).
#[test]
fn generated_program_is_type_correct() {
    for seed in 0..100 {
        generate_program(seed);
    }
}

#[test]
fn generated_program_structure() {
    let program = generate_program(0);
    let ops: Vec<_> = program.instructions.iter().map(|i| &i.operation).collect();

    // Must end with SendMessage, RecvAcceptChannel.
    assert!(
        matches!(ops[ops.len() - 2], Operation::SendMessage),
        "second-to-last instruction should be SendMessage",
    );
    assert!(
        matches!(ops[ops.len() - 1], Operation::RecvAcceptChannel),
        "last instruction should be RecvAcceptChannel",
    );

    // At least one BuildOpenChannel.
    assert!(
        ops.iter()
            .any(|op| matches!(op, Operation::BuildOpenChannel)),
        "expected at least one BuildOpenChannel",
    );

    // At least 6 DerivePoint instructions (fresh basepoints).
    let derive_count = program
        .instructions
        .iter()
        .filter(|i| matches!(i.operation, Operation::DerivePoint))
        .count();
    assert!(
        derive_count >= 6,
        "expected at least 6 DerivePoint, got {derive_count}"
    );
}

#[test]
fn generated_program_postcard_roundtrip() {
    let program = generate_program(42);
    let bytes = postcard::to_allocvec(&program).expect("postcard serialization");
    let decoded: Program = postcard::from_bytes(&bytes).expect("postcard deserialization");
    assert_eq!(program, decoded);
}

#[test]
fn generate_fresh_produces_distinct_indices() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    let a = builder.generate_fresh(VariableType::Amount, &mut rng);
    let b = builder.generate_fresh(VariableType::Amount, &mut rng);
    assert_ne!(a, b);
}

#[test]
fn pick_variable_reuses_existing() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();

    // Generate one Amount variable.
    let first = builder.generate_fresh(VariableType::Amount, &mut rng);

    // pick_variable should mostly reuse the existing variable. Over 100 calls,
    // at least some should return the original index.
    let mut reuse_count = 0;
    for _ in 0..100 {
        let idx = builder.pick_variable(VariableType::Amount, &mut rng);
        if idx == first {
            reuse_count += 1;
        }
    }
    assert!(
        reuse_count > 0,
        "pick_variable never reused existing variable"
    );
}

#[test]
#[should_panic(expected = "cannot generate fresh Message")]
fn generate_fresh_message_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    builder.generate_fresh(VariableType::Message, &mut rng);
}

#[test]
#[should_panic(expected = "cannot generate fresh AcceptChannel")]
fn generate_fresh_accept_channel_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    builder.generate_fresh(VariableType::AcceptChannel, &mut rng);
}

#[test]
#[should_panic(expected = "expected 1 inputs, got 0")]
fn append_wrong_input_count_panics() {
    let mut builder = ProgramBuilder::new();
    builder.append(Operation::DerivePoint, &[]);
}

#[test]
#[should_panic(expected = "index 99 out of bounds")]
fn append_out_of_bounds_panics() {
    let mut builder = ProgramBuilder::new();
    builder.append(Operation::DerivePoint, &[99]);
}

#[test]
#[should_panic(expected = "out of bounds")]
fn append_void_reference_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    OpenChannelGenerator.generate(&mut builder, &mut rng);
    let program = builder.build();
    // SendMessage is second-to-last and has void output.
    let send_idx = program.instructions.len() - 2;
    assert!(
        program.instructions[send_idx]
            .operation
            .output_type()
            .is_none(),
        "expected void operation",
    );
    // Rebuild the same program and try to reference the void instruction.
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    OpenChannelGenerator.generate(&mut builder, &mut rng);
    builder.append(Operation::SendMessage, &[send_idx]);
}

#[test]
#[should_panic(expected = "expected PrivateKey, got Amount")]
fn append_type_mismatch_panics() {
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    let amount = builder.generate_fresh(VariableType::Amount, &mut rng);
    builder.append(Operation::DerivePoint, &[amount]);
}

// -- Program::validate tests --

#[test]
fn validate_accepts_generated_program() {
    for seed in 0..100 {
        let program = generate_program(seed);
        program
            .validate()
            .expect("generated program should validate");
    }
}

#[test]
fn validate_accepts_empty_program() {
    let program = Program {
        instructions: vec![],
    };
    program.validate().expect("empty program should validate");
}

#[test]
fn validate_rejects_wrong_input_count() {
    // DerivePoint expects 1 input; supply 0.
    let program = Program {
        instructions: vec![Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![],
        }],
    };
    assert_eq!(
        program.validate(),
        Err(ValidateError::WrongInputCount {
            instr: 0,
            expected: 1,
            got: 0,
        }),
    );
}

#[test]
fn validate_rejects_input_out_of_bounds() {
    // DerivePoint references instruction index 99, which doesn't exist.
    let program = Program {
        instructions: vec![Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![99],
        }],
    };
    assert_eq!(
        program.validate(),
        Err(ValidateError::InputOutOfBounds {
            instr: 0,
            input: 0,
            index: 99,
        }),
    );
}

#[test]
fn validate_rejects_forward_reference() {
    // Instruction 0 references instruction 1 -- SSA violation, even though the
    // index is in bounds for the program as a whole.
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![1],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(key(1)),
                inputs: vec![],
            },
        ],
    };
    assert_eq!(
        program.validate(),
        Err(ValidateError::InputOutOfBounds {
            instr: 0,
            input: 0,
            index: 1,
        }),
    );
}

#[test]
fn validate_rejects_self_reference() {
    // Instruction 0 references itself -- SSA violation.
    let program = Program {
        instructions: vec![Instruction {
            operation: Operation::DerivePoint,
            inputs: vec![0],
        }],
    };
    assert_eq!(
        program.validate(),
        Err(ValidateError::InputOutOfBounds {
            instr: 0,
            input: 0,
            index: 0,
        }),
    );
}

#[test]
fn validate_rejects_void_input() {
    // Build a valid program, then append a DerivePoint that references the void
    // SendMessage instruction emitted by the generator.
    let mut rng = SmallRng::seed_from_u64(0);
    let mut builder = ProgramBuilder::new();
    OpenChannelGenerator.generate(&mut builder, &mut rng);
    let mut program = builder.build();
    let send_idx = program
        .instructions
        .iter()
        .position(|i| matches!(i.operation, Operation::SendMessage))
        .expect("generator emits SendMessage");
    program.instructions.push(Instruction {
        operation: Operation::DerivePoint,
        inputs: vec![send_idx],
    });
    let bad_idx = program.instructions.len() - 1;
    assert_eq!(
        program.validate(),
        Err(ValidateError::VoidInput {
            instr: bad_idx,
            input: 0,
            index: send_idx,
        }),
    );
}

#[test]
fn validate_rejects_type_mismatch() {
    // DerivePoint expects a PrivateKey input, but we feed it an Amount.
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadAmount(1000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
        ],
    };
    assert_eq!(
        program.validate(),
        Err(ValidateError::TypeMismatch {
            instr: 1,
            input: 0,
            expected: VariableType::PrivateKey,
            got: VariableType::Amount,
        }),
    );
}

#[test]
fn validate_accepts_max_message_size_bytes() {
    let program = Program {
        instructions: vec![Instruction {
            operation: Operation::LoadBytes(vec![0; MAX_MESSAGE_SIZE]),
            inputs: vec![],
        }],
    };
    program
        .validate()
        .expect("bytes at exactly MAX_MESSAGE_SIZE should be valid");
}

#[test]
fn validate_rejects_oversized_bytes() {
    let program = Program {
        instructions: vec![Instruction {
            operation: Operation::LoadBytes(vec![0; MAX_MESSAGE_SIZE + 1]),
            inputs: vec![],
        }],
    };
    assert_eq!(
        program.validate(),
        Err(ValidateError::OversizedBytes {
            instr: 0,
            len: MAX_MESSAGE_SIZE + 1,
        }),
    );
}

#[test]
fn validate_rejects_oversized_features() {
    let program = Program {
        instructions: vec![Instruction {
            operation: Operation::LoadFeatures(vec![0; MAX_MESSAGE_SIZE + 1]),
            inputs: vec![],
        }],
    };
    assert_eq!(
        program.validate(),
        Err(ValidateError::OversizedBytes {
            instr: 0,
            len: MAX_MESSAGE_SIZE + 1,
        }),
    );
}

// -- OperationParamMutator tests --

#[test]
fn param_mutator_changes_values() {
    let original = generate_program(0);
    let mut program = original.clone();
    let mutator = OperationParamMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    for _ in 0..100 {
        mutator.mutate(&mut program, &mut rng);
    }
    assert_ne!(
        program, original,
        "OperationParamMutator never changed the program"
    );
}

#[test]
fn param_mutator_returns_false_on_empty_program() {
    let mut program = Program {
        instructions: vec![],
    };
    let mutator = OperationParamMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    assert!(!mutator.mutate(&mut program, &mut rng));
}

#[test]
fn param_mutator_returns_false_for_singleton_extract_field() {
    // TemporaryChannelId is the only AcceptChannelField with output type
    // ChannelId, so ExtractAcceptChannel(TemporaryChannelId) has no type-
    // compatible alternative to swap to. With it as the only mutable op, the
    // mutator must report no change.
    let mut program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::RecvAcceptChannel,
                inputs: vec![],
            },
            Instruction {
                operation: Operation::ExtractAcceptChannel(AcceptChannelField::TemporaryChannelId),
                inputs: vec![0],
            },
        ],
    };
    let mutator = OperationParamMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    assert!(!mutator.mutate(&mut program, &mut rng));
}

#[test]
fn param_mutator_caps_byte_length() {
    // Start at exactly MAX_MESSAGE_SIZE so any growth would exceed the cap.
    let mut program = Program {
        instructions: vec![Instruction {
            operation: Operation::LoadBytes(vec![0; MAX_MESSAGE_SIZE]),
            inputs: vec![],
        }],
    };

    let mutator = OperationParamMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    for _ in 0..10_000 {
        mutator.mutate(&mut program, &mut rng);
        let Operation::LoadBytes(b) = &program.instructions[0].operation else {
            panic!("operation type changed");
        };
        assert!(
            b.len() <= MAX_MESSAGE_SIZE,
            "bytes exceeded MAX_MESSAGE_SIZE: got {}",
            b.len(),
        );
    }
}

#[test]
fn param_mutator_preserves_extract_field_type() {
    // One ExtractAcceptChannel instruction per field variant.
    let mut instructions = vec![Instruction {
        operation: Operation::RecvAcceptChannel,
        inputs: vec![],
    }];
    for &field in AcceptChannelField::ALL {
        instructions.push(Instruction {
            operation: Operation::ExtractAcceptChannel(field),
            inputs: vec![0],
        });
    }

    let mut program = Program { instructions };
    let original_types: Vec<VariableType> = AcceptChannelField::ALL
        .iter()
        .map(|f| f.output_type())
        .collect();

    let mutator = OperationParamMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    for _ in 0..100 {
        mutator.mutate(&mut program, &mut rng);

        for (i, &expected_type) in original_types.iter().enumerate() {
            let field = match &program.instructions[i + 1].operation {
                Operation::ExtractAcceptChannel(f) => *f,
                other => panic!("expected ExtractAcceptChannel, got {other:?}"),
            };
            assert_eq!(
                field.output_type(),
                expected_type,
                "{field:?} has type {:?}, expected {expected_type:?}",
                field.output_type(),
            );
        }
    }
}

// -- InputSwapMutator tests --

#[test]
fn input_swap_changes_references() {
    let original = generate_program(0);
    let mut program = original.clone();
    let mutator = InputSwapMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    for _ in 0..100 {
        mutator.mutate(&mut program, &mut rng);
    }
    assert_ne!(
        program, original,
        "InputSwapMutator never changed the program"
    );
}

#[test]
fn input_swap_returns_false_on_empty_program() {
    let mut program = Program {
        instructions: vec![],
    };
    let mutator = InputSwapMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    assert!(!mutator.mutate(&mut program, &mut rng));
}

#[test]
fn input_swap_returns_false_when_no_alternatives() {
    // DerivePoint consumes the only PrivateKey -- no alternative to swap to.
    let mut program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey(key(1)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
        ],
    };
    let mutator = InputSwapMutator;
    let mut rng = SmallRng::seed_from_u64(0);
    assert!(!mutator.mutate(&mut program, &mut rng));
}

#[test]
fn input_swap_preserves_types() {
    let original = generate_program(0);
    let mutator = InputSwapMutator;
    let mut rng = SmallRng::seed_from_u64(0);

    for _ in 0..100 {
        let mut program = original.clone();
        if mutator.mutate(&mut program, &mut rng) {
            for (i, instr) in program.instructions.iter().enumerate() {
                let expected_types = instr.operation.input_types();
                for (j, &input_idx) in instr.inputs.iter().enumerate() {
                    assert!(
                        input_idx < i,
                        "instruction {i} input {j}: references undefined variable {input_idx}",
                    );
                    let actual_type = program.instructions[input_idx]
                        .operation
                        .output_type()
                        .unwrap_or_else(|| {
                            panic!("instruction {i} input {j}: references void at {input_idx}")
                        });
                    assert_eq!(
                        actual_type, expected_types[j],
                        "instruction {i} input {j}: expected {:?}, got {actual_type:?}",
                        expected_types[j],
                    );
                }
            }
        }
    }
}

// -- DeadCodeEliminator tests --

#[test]
fn dead_code_removes_dead_instructions() {
    // All three LoadAmount instructions are unreferenced; all three are dropped.
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadAmount(1),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(2),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(3),
                inputs: vec![],
            },
        ],
    };
    let result = DeadCodeEliminator.minimize(program);
    assert!(
        result.instructions.is_empty(),
        "all dead instructions should be removed"
    );
    result.validate().expect("trimmed program should validate");
}

/// Build a program with a dead load appended after the generated program.
/// This gives the `DeadCodeEliminator` at least one candidate to try.
fn program_with_dead_load() -> Program {
    let mut p = generate_program(0);
    p.instructions.push(Instruction {
        operation: Operation::LoadAmount(42),
        inputs: vec![],
    });
    p
}

#[test]
fn dead_code_keeps_send_message() {
    let result = DeadCodeEliminator.minimize(program_with_dead_load());
    let has_send = result
        .instructions
        .iter()
        .any(|i| matches!(i.operation, Operation::SendMessage));
    assert!(has_send, "DeadCodeEliminator must not remove SendMessage");
}

#[test]
fn dead_code_keeps_recv_accept_channel() {
    let result = DeadCodeEliminator.minimize(program_with_dead_load());
    let has_recv = result
        .instructions
        .iter()
        .any(|i| matches!(i.operation, Operation::RecvAcceptChannel));
    assert!(
        has_recv,
        "DeadCodeEliminator must not remove RecvAcceptChannel"
    );
}

#[test]
fn dead_code_result_validates() {
    let result = DeadCodeEliminator.minimize(program_with_dead_load());
    result.validate().expect("final program should validate");
}

#[test]
fn dead_code_reindexes_remaining_inputs() {
    // Indexes 0 and 1 are dead loads; 2 is a referenced load; 3 references 2.
    // After dropping 0 and 1, the surviving load shifts to index 0 and the
    // DerivePoint must be rewritten to reference it.
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadAmount(1),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(2),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(key(1)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![2],
            },
        ],
    };
    let result = DeadCodeEliminator.minimize(program);
    assert_eq!(result.instructions.len(), 2);
    assert!(matches!(
        result.instructions[0].operation,
        Operation::LoadPrivateKey(_)
    ));
    assert!(matches!(
        result.instructions[1].operation,
        Operation::SendMessage
    ));
    assert_eq!(result.instructions[1].inputs, vec![0]);
}

#[test]
fn dead_code_chains_collapse() {
    // DerivePoint is unreferenced, so it gets dropped; that drops the
    // ref-count on its LoadPrivateKey input to zero and the load goes too.
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
        ],
    };
    let result = DeadCodeEliminator.minimize(program);
    assert!(result.instructions.is_empty());
}

#[test]
fn dead_code_idempotent() {
    let once = DeadCodeEliminator.minimize(program_with_dead_load());
    let twice = DeadCodeEliminator.minimize(once.clone());
    assert_eq!(once, twice, "elimination is idempotent");
}

// -- CommonSubexpressionEliminator tests --

#[test]
fn cse_merges_identical_amounts() {
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadAmount(1000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(1000), // duplicate
                inputs: vec![],
            },
        ],
    };
    let result = CommonSubexpressionEliminator.minimize(program);
    assert_eq!(result.instructions.len(), 1, "duplicate should be removed");
    assert!(matches!(
        result.instructions[0].operation,
        Operation::LoadAmount(1000)
    ));
    result.validate().expect("merged program should validate");
}

#[test]
fn cse_rewires_references() {
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadAmount(500),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(500), // duplicate of index 0
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(999),
                inputs: vec![],
            },
        ],
    };
    let result = CommonSubexpressionEliminator.minimize(program);
    assert_eq!(result.instructions.len(), 2);
    assert!(matches!(
        result.instructions[0].operation,
        Operation::LoadAmount(500)
    ));
    assert!(matches!(
        result.instructions[1].operation,
        Operation::LoadAmount(999)
    ));
    result.validate().expect("program should still validate");
}

#[test]
fn cse_merges_all_in_one_pass() {
    // Three identical loads collapse to a single canonical instruction.
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadAmount(1000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(1000),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::LoadAmount(1000),
                inputs: vec![],
            },
        ],
    };
    let result = CommonSubexpressionEliminator.minimize(program);
    assert_eq!(result.instructions.len(), 1);
    assert!(matches!(
        result.instructions[0].operation,
        Operation::LoadAmount(1000)
    ));
}

#[test]
fn cse_result_validates() {
    let result = CommonSubexpressionEliminator.minimize(generate_program(0));
    result.validate().expect("merged program should validate");
}

#[test]
fn cse_idempotent() {
    let once = CommonSubexpressionEliminator.minimize(generate_program(0));
    let twice = CommonSubexpressionEliminator.minimize(once.clone());
    assert_eq!(once, twice, "merging is idempotent");
}

#[test]
fn cse_merges_compute_ops_through_canonicalized_inputs() {
    // Two LoadPrivateKey duplicates feed two DerivePoint instructions.
    // CSE first merges the loads, which canonicalizes the DerivePoint
    // inputs to the same index, which in turn lets CSE merge the
    // DerivePoints themselves.
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadPrivateKey(key(7)),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::LoadPrivateKey(key(7)), // duplicate of 0
                inputs: vec![],
            },
            Instruction {
                operation: Operation::DerivePoint,
                inputs: vec![2], // canonicalizes to 0 -> matches index 1
            },
        ],
    };
    let result = CommonSubexpressionEliminator.minimize(program);
    assert_eq!(result.instructions.len(), 2);
    assert!(matches!(
        result.instructions[0].operation,
        Operation::LoadPrivateKey(_)
    ));
    assert!(matches!(
        result.instructions[1].operation,
        Operation::DerivePoint
    ));
    assert_eq!(result.instructions[1].inputs, vec![0]);
}

#[test]
fn cse_does_not_merge_send_message() {
    // SendMessage is not pure (network side-effect): two with the same
    // input must both survive.
    let program = Program {
        instructions: vec![
            Instruction {
                operation: Operation::LoadBytes(vec![0xab]),
                inputs: vec![],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![0],
            },
            Instruction {
                operation: Operation::SendMessage,
                inputs: vec![0],
            },
        ],
    };
    let result = CommonSubexpressionEliminator.minimize(program);
    let send_count = result
        .instructions
        .iter()
        .filter(|i| matches!(i.operation, Operation::SendMessage))
        .count();
    assert_eq!(send_count, 2, "SendMessage must not be deduplicated");
}
