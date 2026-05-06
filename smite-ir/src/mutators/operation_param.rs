//! Mutator that tweaks embedded literal values in Load and Extract operations.

use rand::seq::IteratorRandom;
use rand::{Rng, RngExt};
use smite::bolt::MAX_MESSAGE_SIZE;

use super::Mutator;
use crate::operation::{AcceptChannelField, ChannelTypeVariant, ShutdownScriptVariant};
use crate::{Operation, Program};

/// Mutates the embedded parameter of a randomly chosen `is_param_mutable`
/// instruction. For numeric loads, applies a random arithmetic tweak. For byte
/// loads, flips/adds/removes bytes. For extract operations, swaps to a random
/// field with the same output type.
pub struct OperationParamMutator;

impl Mutator for OperationParamMutator {
    fn mutate(&self, program: &mut Program, rng: &mut impl Rng) -> bool {
        let Some(idx) = program
            .instructions
            .iter()
            .enumerate()
            .filter_map(|(i, instr)| instr.operation.is_param_mutable().then_some(i))
            .choose(rng)
        else {
            return false;
        };

        mutate_operation(&mut program.instructions[idx].operation, rng)
    }
}

/// Returns `true` if the operation was changed.
fn mutate_operation(op: &mut Operation, rng: &mut impl Rng) -> bool {
    match op {
        Operation::LoadAmount(v) => {
            *v = tweak_u64(*v, rng);
            true
        }
        Operation::LoadFeeratePerKw(v) | Operation::LoadBlockHeight(v) => {
            *v = tweak_u32(*v, rng);
            true
        }
        Operation::LoadU16(v) => {
            *v = tweak_u16(*v, rng);
            true
        }
        Operation::LoadU8(v) => {
            *v = tweak_u8(*v, rng);
            true
        }
        Operation::LoadBytes(bytes) | Operation::LoadFeatures(bytes) => {
            mutate_bytes(bytes, rng);
            true
        }
        Operation::LoadPrivateKey(bytes) | Operation::LoadChannelId(bytes) => {
            mutate_fixed_bytes(bytes, rng);
            true
        }
        Operation::LoadShutdownScript(variant) => {
            mutate_shutdown_script(variant, rng);
            true
        }
        Operation::LoadChannelType(variant) => {
            mutate_channel_type(variant, rng);
            true
        }
        Operation::ExtractAcceptChannel(field) => mutate_extract_field(field, rng),

        // Non-mutable variants. Reaching here means `is_param_mutable` and this
        // match have drifted out of sync.
        Operation::DerivePoint
        | Operation::LoadTargetPubkeyFromContext
        | Operation::LoadChainHashFromContext
        | Operation::BuildOpenChannel
        | Operation::SendMessage
        | Operation::RecvAcceptChannel => {
            unreachable!("is_param_mutable returned true for {op:?}")
        }
    }
}

// -- Numeric tweaks --

fn tweak_u64(v: u64, rng: &mut impl Rng) -> u64 {
    match rng.random_range(0..4) {
        0 => rng.random(),
        1 => v.wrapping_add(rng.random_range(1..=256)),
        2 => v.wrapping_sub(rng.random_range(1..=256)),
        _ => interesting_u64(rng),
    }
}

fn tweak_u32(v: u32, rng: &mut impl Rng) -> u32 {
    match rng.random_range(0..4) {
        0 => rng.random(),
        1 => v.wrapping_add(rng.random_range(1..=256)),
        2 => v.wrapping_sub(rng.random_range(1..=256)),
        _ => interesting_u32(rng),
    }
}

fn tweak_u16(v: u16, rng: &mut impl Rng) -> u16 {
    match rng.random_range(0..4) {
        0 => rng.random(),
        1 => v.wrapping_add(rng.random_range(1..=16)),
        2 => v.wrapping_sub(rng.random_range(1..=16)),
        _ => interesting_u16(rng),
    }
}

fn tweak_u8(v: u8, rng: &mut impl Rng) -> u8 {
    match rng.random_range(0..4) {
        0 => rng.random(),
        1 => v.wrapping_add(rng.random_range(1..=8)),
        2 => v.wrapping_sub(rng.random_range(1..=8)),
        _ => interesting_u8(rng),
    }
}

// -- Byte mutations --

/// Shuffle a random subrange of `bytes` using Fisher-Yates.
fn shuffle_subrange(bytes: &mut [u8], rng: &mut impl Rng) {
    if bytes.len() < 2 {
        return;
    }
    let max_len = bytes.len().min(16);
    let len = rng.random_range(2..=max_len);
    let start = rng.random_range(0..=bytes.len() - len);
    for i in (1..len).rev() {
        let j = rng.random_range(0..=i);
        bytes.swap(start + i, start + j);
    }
}

fn mutate_bytes(bytes: &mut Vec<u8>, rng: &mut impl Rng) {
    match rng.random_range(0..10) {
        // Flip a random bit.
        0 if !bytes.is_empty() => {
            let idx = rng.random_range(0..bytes.len());
            bytes[idx] ^= 1 << rng.random_range(0..8u8);
        }
        // Change a random byte.
        1 if !bytes.is_empty() => {
            let idx = rng.random_range(0..bytes.len());
            bytes[idx] = rng.random();
        }
        // Shuffle a random subrange.
        2 if bytes.len() >= 2 => {
            shuffle_subrange(bytes, rng);
        }
        // Insert a random byte.
        3 if bytes.len() < MAX_MESSAGE_SIZE => {
            let pos = rng.random_range(0..=bytes.len());
            bytes.insert(pos, rng.random());
        }
        // Insert repeated bytes. Requires room for at least 2 bytes.
        4 if bytes.len() + 2 <= MAX_MESSAGE_SIZE => {
            let pos = rng.random_range(0..=bytes.len());
            let max_count = (MAX_MESSAGE_SIZE - bytes.len()).min(128);
            let count = rng.random_range(2..=max_count);
            let byte: u8 = rng.random();
            bytes.splice(pos..pos, std::iter::repeat_n(byte, count));
        }
        // Remove a random byte.
        5 if !bytes.is_empty() => {
            let idx = rng.random_range(0..bytes.len());
            bytes.remove(idx);
        }
        // Erase a byte range (up to half the length).
        6 if bytes.len() >= 2 => {
            let max_erase = bytes.len() / 2;
            let count = rng.random_range(1..=max_erase);
            let start = rng.random_range(0..=bytes.len() - count);
            bytes.drain(start..start + count);
        }
        // Add or subtract a small delta from a random byte.
        7 if !bytes.is_empty() => {
            let idx = rng.random_range(0..bytes.len());
            let delta = rng.random_range(1..=35);
            if rng.random() {
                bytes[idx] = bytes[idx].wrapping_add(delta);
            } else {
                bytes[idx] = bytes[idx].wrapping_sub(delta);
            }
        }
        // Copy a chunk from one position to another.
        8 if bytes.len() >= 2 => {
            let max_len = (bytes.len() - 1).min(32);
            let len = rng.random_range(1..=max_len);
            let src = rng.random_range(0..=bytes.len() - len);
            let dst = rng.random_range(0..=bytes.len() - len);
            bytes.copy_within(src..src + len, dst);
        }
        // Replace with random length and content.
        _ => {
            let len = rng.random_range(0..=256);
            bytes.resize(len, 0);
            rng.fill(&mut bytes[..]);
        }
    }
}

/// In-place byte tweaks that preserve the slice's length.
fn mutate_fixed_bytes(bytes: &mut [u8], rng: &mut impl Rng) {
    if bytes.is_empty() {
        return;
    }
    let n = bytes.len();
    match rng.random_range(0..6) {
        // Flip a random bit.
        0 => {
            let idx = rng.random_range(0..n);
            bytes[idx] ^= 1 << rng.random_range(0..8u8);
        }
        // Change a random byte.
        1 => {
            let idx = rng.random_range(0..n);
            bytes[idx] = rng.random();
        }
        // Shuffle a random subrange.
        2 => shuffle_subrange(bytes, rng),
        // Add or subtract a small delta from a random byte.
        3 => {
            let idx = rng.random_range(0..n);
            let delta = rng.random_range(1..=35);
            if rng.random() {
                bytes[idx] = bytes[idx].wrapping_add(delta);
            } else {
                bytes[idx] = bytes[idx].wrapping_sub(delta);
            }
        }
        // Copy a chunk from one position to another.
        4 if n >= 2 => {
            let max_len = (n - 1).min(32);
            let len = rng.random_range(1..=max_len);
            let src = rng.random_range(0..=n - len);
            let dst = rng.random_range(0..=n - len);
            bytes.copy_within(src..src + len, dst);
        }
        // Randomize entirely.
        _ => rng.fill(bytes),
    }
}

// -- Enum mutations --

/// Swaps to a different `ChannelTypeVariant`.
fn mutate_channel_type(variant: &mut ChannelTypeVariant, rng: &mut impl Rng) {
    let current = *variant;
    *variant = ChannelTypeVariant::ALL
        .iter()
        .copied()
        .filter(|v| *v != current)
        .choose(rng)
        .expect("ChannelTypeVariant::ALL contains multiple variants");
}

/// Mutates a `ShutdownScriptVariant`. Half the time, mutates the variant's
/// embedded bytes in place; otherwise replaces with a random different variant.
/// Falls through to a variant swap if the current variant has no embedded
/// bytes.
fn mutate_shutdown_script(variant: &mut ShutdownScriptVariant, rng: &mut impl Rng) {
    if rng.random() && mutate_shutdown_script_bytes(variant, rng) {
        return;
    }
    let current = std::mem::discriminant(variant);
    for _ in 0..8 {
        let candidate = ShutdownScriptVariant::random(rng);
        if std::mem::discriminant(&candidate) != current {
            *variant = candidate;
            return;
        }
    }
}

/// Mutates the variant's embedded bytes via `mutate_fixed_bytes`. Returns
/// `false` if the variant carries no bytes to mutate.
fn mutate_shutdown_script_bytes(variant: &mut ShutdownScriptVariant, rng: &mut impl Rng) -> bool {
    let bytes: &mut [u8] = match variant {
        ShutdownScriptVariant::Empty => return false,
        ShutdownScriptVariant::P2pkh(h)
        | ShutdownScriptVariant::P2sh(h)
        | ShutdownScriptVariant::P2wpkh(h) => h,
        ShutdownScriptVariant::P2wsh(h) => h,
        ShutdownScriptVariant::AnySegwit { program, .. } => program,
        ShutdownScriptVariant::OpReturn(data) => data,
    };
    mutate_fixed_bytes(bytes, rng);
    true
}

/// Returns `true` if the field was swapped, `false` if no same-type alternative
/// field exists.
fn mutate_extract_field(field: &mut AcceptChannelField, rng: &mut impl Rng) -> bool {
    // Only swap to fields with the same output type to preserve program validity.
    let target_type = field.output_type();
    let Some(new_field) = AcceptChannelField::ALL
        .iter()
        .copied()
        .filter(|f| f.output_type() == target_type && f != field)
        .choose(rng)
    else {
        return false;
    };
    *field = new_field;
    true
}

// -- Interesting boundary values --
//
// Each width includes all boundaries from narrower widths plus width-specific
// boundaries and BOLT-relevant constants.

const INTERESTING_U8: &[u8] = &[0, 1, 0x7F, 0x80, 0xFF];

#[rustfmt::skip]
const INTERESTING_U16: &[u16] = &[
    // u8 boundaries
    0, 1, 0x7F, 0x80, 0xFF,
    // u16 boundaries
    0x100, 0x7FFF, 0x8000, 0xFFFF,
    // BOLT constants
    6,    // minimum confirmation depth
    144,  // blocks per day
    483,  // max accepted HTLCs (BOLT 2)
    2016, // blocks per 2 weeks
];

#[rustfmt::skip]
const INTERESTING_U32: &[u32] = &[
    // u8 boundaries
    0, 1, 0x7F, 0x80, 0xFF,
    // u16 boundaries
    0x100, 0x7FFF, 0x8000, 0xFFFF,
    // u32 boundaries
    0x1_0000, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF,
    // BOLT constants
    6,    // minimum confirmation depth
    144,  // blocks per day
    253,  // min feerate in sat/kw
    2016, // blocks per 2 weeks
];

#[rustfmt::skip]
const INTERESTING_U64: &[u64] = &[
    // u8 boundaries
    0, 1, 0x7F, 0x80, 0xFF,
    // u16 boundaries
    0x100, 0x7FFF, 0x8000, 0xFFFF,
    // u32 boundaries
    0x1_0000, 0x7FFF_FFFF, 0x8000_0000, 0xFFFF_FFFF,
    // u64 boundaries
    0x1_0000_0000, 0x7FFF_FFFF_FFFF_FFFF,
    0x8000_0000_0000_0000, 0xFFFF_FFFF_FFFF_FFFF,
    // BOLT constants (sats and msats)
    546,                        // dust limit (sats)
    546_000,                    // dust limit (msats)
    16_777_216,                 // non-wumbo channel limit, 2^24 (sats)
    16_777_216_000,             // non-wumbo channel limit (msats)
    100_000_000,                // 1 BTC (sats)
    100_000_000_000,            // 1 BTC (msats)
    2_100_000_000_000_000,      // 21M BTC (sats)
    2_100_000_000_000_000_000,  // 21M BTC (msats)
];

fn interesting_u8(rng: &mut impl Rng) -> u8 {
    INTERESTING_U8[rng.random_range(0..INTERESTING_U8.len())]
}

fn interesting_u16(rng: &mut impl Rng) -> u16 {
    INTERESTING_U16[rng.random_range(0..INTERESTING_U16.len())]
}

fn interesting_u32(rng: &mut impl Rng) -> u32 {
    INTERESTING_U32[rng.random_range(0..INTERESTING_U32.len())]
}

fn interesting_u64(rng: &mut impl Rng) -> u64 {
    INTERESTING_U64[rng.random_range(0..INTERESTING_U64.len())]
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::{SeedableRng, rngs::SmallRng};

    #[test]
    fn test_shuffle_subrange_preserves_elements() {
        let mut rng = SmallRng::seed_from_u64(0);
        let sorted = vec![1, 2, 3, 4, 5, 6, 7, 8];
        let mut shuffled = sorted.clone();

        shuffle_subrange(&mut shuffled, &mut rng);

        assert_ne!(shuffled, sorted, "Shuffle must shuffle elements");
        shuffled.sort_unstable();
        assert_eq!(
            shuffled, sorted,
            "Shuffle must preserve all original elements"
        );
    }

    #[test]
    fn test_shuffle_subrange_empty_and_single() {
        let mut rng = SmallRng::seed_from_u64(0);

        let mut empty: Vec<u8> = vec![];
        shuffle_subrange(&mut empty, &mut rng);
        assert!(empty.is_empty());

        let mut single = vec![0xFF];
        shuffle_subrange(&mut single, &mut rng);
        assert_eq!(single, vec![0xFF]);
    }

    #[test]
    fn test_mutate_bytes_respects_max_size() {
        let mut rng = SmallRng::seed_from_u64(0);
        let mut data = vec![0xAA; MAX_MESSAGE_SIZE];

        for _ in 0..50 {
            mutate_bytes(&mut data, &mut rng);

            // The mutator must NEVER exceed the max size, even if it picks
            // the "insert" or "copy part" branches.
            assert!(
                data.len() <= MAX_MESSAGE_SIZE,
                "mutate_bytes exceeded MAX_MESSAGE_SIZE. Current len: {}",
                data.len()
            );
        }
    }

    #[test]
    fn test_mutate_bytes_handles_empty_input() {
        let mut rng = SmallRng::seed_from_u64(0);
        let mut data: Vec<u8> = vec![];

        // Should either safely insert data or do nothing.
        mutate_bytes(&mut data, &mut rng);
    }

    #[test]
    fn test_mutate_fixed_bytes_no_out_of_bounds_panics() {
        let mut rng = SmallRng::seed_from_u64(0);
        let mut bytes = [0x00; 32];

        for _ in 0..500 {
            mutate_fixed_bytes(&mut bytes, &mut rng);
        }
        // Ensure the array actually mutated from all zeros
        assert_ne!(bytes, [0x00; 32], "Array should have been mutated");
    }

    #[test]
    fn test_mutate_extract_field_preserves_type() {
        let mut rng = SmallRng::seed_from_u64(0);
        let mut field = AcceptChannelField::DustLimitSatoshis;
        let original_type = field.output_type();

        if mutate_extract_field(&mut field, &mut rng) {
            assert_ne!(
                field,
                AcceptChannelField::DustLimitSatoshis,
                "Field should be different"
            );
            assert_eq!(
                field.output_type(),
                original_type,
                "Output type must be preserved"
            );
        }
    }

    #[test]
    fn test_mutate_extract_field_handles_unique_types() {
        let mut rng = SmallRng::seed_from_u64(0);

        // Choose a field that has NO other fields with the same output type.
        // MinimumDepth is the only field with a `u32` output type.
        let mut test_field = AcceptChannelField::MinimumDepth;
        let original_field = test_field;

        let changed = mutate_extract_field(&mut test_field, &mut rng);

        assert!(
            !changed,
            "Should return false when no alternative field of same type exists"
        );
        assert_eq!(test_field, original_field, "Field must remain unchanged");
    }
}
