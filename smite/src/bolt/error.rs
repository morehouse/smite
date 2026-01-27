//! Error types for BOLT message encoding/decoding.

/// Errors that can occur during BOLT message encoding/decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoltError {
    // General decoding errors
    /// Not enough bytes to decode (message or field truncated)
    Truncated { expected: usize, actual: usize },
    /// Unknown even message type (must close connection per BOLT 1)
    UnknownEvenType(u16),

    // BigSize errors
    /// `BigSize` not minimally encoded
    BigSizeNotMinimal,
    /// `BigSize` truncated (unexpected EOF)
    BigSizeTruncated,

    // TLV errors
    /// TLV type not in strictly increasing order
    TlvNotIncreasing { previous: u64, current: u64 },
    /// TLV length exceeds remaining bytes
    TlvLengthOverflow,
    /// Unknown even TLV type (must reject per BOLT 1)
    TlvUnknownEvenType(u64),
}

impl std::fmt::Display for BoltError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { expected, actual } => {
                write!(f, "TRUNCATED expected {expected} got {actual}")
            }
            Self::UnknownEvenType(t) => write!(f, "UNKNOWN_EVEN_TYPE {t}"),
            Self::BigSizeNotMinimal => write!(f, "BIGSIZE_NOT_MINIMAL"),
            Self::BigSizeTruncated => write!(f, "BIGSIZE_TRUNCATED"),
            Self::TlvNotIncreasing { previous, current } => {
                write!(
                    f,
                    "TLV_NOT_INCREASING previous {previous} current {current}"
                )
            }
            Self::TlvLengthOverflow => write!(f, "TLV_LENGTH_OVERFLOW"),
            Self::TlvUnknownEvenType(t) => write!(f, "TLV_UNKNOWN_EVEN_TYPE {t}"),
        }
    }
}

impl std::error::Error for BoltError {}
