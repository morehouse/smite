//! Error types for BOLT message encoding/decoding.

/// Errors that can occur during BOLT message encoding/decoding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BoltError {
    // General decoding errors
    /// Not enough bytes to decode (message or field truncated)
    Truncated { expected: usize, actual: usize },

    // BigSize errors
    /// `BigSize` not minimally encoded
    BigSizeNotMinimal,
    /// `BigSize` truncated (unexpected EOF)
    BigSizeTruncated,
}

impl std::fmt::Display for BoltError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Truncated { expected, actual } => {
                write!(f, "TRUNCATED expected {expected} got {actual}")
            }
            Self::BigSizeNotMinimal => write!(f, "BIGSIZE_NOT_MINIMAL"),
            Self::BigSizeTruncated => write!(f, "BIGSIZE_TRUNCATED"),
        }
    }
}

impl std::error::Error for BoltError {}
