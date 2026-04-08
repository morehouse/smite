/// Errors that can occur during Noise protocol handshake and message processing.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum NoiseError {
    /// Act One: Unrecognized handshake version
    #[error("ACT1_BAD_VERSION {0}")]
    ActOneBadVersion(u8),
    /// Act One: Invalid public key encoding
    #[error("ACT1_BAD_PUBKEY")]
    ActOneBadPubkey,
    /// Act One: MAC verification failed
    #[error("ACT1_BAD_TAG")]
    ActOneBadTag,

    /// Act Two: Unrecognized handshake version
    #[error("ACT2_BAD_VERSION {0}")]
    ActTwoBadVersion(u8),
    /// Act Two: Invalid public key encoding
    #[error("ACT2_BAD_PUBKEY")]
    ActTwoBadPubkey,
    /// Act Two: MAC verification failed
    #[error("ACT2_BAD_TAG")]
    ActTwoBadTag,

    /// Act Three: Unrecognized handshake version
    #[error("ACT3_BAD_VERSION {0}")]
    ActThreeBadVersion(u8),
    /// Act Three: MAC verification failed on encrypted static key
    #[error("ACT3_BAD_CIPHERTEXT")]
    ActThreeBadCiphertext,
    /// Act Three: Invalid static public key after decryption
    #[error("ACT3_BAD_PUBKEY")]
    ActThreeBadPubkey,
    /// Act Three: Final MAC verification failed
    #[error("ACT3_BAD_TAG")]
    ActThreeBadTag,

    /// Message decryption failed (bad MAC)
    #[error("DECRYPTION_FAILED")]
    DecryptionFailed,

    /// Handshake not complete - cannot encrypt/decrypt messages yet
    #[error("HANDSHAKE_INCOMPLETE")]
    HandshakeIncomplete,

    /// Invalid handshake state for this operation
    #[error("INVALID_STATE")]
    InvalidState,
}
