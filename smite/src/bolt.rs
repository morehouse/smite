//! BOLT message encoding and decoding.
//!
//! This module implements encoding and decoding for Lightning Network
//! protocol messages as specified in the BOLT specifications.

mod error_msg;
mod init;
mod ping;
mod pong;
mod tlv;
mod types;
mod warning;

pub use error_msg::Error;
pub use init::{Init, InitTlvs};
pub use ping::Ping;
pub use pong::Pong;
pub use tlv::{TlvRecord, TlvStream};
pub use types::{
    CHANNEL_ID_SIZE, ChannelId, MAX_MESSAGE_SIZE, bigsize_len, decode_bigsize, encode_bigsize,
    read_u16_be, write_u16_be,
};
pub use warning::Warning;

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

/// BOLT message type constants.
pub mod msg_type {
    /// Warning message (BOLT 1).
    pub const WARNING: u16 = 1;
    /// Init message (BOLT 1).
    pub const INIT: u16 = 16;
    /// Error message (BOLT 1).
    pub const ERROR: u16 = 17;
    /// Ping message (BOLT 1).
    pub const PING: u16 = 18;
    /// Pong message (BOLT 1).
    pub const PONG: u16 = 19;
}

/// A decoded BOLT message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// Warning message (type 1).
    Warning(Warning),
    /// Init message (type 16).
    Init(Init),
    /// Error message (type 17).
    Error(Error),
    /// Ping message (type 18).
    Ping(Ping),
    /// Pong message (type 19).
    Pong(Pong),
    /// Unknown message type.
    ///
    /// Stored for odd types that we don't recognize but must accept.
    /// Even unknown types cause decode to fail.
    Unknown {
        /// The message type.
        msg_type: u16,
        /// The raw payload (without type prefix).
        payload: Vec<u8>,
    },
}

impl Message {
    /// Returns the message type number.
    #[must_use]
    pub fn msg_type(&self) -> u16 {
        match self {
            Self::Warning(_) => msg_type::WARNING,
            Self::Init(_) => msg_type::INIT,
            Self::Error(_) => msg_type::ERROR,
            Self::Ping(_) => msg_type::PING,
            Self::Pong(_) => msg_type::PONG,
            Self::Unknown { msg_type, .. } => *msg_type,
        }
    }

    /// Encodes to wire format (with 2-byte message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        write_u16_be(self.msg_type(), &mut out);
        match self {
            Self::Warning(m) => out.extend(m.encode()),
            Self::Init(m) => out.extend(m.encode()),
            Self::Error(m) => out.extend(m.encode()),
            Self::Ping(m) => out.extend(m.encode()),
            Self::Pong(m) => out.extend(m.encode()),
            Self::Unknown { payload, .. } => out.extend(payload),
        }
        out
    }

    /// Decodes from wire format (with 2-byte message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the message is too short, `UnknownEvenType` if
    /// the message type is an unknown even number, or a decode error from the
    /// specific message type.
    pub fn decode(data: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = data;
        let msg_type = read_u16_be(&mut cursor)?;

        match msg_type {
            msg_type::WARNING => Ok(Self::Warning(Warning::decode(cursor)?)),
            msg_type::INIT => Ok(Self::Init(Init::decode(cursor)?)),
            msg_type::ERROR => Ok(Self::Error(Error::decode(cursor)?)),
            msg_type::PING => Ok(Self::Ping(Ping::decode(cursor)?)),
            msg_type::PONG => Ok(Self::Pong(Pong::decode(cursor)?)),
            _ => {
                // Unknown even types must be rejected per BOLT 1
                if msg_type % 2 == 0 {
                    Err(BoltError::UnknownEvenType(msg_type))
                } else {
                    Ok(Self::Unknown {
                        msg_type,
                        payload: cursor.to_vec(),
                    })
                }
            }
        }
    }
}

/// Creates a raw message with the given type and payload.
///
/// This is useful for fuzzing - it allows sending arbitrary payloads
/// with any message type, bypassing normal encoding.
#[must_use]
pub fn message_with_type(msg_type: u16, payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    write_u16_be(msg_type, &mut out);
    out.extend_from_slice(payload);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    // Tests ordered by message type number: Warning(1), Init(16), Error(17), Ping(18), Pong(19)

    #[test]
    fn message_warning_roundtrip() {
        let warning = Warning::all_channels("test warning");
        let msg = Message::Warning(warning.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Warning(warning));
    }

    #[test]
    fn message_init_roundtrip() {
        let init = Init::empty();
        let msg = Message::Init(init.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Init(init));
    }

    #[test]
    fn message_error_roundtrip() {
        let error = Error::all_channels("test error");
        let msg = Message::Error(error.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Error(error));
    }

    #[test]
    fn message_ping_roundtrip() {
        let ping = Ping::new(10);
        let msg = Message::Ping(ping.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Ping(ping));
    }

    #[test]
    fn message_pong_roundtrip() {
        let pong = Pong::new(5);
        let msg = Message::Pong(pong.clone());
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, Message::Pong(pong));
    }

    #[test]
    fn message_unknown_roundtrip() {
        let msg = Message::Unknown {
            msg_type: 101,
            payload: vec![0x11, 0x22, 0x33],
        };
        let encoded = msg.encode();
        let decoded = Message::decode(&encoded).unwrap();
        assert_eq!(decoded, msg);
    }

    #[test]
    fn message_type_values() {
        assert_eq!(
            Message::Warning(Warning::all_channels("")).msg_type(),
            msg_type::WARNING
        );
        assert_eq!(Message::Init(Init::empty()).msg_type(), msg_type::INIT);
        assert_eq!(
            Message::Error(Error::all_channels("")).msg_type(),
            msg_type::ERROR
        );
        assert_eq!(Message::Ping(Ping::new(0)).msg_type(), msg_type::PING);
        assert_eq!(Message::Pong(Pong::new(0)).msg_type(), msg_type::PONG);
        assert_eq!(
            Message::Unknown {
                msg_type: 99,
                payload: vec![]
            }
            .msg_type(),
            99
        );
    }

    #[test]
    fn message_decode_unknown_odd() {
        // Type 99 is odd and unknown - should be accepted
        let data = message_with_type(99, &[0xaa, 0xbb]);
        let msg = Message::decode(&data).unwrap();
        assert_eq!(
            msg,
            Message::Unknown {
                msg_type: 99,
                payload: vec![0xaa, 0xbb]
            }
        );
    }

    #[test]
    fn message_decode_unknown_even() {
        // Type 100 is even and unknown - should be rejected
        let data = message_with_type(100, &[0xaa, 0xbb]);
        assert_eq!(Message::decode(&data), Err(BoltError::UnknownEvenType(100)));
    }

    #[test]
    fn message_decode_truncated() {
        // Only 1 byte - need at least 2 for type
        assert_eq!(
            Message::decode(&[0x00]),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn message_with_type_helper() {
        let data = message_with_type(msg_type::PING, &[0x00, 0x04, 0x00, 0x00]);
        assert_eq!(data, [0x00, 0x12, 0x00, 0x04, 0x00, 0x00]); // 0x12 = 18 = PING
    }
}
