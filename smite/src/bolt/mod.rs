//! BOLT message encoding and decoding.
//!
//! This module implements encoding and decoding for Lightning Network
//! protocol messages as specified in the BOLT specifications.

mod error;
mod error_msg;
mod init;
mod ping;
mod pong;
mod tlv;
mod types;
mod warning;

pub use error::BoltError;
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
