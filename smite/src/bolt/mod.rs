//! BOLT message encoding and decoding.
//!
//! This module implements encoding and decoding for Lightning Network
//! protocol messages as specified in the BOLT specifications.

mod error;
mod types;

pub use error::BoltError;
pub use types::{
    CHANNEL_ID_SIZE, ChannelId, MAX_MESSAGE_SIZE, bigsize_len, decode_bigsize, encode_bigsize,
    read_u16_be, write_u16_be,
};
