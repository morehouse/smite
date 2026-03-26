//! BOLT 2 shutdown message.

use super::BoltError;
use super::types::{ChannelId, MAX_MESSAGE_SIZE};
use super::wire::WireFormat;

/// BOLT 2 shutdown message (type 38).
///
/// Sent by either peer to initiate a cooperative close.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Shutdown {
    /// Channel to be closed.
    pub channel_id: ChannelId,
    /// The output script where that peer wants to receive their funds.
    pub scriptpubkey: Vec<u8>,
}

impl Shutdown {
    /// Creates a shutdown for a specific channel.
    ///
    /// # Panics
    ///
    /// Panics if `scriptpubkey` exceeds `MAX_MESSAGE_SIZE` bytes.
    #[must_use]
    pub fn for_channel(channel_id: ChannelId, scriptpubkey: Vec<u8>) -> Self {
        assert!(
            scriptpubkey.len() <= MAX_MESSAGE_SIZE,
            "shutdown scriptpubkey exceeds maximum size"
        );
        Self {
            channel_id,
            scriptpubkey,
        }
    }

    /// Encodes to wire format (without message type prefix).
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        self.channel_id.write(&mut out);
        self.scriptpubkey.write(&mut out);
        out
    }

    /// Decodes from wire format (without message type prefix).
    ///
    /// # Errors
    ///
    /// Returns `Truncated` if the payload is too short.
    pub fn decode(payload: &[u8]) -> Result<Self, BoltError> {
        let mut cursor = payload;
        let channel_id = ChannelId::read(&mut cursor)?;
        let scriptpubkey = Vec::<u8>::read(&mut cursor)?;

        Ok(Self {
            channel_id,
            scriptpubkey,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::super::CHANNEL_ID_SIZE;
    use super::*;

    #[test]
    fn shutdown_for_channel() {
        let channel_id = ChannelId::new([0x42; CHANNEL_ID_SIZE]);
        let spk = vec![0x00, 0x14, 0xab, 0xcd];
        let shutdown = Shutdown::for_channel(channel_id, spk);
        assert_eq!(shutdown.channel_id, channel_id);
        assert_eq!(shutdown.scriptpubkey, &[0x00, 0x14, 0xab, 0xcd]);
    }

    #[test]
    fn shutdown_encode() {
        let channel_id = ChannelId::new([0x00; CHANNEL_ID_SIZE]);
        let spk = vec![0x51, 0x20]; // p2tr-ish prefix
        let shutdown = Shutdown::for_channel(channel_id, spk);
        let encoded = shutdown.encode();
        // channel_id(32) + len(2) + scriptpubkey(2)
        assert_eq!(encoded.len(), CHANNEL_ID_SIZE + 2 + 2);
        assert_eq!(
            &encoded[CHANNEL_ID_SIZE..CHANNEL_ID_SIZE + 2],
            &[0x00, 0x02]
        );
        assert_eq!(&encoded[CHANNEL_ID_SIZE + 2..], &[0x51, 0x20]);
    }

    #[test]
    fn shutdown_decode() {
        let mut data = vec![0x11u8; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 0x03]); // len = 3
        data.extend_from_slice(&[0xaa, 0xbb, 0xcc]);

        let shutdown = Shutdown::decode(&data).unwrap();
        assert_eq!(
            shutdown.channel_id,
            ChannelId::new([0x11u8; CHANNEL_ID_SIZE])
        );
        assert_eq!(shutdown.scriptpubkey, vec![0xaa, 0xbb, 0xcc]);
    }

    #[test]
    fn shutdown_roundtrip() {
        let original = Shutdown::for_channel(
            ChannelId::new([0xab; CHANNEL_ID_SIZE]),
            vec![0x00, 0x14, 0x01, 0x02, 0x03],
        );
        let encoded = original.encode();
        let decoded = Shutdown::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn shutdown_decode_truncated_channel_id() {
        assert_eq!(
            Shutdown::decode(&[0x00; 20]),
            Err(BoltError::Truncated {
                expected: CHANNEL_ID_SIZE,
                actual: 20
            })
        );
    }

    #[test]
    fn shutdown_decode_truncated_len() {
        let mut data = vec![0x00u8; CHANNEL_ID_SIZE];
        data.push(0x00); // only 1 byte of len
        assert_eq!(
            Shutdown::decode(&data),
            Err(BoltError::Truncated {
                expected: 2,
                actual: 1
            })
        );
    }

    #[test]
    fn shutdown_decode_truncated_scriptpubkey() {
        let mut data = vec![0x00u8; CHANNEL_ID_SIZE];
        data.extend_from_slice(&[0x00, 0x10]); // len = 16
        data.extend_from_slice(&[0x01, 0x02, 0x03]); // only 3 bytes
        assert_eq!(
            Shutdown::decode(&data),
            Err(BoltError::Truncated {
                expected: 16,
                actual: 3
            })
        );
    }

    #[test]
    fn shutdown_empty_scriptpubkey() {
        let original = Shutdown::for_channel(ChannelId::new([0xff; CHANNEL_ID_SIZE]), vec![]);
        let encoded = original.encode();
        let decoded = Shutdown::decode(&encoded).unwrap();
        assert_eq!(original, decoded);
        assert!(decoded.scriptpubkey.is_empty());
    }
}
