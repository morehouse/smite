//! TLV (Type-Length-Value) stream encoding and decoding.
//!
//! TLV streams are used for optional and extension fields in BOLT messages.
//! See BOLT 1 for the specification.

use super::BoltError;
use super::types::BigSize;
use super::wire::WireFormat;

/// A single TLV record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlvRecord {
    /// The type identifier for this record.
    pub tlv_type: u64,
    /// The value bytes.
    pub value: Vec<u8>,
}

/// A parsed TLV stream containing zero or more records.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TlvStream {
    records: Vec<TlvRecord>,
}

impl TlvStream {
    /// Creates an empty TLV stream.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Adds a record to the stream.
    ///
    /// Records are maintained in sorted order by type.
    ///
    /// # Panics
    ///
    /// Panics if a record with this type already exists.
    pub fn add(&mut self, tlv_type: u64, value: Vec<u8>) {
        // Find insertion point to maintain sorted order
        let pos = self
            .records
            .iter()
            .position(|r| r.tlv_type >= tlv_type)
            .unwrap_or(self.records.len());

        assert!(
            pos == self.records.len() || self.records[pos].tlv_type != tlv_type,
            "duplicate TLV type {tlv_type}"
        );

        self.records.insert(pos, TlvRecord { tlv_type, value });
    }

    /// Gets a record by type, returning the value if found.
    #[must_use]
    pub fn get(&self, tlv_type: u64) -> Option<&[u8]> {
        self.records
            .iter()
            .find(|r| r.tlv_type == tlv_type)
            .map(|r| r.value.as_slice())
    }

    /// Gets a record by type and decodes it as a fixed-size `WireFormat` value.
    ///
    /// Returns `None` if the record is absent. Rejects TLV values that are
    /// longer than the type's known wire encoding.
    ///
    /// # Errors
    ///
    /// Returns a `BoltError` if the value is truncated or contains trailing
    /// bytes after decoding.
    pub fn get_as<T: WireFormat>(&self, tlv_type: u64) -> Result<Option<T>, BoltError> {
        self.get(tlv_type)
            .map(|data| {
                let mut cursor = data;
                let value = T::read(&mut cursor)?;
                // we must fail to parse the stream
                // "if length is not exactly equal to that required for the known encoding for type"
                // [BOLT 1]: https://github.com/lightning/bolts/blob/master/01-messaging.md#type-length-value-format
                if !cursor.is_empty() {
                    let bytes_read = data.len() - cursor.len();
                    return Err(BoltError::TlvTrailingBytes {
                        tlv_type,
                        expected: bytes_read,
                        actual: data.len(),
                    });
                }
                Ok(value)
            })
            .transpose()
    }

    /// Gets all records by type and decodes them as fixed-size `WireFormat`
    /// values.
    ///
    /// Returns `None` if no records are found, or `Some(vec)` if present.
    ///
    /// # Errors
    ///
    /// Returns a `BoltError` if decoding a TLV value fails or the TLV values
    /// cannot be divided into fixed-size chunks.
    pub fn get_as_many<T: WireFormat>(&self, tlv_type: u64) -> Result<Option<Vec<T>>, BoltError> {
        match self.get(tlv_type) {
            Some(data) => {
                if data.is_empty() {
                    return Ok(Some(Vec::new()));
                }

                let total_bytes = data.len();
                let mut cursor = data;

                // read first element to determine chunk size
                let first = T::read(&mut cursor)?;

                let chunk_size = total_bytes - cursor.len();
                if chunk_size == 0 {
                    return Err(BoltError::Truncated {
                        expected: 1,
                        actual: 0,
                    });
                }
                if total_bytes % chunk_size != 0 {
                    return Err(BoltError::TlvTrailingBytes {
                        tlv_type,
                        expected: (total_bytes / chunk_size) * chunk_size,
                        actual: total_bytes,
                    });
                }

                let mut values = Vec::with_capacity(total_bytes / chunk_size);
                values.push(first);
                for chunk in cursor.chunks(chunk_size) {
                    let mut chunk_cursor = chunk;
                    values.push(T::read(&mut chunk_cursor)?);
                }
                Ok(Some(values))
            }
            None => Ok(None),
        }
    }

    /// Returns an iterator over all records.
    pub fn iter(&self) -> impl Iterator<Item = &TlvRecord> {
        self.records.iter()
    }

    /// Returns true if the stream contains no records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.records.is_empty()
    }

    /// Encodes the TLV stream to bytes.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::new();
        for record in &self.records {
            BigSize::new(record.tlv_type).write(&mut out);
            BigSize::new(record.value.len() as u64).write(&mut out);
            out.extend(&record.value);
        }
        out
    }

    /// Decodes a TLV stream from bytes.
    ///
    /// Validates that types are strictly increasing and rejects all even types.
    /// Unknown odd types are stored but their semantics are ignored.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream is malformed or contains even types.
    pub fn decode(data: &[u8]) -> Result<Self, BoltError> {
        Self::decode_with_known(data, &[])
    }

    /// Same as `decode`, but treats the specified even types as known.
    ///
    /// # Errors
    ///
    /// Returns an error if the stream is malformed or contains unknown even types.
    pub fn decode_with_known(data: &[u8], known_even: &[u64]) -> Result<Self, BoltError> {
        let mut stream = Self::new();
        let mut cursor: &[u8] = data;
        let mut last_type: Option<u64> = None;

        while !cursor.is_empty() {
            // Decode type
            let tlv_type = BigSize::read(&mut cursor)?.value();

            // Check strictly increasing order
            if let Some(prev) = last_type
                && tlv_type <= prev
            {
                return Err(BoltError::TlvNotIncreasing {
                    previous: prev,
                    current: tlv_type,
                });
            }
            last_type = Some(tlv_type);

            // Decode length
            let length = BigSize::read(&mut cursor)?.value();

            // Check we have enough bytes for value
            let length = usize::try_from(length).map_err(|_| BoltError::TlvLengthOverflow)?;
            if length > cursor.len() {
                return Err(BoltError::TlvLengthOverflow);
            }

            // Check even/odd rule: unknown even types are errors
            let is_even = tlv_type % 2 == 0;
            if is_even && !known_even.contains(&tlv_type) {
                return Err(BoltError::TlvUnknownEvenType(tlv_type));
            }

            // Store the record
            let value = cursor[..length].to_vec();
            cursor = &cursor[length..];

            stream.records.push(TlvRecord { tlv_type, value });
        }

        Ok(stream)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // ===== Basic functionality tests =====

    #[test]
    fn empty_stream() {
        let stream = TlvStream::new();
        assert!(stream.is_empty());
        assert_eq!(stream.encode(), Vec::<u8>::new());
    }

    #[test]
    fn single_record() {
        let mut stream = TlvStream::new();
        stream.add(1, vec![0xaa, 0xbb]);

        let encoded = stream.encode();
        // type=1 (1 byte), length=2 (1 byte), value=aabb (2 bytes)
        assert_eq!(encoded, [0x01, 0x02, 0xaa, 0xbb]);

        let decoded = TlvStream::decode(&encoded).unwrap();
        assert_eq!(decoded.get(1), Some(&[0xaa, 0xbb][..]));
    }

    #[test]
    fn multiple_records_sorted() {
        let mut stream = TlvStream::new();
        // Add out of order - should be sorted
        stream.add(5, vec![0x55]);
        stream.add(1, vec![0x11]);
        stream.add(3, vec![0x33]);

        let encoded = stream.encode();
        // Should be type 1, then 3, then 5
        assert_eq!(
            encoded,
            [
                0x01, 0x01, 0x11, // type=1, len=1, val=0x11
                0x03, 0x01, 0x33, // type=3, len=1, val=0x33
                0x05, 0x01, 0x55, // type=5, len=1, val=0x55
            ]
        );
    }

    #[test]
    fn roundtrip() {
        let mut stream = TlvStream::new();
        stream.add(1, vec![0x01, 0x02, 0x03]);
        stream.add(3, vec![]);
        stream.add(255, vec![0xff; 100]);

        let encoded = stream.encode();
        let decoded = TlvStream::decode(&encoded).unwrap();

        assert_eq!(decoded.get(1), Some(&[0x01, 0x02, 0x03][..]));
        assert_eq!(decoded.get(3), Some(&[][..]));
        assert_eq!(decoded.get(255), Some(&[0xff; 100][..]));
    }

    #[test]
    fn get_as_missing_returns_none() {
        let stream = TlvStream::new();
        assert_eq!(stream.get_as::<u64>(1).unwrap(), None);
    }

    #[test]
    fn get_as_exact_length() {
        let mut stream = TlvStream::new();
        let mut value = Vec::new();
        42u64.write(&mut value);
        stream.add(1, value);

        assert_eq!(stream.get_as::<u64>(1).unwrap(), Some(42));
    }

    #[test]
    fn get_as_overlength_rejected() {
        let mut stream = TlvStream::new();
        let mut value = Vec::new();
        42u64.write(&mut value);
        value.push(0xff);
        stream.add(1, value);

        assert_eq!(
            stream.get_as::<u64>(1),
            Err(BoltError::TlvTrailingBytes {
                tlv_type: 1,
                expected: 8,
                actual: 9
            })
        );
    }

    #[test]
    fn get_as_underlength_truncated() {
        let mut stream = TlvStream::new();
        stream.add(1, vec![0xaa; 4]);

        assert_eq!(
            stream.get_as::<u64>(1),
            Err(BoltError::Truncated {
                expected: 8,
                actual: 4
            })
        );
    }

    #[test]
    fn get_as_many() {
        let mut stream = TlvStream::new();
        let value = [[0u8; 32], [1u8; 32]].as_flattened().to_vec();
        stream.add(1, value);

        assert_eq!(
            stream.get_as_many::<[u8; 32]>(1).unwrap(),
            Some(vec![[0u8; 32], [1u8; 32]])
        );
    }

    #[test]
    fn get_as_many_reject_trailing_bytes() {
        let mut stream = TlvStream::new();
        stream.add(1, vec![0u8; 33]);

        assert_eq!(
            stream.get_as_many::<[u8; 32]>(1),
            Err(BoltError::TlvTrailingBytes {
                tlv_type: 1,
                expected: 32,
                actual: 33
            })
        );
    }

    #[test]
    fn known_even_accepted() {
        // type=2 is even but known
        let data = [0x02, 0x01, 0xaa];
        let decoded = TlvStream::decode_with_known(&data, &[2]).unwrap();
        assert_eq!(decoded.get(2), Some(&[0xaa][..]));
    }

    #[test]
    #[should_panic(expected = "duplicate TLV type")]
    fn add_duplicate_panics() {
        let mut stream = TlvStream::new();
        stream.add(1, vec![0x11]);
        stream.add(1, vec![0x22]); // Should panic
    }

    // ===== BOLT 1 Appendix B: TLV Decoding Failures (any namespace) =====

    #[test]
    fn bolt_type_truncated() {
        // 0xfd - type truncated
        assert!(matches!(
            TlvStream::decode(&[0xfd]),
            Err(BoltError::BigSizeTruncated)
        ));
        // 0xfd01 - type truncated
        assert!(matches!(
            TlvStream::decode(&[0xfd, 0x01]),
            Err(BoltError::BigSizeTruncated)
        ));
    }

    #[test]
    fn bolt_type_not_minimal() {
        // 0xfd0001 00 - not minimally encoded type (type=1 encoded as 3 bytes)
        assert!(matches!(
            TlvStream::decode(&[0xfd, 0x00, 0x01, 0x00]),
            Err(BoltError::BigSizeNotMinimal)
        ));
    }

    #[test]
    fn bolt_missing_length() {
        // 0xfd0101 - type=257, missing length
        assert!(matches!(
            TlvStream::decode(&[0xfd, 0x01, 0x01]),
            Err(BoltError::BigSizeTruncated)
        ));
    }

    #[test]
    fn bolt_length_truncated() {
        // 0x0f fd - type=15, length truncated (0xfd needs 2 more bytes)
        assert!(matches!(
            TlvStream::decode(&[0x0f, 0xfd]),
            Err(BoltError::BigSizeTruncated)
        ));
        // 0x0f fd26 - type=15, length truncated
        assert!(matches!(
            TlvStream::decode(&[0x0f, 0xfd, 0x26]),
            Err(BoltError::BigSizeTruncated)
        ));
    }

    #[test]
    fn bolt_missing_value() {
        // 0x0f fd2602 - type=15, length=9730, missing value
        assert!(matches!(
            TlvStream::decode(&[0x0f, 0xfd, 0x26, 0x02]),
            Err(BoltError::TlvLengthOverflow)
        ));
    }

    #[test]
    fn bolt_length_not_minimal() {
        // 0x0f fd0001 00 - type=15, length=1 not minimally encoded
        assert!(matches!(
            TlvStream::decode(&[0x0f, 0xfd, 0x00, 0x01, 0x00]),
            Err(BoltError::BigSizeNotMinimal)
        ));
    }

    #[test]
    fn bolt_value_truncated() {
        // 0x0f fd0201 <256 zeros> - type=15, length=513, but only 256 bytes of value
        let mut data = vec![0x0f, 0xfd, 0x02, 0x01]; // type=15, length=513
        data.extend_from_slice(&[0x00; 256]); // only 256 bytes of value (need 513)
        assert!(matches!(
            TlvStream::decode(&data),
            Err(BoltError::TlvLengthOverflow)
        ));
    }

    // ===== BOLT 1 Appendix B: Unknown even types =====
    // Tests use the union of the n1 and n2 namespaces which know even types 0,
    // 2, and 254.

    const N1_N2_KNOWN_EVEN: &[u64] = &[0, 2, 254];

    #[test]
    fn bolt_unknown_even_1byte() {
        // 0x12 00 - unknown even type 18 (not in n1's known types)
        assert_eq!(
            TlvStream::decode_with_known(&[0x12, 0x00], N1_N2_KNOWN_EVEN),
            Err(BoltError::TlvUnknownEvenType(18))
        );
    }

    #[test]
    fn bolt_unknown_even_2byte() {
        // 0xfd0102 00 - unknown even type 258
        assert_eq!(
            TlvStream::decode_with_known(&[0xfd, 0x01, 0x02, 0x00], N1_N2_KNOWN_EVEN),
            Err(BoltError::TlvUnknownEvenType(258))
        );
    }

    #[test]
    fn bolt_unknown_even_4byte() {
        // 0xfe01000002 00 - unknown even type 16777218
        assert_eq!(
            TlvStream::decode_with_known(&[0xfe, 0x01, 0x00, 0x00, 0x02, 0x00], N1_N2_KNOWN_EVEN),
            Err(BoltError::TlvUnknownEvenType(16_777_218))
        );
    }

    #[test]
    fn bolt_unknown_even_8byte() {
        // 0xff0100000000000002 00 - unknown even type 72057594037927938
        assert_eq!(
            TlvStream::decode_with_known(
                &[0xff, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x02, 0x00],
                N1_N2_KNOWN_EVEN
            ),
            Err(BoltError::TlvUnknownEvenType(72_057_594_037_927_938))
        );
    }

    // ===== BOLT 1 Appendix B: TLV Decoding Successes =====

    #[test]
    fn bolt_empty_valid() {
        // Empty stream is valid
        let decoded = TlvStream::decode(&[]).unwrap();
        assert!(decoded.is_empty());
    }

    #[test]
    fn bolt_unknown_odd_1byte() {
        // 0x21 00 - unknown odd type 33
        let decoded = TlvStream::decode(&[0x21, 0x00]).unwrap();
        assert_eq!(decoded.get(33), Some(&[][..]));
    }

    #[test]
    fn bolt_unknown_odd_2byte() {
        // 0xfd0201 00 - unknown odd type 513
        let decoded = TlvStream::decode(&[0xfd, 0x02, 0x01, 0x00]).unwrap();
        assert_eq!(decoded.get(513), Some(&[][..]));
    }

    #[test]
    fn bolt_unknown_odd_type_253() {
        // 0xfd00fd 00 - unknown odd type 253
        let decoded = TlvStream::decode(&[0xfd, 0x00, 0xfd, 0x00]).unwrap();
        assert_eq!(decoded.get(253), Some(&[][..]));
    }

    #[test]
    fn bolt_unknown_odd_type_255() {
        // 0xfd00ff 00 - unknown odd type 255
        let decoded = TlvStream::decode(&[0xfd, 0x00, 0xff, 0x00]).unwrap();
        assert_eq!(decoded.get(255), Some(&[][..]));
    }

    #[test]
    fn bolt_unknown_odd_4byte() {
        // 0xfe02000001 00 - unknown odd type 33554433
        let decoded = TlvStream::decode(&[0xfe, 0x02, 0x00, 0x00, 0x01, 0x00]).unwrap();
        assert_eq!(decoded.get(33_554_433), Some(&[][..]));
    }

    #[test]
    fn bolt_unknown_odd_8byte() {
        // 0xff0200000000000001 00 - unknown odd type 144115188075855873
        let decoded =
            TlvStream::decode(&[0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00])
                .unwrap();
        assert_eq!(decoded.get(144_115_188_075_855_873), Some(&[][..]));
    }

    // ===== Ordering tests =====

    #[test]
    fn not_increasing() {
        // type=3, then type=1 (not increasing)
        let data = [
            0x03, 0x01, 0xaa, // type=3, len=1, val=0xaa
            0x01, 0x01, 0xbb, // type=1, len=1, val=0xbb (error: 1 < 3)
        ];
        assert_eq!(
            TlvStream::decode(&data),
            Err(BoltError::TlvNotIncreasing {
                previous: 3,
                current: 1
            })
        );
    }

    #[test]
    fn duplicate_type() {
        // type=1 twice (not strictly increasing)
        let data = [
            0x01, 0x01, 0xaa, // type=1
            0x01, 0x01, 0xbb, // type=1 again
        ];
        assert_eq!(
            TlvStream::decode(&data),
            Err(BoltError::TlvNotIncreasing {
                previous: 1,
                current: 1
            })
        );
    }
}
