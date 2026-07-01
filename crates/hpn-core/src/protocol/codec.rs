//! Serialization and deserialization traits for protocol messages.

use crate::error::ProtocolError;

/// Trait for encoding values to bytes.
pub trait Encode {
    /// Encode to a byte vector.
    fn encode(&self) -> Vec<u8>;

    /// Encode to a buffer, returning the number of bytes written.
    ///
    /// # Errors
    ///
    /// Returns an error if the buffer is too small.
    fn encode_to(&self, buf: &mut [u8]) -> Result<usize, ProtocolError>;
}

/// Trait for decoding values from bytes.
pub trait Decode: Sized {
    /// Decode from bytes.
    ///
    /// # Errors
    ///
    /// Returns an error if decoding fails.
    fn decode(buf: &[u8]) -> Result<Self, ProtocolError>;
}

/// Write a u8 to a buffer at the given offset.
#[inline]
pub fn write_u8(buf: &mut [u8], offset: usize, value: u8) -> usize {
    buf[offset] = value;
    1
}

/// Write a u16 (big-endian) to a buffer at the given offset.
#[inline]
pub fn write_u16(buf: &mut [u8], offset: usize, value: u16) -> usize {
    buf[offset..offset + 2].copy_from_slice(&value.to_be_bytes());
    2
}

/// Write a u32 (big-endian) to a buffer at the given offset.
#[inline]
pub fn write_u32(buf: &mut [u8], offset: usize, value: u32) -> usize {
    buf[offset..offset + 4].copy_from_slice(&value.to_be_bytes());
    4
}

/// Write a u64 (big-endian) to a buffer at the given offset.
#[inline]
pub fn write_u64(buf: &mut [u8], offset: usize, value: u64) -> usize {
    buf[offset..offset + 8].copy_from_slice(&value.to_be_bytes());
    8
}

/// Write bytes to a buffer at the given offset.
#[inline]
pub fn write_bytes(buf: &mut [u8], offset: usize, bytes: &[u8]) -> usize {
    buf[offset..offset + bytes.len()].copy_from_slice(bytes);
    bytes.len()
}

/// Read a u8 from a buffer at the given offset.
#[inline]
pub const fn read_u8(buf: &[u8], offset: usize) -> u8 {
    buf[offset]
}

/// Read a u16 (big-endian) from a buffer at the given offset.
#[inline]
pub fn read_u16(buf: &[u8], offset: usize) -> u16 {
    u16::from_be_bytes([buf[offset], buf[offset + 1]])
}

/// Read a u32 (big-endian) from a buffer at the given offset.
#[inline]
pub fn read_u32(buf: &[u8], offset: usize) -> u32 {
    u32::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
    ])
}

/// Read a u64 (big-endian) from a buffer at the given offset.
#[inline]
pub fn read_u64(buf: &[u8], offset: usize) -> u64 {
    u64::from_be_bytes([
        buf[offset],
        buf[offset + 1],
        buf[offset + 2],
        buf[offset + 3],
        buf[offset + 4],
        buf[offset + 5],
        buf[offset + 6],
        buf[offset + 7],
    ])
}

/// Write a length-prefixed byte slice.
///
/// # Panics
/// Panics if `bytes.len()` exceeds `u16::MAX` (65535).
#[inline]
pub fn write_length_prefixed(buf: &mut [u8], offset: usize, bytes: &[u8]) -> usize {
    assert!(
        u16::try_from(bytes.len()).is_ok(),
        "payload exceeds u16 length prefix capacity"
    );
    let len = bytes.len() as u16;
    let mut written = write_u16(buf, offset, len);
    written += write_bytes(buf, offset + written, bytes);
    written
}

/// Read a length-prefixed byte slice.
///
/// # Errors
///
/// Returns an error if the buffer is too short.
pub fn read_length_prefixed(buf: &[u8], offset: usize) -> Result<(Vec<u8>, usize), ProtocolError> {
    if buf.len() < offset + 2 {
        return Err(ProtocolError::PacketTooShort {
            needed: offset + 2,
            available: buf.len(),
        });
    }

    let len = read_u16(buf, offset) as usize;
    let data_offset = offset + 2;

    if buf.len() < data_offset + len {
        return Err(ProtocolError::PacketTooShort {
            needed: data_offset + len,
            available: buf.len(),
        });
    }

    let data = buf[data_offset..data_offset + len].to_vec();
    Ok((data, 2 + len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_write_read_u8() {
        let mut buf = [0u8; 10];
        write_u8(&mut buf, 3, 0x42);
        assert_eq!(read_u8(&buf, 3), 0x42);
    }

    #[test]
    fn test_write_read_u16() {
        let mut buf = [0u8; 10];
        write_u16(&mut buf, 2, 0x1234);
        assert_eq!(read_u16(&buf, 2), 0x1234);
    }

    #[test]
    fn test_write_read_u32() {
        let mut buf = [0u8; 10];
        write_u32(&mut buf, 1, 0x1234_5678);
        assert_eq!(read_u32(&buf, 1), 0x1234_5678);
    }

    #[test]
    fn test_write_read_u64() {
        let mut buf = [0u8; 16];
        write_u64(&mut buf, 4, 0x1234_5678_9ABC_DEF0);
        assert_eq!(read_u64(&buf, 4), 0x1234_5678_9ABC_DEF0);
    }

    #[test]
    fn test_length_prefixed_roundtrip() {
        let data = b"Hello, HPN!";
        let mut buf = [0u8; 64];

        let written = write_length_prefixed(&mut buf, 5, data);
        assert_eq!(written, 2 + data.len());

        let (read_data, read_len) = read_length_prefixed(&buf, 5).unwrap();
        assert_eq!(read_len, written);
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_write_read_bytes() {
        let mut buf = [0u8; 20];
        let data = b"test data";

        let written = write_bytes(&mut buf, 5, data);
        assert_eq!(written, data.len());

        assert_eq!(&buf[5..5 + data.len()], data);
    }

    #[test]
    fn test_write_u8_at_start() {
        let mut buf = [0u8; 10];
        write_u8(&mut buf, 0, 0xFF);
        assert_eq!(buf[0], 0xFF);
    }

    #[test]
    fn test_write_u16_big_endian() {
        let mut buf = [0u8; 10];
        write_u16(&mut buf, 0, 0xABCD);
        assert_eq!(buf[0], 0xAB);
        assert_eq!(buf[1], 0xCD);
    }

    #[test]
    fn test_write_u32_big_endian() {
        let mut buf = [0u8; 10];
        write_u32(&mut buf, 0, 0x1234_5678);
        assert_eq!(buf[0], 0x12);
        assert_eq!(buf[1], 0x34);
        assert_eq!(buf[2], 0x56);
        assert_eq!(buf[3], 0x78);
    }

    #[test]
    fn test_write_u64_big_endian() {
        let mut buf = [0u8; 10];
        write_u64(&mut buf, 0, 0x0102_0304_0506_0708);
        assert_eq!(buf[0], 0x01);
        assert_eq!(buf[1], 0x02);
        assert_eq!(buf[7], 0x08);
    }

    #[test]
    fn test_read_u8_max() {
        let mut buf = [0u8; 10];
        write_u8(&mut buf, 0, 0xFF);
        assert_eq!(read_u8(&buf, 0), 0xFF);
    }

    #[test]
    fn test_read_u16_max() {
        let mut buf = [0u8; 10];
        write_u16(&mut buf, 0, 0xFFFF);
        assert_eq!(read_u16(&buf, 0), 0xFFFF);
    }

    #[test]
    fn test_read_u32_max() {
        let mut buf = [0u8; 10];
        write_u32(&mut buf, 0, 0xFFFF_FFFF);
        assert_eq!(read_u32(&buf, 0), 0xFFFF_FFFF);
    }

    #[test]
    fn test_read_u64_max() {
        let mut buf = [0u8; 10];
        write_u64(&mut buf, 0, u64::MAX);
        assert_eq!(read_u64(&buf, 0), u64::MAX);
    }

    #[test]
    fn test_length_prefixed_empty_data() {
        let mut buf = [0u8; 10];
        let empty: &[u8] = &[];

        let written = write_length_prefixed(&mut buf, 0, empty);
        assert_eq!(written, 2);

        let (read_data, read_len) = read_length_prefixed(&buf, 0).unwrap();
        assert_eq!(read_len, 2);
        assert_eq!(read_data.len(), 0);
    }

    #[test]
    fn test_length_prefixed_large_data() {
        let data = vec![0x42u8; 1000];
        let mut buf = vec![0u8; 1100];

        let written = write_length_prefixed(&mut buf, 0, &data);
        assert_eq!(written, 2 + 1000);

        let (read_data, read_len) = read_length_prefixed(&buf, 0).unwrap();
        assert_eq!(read_len, written);
        assert_eq!(read_data, data);
    }

    #[test]
    fn test_read_length_prefixed_buffer_too_short() {
        let buf = [0u8; 1];
        let result = read_length_prefixed(&buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_read_length_prefixed_data_too_short() {
        let mut buf = [0u8; 10];
        write_u16(&mut buf, 0, 100); // Claim 100 bytes but buffer is only 10

        let result = read_length_prefixed(&buf, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_write_bytes_returns_length() {
        let mut buf = [0u8; 20];
        let data = b"12345";

        let written = write_bytes(&mut buf, 0, data);
        assert_eq!(written, 5);
    }

    #[test]
    fn test_multiple_writes_sequential() {
        let mut buf = [0u8; 20];
        let mut offset = 0;

        offset += write_u8(&mut buf, offset, 0x11);
        offset += write_u16(&mut buf, offset, 0x2233);
        offset += write_u32(&mut buf, offset, 0x4455_6677);

        assert_eq!(offset, 1 + 2 + 4);
        assert_eq!(read_u8(&buf, 0), 0x11);
        assert_eq!(read_u16(&buf, 1), 0x2233);
        assert_eq!(read_u32(&buf, 3), 0x4455_6677);
    }
}
