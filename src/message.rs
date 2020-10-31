use serde::Serialize;
use crate::result::VentedResult;
use byteorder::{BigEndian, ByteOrder};
use crc::crc32;

#[derive(Clone, Debug)]
pub struct Message<T> {
    event_name: String,
    payload: T,
}

impl<T> Message<T> where T: Serialize {
    /// Returns the byte representation for the message
    /// the format is
    /// name-length: u16,
    /// name: name-length,
    /// payload-length: u64,
    /// payload: payload-length,
    /// crc: u32
    pub fn to_bytes(&self) -> VentedResult<Vec<u8>> {
        let mut payload_raw = rmp_serde::to_vec(&self.payload)?;
        let mut name_raw = self.event_name.as_bytes().to_vec();

        let name_length = name_raw.len();
        let mut name_length_raw = [0u8; 2];
        BigEndian::write_u16(&mut name_length_raw, name_length as u16);

        let payload_length = payload_raw.len();
        let mut payload_length_raw = [0u8; 8];
        BigEndian::write_u64(&mut payload_length_raw, payload_length as u64);

        let mut data = Vec::new();

        data.append(&mut name_length_raw.to_vec());
        data.append(&mut name_raw);
        data.append(&mut payload_length_raw.to_vec());
        data.append(&mut payload_raw);
        let crc = crc32::checksum_ieee(&data);
        let mut crc_raw = [0u8; 4];
        BigEndian::write_u32(&mut crc_raw, crc);
        data.append(&mut crc_raw.to_vec());

        Ok(data)
    }
}