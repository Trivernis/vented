use serde::{Serialize};
use crate::result::{VentedResult, VentedError};
use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use std::io::Read;
use serde::de::DeserializeOwned;

/// A single event that has a name and payload.
/// The payload is encoded with message pack
#[derive(Clone, Debug)]
pub struct Event<T> {
    event_name: String,
    payload: T,
}

impl<T> Event<T> where T: Serialize + DeserializeOwned {
    /// Returns the byte representation for the message
    /// the format is
    /// `name-length`: `u16`,
    /// `name`: `name-length`,
    /// `payload-length`: `u64`,
    /// `payload`: `payload-length`,
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

        Ok(data)
    }

    /// Deserializes the message from bytes that can be read from the given reader
    /// The result will be the Message with the specific message payload type
    pub fn from_bytes<R: Read>(bytes: &mut R) -> VentedResult<Self> {
        let name_length = bytes.read_u16::<BigEndian>()?;
        let mut name_buf = vec![0u8; name_length as usize];
        bytes.read_exact(&mut name_buf)?;
        let event_name = String::from_utf8(name_buf).map_err(|_| VentedError::NameDecodingError)?;

        let payload_length = bytes.read_u64::<BigEndian>()?;
        let payload = rmp_serde::from_read(bytes.take(payload_length))?;

        Ok(Self {
            event_name,
            payload,
        })
    }
}