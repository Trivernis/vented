use std::io::Read;

use byteorder::{BigEndian, ByteOrder, ReadBytesExt};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use crate::result::{VentedError, VentedResult};

pub trait GenericEvent {}

#[cfg(test)]
mod tests;

#[derive(Clone, Serialize, Deserialize)]
pub struct EmptyPayload {}

/// A single event that has a name and payload.
/// The payload is encoded with message pack
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Event {
    pub name: String,
    pub payload: Vec<u8>,
}

impl Event {
    /// Creates a new Event with an empty payload
    pub fn new<S: ToString>(name: S) -> Self {
        Self {
            name: name.to_string(),
            payload: Vec::with_capacity(0),
        }
    }
}

impl Event {
    /// Creates a new Event with a payload
    pub fn with_payload<T: Serialize, S: ToString>(name: S, payload: &T) -> Self {
        let payload = rmp_serde::encode::to_vec(payload).unwrap();
        Self {
            name: name.to_string(),
            payload,
        }
    }

    /// Returns the byte representation for the message
    /// the format is
    /// `name-length`: `u16`,
    /// `name`: `name-length`,
    /// `payload-length`: `u64`,
    /// `payload`: `payload-length`,
    pub fn as_bytes(&mut self) -> Vec<u8> {
        let mut name_raw = self.name.as_bytes().to_vec();

        let name_length = name_raw.len();
        let mut name_length_raw = [0u8; 2];
        BigEndian::write_u16(&mut name_length_raw, name_length as u16);

        let payload_length = self.payload.len();
        let mut payload_length_raw = [0u8; 8];
        BigEndian::write_u64(&mut payload_length_raw, payload_length as u64);

        let mut data = Vec::new();

        data.append(&mut name_length_raw.to_vec());
        data.append(&mut name_raw);
        data.append(&mut payload_length_raw.to_vec());
        data.append(&mut self.payload);

        data
    }

    /// Deserializes the message from bytes that can be read from the given reader
    /// The result will be the Message with the specific message payload type
    pub fn from_bytes<R: Read>(bytes: &mut R) -> VentedResult<Self> {
        let name_length = bytes.read_u16::<BigEndian>()?;
        let mut name_buf = vec![0u8; name_length as usize];
        bytes.read_exact(&mut name_buf)?;
        let event_name = String::from_utf8(name_buf).map_err(|_| VentedError::NameDecodingError)?;

        let payload_length = bytes.read_u64::<BigEndian>()?;
        let mut payload = vec![0u8; payload_length as usize];
        bytes.read_exact(&mut payload)?;

        Ok(Self {
            name: event_name,
            payload,
        })
    }

    /// Returns the payload of the event as a deserialized messagepack value
    pub fn get_payload<T: DeserializeOwned>(&self) -> VentedResult<T> {
        let payload = rmp_serde::decode::from_read(&self.payload[..])?;

        Ok(payload)
    }
}
