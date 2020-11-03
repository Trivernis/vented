use std::error::Error;
use std::{fmt, io};

pub type VentedResult<T> = Result<T, VentedError>;

#[derive(Debug)]
pub enum VentedError {
    NameDecodingError,
    IOError(io::Error),
    TLSError(native_tls::Error),
    SerializeError(rmp_serde::encode::Error),
    DeserializeError(rmp_serde::decode::Error),
}

impl fmt::Display for VentedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameDecodingError => write!(f, "Failed to decode event name"),
            Self::IOError(e) => write!(f, "IO Error: {}", e.to_string()),
            Self::SerializeError(e) => write!(f, "Serialization Error: {}", e.to_string()),
            Self::DeserializeError(e) => write!(f, "Deserialization Error: {}", e.to_string()),
            Self::TLSError(e) => write!(f, "TLS Error: {}", e.to_string()),
        }
    }
}

impl Error for VentedError {}

impl From<io::Error> for VentedError {
    fn from(other: io::Error) -> Self {
        Self::IOError(other)
    }
}

impl From<rmp_serde::encode::Error> for VentedError {
    fn from(other: rmp_serde::encode::Error) -> Self {
        Self::SerializeError(other)
    }
}

impl From<rmp_serde::decode::Error> for VentedError {
    fn from(other: rmp_serde::decode::Error) -> Self {
        Self::DeserializeError(other)
    }
}

impl From<native_tls::Error> for VentedError {
    fn from(other: native_tls::Error) -> Self {
        Self::TLSError(other)
    }
}
