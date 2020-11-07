use crate::server::CRATE_VERSION;
use std::error::Error;
use std::{fmt, io};

pub type VentedResult<T> = Result<T, VentedError>;

#[derive(Debug)]
pub enum VentedError {
    NameDecodingError,
    NotReady,
    NotAServer(String),
    IOError(io::Error),
    SerializeError(rmp_serde::encode::Error),
    DeserializeError(rmp_serde::decode::Error),
    CryptoError(crypto_box::aead::Error),
    UnexpectedEvent(String),
    UnknownNode(String),
    Rejected,
    AuthFailed,
    VersionMismatch(String),
}

impl fmt::Display for VentedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NameDecodingError => write!(f, "Failed to decode event name"),
            Self::IOError(e) => write!(f, "IO Error: {}", e),
            Self::SerializeError(e) => write!(f, "Serialization Error: {}", e),
            Self::DeserializeError(e) => write!(f, "Deserialization Error: {}", e),
            Self::CryptoError(e) => write!(f, "Cryptography Error: {}", e),
            Self::UnexpectedEvent(e) => write!(f, "Received unexpected event: {}", e),
            Self::UnknownNode(n) => write!(f, "Received connection from unknown node: {}", n),
            Self::NotReady => write!(f, "The connection is still being established."),
            Self::NotAServer(n) => write!(f, "The given node {} is not a server", n),
            Self::Rejected => write!(f, "The connection was rejected"),
            Self::AuthFailed => write!(f, "Failed to authenticate the other party"),
            Self::VersionMismatch(version) => write!(
                f,
                "Version mismatch: Expected {} got {}",
                CRATE_VERSION, version
            ),
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

impl From<crypto_box::aead::Error> for VentedError {
    fn from(other: crypto_box::aead::Error) -> Self {
        Self::CryptoError(other)
    }
}
