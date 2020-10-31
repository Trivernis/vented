use std::{fmt, io};

pub type VentedResult<T> = Result<T, VentedError>;

pub enum VentedError {
    IOError(io::Error),
    SerializeError(rmp_serde::encode::Error)
}

impl fmt::Display for VentedError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::IOError(e) => write!(f, "IO Error: {}", e.to_string()),
            Self::SerializeError(e) => write!(f, "Serialization Error: {}", e.to_string()),
        }
    }
}

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