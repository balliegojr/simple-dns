use std::{error::Error, fmt::Display};

/// Error types for SimpleDns
#[derive(Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum ParseError {
    UnexpectedEndOfInput,
    /// Invalid value for QCLASS type
    InvalidToken(String),
    /// Failed to read file
    FileAccess(String),
    UnsupportedResourceRecord(String),
    MissingInformation(&'static str),
}

impl From<std::io::Error> for ParseError {
    fn from(value: std::io::Error) -> Self {
        Self::FileAccess(value.to_string())
    }
}

impl Error for ParseError {}

impl Display for ParseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        todo!()
    }
}
