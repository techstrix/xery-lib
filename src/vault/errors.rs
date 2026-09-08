use std::{error, io};

use argon2::password_hash;

#[derive(Debug)]
pub enum VaultError {
    DatabaseIO(sqlite::Error),
    IoError(io::Error),
    HashError(password_hash::Error),
    WrongPassword,
    VaultNotFound,
    AlreadyLoggedIn,
    NotLoggedIn,
    VaultAlreadyExists,
    JsonError(serde_json::Error),
    HexDecodeError(hex::FromHexError),
    AnyError(Box<dyn error::Error>),
    InvalidNonceLength,
    InvalidSaltLength,
    HashErrorPHC(password_hash::phc::Error),
}
impl From<Box<dyn error::Error>> for VaultError {
    fn from(error: Box<dyn error::Error>) -> Self {
        VaultError::AnyError(error)
    }
}
impl From<serde_json::Error> for VaultError {
    fn from(error: serde_json::Error) -> Self {
        VaultError::JsonError(error)
    }
}
impl From<password_hash::phc::Error> for VaultError {
    fn from(error: password_hash::phc::Error) -> Self {
        VaultError::HashErrorPHC(error)
    }
}
impl From<sqlite::Error> for VaultError {
    fn from(error: sqlite::Error) -> Self {
        VaultError::DatabaseIO(error)
    }
}

impl From<hex::FromHexError> for VaultError {
    fn from(error: hex::FromHexError) -> Self {
        VaultError::HexDecodeError(error)
    }
}
impl From<password_hash::Error> for VaultError {
    fn from(error: password_hash::Error) -> Self {
        VaultError::HashError(error)
    }
}
impl From<io::Error> for VaultError {
    fn from(error: io::Error) -> Self {
        VaultError::IoError(error)
    }
}
