use std::{io, path::Display};

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
}

impl From<sqlite::Error> for VaultError {
    fn from(error: sqlite::Error) -> Self {
        VaultError::DatabaseIO(error)
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
