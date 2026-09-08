use std::error::Error;

use argon2::{
    Argon2, PasswordHash, PasswordHasher, PasswordVerifier,
    password_hash::{self},
};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};

use rand::RngExt;

use crate::VaultError;
type EncryptedPasswordDetails = Result<(Vec<u8>, [u8; 16], [u8; 12]), Box<dyn std::error::Error>>;
#[derive(Default)]
pub struct PasswordService {
    pub password_hash: String,
}
/*
    hash_password and check_password are for hashing an checking the master password of a vault.
*/
impl PasswordService {
    pub fn hash_password(&mut self, password: &str) -> Result<(), password_hash::Error> {
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes())?.to_string();

        self.password_hash = password_hash;
        Ok(())
    }

    pub fn check_password(&self, password: &str, hash: &str) -> Result<(), VaultError> {
        let parsed_hash = PasswordHash::new(hash)?;

        Argon2::default().verify_password(password.as_bytes(), &parsed_hash)?;

        Ok(())
    }
    pub fn encrypt_password(
        &mut self,
        vault_password: &str,
        password: &str,
    ) -> EncryptedPasswordDetails {
        let mut salt = [0u8; 16];
        rand::rng().fill(&mut salt);

        let mut key = [0u8; 32];
        Argon2::default().hash_password_into(vault_password.as_bytes(), &salt, &mut key)?;
        //cipher
        let cipher = ChaCha20Poly1305::new(&key.into());

        //nonce
        let mut nonce_bytes = [0u8; 12];
        rand::rng().fill(&mut nonce_bytes);

        //encryption
        let nonce = Nonce::try_from(nonce_bytes.as_slice())?;
        let encrypted = cipher.encrypt(&nonce, password.as_bytes())?;
        Ok((encrypted, salt, nonce_bytes))
    }
    pub fn decrypt_password(
        &mut self,
        vault_password: &str,
        encrypted: &[u8],
        salt: [u8; 16],
        nonce_bytes: [u8; 12],
    ) -> Result<String, Box<dyn Error>> {
        let mut key = [0u8; 32];
        Argon2::default().hash_password_into(vault_password.as_bytes(), &salt, &mut key)?;
        let cipher = ChaCha20Poly1305::new(&key.into());

        let nonce = Nonce::try_from(nonce_bytes.as_slice())?;
        let decrypted = cipher.decrypt(&nonce, encrypted)?;

        Ok(String::from_utf8(decrypted)?)
    }
}
