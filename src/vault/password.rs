use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::Error};
#[derive(Default)]
pub struct PasswordService {
    pub password_hash: String,
}

impl PasswordService {
    pub fn hash_password(&mut self, password: &str) -> Result<(), Error> {
        let argon2 = Argon2::default();
        let password_hash = argon2.hash_password(password.as_bytes())?.to_string();

        self.password_hash = password_hash;
        Ok(())
    }

    pub fn check_password(&self, password: &str, hash: &str) -> Result<bool, Error> {
        if self.password_hash.is_empty() {
            return Err(Error::PasswordInvalid);
        }
        let parsed_hash = PasswordHash::new(hash)?;
        if Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
        {
            return Ok(true);
        }
        Ok(false)
    }
}
