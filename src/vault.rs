mod errors;
mod password;
use crate::vault::{self, password::PasswordService};
pub use errors::VaultError;
use sqlite::Connection;

pub struct Vault {
    name: String,
    password: String,
    password_service: PasswordService,
    login_status: bool,
    active_vault: Option<String>,
    db_connection: Connection,
    active_hash: Option<String>,
}

impl Default for Vault {
    fn default() -> Self {
        let db_connection = sqlite::open("vaults.db").unwrap();
        Self::new(db_connection)
    }
}
impl Vault {
    pub fn new(db_connection: sqlite::Connection) -> Self {
        let    query = "CREATE TABLE IF NOT EXISTS  vault_details (id INTEGER PRIMARY KEY,name TEXT UNIQUE,password_hash TEXT);
                       CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY,identifier TEXT UNIQUE,username TEXT NOT NULL,encrypted_data TEXT NOT NULL,vault TEXT NOT NULL);
                   ";
        db_connection.execute(query).unwrap();
        Self {
            name: String::new(),
            password: String::new(),
            password_service: PasswordService::default(),
            login_status: false,
            db_connection,
            active_hash: None,
            active_vault: None,
        }
    }
    pub fn create_vault(&mut self, name: String, password: String) -> Result<(), VaultError> {
        self.name = name;
        self.password = password;

        match self.password_service.hash_password(self.password.as_str()) {
            Ok(()) => {
                let mut statement = self
                    .db_connection
                    .prepare("INSERT INTO vault_details (name, password_hash) VALUES (?, ?)")?;

                statement.bind((1, self.name.as_str()))?;
                statement.bind((2, self.password_service.password_hash.as_str()))?;
                statement.next()?;
            }
            Err(e) => {
                return Err(VaultError::HashError(e));
            }
        }
        Ok(())
    }
    pub fn list_vaults(&mut self) -> Result<Vec<String>, VaultError> {
        let query = "SELECT name FROM vault_details";
        let mut statement = self.db_connection.prepare(query)?;
        let mut vault_names: Vec<String> = Vec::new();
        while let sqlite::State::Row = statement.next()? {
            let name: String = statement.read(0)?;
            vault_names.push(name);
        }

        Ok(vault_names)
    }
    pub fn login_vault(&mut self, vault_name: &str, password: &str) -> Result<(), VaultError> {
        if self.login_status {
            return Err(VaultError::AlreadyLoggedIn);
        }

        let mut statement = self
            .db_connection
            .prepare("SELECT id,name,password_hash FROM vault_details WHERE name=?")?;
        statement.bind((1, vault_name))?;
        if let sqlite::State::Row = statement.next()? {
            let vault_hash: String = statement.read(2)?;

            if self
                .password_service
                .check_password(password, vault_hash.as_str())
                .is_ok()
            {
                self.login_status = true;
                self.active_vault = Some(vault_name.to_string());
                self.active_hash = Some(vault_hash);
            } else {
                return Err(VaultError::WrongPassword);
            }
        }

        Ok(())
    }

    fn check_vault_pass_validity(&self, vault_password: &str) -> Result<(), VaultError> {
        if let (Some(_), Some(hash)) = (&self.active_vault, &self.active_hash)
            && self
                .password_service
                .check_password(vault_password, hash)
                .is_err()
        {
            return Err(VaultError::WrongPassword);
        }
        Ok(())
    }
    // To add a password you require the master password for added security.
    pub fn add_password(
        &mut self,
        identifier: &str,
        username: &str,
        password: &str,
        vault_password: &str,
    ) -> Result<(), VaultError> {
        if !self.login_status {
            return Err(VaultError::NotLoggedIn);
        }
        // Will err if the vault_password does not match the actively logged into vault
        self.check_vault_pass_validity(vault_password)?;

        //     CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY,identifier TEXT UNIQUE,username TEXT NOT NULL,encrypted_data TEXT NOT NULL,vault TEXT NOT NULL);
        let (encrypted, salt, nonce) = self
            .password_service
            .encrypt_password(vault_password, password)?;
        let data = serde_json::json!(
            {
                "salt":&hex::encode(salt),
                "nonce":&hex::encode(nonce),
                "cipher_text":&hex::encode(encrypted)
            }
        );

        let json = serde_json::to_string(&data)?;

        let mut statement = self.db_connection.prepare(
            "INSERT INTO passwords
        (identifier,username,encrypted_data,vault) VALUES (?,?,?,?)",
        )?;
        statement.bind((1, identifier))?;
        statement.bind((2, username))?;
        statement.bind((3, json.as_str()))?;
        if let Some(vault) = &self.active_vault {
            statement.bind((4, vault.as_str()))?;
        }

        statement.next()?;

        Ok(())
    }

    pub fn read_password(
        &mut self,
        vault_password: &str,
        identifier: &str,
    ) -> Result<String, VaultError> {
        if !self.login_status {
            return Err(VaultError::NotLoggedIn);
        }

        // Check if the vault_password is valid for the currently logged into vault -> This function returns if the password is invalid for the active vault
        self.check_vault_pass_validity(vault_password)?;
        let mut retrieved_password: String = String::new();
        let mut statement = self
            .db_connection
            .prepare("SELECT encrypted_data FROM passwords WHERE identifier = ?")?;
        statement.bind((1, identifier))?;

        if let sqlite::State::Row = statement.next()? {
            let json_string: String = statement.read(0)?;
            let data: serde_json::Value = serde_json::from_str(&json_string)?;
            let salt = hex::decode(data["salt"].as_str().unwrap())?;
            let nonce = hex::decode(data["nonce"].as_str().unwrap())?;
            let cipher_text = hex::decode(data["cipher_text"].as_str().unwrap())?;

            let salt: [u8; 16] = salt.try_into().map_err(|_| VaultError::InvalidSaltLength)?;
            let nonce: [u8; 12] = nonce
                .try_into()
                .map_err(|_| VaultError::InvalidNonceLength)?;
            retrieved_password = self.password_service.decrypt_password(
                vault_password,
                &cipher_text,
                salt,
                nonce,
            )?;
        }
        Ok(retrieved_password)
    }

    pub fn logout_vault(&mut self) -> Result<(), VaultError> {
        if !self.login_status {
            return Err(VaultError::NotLoggedIn);
        }

        self.login_status = false;
        self.active_vault = None;
        self.active_hash = None;
        Ok(())
    }
}
