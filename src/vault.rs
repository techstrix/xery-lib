mod errors;
mod password;
use crate::vault::password::PasswordService;
pub use errors::VaultError;
use sqlite::Connection;

pub struct Vault {
    name: String,
    password: String,
    password_service: PasswordService,
    login_status: bool,
    active_vault: Option<String>,
    db_connection: Connection,
}

impl Default for Vault {
    fn default() -> Self {
        let db_connection = sqlite::open("vaults.db").unwrap();

        let    query = "CREATE TABLE IF NOT EXISTS  vault_details (id INTEGER PRIMARY KEY,name TEXT UNIQUE,password_hash TEXT);
                CREATE TABLE IF NOT EXISTS passwords (id INTEGER PRIMARY KEY,identifier TEXT UNIQUE,username TEXT,password TEXT,vault TEXT);
            ";
        db_connection.execute(query).unwrap();
        Self {
            name: String::new(),
            password: String::new(),
            password_service: PasswordService::default(),
            login_status: false,
            db_connection,
            active_vault: None,
        }
    }
}
impl Vault {
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

            if let Ok(status) = self
                .password_service
                .check_password(password, vault_hash.as_str())
                && status
            {
                self.login_status = true;
                self.active_vault = Some(vault_name.to_string());
            }
        } else {
            return Err(VaultError::WrongPassword);
        }

        Ok(())
    }
    pub fn add_password(
        &mut self,
        identifier: &str,
        username: &str,
        password: &str,
    ) -> Result<(), VaultError> {
        if !self.login_status {
            return Err(VaultError::NotLoggedIn);
        }
        self.password_service.hash_password(password)?;
        let password = &self.password_service.password_hash;
        let mut statement = self.db_connection.prepare(
            "INSERT INTO passwords
        (identifier,username,password,vault) VALUES (?,?,?,?)",
        )?;
        statement.bind((1, identifier))?;
        statement.bind((2, username))?;
        statement.bind((3, password.as_str()))?;
        if let Some(vault) = &self.active_vault {
            statement.bind((4, vault.as_str()))?;
        }

        statement.next()?;

        Ok(())
    }
    pub fn logout_vault(&mut self) {
        if self.login_status {
            self.login_status = false;
            self.active_vault = None;
        }
    }
}
