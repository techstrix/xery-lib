use xery_lib::{Vault, VaultError};

fn main() -> Result<(), VaultError> {
    let mut vault_container = Vault::default();

    vault_container.create_vault(String::from("Cool_vault"), String::from("Awesomepassword"))?;
    vault_container.login_vault("Cool_vault", "Awesomepassword")?;
    vault_container.add_password("IgPassword", "xorbi404", "123456")?;

    Ok(())
}
