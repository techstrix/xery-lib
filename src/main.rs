use xery_lib::{Vault, VaultError};

fn main() -> Result<(), VaultError> {
    let mut vault_container = Vault::default();

    //    vault_container.create_vault(String::from("Cool_vault"), String::from("Awesomepassword"))?;
    vault_container.login_vault("Cool_vault", "Awesomepassword")?;
    vault_container.add_password("Hulu", "xorbi4042", "1234546789", "Awesomepassword")?;
    let password = vault_container.read_password("Awesomepassword", "Hulu")?;
    println!("{}", password);
    Ok(())
}
