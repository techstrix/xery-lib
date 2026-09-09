mod vault;
pub use vault::Vault;
pub use vault::VaultError;
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_new_vault() {
        let connection = sqlite::open(":memory:").unwrap();

        let mut vault_container = Vault::new(connection);
        assert!(
            vault_container
                .create_vault(
                    String::from("Awesome Vault"),
                    String::from("Very cool password"),
                )
                .is_ok()
        );
    }
    #[test]
    fn successful_vault_login() {
        let connection = sqlite::open(":memory:").unwrap();

        let mut vault_container = Vault::new(connection);
        vault_container
            .create_vault(
                String::from("Awesome Vault"),
                String::from("Very cool password"),
            )
            .unwrap();
        assert!(
            vault_container
                .login_vault("Awesome Vault", "Very cool password")
                .is_ok()
        );
    }
    #[test]
    fn successful_vault_logout() {
        let connection = sqlite::open(":memory:").unwrap();

        let mut vault_container = Vault::new(connection);
        vault_container
            .create_vault(
                String::from("Awesome Vault"),
                String::from("Very cool password"),
            )
            .unwrap();
        vault_container
            .login_vault("Awesome Vault", "Very cool password")
            .unwrap();
        assert!(vault_container.logout_vault().is_ok());
    }
    #[test]
    fn successful_passowrd_add() {
        let connection = sqlite::open(":memory:").unwrap();

        let mut vault_container = Vault::new(connection);
        vault_container
            .create_vault(
                String::from("Awesome Vault"),
                String::from("Very cool password"),
            )
            .unwrap();
        vault_container
            .login_vault("Awesome Vault", "Very cool password")
            .unwrap();

        assert!(
            vault_container
                .add_password("Netflix", "xorbi404", "123456789", "Very cool password")
                .is_ok()
        );
    }
    #[test]
    fn successful_password_read() {
        let connection = sqlite::open(":memory:").unwrap();

        let mut vault_container = Vault::new(connection);
        vault_container
            .create_vault(
                String::from("Awesome Vault"),
                String::from("Very cool password"),
            )
            .unwrap();
        vault_container
            .login_vault("Awesome Vault", "Very cool password")
            .unwrap();

        vault_container
            .add_password("Netflix", "xorbi404", "123456789", "Very cool password")
            .unwrap();
        let password = vault_container
            .read_password("Very cool password", "Netflix")
            .unwrap();
        assert_eq!(password, "123456789");
    }
    #[test]
    fn successful_list_vaults() {
        let connection = sqlite::open(":memory:").unwrap();

        let mut vault_container = Vault::new(connection);
        vault_container
            .create_vault(
                String::from("Awesome Vault"),
                String::from("Very cool password"),
            )
            .unwrap();

        vault_container
            .create_vault(
                String::from("Awesome Vault2"),
                String::from("Very cool password"),
            )
            .unwrap();

        let vaults = vault_container.list_vaults().unwrap();
        let expected = vec![
            String::from("Awesome Vault"),
            String::from("Awesome Vault2"),
        ];
        assert_eq!(vaults, expected);
    }
}
