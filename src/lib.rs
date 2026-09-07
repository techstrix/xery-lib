mod vault;
pub use vault::Vault;
pub use vault::VaultError;
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn successful_new_vault() {
        let mut vault = Vault::default();
        assert!(
            vault
                .create_vault(
                    String::from("Awesome Vault"),
                    String::from("Very cool password"),
                )
                .is_ok()
        );
    }
}
