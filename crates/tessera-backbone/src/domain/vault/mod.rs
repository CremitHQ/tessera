mod vault_service;

#[cfg(test)]
pub(crate) use vault_service::MockVaultService;
pub(crate) use vault_service::{Error, VaultService, VaultServiceImpl};

