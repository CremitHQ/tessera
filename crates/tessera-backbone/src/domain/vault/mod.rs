use async_trait::async_trait;
use mockall::automock;
use sea_orm::DatabaseTransaction;

#[automock]
#[async_trait]
pub(crate) trait VaultService {
    async fn create(&self, transaction: &DatabaseTransaction, name: &str) -> Result<()>;
}

pub(crate) struct VaultServiceImpl {}

impl VaultServiceImpl {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl VaultService for VaultServiceImpl {
    async fn create(&self, transaction: &DatabaseTransaction, name: &str) -> Result<()> {
        todo!()
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {}

pub(crate) type Result<T> = std::result::Result<T, Error>;
