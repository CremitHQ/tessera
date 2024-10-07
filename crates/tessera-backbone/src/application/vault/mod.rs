use sea_orm::DatabaseConnection;

use self::command::CreatingVaultCommand;

pub mod command;

pub(crate) trait VaultUseCase {
    fn create(&self, cmd: CreatingVaultCommand) -> impl std::future::Future<Output = Result<()>> + Send;
}

#[derive(Default)]
pub(crate) struct VaultUseCaseImpl {
    database_connection: DatabaseConnection,
}

impl VaultUseCaseImpl {
    pub fn new(database_connection: DatabaseConnection) -> Self {
        Self { database_connection }
    }
}

impl VaultUseCase for VaultUseCaseImpl {
    async fn create(&self, cmd: CreatingVaultCommand) -> Result<()> {
        todo!()
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {}
pub type Result<T> = std::result::Result<T, Error>;
