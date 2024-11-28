use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, DbErr};

use crate::{
    database::OrganizationScopedTransaction,
    domain::{self, authority::AuthorityService},
};

#[async_trait]
pub trait AuthorityUseCase {
    async fn register_authority(&self, name: &str, host: &str) -> Result<()>;
}

pub struct AuthorityUseCaseImpl {
    workspace_name: String,
    database_connection: Arc<DatabaseConnection>,
    authority_service: Arc<dyn AuthorityService + Sync + Send>,
}

impl AuthorityUseCaseImpl {
    pub fn new(
        workspace_name: String,
        database_connection: Arc<DatabaseConnection>,
        authority_service: Arc<dyn AuthorityService + Sync + Send>,
    ) -> Self {
        Self { workspace_name, database_connection, authority_service }
    }
}

#[async_trait]
impl AuthorityUseCase for AuthorityUseCaseImpl {
    async fn register_authority(&self, name: &str, host: &str) -> Result<()> {
        let transaction = self.database_connection.begin_with_organization_scope(&self.workspace_name).await?;
        self.authority_service.register_authority(&transaction, name, host).await?;
        transaction.commit().await?;
        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Authority name is already in use")]
    NameAlreadyInUse { entered_authority_name: String },
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<DbErr> for Error {
    fn from(value: DbErr) -> Self {
        Self::Anyhow(value.into())
    }
}

impl From<domain::authority::Error> for Error {
    fn from(value: domain::authority::Error) -> Self {
        match value {
            domain::authority::Error::NameAlreadyInUse { entered_authority_name } => {
                Self::NameAlreadyInUse { entered_authority_name }
            }
            domain::authority::Error::Anyhow(e) => Self::Anyhow(e),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
