use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use ulid::Ulid;

use crate::{
    database::OrganizationScopedTransaction,
    domain::{
        self,
        secret::{Secret, SecretService},
    },
};

#[async_trait]
pub(crate) trait SecretUseCase {
    async fn list(&self, path: &str) -> Result<Vec<SecretData>>;
}

pub(crate) struct SecretUseCaseImpl {
    workspace_name: String,
    database_connection: Arc<DatabaseConnection>,
    secret_service: Arc<dyn SecretService + Sync + Send>,
}

impl SecretUseCaseImpl {
    pub fn new(
        workspace_name: String,
        database_connection: Arc<DatabaseConnection>,
        secret_service: Arc<dyn SecretService + Sync + Send>,
    ) -> Self {
        Self { workspace_name, database_connection, secret_service }
    }
}

#[async_trait]
impl SecretUseCase for SecretUseCaseImpl {
    async fn list(&self, path: &str) -> Result<Vec<SecretData>> {
        let transaction = self.database_connection.begin_with_organization_scope(&self.workspace_name).await?;
        let secrets = self.secret_service.list(&transaction, path).await?;
        transaction.commit().await?;

        Ok(secrets.into_iter().map(SecretData::from).collect())
    }
}

pub(crate) struct SecretData {
    pub key: String,
    pub path: String,
    pub reader_policy_ids: Vec<Ulid>,
    pub writer_policy_ids: Vec<Ulid>,
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<sea_orm::DbErr> for Error {
    fn from(value: sea_orm::DbErr) -> Self {
        Self::Anyhow(value.into())
    }
}

impl From<domain::secret::Error> for Error {
    fn from(value: domain::secret::Error) -> Self {
        match value {}
    }
}

impl From<Secret> for SecretData {
    fn from(value: Secret) -> Self {
        Self {
            key: value.key,
            path: value.path,
            reader_policy_ids: value.reader_policy_ids,
            writer_policy_ids: value.writer_policy_ids,
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
