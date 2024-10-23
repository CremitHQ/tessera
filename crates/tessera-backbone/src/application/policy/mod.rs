use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use ulid::Ulid;

use crate::{
    database::OrganizationScopedTransaction,
    domain::{self, policy::PolicyService},
};

#[async_trait]
pub(crate) trait PolicyUseCase {
    async fn get_all(&self) -> Result<Vec<PolicyData>>;
}

pub(crate) struct PolicyUseCaseImpl {
    workspace_name: String,
    database_connection: Arc<DatabaseConnection>,
    policy_service: Arc<dyn PolicyService + Sync + Send>,
}

impl PolicyUseCaseImpl {
    pub fn new(
        workspace_name: String,
        database_connection: Arc<DatabaseConnection>,
        policy_service: Arc<dyn PolicyService + Sync + Send>,
    ) -> Self {
        Self { workspace_name, database_connection, policy_service }
    }
}

#[async_trait]
impl PolicyUseCase for PolicyUseCaseImpl {
    async fn get_all(&self) -> Result<Vec<PolicyData>> {
        let transaction = self.database_connection.begin_with_organization_scope(&self.workspace_name).await?;

        let policies = self.policy_service.get_all(&transaction).await?;

        transaction.commit().await?;

        return Ok(policies.into_iter().map(PolicyData::from).collect());
    }
}

pub(crate) struct PolicyData {
    pub id: Ulid,
    pub name: String,
    pub expression: String,
}

impl From<domain::policy::Policy> for PolicyData {
    fn from(value: domain::policy::Policy) -> Self {
        Self { id: value.id, name: value.name, expression: value.expression }
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<sea_orm::DbErr> for Error {
    fn from(value: sea_orm::DbErr) -> Self {
        Error::Anyhow(value.into())
    }
}

impl From<domain::policy::Error> for Error {
    fn from(value: domain::policy::Error) -> Self {
        match value {}
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
