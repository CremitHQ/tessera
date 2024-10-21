use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use tessera_abe::{curves::bls24479::Bls24479Curve, schemes::rw15::GlobalParams};

use crate::{
    database::OrganizationScopedTransaction,
    domain::{
        self,
        parameter::{Parameter, ParameterService},
    },
};

#[async_trait]
pub(crate) trait ParameterUseCase {
    async fn create(&self) -> Result<ParameterData>;
}

pub(crate) struct ParameterUseCaseImpl {
    workspace_name: String,
    database_connection: Arc<DatabaseConnection>,
    parameter_service: Arc<dyn ParameterService + Sync + Send>,
}

impl ParameterUseCaseImpl {
    pub fn new(
        workspace_name: String,
        database_connection: Arc<DatabaseConnection>,
        parameter_service: Arc<dyn ParameterService + Sync + Send>,
    ) -> Self {
        Self { workspace_name, database_connection, parameter_service }
    }
}

#[async_trait]
impl ParameterUseCase for ParameterUseCaseImpl {
    async fn create(&self) -> Result<ParameterData> {
        let transaction = self.database_connection.begin_with_organization_scope(&self.workspace_name).await?;
        let parameter = self.parameter_service.create(&transaction).await.map_err(Error::CreateParameterFailed)?;
        transaction.commit().await?;

        Ok(parameter.into())
    }
}

pub(crate) struct ParameterData {
    pub version: i32,
    pub value: GlobalParams<Bls24479Curve>,
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("Failed to create parameter: {0}")]
    CreateParameterFailed(#[source] domain::parameter::Error),
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
        match value {
            domain::secret::Error::Anyhow(e) => Self::Anyhow(e),
        }
    }
}

impl From<Parameter> for ParameterData {
    fn from(value: Parameter) -> Self {
        Self { version: value.version, value: value.value }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
