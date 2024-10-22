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
    async fn get(&self) -> Result<ParameterData>;
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

    async fn get(&self) -> Result<ParameterData> {
        let transaction = self.database_connection.begin_with_organization_scope(&self.workspace_name).await?;
        let parameter = self.parameter_service.get(&transaction).await.map_err(Error::GetParameterFailed)?;
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

    #[error("Failed to get parameter: {0}")]
    GetParameterFailed(#[source] domain::parameter::Error),

    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<sea_orm::DbErr> for Error {
    fn from(value: sea_orm::DbErr) -> Self {
        Self::Anyhow(value.into())
    }
}

impl From<Parameter> for ParameterData {
    fn from(value: Parameter) -> Self {
        Self { version: value.version, value: value.value }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    use tessera_abe::{
        curves::{bls24479::Bls24479Curve, PairingCurve},
        schemes::rw15::GlobalParams,
    };

    use crate::domain::parameter::{MockParameterService, Parameter};

    use super::{ParameterUseCase, ParameterUseCaseImpl};

    #[tokio::test]
    async fn when_creating_parameter_data_is_successful_then_parameter_usecase_returns_parameter_ok() {
        let workspace_name = "workspace".to_string();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut rng = <Bls24479Curve as PairingCurve>::Rng::new();
        let mut mock_parameter_service = MockParameterService::new();
        mock_parameter_service
            .expect_create()
            .times(1)
            .returning(move |_| Ok(Parameter { version: 1, value: GlobalParams::<Bls24479Curve>::new(&mut rng) }));

        let parameter_usecase = ParameterUseCaseImpl::new(
            workspace_name.clone(),
            mock_connection.clone(),
            Arc::new(mock_parameter_service),
        );

        let result = parameter_usecase.create().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn when_creating_parameter_data_is_failed_then_parameter_usecase_returns_parameter_err() {
        let workspace_name = "workspace".to_string();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_parameter_service = MockParameterService::new();
        mock_parameter_service
            .expect_create()
            .times(1)
            .returning(move |_| Err(crate::domain::parameter::Error::Anyhow(anyhow::anyhow!(""))));

        let parameter_usecase = ParameterUseCaseImpl::new(
            workspace_name.clone(),
            mock_connection.clone(),
            Arc::new(mock_parameter_service),
        );

        let result = parameter_usecase.create().await;

        assert!(result.is_err());
    }

    #[tokio::test]
    async fn when_getting_parameter_data_is_successful_then_parameter_usecase_returns_parameter_ok() {
        let workspace_name = "workspace".to_string();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut rng = <Bls24479Curve as PairingCurve>::Rng::new();
        let mut mock_parameter_service = MockParameterService::new();
        mock_parameter_service
            .expect_get()
            .times(1)
            .returning(move |_| Ok(Parameter { version: 1, value: GlobalParams::<Bls24479Curve>::new(&mut rng) }));

        let parameter_usecase = ParameterUseCaseImpl::new(
            workspace_name.clone(),
            mock_connection.clone(),
            Arc::new(mock_parameter_service),
        );

        let result = parameter_usecase.get().await;

        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn when_getting_parameter_data_is_failed_then_parameter_usecase_returns_parameter_err() {
        let workspace_name = "workspace".to_string();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_parameter_service = MockParameterService::new();
        mock_parameter_service
            .expect_get()
            .times(1)
            .returning(move |_| Err(crate::domain::parameter::Error::Anyhow(anyhow::anyhow!(""))));

        let parameter_usecase = ParameterUseCaseImpl::new(
            workspace_name.clone(),
            mock_connection.clone(),
            Arc::new(mock_parameter_service),
        );

        let result = parameter_usecase.get().await;

        assert!(result.is_err());
    }
}
