use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, TransactionTrait};

use crate::{
    database::Persistable,
    domain::{
        parameter::Error as ParameterError,
        secret::Error as SecretError,
        workspace::{Error as WorkspaceServiceError, Workspace, WorkspaceService},
    },
};

use self::{command::CreatingWorkspaceCommand, data::WorkspaceData};

use super::{ParameterService, SecretService};

pub mod command;
pub mod data;

#[async_trait]
pub(crate) trait WorkspaceUseCase {
    async fn get_all(&self) -> Result<Vec<WorkspaceData>>;
    async fn create(&self, cmd: CreatingWorkspaceCommand) -> Result<()>;
    async fn delete_by_name(&self, name: &str) -> Result<()>;
}

pub(crate) struct WorkspaceUseCaseImpl {
    database_connection: Arc<DatabaseConnection>,
    workspace_service: Arc<dyn WorkspaceService + Sync + Send>,
    secret_service: Arc<dyn SecretService + Sync + Send>,
    parameter_service: Arc<dyn ParameterService + Sync + Send>,
}

impl WorkspaceUseCaseImpl {
    pub fn new(
        database_connection: Arc<DatabaseConnection>,
        workspace_service: Arc<dyn WorkspaceService + Sync + Send>,
        secret_service: Arc<dyn SecretService + Sync + Send>,
        parameter_service: Arc<dyn ParameterService + Sync + Send>,
    ) -> Self {
        Self { database_connection, workspace_service, secret_service, parameter_service }
    }
}

#[async_trait]
impl WorkspaceUseCase for WorkspaceUseCaseImpl {
    async fn get_all(&self) -> Result<Vec<WorkspaceData>> {
        let transaction = self.database_connection.begin().await.map_err(anyhow::Error::from)?;

        let workspaces = self.workspace_service.get_all(&transaction).await?;
        let data = workspaces.into_iter().map(|workspace| workspace.into()).collect();

        transaction.commit().await.map_err(anyhow::Error::from)?;

        Ok(data)
    }

    async fn create(&self, cmd: CreatingWorkspaceCommand) -> Result<()> {
        let transaction = self.database_connection.begin().await.map_err(anyhow::Error::from)?;

        self.workspace_service.create(&transaction, &cmd.name).await?;
        self.secret_service.initialize_root_path(&transaction).await?;
        self.parameter_service.create(&transaction).await?;

        transaction.commit().await.map_err(anyhow::Error::from)?;

        Ok(())
    }

    async fn delete_by_name(&self, name: &str) -> Result<()> {
        let transaction = self.database_connection.begin().await.map_err(anyhow::Error::from)?;

        let mut workspace =
            self.workspace_service.get_by_name(&transaction, name).await?.ok_or_else(|| Error::WorkspaceNotExists)?;
        workspace.delete();
        workspace.persist(&transaction).await?;

        transaction.commit().await.map_err(anyhow::Error::from)?;

        Ok(())
    }
}

impl From<Workspace> for WorkspaceData {
    fn from(value: Workspace) -> Self {
        Self { name: value.name }
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("workspace not exists")]
    WorkspaceNotExists,
    #[error("workspace name already exists")]
    WorkspaceNameConflicted,
    #[error("Workspace name is invalid")]
    InvalidWorkspaceName,
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<SecretError> for Error {
    fn from(value: SecretError) -> Self {
        match value {
            SecretError::Anyhow(e) => Self::Anyhow(e),
            _ => Self::Anyhow(value.into()),
        }
    }
}

impl From<ParameterError> for Error {
    fn from(value: ParameterError) -> Self {
        match value {
            ParameterError::Anyhow(e) => Self::Anyhow(e),
            _ => Self::Anyhow(value.into()),
        }
    }
}

impl From<WorkspaceServiceError> for Error {
    fn from(value: WorkspaceServiceError) -> Self {
        match value {
            WorkspaceServiceError::Anyhow(e) => e.into(),
            WorkspaceServiceError::InvalidWorkspaceName => Self::InvalidWorkspaceName,
            WorkspaceServiceError::WorkspaceNameConflicted => Self::WorkspaceNameConflicted,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use anyhow::anyhow;
    use nebula_abe::{
        curves::{bn462::Bn462Curve, PairingCurve},
        schemes::isabella24::GlobalParams,
    };
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    use ulid::Ulid;

    use super::{command::CreatingWorkspaceCommand, Error, WorkspaceUseCase, WorkspaceUseCaseImpl};

    use crate::domain::{
        parameter::{MockParameterService, Parameter},
        secret::MockSecretService,
        workspace::{Error as WorkspaceServiceError, MockWorkspaceService, Workspace},
    };

    #[tokio::test]
    async fn when_creating_workspace_use_case_should_delegate_to_service() {
        const WORKSPACE_NAME: &str = "testworkspace";
        let mock_database = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
        let mut workspace_service_mock = MockWorkspaceService::new();

        workspace_service_mock
            .expect_create()
            .withf(|_, name| name == WORKSPACE_NAME)
            .times(1)
            .returning(|_, _| Ok(()));

        let mut secret_service_mock = MockSecretService::new();
        secret_service_mock.expect_initialize_root_path().times(1).returning(|_| Ok(()));

        let mut rng = <Bn462Curve as PairingCurve>::Rng::new();
        let mut parameter_service_mock = MockParameterService::new();
        parameter_service_mock
            .expect_create()
            .times(1)
            .returning(move |_| Ok(Parameter { version: 1, value: GlobalParams::<Bn462Curve>::new(&mut rng) }));

        let workspace_use_case = WorkspaceUseCaseImpl::new(
            mock_database,
            Arc::new(workspace_service_mock),
            Arc::new(secret_service_mock),
            Arc::new(parameter_service_mock),
        );
        workspace_use_case
            .create(CreatingWorkspaceCommand { name: WORKSPACE_NAME.to_owned() })
            .await
            .expect("creating workspace should be successful");
    }

    #[tokio::test]
    async fn when_creating_workspace_failed_with_anyhow_use_case_should_returns_anyhow() {
        const WORKSPACE_NAME: &str = "testworkspace";
        let mock_database = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
        let mut workspace_service_mock = MockWorkspaceService::new();

        workspace_service_mock
            .expect_create()
            .withf(|_, name| name == WORKSPACE_NAME)
            .times(1)
            .returning(|_, _| Err(WorkspaceServiceError::Anyhow(anyhow!("some error"))));
        let secret_service_mock = MockSecretService::new();
        let parameter_service_mock = MockParameterService::new();

        let workspace_use_case = WorkspaceUseCaseImpl::new(
            mock_database,
            Arc::new(workspace_service_mock),
            Arc::new(secret_service_mock),
            Arc::new(parameter_service_mock),
        );
        let result = workspace_use_case.create(CreatingWorkspaceCommand { name: WORKSPACE_NAME.to_owned() }).await;

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "some error");
    }

    #[tokio::test]
    async fn when_creating_workspace_failed_with_workspace_name_conflicted_use_case_should_returns_workspace_name_conflicted_err(
    ) {
        const WORKSPACE_NAME: &str = "testworkspace";
        let mock_database = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
        let mut workspace_service_mock = MockWorkspaceService::new();

        workspace_service_mock
            .expect_create()
            .withf(|_, name| name == WORKSPACE_NAME)
            .times(1)
            .returning(|_, _| Err(WorkspaceServiceError::WorkspaceNameConflicted));
        let secret_service_mock = MockSecretService::new();
        let parameter_service_mock = MockParameterService::new();

        let workspace_use_case = WorkspaceUseCaseImpl::new(
            mock_database,
            Arc::new(workspace_service_mock),
            Arc::new(secret_service_mock),
            Arc::new(parameter_service_mock),
        );
        let result = workspace_use_case.create(CreatingWorkspaceCommand { name: WORKSPACE_NAME.to_owned() }).await;

        assert!(matches!(result, Err(Error::WorkspaceNameConflicted)));
    }

    #[tokio::test]
    async fn when_getting_workspaces_succeed_use_case_should_returns_workspaces() {
        let mock_database = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
        let mut workspace_service_mock = MockWorkspaceService::new();

        workspace_service_mock
            .expect_get_all()
            .times(1)
            .returning(|_| Ok(vec![Workspace::new(Ulid::new(), "testworkspace".to_owned())]));
        let secret_service_mock = MockSecretService::new();
        let parameter_service_mock = MockParameterService::new();

        let workspace_use_case = WorkspaceUseCaseImpl::new(
            mock_database,
            Arc::new(workspace_service_mock),
            Arc::new(secret_service_mock),
            Arc::new(parameter_service_mock),
        );
        let result = workspace_use_case.get_all().await;

        assert_eq!(result.expect("getting workspaces should be successful")[0].name, "testworkspace");
    }

    #[tokio::test]
    async fn when_deleting_workspace_succeed_use_case_should_returns_empty_ok() {
        const WORKSPACE_NAME: &str = "testworkspace";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_database = Arc::new(mock_database.into_connection());
        let mut workspace_service_mock = MockWorkspaceService::new();
        let secret_service_mock = MockSecretService::new();
        let parameter_service_mock = MockParameterService::new();

        workspace_service_mock
            .expect_get_by_name()
            .withf(|_, name| name == WORKSPACE_NAME)
            .times(1)
            .returning(|_, _| Ok(Some(Workspace::new(Ulid::new(), "testworkspace".to_owned()))));

        let workspace_use_case = WorkspaceUseCaseImpl::new(
            mock_database,
            Arc::new(workspace_service_mock),
            Arc::new(secret_service_mock),
            Arc::new(parameter_service_mock),
        );
        let result = workspace_use_case.delete_by_name(WORKSPACE_NAME).await;

        assert!(matches!(result, Ok(())));
    }

    #[tokio::test]
    async fn when_deleting_workspace_failed_with_empty_workspace_use_case_should_returns_workspace_not_exists_error() {
        const WORKSPACE_NAME: &str = "testworkspace";
        let mock_database = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
        let mut workspace_service_mock = MockWorkspaceService::new();

        let secret_service_mock = MockSecretService::new();
        let parameter_service_mock = MockParameterService::new();
        workspace_service_mock
            .expect_get_by_name()
            .withf(|_, name| name == WORKSPACE_NAME)
            .times(1)
            .returning(|_, _| Ok(None));

        let workspace_use_case = WorkspaceUseCaseImpl::new(
            mock_database,
            Arc::new(workspace_service_mock),
            Arc::new(secret_service_mock),
            Arc::new(parameter_service_mock),
        );
        let result = workspace_use_case.delete_by_name(WORKSPACE_NAME).await;

        assert!(matches!(result, Err(Error::WorkspaceNotExists)));
    }
}
