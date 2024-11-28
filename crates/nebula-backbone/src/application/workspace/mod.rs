use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, TransactionTrait};

use crate::{
    database::Persistable,
    domain::workspace::{Error as WorkspaceServiceError, Workspace, WorkspaceService},
};

use self::{command::CreatingWorkspaceCommand, data::WorkspaceData};

pub mod command;
pub mod data;

#[async_trait]
pub(crate) trait WorkspaceUseCase {
    async fn get_all(&self) -> Result<Vec<WorkspaceData>>;
    async fn create(&self, cmd: CreatingWorkspaceCommand) -> Result<()>;
    async fn delete_by_name(&self, name: &str) -> Result<()>;
}

#[derive(Default)]
pub(crate) struct WorkspaceUseCaseImpl<W: WorkspaceService + Sync + Send> {
    database_connection: Arc<DatabaseConnection>,
    workspace_service: Arc<W>,
}

impl<W: WorkspaceService + Sync + Send> WorkspaceUseCaseImpl<W> {
    pub fn new(database_connection: Arc<DatabaseConnection>, workspace_service: Arc<W>) -> Self {
        Self { database_connection, workspace_service }
    }
}

#[async_trait]
impl<W: WorkspaceService + Sync + Send> WorkspaceUseCase for WorkspaceUseCaseImpl<W> {
    async fn get_all(&self) -> Result<Vec<WorkspaceData>> {
        let transaction = self.database_connection.begin().await.map_err(anyhow::Error::from)?;

        let workspaces = self.workspace_service.get_all(&transaction).await?;
        let data = workspaces.into_iter().map(|workspace| workspace.into()).collect();

        transaction.commit().await.map_err(anyhow::Error::from)?;

        Ok(data)
    }

    async fn create(&self, cmd: CreatingWorkspaceCommand) -> Result<()> {
        let transaction = self.database_connection.begin().await.map_err(anyhow::Error::from)?;

        self.workspace_service.create(&self.database_connection, &transaction, &cmd.name).await?;

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
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<WorkspaceServiceError> for Error {
    fn from(value: WorkspaceServiceError) -> Self {
        match value {
            WorkspaceServiceError::Anyhow(e) => e.into(),
            WorkspaceServiceError::WorkspaceNameConflicted => Self::WorkspaceNameConflicted,
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use anyhow::anyhow;
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    use ulid::Ulid;

    use super::{command::CreatingWorkspaceCommand, Error, WorkspaceUseCase, WorkspaceUseCaseImpl};

    use crate::domain::workspace::{Error as WorkspaceServiceError, MockWorkspaceService, Workspace};

    #[tokio::test]
    async fn when_creating_workspace_use_case_should_delegate_to_service() {
        const WORKSPACE_NAME: &str = "test_workspace";
        let mock_database = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
        let mut workspace_service_mock = MockWorkspaceService::new();

        workspace_service_mock
            .expect_create()
            .withf(|_, name| name == WORKSPACE_NAME)
            .times(1)
            .returning(|_, _| Ok(()));

        let workspace_use_case = WorkspaceUseCaseImpl::new(mock_database, Arc::new(workspace_service_mock));
        workspace_use_case
            .create(CreatingWorkspaceCommand { name: WORKSPACE_NAME.to_owned() })
            .await
            .expect("creating workspace should be successful");
    }

    #[tokio::test]
    async fn when_creating_workspace_succeed_use_case_should_returns_empty_ok() {
        const WORKSPACE_NAME: &str = "test_workspace";
        let mock_database = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
        let mut workspace_service_mock = MockWorkspaceService::new();

        workspace_service_mock
            .expect_create()
            .withf(|_, name| name == WORKSPACE_NAME)
            .times(1)
            .returning(|_, _| Ok(()));

        let workspace_use_case = WorkspaceUseCaseImpl::new(mock_database, Arc::new(workspace_service_mock));
        let result = workspace_use_case.create(CreatingWorkspaceCommand { name: WORKSPACE_NAME.to_owned() }).await;

        assert!(matches!(result, Ok(())));
    }

    #[tokio::test]
    async fn when_creating_workspace_failed_with_anyhow_use_case_should_returns_anyhow() {
        const WORKSPACE_NAME: &str = "test_workspace";
        let mock_database = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
        let mut workspace_service_mock = MockWorkspaceService::new();

        workspace_service_mock
            .expect_create()
            .withf(|_, name| name == WORKSPACE_NAME)
            .times(1)
            .returning(|_, _| Err(WorkspaceServiceError::Anyhow(anyhow!("some error"))));

        let workspace_use_case = WorkspaceUseCaseImpl::new(mock_database, Arc::new(workspace_service_mock));
        let result = workspace_use_case.create(CreatingWorkspaceCommand { name: WORKSPACE_NAME.to_owned() }).await;

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "some error");
    }

    #[tokio::test]
    async fn when_creating_workspace_failed_with_workspace_name_conflicted_use_case_should_returns_workspace_name_conflicted_err(
    ) {
        const WORKSPACE_NAME: &str = "test_workspace";
        let mock_database = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
        let mut workspace_service_mock = MockWorkspaceService::new();

        workspace_service_mock
            .expect_create()
            .withf(|_, name| name == WORKSPACE_NAME)
            .times(1)
            .returning(|_, _| Err(WorkspaceServiceError::WorkspaceNameConflicted));

        let workspace_use_case = WorkspaceUseCaseImpl::new(mock_database, Arc::new(workspace_service_mock));
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
            .returning(|_| Ok(vec![Workspace::new(Ulid::new(), "test_workspace".to_owned())]));

        let workspace_use_case = WorkspaceUseCaseImpl::new(mock_database, Arc::new(workspace_service_mock));
        let result = workspace_use_case.get_all().await;

        assert_eq!(result.expect("getting workspaces should be successful")[0].name, "test_workspace");
    }

    #[tokio::test]
    async fn when_deleting_workspace_succeed_use_case_should_returns_empty_ok() {
        const WORKSPACE_NAME: &str = "test_workspace";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_database = Arc::new(mock_database.into_connection());
        let mut workspace_service_mock = MockWorkspaceService::new();

        workspace_service_mock
            .expect_get_by_name()
            .withf(|_, name| name == WORKSPACE_NAME)
            .times(1)
            .returning(|_, _| Ok(Some(Workspace::new(Ulid::new(), "test_workspace".to_owned()))));

        let workspace_use_case = WorkspaceUseCaseImpl::new(mock_database, Arc::new(workspace_service_mock));
        let result = workspace_use_case.delete_by_name(WORKSPACE_NAME).await;

        assert!(matches!(result, Ok(())));
    }

    #[tokio::test]
    async fn when_deleting_workspace_failed_with_empty_workspace_use_case_should_returns_workspace_not_exists_error() {
        const WORKSPACE_NAME: &str = "test_workspace";
        let mock_database = Arc::new(MockDatabase::new(DatabaseBackend::Postgres).into_connection());
        let mut workspace_service_mock = MockWorkspaceService::new();

        workspace_service_mock
            .expect_get_by_name()
            .withf(|_, name| name == WORKSPACE_NAME)
            .times(1)
            .returning(|_, _| Ok(None));

        let workspace_use_case = WorkspaceUseCaseImpl::new(mock_database, Arc::new(workspace_service_mock));
        let result = workspace_use_case.delete_by_name(WORKSPACE_NAME).await;

        assert!(matches!(result, Err(Error::WorkspaceNotExists)));
    }
}
