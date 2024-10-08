use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, TransactionTrait};

use crate::domain::workspace::{Error as WorkspaceServiceError, WorkspaceService};

use self::command::CreatingWorkspaceCommand;

pub mod command;

#[async_trait]
pub(crate) trait WorkspaceUseCase {
    async fn create(&self, cmd: CreatingWorkspaceCommand) -> Result<()>;
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
    async fn create(&self, cmd: CreatingWorkspaceCommand) -> Result<()> {
        let transaction = self.database_connection.begin().await.map_err(anyhow::Error::from)?;

        self.workspace_service.create(&transaction, &cmd.name).await?;

        transaction.commit().await.map_err(anyhow::Error::from)?;

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
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
    use sea_orm::{DatabaseBackend, MockDatabase};

    use super::{command::CreatingWorkspaceCommand, Error, WorkspaceUseCase, WorkspaceUseCaseImpl};

    use crate::domain::workspace::{Error as WorkspaceServiceError, MockWorkspaceService};

    #[tokio::test]
    async fn when_creating_workspace_use_case_should_delegate_to_service() {
        const WORKSPACE_NAME: &'static str = "test_workspace";
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
        const WORKSPACE_NAME: &'static str = "test_workspace";
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
        const WORKSPACE_NAME: &'static str = "test_workspace";
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
        const WORKSPACE_NAME: &'static str = "test_workspace";
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
}
