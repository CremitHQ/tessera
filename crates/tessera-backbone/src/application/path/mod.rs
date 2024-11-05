use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::DatabaseConnection;

use crate::{
    database::OrganizationScopedTransaction,
    domain::secret::{self, Path, SecretService},
};

pub(crate) struct PathData {
    pub path: String,
}

#[async_trait]
pub(crate) trait PathUseCase {
    async fn get_all(&self) -> Result<Vec<PathData>>;
    async fn register(&self, path: String) -> Result<()>;
}

pub(crate) struct PathUseCaseImpl {
    workspace_name: String,
    database_connection: Arc<DatabaseConnection>,
    secret_service: Arc<dyn SecretService + Sync + Send>,
}

impl PathUseCaseImpl {
    pub fn new(
        workspace_name: String,
        database_connection: Arc<DatabaseConnection>,
        secret_service: Arc<dyn SecretService + Sync + Send>,
    ) -> Self {
        Self { workspace_name, database_connection, secret_service }
    }
}

#[async_trait]
impl PathUseCase for PathUseCaseImpl {
    async fn get_all(&self) -> Result<Vec<PathData>> {
        let transaction = self.database_connection.begin_with_organization_scope(&self.workspace_name).await?;
        let paths = self.secret_service.get_paths(&transaction).await?;
        transaction.commit().await?;

        Ok(paths.into_iter().map(PathData::from).collect())
    }

    async fn register(&self, path: String) -> Result<()> {
        // TODO: register path in transaction
        todo!()
    }
}

impl From<Path> for PathData {
    fn from(value: Path) -> Self {
        Self { path: value.path }
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<secret::Error> for Error {
    fn from(value: secret::Error) -> Self {
        match value {
            secret::Error::InvalidSecretIdentifier { .. } => Self::Anyhow(value.into()),
            secret::Error::SecretNotExists => Self::Anyhow(value.into()),
            secret::Error::Anyhow(e) => Self::Anyhow(e),
            secret::Error::PathNotExists { .. } => Self::Anyhow(value.into()),
            secret::Error::IdentifierConflicted { .. } => Self::Anyhow(value.into()),
        }
    }
}

impl From<sea_orm::DbErr> for Error {
    fn from(value: sea_orm::DbErr) -> Self {
        Error::Anyhow(value.into())
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};

    use crate::domain::secret::{MockSecretService, Path};

    use super::{Error, PathUseCase, PathUseCaseImpl};

    #[tokio::test]
    async fn when_getting_paths_is_successful_then_policy_usecase_returns_paths_ok() {
        let path = "/frontend";

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_secret_service = MockSecretService::new();
        mock_secret_service
            .expect_get_paths()
            .withf(|_| true)
            .times(1)
            .returning(move |_| Ok(vec![Path { path: path.to_owned() }]));

        let path_usecase =
            PathUseCaseImpl::new("test_workspace".to_owned(), mock_connection, Arc::new(mock_secret_service));

        let result = path_usecase.get_all().await.expect("creating workspace should be successful");

        assert_eq!(result[0].path, path);
    }

    #[tokio::test]
    async fn when_getting_secret_is_failed_with_anyhow_then_secret_usecase_returns_anyhow_err() {
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_secret_service = MockSecretService::new();
        mock_secret_service
            .expect_get_paths()
            .withf(|_| true)
            .times(1)
            .returning(move |_| Err(crate::domain::secret::Error::Anyhow(anyhow::anyhow!("some error"))));
        let path_usecase =
            PathUseCaseImpl::new("test_workspace".to_owned(), mock_connection, Arc::new(mock_secret_service));

        let result = path_usecase.get_all().await;

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "some error");
    }
}
