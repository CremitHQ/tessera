use async_trait::async_trait;
use chrono::Utc;
use mockall::automock;
use sea_orm::{ActiveModelTrait, DatabaseTransaction};
use ulid::Ulid;

use crate::IntoAnyhow;

#[automock]
#[async_trait]
pub(crate) trait WorkspaceService {
    async fn create(&self, transaction: &DatabaseTransaction, name: &str) -> Result<()>;
}

pub(crate) struct WorkspaceServiceImpl {}

impl WorkspaceServiceImpl {
    pub(crate) fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl WorkspaceService for WorkspaceServiceImpl {
    async fn create(&self, transaction: &DatabaseTransaction, name: &str) -> Result<()> {
        use crate::database::workspace::ActiveModel;
        use sea_orm::ActiveValue;

        let now = Utc::now();

        ActiveModel {
            id: ActiveValue::Set(Ulid::new().into()),
            name: ActiveValue::Set(name.to_owned()),
            created_at: ActiveValue::Set(now.clone()),
            updated_at: ActiveValue::Set(now.clone()),
        }
        .insert(transaction)
        .await
        .anyhow()?;

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use chrono::Utc;
    use sea_orm::{DatabaseBackend, DbErr, MockDatabase, TransactionTrait};
    use ulid::Ulid;

    use super::{Error, WorkspaceService, WorkspaceServiceImpl};

    #[tokio::test]
    async fn when_insert_is_successful_then_workspace_service_returns_ok() {
        use crate::database::workspace::Model;

        const WORKSPACE_NAME: &'static str = "test_workspace";
        let now = Utc::now();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres).append_query_results([vec![Model {
            id: Ulid::new().into(),
            name: WORKSPACE_NAME.to_owned(),
            created_at: now.clone(),
            updated_at: now.clone(),
        }]]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let workspace_service = WorkspaceServiceImpl::new();

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = workspace_service.create(&transaction, WORKSPACE_NAME).await;

        transaction.commit().await.expect("commiting transaction should be successful");

        result.expect("creating workspace should be successful")
    }

    #[tokio::test]
    async fn when_insert_is_failed_then_workspace_service_returns_anyhow_err() {
        const WORKSPACE_NAME: &'static str = "test_workspace";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let workspace_service = WorkspaceServiceImpl::new();

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = workspace_service.create(&transaction, WORKSPACE_NAME).await;

        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "Custom Error: some error");
    }
}
