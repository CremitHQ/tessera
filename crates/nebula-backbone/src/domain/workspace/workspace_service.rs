use std::sync::Arc;

use super::Error;
use crate::{
    database::{migrate_workspace, AuthMethod},
    domain::workspace::Workspace,
};
use async_trait::async_trait;
use chrono::Utc;
#[cfg(test)]
use mockall::automock;
use nebula_common::validate_workspace_name;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, DbErr,
    EntityTrait, PaginatorTrait, QueryFilter, RuntimeErr, SqlxError, Statement,
};
use tracing::info;
use ulid::Ulid;

#[cfg_attr(test, automock)]
#[async_trait]
pub(crate) trait WorkspaceService {
    async fn get_all(&self, transaction: &DatabaseTransaction) -> Result<Vec<Workspace>>;
    async fn get_by_name(&self, transaction: &DatabaseTransaction, name: &str) -> Result<Option<Workspace>>;
    async fn create(&self, transaction: &DatabaseTransaction, name: &str) -> Result<()>;
}

pub(crate) struct WorkspaceServiceImpl {
    connection: Arc<DatabaseConnection>,
    database_host: String,
    database_port: u16,
    database_name: String,
    database_auth: AuthMethod,
}

impl WorkspaceServiceImpl {
    pub(crate) fn new(
        connection: Arc<DatabaseConnection>,
        database_host: String,
        database_port: u16,
        database_name: String,
        database_auth: AuthMethod,
    ) -> Self {
        Self { connection, database_host, database_port, database_name, database_auth }
    }

    async fn exists_by_name(&self, transaction: &DatabaseTransaction, name: &str) -> Result<bool> {
        use crate::database::workspace;

        Ok(workspace::Entity::find().filter(workspace::Column::Name.eq(name)).count(transaction).await? > 0)
    }
}

#[async_trait]
impl WorkspaceService for WorkspaceServiceImpl {
    async fn get_all(&self, transaction: &DatabaseTransaction) -> Result<Vec<Workspace>> {
        use crate::database::workspace::Entity;

        let workspace_models = Entity::find().all(transaction).await?;

        return Ok(workspace_models.into_iter().map(Workspace::from).collect());
    }

    async fn get_by_name(&self, transaction: &DatabaseTransaction, name: &str) -> Result<Option<Workspace>> {
        use crate::database::workspace::{Column, Entity};

        let workspace_model = Entity::find().filter(Column::Name.eq(name)).one(transaction).await?;

        Ok(workspace_model.map(Workspace::from))
    }

    async fn create(&self, transaction: &DatabaseTransaction, name: &str) -> Result<()> {
        use crate::database::workspace::ActiveModel;
        use sea_orm::ActiveValue;

        if !validate_workspace_name(name) {
            return Err(Error::InvalidWorkspaceName);
        }

        self.connection
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                format!("CREATE SCHEMA IF NOT EXISTS \"{name}\";"),
            ))
            .await?;

        migrate_workspace(name, &self.database_host, self.database_port, &self.database_name, &self.database_auth)
            .await?;

        if self.exists_by_name(transaction, name).await? {
            return Err(Error::WorkspaceNameConflicted);
        }

        let now = Utc::now();

        ActiveModel {
            id: ActiveValue::Set(Ulid::new().into()),
            name: ActiveValue::Set(name.to_owned()),
            created_at: ActiveValue::Set(now),
            updated_at: ActiveValue::Set(now),
        }
        .insert(transaction)
        .await?;

        info!("workspace(name: {name}) created.");

        Ok(())
    }
}

impl From<crate::database::workspace::Model> for Workspace {
    fn from(value: crate::database::workspace::Model) -> Self {
        Workspace::new(value.id.inner(), value.name)
    }
}

impl From<DbErr> for Error {
    fn from(value: DbErr) -> Self {
        if let DbErr::Query(RuntimeErr::SqlxError(SqlxError::Database(e))) = value {
            if e.code().as_deref() == Some("23505") {
                Self::WorkspaceNameConflicted
            } else {
                Self::Anyhow(e.into())
            }
        } else {
            Self::Anyhow(value.into())
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test {
    use std::sync::Arc;

    use chrono::Utc;
    use sea_orm::{DatabaseBackend, DbErr, MockDatabase, MockExecResult, TransactionTrait};
    use ulid::Ulid;

    use crate::database::AuthMethod;

    use super::{Error, WorkspaceService, WorkspaceServiceImpl};

    #[tokio::test]
    async fn when_insert_is_successful_then_workspace_service_returns_ok() {
        use crate::database::workspace::Model;

        const WORKSPACE_NAME: &str = "test_workspace";
        let now = Utc::now();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[maplit::btreemap! {
                "num_items" => sea_orm::Value::BigInt(Some(0))
            }]])
            .append_query_results([vec![Model {
                id: Ulid::new().into(),
                name: WORKSPACE_NAME.to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 0 }]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let workspace_service = WorkspaceServiceImpl::new(
            mock_connection.clone(),
            "mock.database.host".to_owned(),
            5432,
            "postgres".to_owned(),
            AuthMethod::Credential { username: "postgres".to_owned(), password: None },
        );

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = workspace_service.create(&transaction, WORKSPACE_NAME).await;

        transaction.commit().await.expect("commiting transaction should be successful");

        result.expect("creating workspace should be successful");
    }

    #[tokio::test]
    async fn when_workspace_already_exists_then_workspace_service_returns_workspace_name_conflicted_error() {
        const WORKSPACE_NAME: &str = "test_workspace";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres).append_query_results([[maplit::btreemap! {
            "num_items" => sea_orm::Value::BigInt(Some(1))
        }]]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let workspace_service = WorkspaceServiceImpl::new(
            mock_connection.clone(),
            "mock.database.host".to_owned(),
            5432,
            "postgres".to_owned(),
            AuthMethod::Credential { username: "postgres".to_owned(), password: None },
        );

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = workspace_service.create(&transaction, WORKSPACE_NAME).await;

        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::WorkspaceNameConflicted)));
    }

    #[tokio::test]
    async fn when_insert_is_failed_then_workspace_service_returns_anyhow_err() {
        const WORKSPACE_NAME: &str = "test_workspace";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let workspace_service = WorkspaceServiceImpl::new(
            mock_connection.clone(),
            "mock.database.host".to_owned(),
            5432,
            "postgres".to_owned(),
            AuthMethod::Credential { username: "postgres".to_owned(), password: None },
        );

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = workspace_service.create(&transaction, WORKSPACE_NAME).await;

        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "Custom Error: some error");
    }

    #[tokio::test]
    async fn when_getting_workspaces_is_successful_then_workspace_service_returns_workspaces_ok() {
        use crate::database::workspace::Model;

        const WORKSPACE_NAME: &str = "test_workspace";
        let now = Utc::now();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres).append_query_results([vec![Model {
            id: Ulid::new().into(),
            name: WORKSPACE_NAME.to_owned(),
            created_at: now,
            updated_at: now,
        }]]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let workspace_service = WorkspaceServiceImpl::new(
            mock_connection.clone(),
            "mock.database.host".to_owned(),
            5432,
            "postgres".to_owned(),
            AuthMethod::Credential { username: "postgres".to_owned(), password: None },
        );

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = workspace_service.get_all(&transaction).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(result.expect("creating workspace should be successful")[0].name, WORKSPACE_NAME);
    }

    #[tokio::test]
    async fn when_getting_workspaces_is_failed_then_workspace_service_returns_anyhow_err() {
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let workspace_service = WorkspaceServiceImpl::new(
            mock_connection.clone(),
            "mock.database.host".to_owned(),
            5432,
            "postgres".to_owned(),
            AuthMethod::Credential { username: "postgres".to_owned(), password: None },
        );

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = workspace_service.get_all(&transaction).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "Custom Error: some error");
    }

    #[tokio::test]
    async fn when_getting_not_existing_workspace_then_workspace_service_returns_ok_of_none() {
        use crate::database::workspace::Model;
        const WORKSPACE_NAME: &str = "test_workspace";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres).append_query_results([Vec::<Model>::new()]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let workspace_service = WorkspaceServiceImpl::new(
            mock_connection.clone(),
            "mock.database.host".to_owned(),
            5432,
            "postgres".to_owned(),
            AuthMethod::Credential { username: "postgres".to_owned(), password: None },
        );

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = workspace_service.get_by_name(&transaction, WORKSPACE_NAME).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(result.expect("creating workspace should be successful"), None);
    }

    #[tokio::test]
    async fn when_getting_workspace_is_failed_then_workspace_service_returns_anyhow_err() {
        const WORKSPACE_NAME: &str = "test_workspace";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let workspace_service = WorkspaceServiceImpl::new(
            mock_connection.clone(),
            "mock.database.host".to_owned(),
            5432,
            "postgres".to_owned(),
            AuthMethod::Credential { username: "postgres".to_owned(), password: None },
        );

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = workspace_service.get_by_name(&transaction, WORKSPACE_NAME).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "Custom Error: some error");
    }

    #[tokio::test]
    async fn when_getting_workspace_is_succeed_then_workspace_service_returns_ok_of_workspace() {
        use crate::database::workspace::Model;
        const WORKSPACE_NAME: &str = "test_workspace";

        let now = Utc::now();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres).append_query_results([vec![Model {
            id: Ulid::new().into(),
            name: WORKSPACE_NAME.to_owned(),
            created_at: now,
            updated_at: now,
        }]]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let workspace_service = WorkspaceServiceImpl::new(
            mock_connection.clone(),
            "mock.database.host".to_owned(),
            5432,
            "postgres".to_owned(),
            AuthMethod::Credential { username: "postgres".to_owned(), password: None },
        );

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = workspace_service.get_by_name(&transaction, WORKSPACE_NAME).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(
            result.expect("getting workspace should be successful").expect("workspace should be exists").name,
            WORKSPACE_NAME
        )
    }
}
