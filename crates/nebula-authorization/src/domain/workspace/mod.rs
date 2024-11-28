use std::sync::Arc;

use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, ConnectionTrait, DatabaseBackend, DatabaseConnection, DatabaseTransaction, DbErr,
    EntityTrait, PaginatorTrait, QueryFilter, RuntimeErr, SqlxError, Statement,
};
use tracing::info;
use ulid::Ulid;

use crate::database::{migrate_workspace, AuthMethod};

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("workspace name already exists")]
    WorkspaceNameConflicted,
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) struct WorkspaceService {
    connection: Arc<DatabaseConnection>,
    database_host: String,
    database_port: u16,
    database_name: String,
    database_auth: AuthMethod,
}

impl WorkspaceService {}

impl WorkspaceService {
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

    pub(crate) async fn create(&self, transaction: &DatabaseTransaction, name: &str) -> Result<()> {
        use crate::database::workspace::ActiveModel;
        use sea_orm::ActiveValue;

        if self.exists_by_name(transaction, name).await? {
            migrate_workspace(name, &self.database_host, self.database_port, &self.database_name, &self.database_auth)
                .await?;
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

        self.connection
            .execute(Statement::from_string(
                DatabaseBackend::Postgres,
                format!("CREATE SCHEMA IF NOT EXISTS \"{name}\";"),
            ))
            .await?;

        migrate_workspace(name, &self.database_host, self.database_port, &self.database_name, &self.database_auth)
            .await?;

        info!("workspace(name: {name}) created.");

        Ok(())
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
