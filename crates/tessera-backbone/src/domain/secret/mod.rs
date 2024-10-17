use async_trait::async_trait;
use sea_orm::{ColumnTrait, DatabaseTransaction, EntityTrait, QueryFilter};
use ulid::Ulid;

use crate::database::secret_metadata;

pub(crate) struct SecretEntry {
    pub key: String,
    pub path: String,
    pub reader_policy_ids: Vec<Ulid>,
    pub writer_policy_ids: Vec<Ulid>,
}

#[async_trait]
pub(crate) trait SecretService {
    async fn list(&self, transaction: &DatabaseTransaction, path_prefix: &str) -> Result<Vec<SecretEntry>>;
}

pub(crate) struct PostgresSecretService {}

#[async_trait]
impl SecretService for PostgresSecretService {
    async fn list(&self, transaction: &DatabaseTransaction, path_prefix: &str) -> Result<Vec<SecretEntry>> {
        let metadata = secret_metadata::Entity::find()
            .filter(secret_metadata::Column::Path.like(format!("{path_prefix}%")))
            .all(transaction)
            .await?;

        let entries = metadata
            .into_iter()
            .map(|metadata| SecretEntry {
                key: metadata.key,
                path: metadata.path,
                reader_policy_ids: vec![],
                writer_policy_ids: vec![],
            })
            .collect();

        Ok(entries)
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<sea_orm::DbErr> for Error {
    fn from(value: sea_orm::DbErr) -> Self {
        Self::Anyhow(value.into())
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
