use async_trait::async_trait;
use sea_orm::{ColumnTrait, DatabaseTransaction, EntityTrait, LoaderTrait, QueryFilter};
use ulid::Ulid;

use crate::database::{applied_policy, secret_metadata};

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
        let applied_policies = metadata.load_many(applied_policy::Entity, transaction).await?;

        Ok(metadata
            .into_iter()
            .zip(applied_policies.into_iter())
            .map(|(metadata, applied_policies)| {
                let mut reader_policy_ids: Vec<Ulid> = vec![];
                let mut writer_policy_ids: Vec<Ulid> = vec![];

                // TODO: get cipher from storage
                for applied_policy in applied_policies {
                    match applied_policy.r#type {
                        applied_policy::PolicyApplicationType::Read => {
                            reader_policy_ids.push(applied_policy.id.inner())
                        }
                        applied_policy::PolicyApplicationType::Write => {
                            writer_policy_ids.push(applied_policy.id.inner())
                        }
                    }
                }

                SecretEntry { key: metadata.key, path: metadata.path, reader_policy_ids, writer_policy_ids }
            })
            .collect())
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
