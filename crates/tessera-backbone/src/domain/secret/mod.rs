use async_trait::async_trait;
#[cfg(test)]
use mockall::automock;
use sea_orm::{ColumnTrait, DatabaseTransaction, EntityTrait, LoaderTrait, QueryFilter};
use ulid::Ulid;

use crate::database::{applied_policy, secret_metadata};

pub(crate) struct SecretEntry {
    pub key: String,
    pub path: String,
    pub reader_policy_ids: Vec<Ulid>,
    pub writer_policy_ids: Vec<Ulid>,
}

#[cfg_attr(test, automock)]
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

#[cfg(test)]
mod test {
    use std::{str::FromStr, sync::Arc};

    use chrono::Utc;
    use sea_orm::{DatabaseBackend, DbErr, MockDatabase, TransactionTrait};
    use ulid::Ulid;

    use super::{Error, PostgresSecretService, SecretService};
    use crate::database::{applied_policy, secret_metadata, UlidId};

    #[tokio::test]
    async fn when_getting_secret_data_is_successful_then_secret_service_returns_secrets_ok() {
        let now = Utc::now();
        let metadata_id = UlidId::new(Ulid::from_str("01JACYVTYB4F2PEBFRG1BB7BKP").unwrap());
        let key = "TEST_KEY";
        let path = "/test/path";
        let applied_policy_ids = [
            UlidId::new(Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap()),
            UlidId::new(Ulid::from_str("01JACZ1FG1RYABQW2KB6YSEZ84").unwrap()),
        ];
        let policy_id = UlidId::new(Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap());

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![secret_metadata::Model {
                id: metadata_id.to_owned(),
                key: key.to_owned(),
                path: path.to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([vec![
                applied_policy::Model {
                    id: applied_policy_ids[0].to_owned(),
                    secret_metadata_id: metadata_id.to_owned(),
                    r#type: applied_policy::PolicyApplicationType::Read,
                    policy_id: policy_id.to_owned(),
                    created_at: now,
                    updated_at: now,
                },
                applied_policy::Model {
                    id: applied_policy_ids[1].to_owned(),
                    secret_metadata_id: metadata_id.to_owned(),
                    r#type: applied_policy::PolicyApplicationType::Write,
                    policy_id: policy_id.to_owned(),
                    created_at: now,
                    updated_at: now,
                },
            ]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.list(&transaction, "/").await.expect("creating workspace should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(result[0].key, key);
        assert_eq!(result[0].path, path);
        assert_eq!(result[0].reader_policy_ids[0], Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap());
        assert_eq!(result[0].writer_policy_ids[0], Ulid::from_str("01JACZ1FG1RYABQW2KB6YSEZ84").unwrap());
    }

    #[tokio::test]
    async fn when_getting_secret_is_failed_then_secret_service_returns_anyhow_err() {
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.list(&transaction, "/").await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "Custom Error: some error");
    }
}
