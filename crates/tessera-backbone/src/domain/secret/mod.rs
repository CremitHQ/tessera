use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use chrono::Utc;
use lazy_static::lazy_static;
#[cfg(test)]
use mockall::automock;
use regex::Regex;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseTransaction, EntityTrait, LoaderTrait, PaginatorTrait,
    QueryFilter, QuerySelect, QueryTrait, Set,
};
use ulid::Ulid;

use crate::database::{
    applied_policy::{self, PolicyApplicationType},
    path, secret_metadata, secret_value, Persistable, UlidId,
};

use super::policy::Policy;

pub(crate) struct SecretEntry {
    pub key: String,
    pub path: String,
    pub cipher: Vec<u8>,
    pub access_policy_ids: Vec<Ulid>,
    pub management_policy_ids: Vec<Ulid>,
    deleted: bool,
    updated_path: Option<String>,
    updated_cipher: Option<Vec<u8>>,
    updated_access_policy_ids: Option<Vec<Ulid>>,
    updated_management_policy_ids: Option<Vec<Ulid>>,
}

impl SecretEntry {
    pub(crate) fn new(
        key: String,
        path: String,
        cipher: Vec<u8>,
        access_policy_ids: Vec<Ulid>,
        management_policy_ids: Vec<Ulid>,
    ) -> Self {
        Self {
            key,
            path,
            cipher,
            access_policy_ids,
            management_policy_ids,
            deleted: false,
            updated_path: None,
            updated_cipher: None,
            updated_access_policy_ids: None,
            updated_management_policy_ids: None,
        }
    }

    pub fn delete(&mut self) {
        self.deleted = true
    }

    pub fn update_path(&mut self, new_path: String) {
        if self.path == new_path {
            return;
        }

        self.updated_path = Some(new_path)
    }

    pub fn update_cipher(&mut self, new_cipher: Vec<u8>) {
        if self.cipher == new_cipher {
            return;
        }
        self.updated_cipher = Some(new_cipher)
    }

    pub fn update_access_policies(&mut self, new_access_policies: Vec<Policy>) {
        let new_access_policy_ids: Vec<_> = new_access_policies.into_iter().map(|policy| policy.id).collect();

        if self.access_policy_ids.iter().collect::<HashSet<_>>() == new_access_policy_ids.iter().collect::<HashSet<_>>()
        {
            return;
        }

        self.updated_access_policy_ids = Some(new_access_policy_ids);
    }

    pub fn update_management_policies(&mut self, new_management_policies: Vec<Policy>) {
        let new_management_policy_ids: Vec<_> = new_management_policies.into_iter().map(|policy| policy.id).collect();

        if self.management_policy_ids.iter().collect::<HashSet<_>>()
            == new_management_policy_ids.iter().collect::<HashSet<_>>()
        {
            return;
        }

        self.updated_management_policy_ids = Some(new_management_policy_ids);
    }
}

#[async_trait]
impl Persistable for SecretEntry {
    type Error = Error;

    async fn persist(self, transaction: &DatabaseTransaction) -> std::result::Result<(), Self::Error> {
        if self.deleted {
            secret_value::Entity::delete_many()
                .filter(secret_value::Column::Identifier.eq(create_identifier(&self.path, &self.key)))
                .exec(transaction)
                .await?;
            applied_policy::Entity::delete_many()
                .filter(
                    applied_policy::Column::SecretMetadataId.in_subquery(
                        secret_metadata::Entity::find()
                            .select_only()
                            .column(secret_metadata::Column::Id)
                            .filter(secret_metadata::Column::Path.eq(&self.path))
                            .filter(secret_metadata::Column::Key.eq(&self.key))
                            .into_query(),
                    ),
                )
                .exec(transaction)
                .await?;
            secret_metadata::Entity::delete_many()
                .filter(secret_metadata::Column::Path.eq(self.path))
                .filter(secret_metadata::Column::Key.eq(self.key))
                .exec(transaction)
                .await?;

            return Ok(());
        }

        let now = Utc::now();

        // update applied polciies
        if self.updated_access_policy_ids.is_some() || self.updated_management_policy_ids.is_some() {
            let metadata_id: UlidId = if let Some(metadata_id) = secret_metadata::Entity::find()
                .select_only()
                .column(secret_metadata::Column::Id)
                .filter(secret_metadata::Column::Path.eq(&self.path))
                .filter(secret_metadata::Column::Key.eq(&self.key))
                .into_tuple()
                .one(transaction)
                .await?
            {
                metadata_id
            } else {
                return Ok(());
            };

            if let Some(updated_access_policy_ids) = self.updated_access_policy_ids {
                applied_policy::Entity::delete_many()
                    .filter(applied_policy::Column::SecretMetadataId.eq(metadata_id.clone()))
                    .filter(applied_policy::Column::Type.eq(PolicyApplicationType::Access))
                    .exec(transaction)
                    .await?;

                if !updated_access_policy_ids.is_empty() {
                    let applied_access_policies =
                        updated_access_policy_ids.into_iter().map(|policy_id| applied_policy::ActiveModel {
                            id: Set(UlidId::new(Ulid::new())),
                            secret_metadata_id: Set(metadata_id.clone()),
                            r#type: Set(PolicyApplicationType::Access),
                            policy_id: Set(UlidId::new(policy_id)),
                            created_at: Set(now),
                            updated_at: Set(now),
                        });

                    applied_policy::Entity::insert_many(applied_access_policies).exec(transaction).await?;
                }
            }
            if let Some(updated_management_policy_ids) = self.updated_management_policy_ids {
                applied_policy::Entity::delete_many()
                    .filter(applied_policy::Column::SecretMetadataId.eq(metadata_id.clone()))
                    .filter(applied_policy::Column::Type.eq(PolicyApplicationType::Management))
                    .exec(transaction)
                    .await?;

                if !updated_management_policy_ids.is_empty() {
                    let applied_management_policies =
                        updated_management_policy_ids.into_iter().map(|policy_id| applied_policy::ActiveModel {
                            id: Set(UlidId::new(Ulid::new())),
                            secret_metadata_id: Set(metadata_id.clone()),
                            r#type: Set(PolicyApplicationType::Management),
                            policy_id: Set(UlidId::new(policy_id)),
                            created_at: Set(now),
                            updated_at: Set(now),
                        });

                    applied_policy::Entity::insert_many(applied_management_policies).exec(transaction).await?;
                }
            }
        }

        // update secret metadata
        let path_setter = self.updated_path.clone().map(Set).unwrap_or_default();

        let active_model = secret_metadata::ActiveModel { path: path_setter, ..Default::default() };

        if active_model.is_changed() {
            secret_metadata::Entity::update_many()
                .set(active_model)
                .filter(secret_metadata::Column::Path.eq(&self.path))
                .filter(secret_metadata::Column::Key.eq(&self.key))
                .exec(transaction)
                .await?;
        }

        // update secret value
        let identifier_setter = if self.updated_path.as_deref().is_some() {
            let new_identifier = create_identifier(self.updated_path.as_deref().unwrap_or(&self.path), &self.key);
            Set(new_identifier)
        } else {
            ActiveValue::default()
        };
        let cipher_setter = self.updated_cipher.map(Set).unwrap_or_default();

        let active_model =
            secret_value::ActiveModel { identifier: identifier_setter, cipher: cipher_setter, ..Default::default() };

        if active_model.is_changed() {
            secret_value::Entity::update_many()
                .set(active_model)
                .filter(secret_value::Column::Identifier.eq(create_identifier(&self.path, &self.key)))
                .exec(transaction)
                .await?;
        }

        Ok(())
    }
}

impl From<(secret_metadata::Model, Vec<applied_policy::Model>, Vec<u8>)> for SecretEntry {
    fn from(
        (metadata, applied_policies, cipher): (secret_metadata::Model, Vec<applied_policy::Model>, Vec<u8>),
    ) -> Self {
        let mut access_policy_ids: Vec<Ulid> = vec![];
        let mut management_policy_ids: Vec<Ulid> = vec![];

        for applied_policy in applied_policies {
            match applied_policy.r#type {
                applied_policy::PolicyApplicationType::Access => {
                    access_policy_ids.push(applied_policy.policy_id.inner())
                }
                applied_policy::PolicyApplicationType::Management => {
                    management_policy_ids.push(applied_policy.policy_id.inner())
                }
            }
        }

        SecretEntry {
            key: metadata.key,
            cipher,
            path: metadata.path,
            access_policy_ids,
            management_policy_ids,
            deleted: false,
            updated_path: None,
            updated_cipher: None,
            updated_access_policy_ids: None,
            updated_management_policy_ids: None,
        }
    }
}

pub(crate) struct Path {
    pub path: String,
}

impl From<path::Model> for Path {
    fn from(value: path::Model) -> Self {
        Self { path: value.path }
    }
}

#[cfg_attr(test, automock)]
#[async_trait]
pub(crate) trait SecretService {
    async fn list(&self, transaction: &DatabaseTransaction, path_prefix: &str) -> Result<Vec<SecretEntry>>;

    async fn get(&self, transaction: &DatabaseTransaction, secret_identifier: &str) -> Result<SecretEntry>;

    async fn get_paths(&self, transaction: &DatabaseTransaction) -> Result<Vec<Path>>;

    async fn register_secret(
        &self,
        transaction: &DatabaseTransaction,
        path: String,
        key: String,
        cipher: Vec<u8>,
        access_policies: Vec<Policy>,
        management_policies: Vec<Policy>,
    ) -> Result<()>;

    async fn register_path(&self, transaction: &DatabaseTransaction, path: String) -> Result<()>;
}

lazy_static! {
    static ref IDENTIFIER_PATTERN: Regex =
        Regex::new(r"^((?:/[^/]+)*)/([^/]+)$").expect("IDENTIFIER_PATTERN should be compiled successfully");
}

fn parse_identifier(full_path: &str) -> Option<(String, String)> {
    let mut capture = IDENTIFIER_PATTERN.captures_iter(full_path);
    let (_, [path, key]) = capture.next().map(|c| c.extract())?;

    let path = if path.is_empty() { "/".to_owned() } else { path.to_owned() };

    Some((path.to_owned(), key.to_owned()))
}

fn create_identifier(path: &str, key: &str) -> String {
    if path == "/" || path.is_empty() {
        format!("/{key}")
    } else {
        format!("{path}/{key}")
    }
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
        let mut ciphers: HashMap<String, Vec<u8>> = secret_value::Entity::find()
            .filter(
                secret_value::Column::Identifier
                    .is_in(metadata.iter().map(|metadata| create_identifier(&metadata.path, &metadata.key))),
            )
            .all(transaction)
            .await?
            .into_iter()
            .map(|secret_value| (secret_value.identifier, secret_value.cipher))
            .collect();

        Ok(metadata
            .into_iter()
            .zip(applied_policies.into_iter())
            .map(|(metadata, applied_policies)| {
                let cipher = ciphers.remove(&create_identifier(&metadata.path, &metadata.key)).unwrap_or_default();

                SecretEntry::from((metadata, applied_policies, cipher))
            })
            .collect())
    }

    async fn get(&self, transaction: &DatabaseTransaction, secret_identifier: &str) -> Result<SecretEntry> {
        let (path, key) = parse_identifier(secret_identifier)
            .ok_or_else(|| Error::InvalidSecretIdentifier { entered_identifier: secret_identifier.to_owned() })?;

        let metadata = secret_metadata::Entity::find()
            .filter(secret_metadata::Column::Path.eq(path))
            .filter(secret_metadata::Column::Key.eq(key))
            .one(transaction)
            .await?
            .ok_or_else(|| Error::SecretNotExists)?;
        let applied_policies = applied_policy::Entity::find()
            .filter(applied_policy::Column::SecretMetadataId.eq(metadata.id.to_owned()))
            .all(transaction)
            .await?;
        let cipher = secret_value::Entity::find()
            .filter(secret_value::Column::Identifier.eq(create_identifier(&metadata.path, &metadata.key)))
            .one(transaction)
            .await?
            .map(|secret_value| secret_value.cipher)
            .unwrap_or_default();

        Ok(SecretEntry::from((metadata, applied_policies, cipher)))
    }

    async fn get_paths(&self, transaction: &DatabaseTransaction) -> Result<Vec<Path>> {
        let metadata = path::Entity::find().all(transaction).await?;

        Ok(metadata.into_iter().map(Path::from).collect())
    }

    async fn register_secret(
        &self,
        transaction: &DatabaseTransaction,
        path: String,
        key: String,
        cipher: Vec<u8>,
        access_policies: Vec<Policy>,
        management_policies: Vec<Policy>,
    ) -> Result<()> {
        if path::Entity::find().filter(path::Column::Path.eq(&path)).count(transaction).await? == 0 {
            return Err(Error::PathNotExists { entered_path: path });
        }

        let identifier = create_identifier(&path, &key);

        if secret_metadata::Entity::find()
            .filter(secret_metadata::Column::Path.eq(&path))
            .filter(secret_metadata::Column::Key.eq(&key))
            .count(transaction)
            .await?
            > 0
        {
            return Err(Error::IdentifierConflicted { entered_identifier: identifier });
        }

        let now = Utc::now();

        let secret_metadata_id = UlidId::new(Ulid::new());
        secret_metadata::ActiveModel {
            id: Set(secret_metadata_id.clone()),
            key: Set(key),
            path: Set(path),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(transaction)
        .await?;

        let applied_access_policies = access_policies.into_iter().map(|access_policy| applied_policy::ActiveModel {
            id: Set(UlidId::new(Ulid::new())),
            secret_metadata_id: Set(secret_metadata_id.clone()),
            r#type: Set(PolicyApplicationType::Access),
            policy_id: Set(UlidId::new(access_policy.id)),
            created_at: Set(now),
            updated_at: Set(now),
        });
        let applied_management_policies =
            management_policies.into_iter().map(|management_policy| applied_policy::ActiveModel {
                id: Set(UlidId::new(Ulid::new())),
                secret_metadata_id: Set(secret_metadata_id.clone()),
                r#type: Set(PolicyApplicationType::Management),
                policy_id: Set(UlidId::new(management_policy.id)),
                created_at: Set(now),
                updated_at: Set(now),
            });

        applied_policy::Entity::insert_many(applied_access_policies.chain(applied_management_policies))
            .exec(transaction)
            .await?;

        secret_value::ActiveModel {
            id: Set(UlidId::new(Ulid::new())),
            identifier: Set(identifier),
            cipher: Set(cipher),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(transaction)
        .await?;

        Ok(())
    }

    async fn register_path(&self, transaction: &DatabaseTransaction, path: String) -> Result<()> {
        todo!()
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("Entered identifier conflicted with existing secret")]
    IdentifierConflicted { entered_identifier: String },
    #[error("Invalid secret identifier({entered_identifier}) is entered")]
    InvalidSecretIdentifier { entered_identifier: String },
    #[error("Secret Not exists")]
    SecretNotExists,
    #[error("Path({entered_path}) is not registered")]
    PathNotExists { entered_path: String },
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
    use crate::{
        database::{applied_policy, path, secret_metadata, secret_value, UlidId},
        domain::{policy::Policy, secret::SecretEntry},
    };

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
                    r#type: applied_policy::PolicyApplicationType::Access,
                    policy_id: policy_id.to_owned(),
                    created_at: now,
                    updated_at: now,
                },
                applied_policy::Model {
                    id: applied_policy_ids[1].to_owned(),
                    secret_metadata_id: metadata_id.to_owned(),
                    r#type: applied_policy::PolicyApplicationType::Management,
                    policy_id: policy_id.to_owned(),
                    created_at: now,
                    updated_at: now,
                },
            ]])
            .append_query_results([vec![secret_value::Model {
                id: UlidId::new(Ulid::new()),
                identifier: "/test/path/TEST_KEY".to_owned(),
                cipher: vec![1, 2, 3],
                created_at: now,
                updated_at: now,
            }]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.list(&transaction, "/").await.expect("creating workspace should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(result[0].key, key);
        assert_eq!(result[0].path, path);
        assert_eq!(result[0].cipher, vec![1, 2, 3]);
        assert_eq!(result[0].access_policy_ids[0], Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap());
        assert_eq!(result[0].management_policy_ids[0], Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap());
    }

    #[tokio::test]
    async fn when_getting_secrets_is_failed_then_secret_service_returns_anyhow_err() {
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

    #[tokio::test]
    async fn when_getting_secret_data_is_successful_then_secret_service_returns_secret_ok() {
        let now = Utc::now();
        let identifier = "/test/path/TEST_KEY";
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
                    r#type: applied_policy::PolicyApplicationType::Access,
                    policy_id: policy_id.to_owned(),
                    created_at: now,
                    updated_at: now,
                },
                applied_policy::Model {
                    id: applied_policy_ids[1].to_owned(),
                    secret_metadata_id: metadata_id.to_owned(),
                    r#type: applied_policy::PolicyApplicationType::Management,
                    policy_id: policy_id.to_owned(),
                    created_at: now,
                    updated_at: now,
                },
            ]])
            .append_query_results([vec![secret_value::Model {
                id: UlidId::new(Ulid::new()),
                identifier: "/test/path/TEST_KEY".to_owned(),
                cipher: vec![1, 2, 3],
                created_at: now,
                updated_at: now,
            }]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result =
            secret_service.get(&transaction, identifier).await.expect("creating workspace should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(result.key, key);
        assert_eq!(result.path, path);
        assert_eq!(result.cipher, vec![1, 2, 3]);
        assert_eq!(result.access_policy_ids[0], Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap());
        assert_eq!(result.management_policy_ids[0], Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap());
    }

    #[tokio::test]
    async fn when_getting_secret_is_failed_then_secret_service_returns_anyhow_err() {
        let identifier = "/some/secret";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get(&transaction, identifier).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "Custom Error: some error");
    }

    #[tokio::test]
    async fn when_getting_secret_path_without_slash_then_secret_service_returns_invalid_secret_identifier_error() {
        let identifier = "just_key";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get(&transaction, identifier).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::InvalidSecretIdentifier { .. })));
    }

    #[tokio::test]
    async fn when_getting_secret_path_without_leading_slash_then_secret_service_returns_invalid_secret_identifier_error(
    ) {
        let identifier = "some/secret";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get(&transaction, identifier).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::InvalidSecretIdentifier { .. })));
    }

    #[tokio::test]
    async fn when_getting_secret_path_contains_empty_segment_then_secret_service_returns_invalid_secret_identifier_error(
    ) {
        let identifier = "/some//secret";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get(&transaction, identifier).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::InvalidSecretIdentifier { .. })));
    }

    #[tokio::test]
    async fn when_getting_not_existing_secret_then_secret_service_returns_secret_not_exists_error() {
        let identifier = "/some/secret";
        let mock_database =
            MockDatabase::new(DatabaseBackend::Postgres).append_query_results([Vec::<secret_metadata::Model>::new()]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get(&transaction, identifier).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::SecretNotExists { .. })));
    }

    #[tokio::test]
    async fn when_getting_paths_from_database_is_successful_then_secret_service_returns_paths_ok() {
        let now = Utc::now();
        let path_id = UlidId::new(Ulid::from_str("01JACYVTYB4F2PEBFRG1BB7BKP").unwrap());
        let path = "/test/path";

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres).append_query_results([vec![path::Model {
            id: path_id.to_owned(),
            path: path.to_owned(),
            created_at: now,
            updated_at: now,
        }]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get_paths(&transaction).await.expect("creating workspace should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(result[0].path, path);
    }

    #[tokio::test]
    async fn when_getting_paths_from_database_is_failed_then_secret_service_returns_anyhow_err() {
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get_paths(&transaction).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "Custom Error: some error");
    }

    #[tokio::test]
    async fn when_registering_secret_is_successful_then_secret_service_returns_unit_ok() {
        let now = Utc::now();
        let path = "/test/path";
        let key = "TEST_KEY";
        let access_policies = vec![Policy {
            id: Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap(),
            name: "test policy".to_owned(),
            expression: "(\"role=FRONTEND\")".to_owned(),
        }];
        let management_policies = vec![Policy {
            id: Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap(),
            name: "test policy".to_owned(),
            expression: "(\"role=FRONTEND\")".to_owned(),
        }];

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[maplit::btreemap! {
                "num_items" => sea_orm::Value::BigInt(Some(1))
            }]])
            .append_query_results([[maplit::btreemap! {
                "num_items" => sea_orm::Value::BigInt(Some(0))
            }]])
            .append_query_results([[secret_metadata::Model {
                id: UlidId::new(Ulid::new()),
                key: key.to_owned(),
                path: path.to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([vec![
                applied_policy::Model {
                    id: UlidId::new(Ulid::new()),
                    secret_metadata_id: UlidId::new(Ulid::new()),
                    r#type: applied_policy::PolicyApplicationType::Access,
                    policy_id: UlidId::new(Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap()),
                    created_at: now,
                    updated_at: now,
                },
                applied_policy::Model {
                    id: UlidId::new(Ulid::new()),
                    secret_metadata_id: UlidId::new(Ulid::new()),
                    r#type: applied_policy::PolicyApplicationType::Management,
                    policy_id: UlidId::new(Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap()),
                    created_at: now,
                    updated_at: now,
                },
            ]])
            .append_query_results([vec![secret_value::Model {
                id: UlidId::new(Ulid::new()),
                identifier: "/test/path/TEST_KEY".to_owned(),
                cipher: vec![1, 2, 3],
                created_at: now,
                updated_at: now,
            }]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        secret_service
            .register_secret(
                &transaction,
                path.to_owned(),
                key.to_owned(),
                vec![1, 2, 3],
                access_policies,
                management_policies,
            )
            .await
            .expect("creating workspace should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");
    }

    #[tokio::test]
    async fn when_registering_secret_with_not_existing_path_then_secret_service_returns_path_not_exists_err() {
        let path = "/test/path";
        let key = "TEST_KEY";
        let access_policies = vec![Policy {
            id: Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap(),
            name: "test policy".to_owned(),
            expression: "(\"role=FRONTEND\")".to_owned(),
        }];
        let management_policies = vec![Policy {
            id: Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap(),
            name: "test policy".to_owned(),
            expression: "(\"role=FRONTEND\")".to_owned(),
        }];

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres).append_query_results([[maplit::btreemap! {
            "num_items" => sea_orm::Value::BigInt(Some(0))
        }]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service
            .register_secret(
                &transaction,
                path.to_owned(),
                key.to_owned(),
                vec![],
                access_policies,
                management_policies,
            )
            .await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::PathNotExists { .. })));
    }

    #[tokio::test]
    async fn when_registering_secret_with_already_used_key_then_secret_service_returns_identifier_conflicted_err() {
        let path = "/test/path";
        let key = "TEST_KEY";
        let access_policies = vec![Policy {
            id: Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap(),
            name: "test policy".to_owned(),
            expression: "(\"role=FRONTEND\")".to_owned(),
        }];
        let management_policies = vec![Policy {
            id: Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap(),
            name: "test policy".to_owned(),
            expression: "(\"role=FRONTEND\")".to_owned(),
        }];

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[maplit::btreemap! {
                "num_items" => sea_orm::Value::BigInt(Some(1))
            }]])
            .append_query_results([[maplit::btreemap! {
                "num_items" => sea_orm::Value::BigInt(Some(1))
            }]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service
            .register_secret(
                &transaction,
                path.to_owned(),
                key.to_owned(),
                vec![],
                access_policies,
                management_policies,
            )
            .await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::IdentifierConflicted { .. })));
    }

    #[tokio::test]
    async fn when_delete_secret_entry_then_delete_property_turns_into_true() {
        let mut secret_entry = SecretEntry {
            key: "TEST_KEY".to_owned(),
            path: "/test/path".to_owned(),
            cipher: vec![1, 2, 3],
            access_policy_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            management_policy_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            deleted: false,
            updated_path: None,
            updated_cipher: None,
            updated_access_policy_ids: None,
            updated_management_policy_ids: None,
        };

        secret_entry.delete();

        assert!(secret_entry.deleted)
    }

    #[tokio::test]
    async fn when_update_path_of_secret_entry_then_write_new_path_to_field() {
        let mut secret_entry = SecretEntry {
            key: "TEST_KEY".to_owned(),
            path: "/test/path".to_owned(),
            cipher: vec![1, 2, 3],
            access_policy_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            management_policy_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            deleted: false,
            updated_path: None,
            updated_cipher: None,
            updated_access_policy_ids: None,
            updated_management_policy_ids: None,
        };

        secret_entry.update_path("/test/path/2".to_owned());

        assert_eq!(secret_entry.updated_path.as_deref(), Some("/test/path/2"));
    }

    #[tokio::test]
    async fn when_update_cipher_of_secret_entry_then_write_new_cipher_to_field() {
        let mut secret_entry = SecretEntry {
            key: "TEST_KEY".to_owned(),
            path: "/test/path".to_owned(),
            cipher: vec![1, 2, 3],
            access_policy_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            management_policy_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            deleted: false,
            updated_path: None,
            updated_cipher: None,
            updated_access_policy_ids: None,
            updated_management_policy_ids: None,
        };

        secret_entry.update_cipher(vec![4, 5, 6]);

        assert_eq!(secret_entry.updated_cipher, Some(vec![4, 5, 6]));
    }

    #[tokio::test]
    async fn when_update_access_policies_of_secret_entry_then_write_new_access_policy_ids_to_field() {
        let mut secret_entry = SecretEntry {
            key: "TEST_KEY".to_owned(),
            path: "/test/path".to_owned(),
            cipher: vec![1, 2, 3],
            access_policy_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            management_policy_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            deleted: false,
            updated_path: None,
            updated_cipher: None,
            updated_access_policy_ids: None,
            updated_management_policy_ids: None,
        };

        secret_entry.update_access_policies(vec![Policy {
            id: Ulid::from_str("01JBS3ATPE50HBBFENKJDDBM08").unwrap(),
            name: "test policy2".to_owned(),
            expression: "(\"role=BACKEND\")".to_owned(),
        }]);

        assert_eq!(
            secret_entry.updated_access_policy_ids,
            Some(vec![Ulid::from_str("01JBS3ATPE50HBBFENKJDDBM08").unwrap()])
        );
    }

    #[tokio::test]
    async fn when_update_management_policies_of_secret_entry_then_write_new_access_policy_ids_to_field() {
        let mut secret_entry = SecretEntry {
            key: "TEST_KEY".to_owned(),
            path: "/test/path".to_owned(),
            cipher: vec![1, 2, 3],
            access_policy_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            management_policy_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            deleted: false,
            updated_path: None,
            updated_cipher: None,
            updated_access_policy_ids: None,
            updated_management_policy_ids: None,
        };

        secret_entry.update_management_policies(vec![Policy {
            id: Ulid::from_str("01JBS3ATPE50HBBFENKJDDBM08").unwrap(),
            name: "test policy2".to_owned(),
            expression: "(\"role=BACKEND\")".to_owned(),
        }]);

        assert_eq!(
            secret_entry.updated_management_policy_ids,
            Some(vec![Ulid::from_str("01JBS3ATPE50HBBFENKJDDBM08").unwrap()])
        );
    }
}
