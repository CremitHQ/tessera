use std::sync::Arc;

use async_trait::async_trait;
use nebula_token::claim::NebulaClaim;
use sea_orm::{DatabaseConnection, DatabaseTransaction};
use ulid::Ulid;

use crate::{
    database::{Persistable, WorkspaceScopedTransaction},
    domain::{
        self,
        policy::{AccessCondition, PolicyService},
        secret::{SecretEntry, SecretService},
    },
};

#[async_trait]
pub(crate) trait SecretUseCase {
    async fn list(&self, path: &str, claim: &NebulaClaim) -> Result<Vec<SecretData>>;
    async fn get(&self, secret_identifier: &str, claim: &NebulaClaim) -> Result<SecretData>;
    async fn register(&self, cmd: SecretRegisterCommand, claim: &NebulaClaim) -> Result<()>;
    async fn delete(&self, secret_identifier: &str, claim: &NebulaClaim) -> Result<()>;
    async fn update(&self, secret_identifier: &str, update: SecretUpdate, claim: &NebulaClaim) -> Result<()>;
}

pub(crate) struct SecretUseCaseImpl {
    workspace_name: String,
    database_connection: Arc<DatabaseConnection>,
    secret_service: Arc<dyn SecretService + Sync + Send>,
    policy_service: Arc<dyn PolicyService + Sync + Send>,
}

impl SecretUseCaseImpl {
    pub fn new(
        workspace_name: String,
        database_connection: Arc<DatabaseConnection>,
        secret_service: Arc<dyn SecretService + Sync + Send>,
        policy_service: Arc<dyn PolicyService + Sync + Send>,
    ) -> Self {
        Self { workspace_name, database_connection, secret_service, policy_service }
    }

    async fn get_policies(&self, transaction: &DatabaseTransaction, ids: Vec<Ulid>) -> Result<Vec<AccessCondition>> {
        let mut policies = vec![];

        for id in ids {
            policies.push(
                self.policy_service
                    .get(transaction, &id)
                    .await?
                    .ok_or_else(|| Error::PolicyNotExists { entered_policy_id: id })?,
            );
        }

        Ok(policies)
    }
}

#[async_trait]
impl SecretUseCase for SecretUseCaseImpl {
    async fn list(&self, path: &str, claim: &NebulaClaim) -> Result<Vec<SecretData>> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;
        let secrets = self.secret_service.list_secret(&transaction, path, claim).await?;
        transaction.commit().await?;

        Ok(secrets.into_iter().map(SecretData::from).collect())
    }

    async fn get(&self, secret_identifier: &str, claim: &NebulaClaim) -> Result<SecretData> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;
        let secret = self.secret_service.get_secret(&transaction, secret_identifier, claim).await?;
        transaction.commit().await?;

        Ok(secret.into())
    }

    async fn register(&self, cmd: SecretRegisterCommand, claim: &NebulaClaim) -> Result<()> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;

        let access_conditions = self.get_policies(&transaction, cmd.access_condition_ids).await?;

        self.secret_service
            .register_secret(&transaction, cmd.path, cmd.key, cmd.cipher, access_conditions, claim)
            .await?;

        transaction.commit().await?;

        Ok(())
    }

    async fn delete(&self, secret_identifier: &str, claim: &NebulaClaim) -> Result<()> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;
        let mut secret = self.secret_service.get_secret(&transaction, secret_identifier, claim).await?;
        secret.delete(&transaction, claim).await?;
        secret.persist(&transaction).await?;
        transaction.commit().await?;

        Ok(())
    }

    async fn update(&self, secret_identifier: &str, update: SecretUpdate, claim: &NebulaClaim) -> Result<()> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;

        let mut secret = self.secret_service.get_secret(&transaction, secret_identifier, claim).await?;

        if let Some(updated_access_policy_ids) = update.access_condition_ids {
            let updated_access_policies = self.get_policies(&transaction, updated_access_policy_ids).await?;
            secret.update_access_conditions(&transaction, updated_access_policies, claim).await?;
        }
        if let Some(updated_path) = update.path {
            secret.update_path(&transaction, updated_path, claim).await?;
        }
        if let Some(updated_cipher) = update.cipher {
            secret.update_cipher(&transaction, updated_cipher, claim).await?;
        }

        secret.persist(&transaction).await?;
        transaction.commit().await?;

        Ok(())
    }
}

pub(crate) struct SecretData {
    pub key: String,
    pub path: String,
    pub cipher: Vec<u8>,
    pub access_condition_ids: Vec<Ulid>,
}

pub(crate) struct SecretUpdate {
    pub path: Option<String>,
    pub cipher: Option<Vec<u8>>,
    pub access_condition_ids: Option<Vec<Ulid>>,
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("Entered identifier conflicted with existing secret")]
    IdentifierConflicted { entered_identifier: String },
    #[error("Invalid secret identifier({entered_identifier}) is entered")]
    InvalidSecretIdentifier { entered_identifier: String },
    #[error("Secret is not exists")]
    SecretNotExists,
    #[error("Policy({entered_policy_id}) is not exists")]
    PolicyNotExists { entered_policy_id: Ulid },
    #[error("Path({entered_path}) is not registered")]
    PathNotExists { entered_path: String },
    #[error("Access denied")]
    AccessDenied,
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<sea_orm::DbErr> for Error {
    fn from(value: sea_orm::DbErr) -> Self {
        Self::Anyhow(value.into())
    }
}

impl From<domain::secret::Error> for Error {
    fn from(value: domain::secret::Error) -> Self {
        match value {
            domain::secret::Error::Anyhow(e) => Self::Anyhow(e),
            domain::secret::Error::InvalidSecretIdentifier { entered_identifier } => {
                Error::InvalidSecretIdentifier { entered_identifier }
            }
            domain::secret::Error::SecretNotExists => Error::SecretNotExists,
            domain::secret::Error::IdentifierConflicted { entered_identifier } => {
                Error::IdentifierConflicted { entered_identifier }
            }
            domain::secret::Error::InvalidPath { .. } => Self::Anyhow(value.into()),
            domain::secret::Error::ParentPathNotExists { entered_path } => Self::PathNotExists { entered_path },
            domain::secret::Error::PathDuplicated { .. } => Self::Anyhow(value.into()),
            domain::secret::Error::PathIsInUse { .. } => Self::Anyhow(value.into()),
            domain::secret::Error::InvalidPathPolicy => Self::Anyhow(value.into()),
            domain::secret::Error::AccessDenied => Self::AccessDenied,
            domain::secret::Error::InvalidSecretPolicy => Self::Anyhow(value.into()),
        }
    }
}

impl From<domain::policy::Error> for Error {
    fn from(value: domain::policy::Error) -> Self {
        match value {
            domain::policy::Error::Anyhow(e) => Self::Anyhow(e),
            domain::policy::Error::InvalidExpression(_) => Self::Anyhow(value.into()),
            domain::policy::Error::PolicyNameDuplicated { .. } => Self::Anyhow(value.into()),
        }
    }
}

impl From<SecretEntry> for SecretData {
    fn from(value: SecretEntry) -> Self {
        Self {
            key: value.key,
            path: value.path,
            cipher: value.cipher,
            access_condition_ids: value.access_condition_ids,
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) struct SecretRegisterCommand {
    pub path: String,
    pub key: String,
    pub cipher: Vec<u8>,
    pub access_condition_ids: Vec<Ulid>,
}

#[cfg(test)]
mod test {
    use std::{collections::HashMap, str::FromStr, sync::Arc};

    use nebula_token::claim::{NebulaClaim, Role};
    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    use ulid::Ulid;

    use crate::{
        application::secret::SecretRegisterCommand,
        domain::{
            policy::{AccessCondition, MockPolicyService},
            secret::{MockSecretService, SecretEntry},
        },
    };

    use super::{Error, SecretUseCase, SecretUseCaseImpl};

    #[tokio::test]
    async fn when_getting_secret_data_is_successful_then_secret_usecase_returns_secrets_ok() {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let key = "TEST_KEY";
        let path = "/test/path";
        let applied_policy_ids = [
            Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap(),
            Ulid::from_str("01JACZ1FG1RYABQW2KB6YSEZ84").unwrap(),
        ];

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_secret_service = MockSecretService::new();
        mock_secret_service.expect_list_secret().withf(|_, path, _| path == "/").times(1).returning(move |_, _, _| {
            Ok(vec![SecretEntry::new(
                key.to_owned(),
                path.to_owned(),
                vec![4, 5, 6],
                vec![applied_policy_ids[0].to_owned()],
            )])
        });
        let mock_policy_service = MockPolicyService::new();

        let secret_usecase = SecretUseCaseImpl::new(
            "testworkspace".to_owned(),
            mock_connection,
            Arc::new(mock_secret_service),
            Arc::new(mock_policy_service),
        );

        let result = secret_usecase.list("/", &claim).await.expect("creating workspace should be successful");

        assert_eq!(result[0].key, key);
        assert_eq!(result[0].path, path);
        assert_eq!(result[0].cipher, vec![4, 5, 6]);
        assert_eq!(result[0].access_condition_ids[0], applied_policy_ids[0]);
    }

    #[tokio::test]
    async fn when_getting_secret_is_failed_then_secret_usecase_returns_anyhow_err() {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_secret_service = MockSecretService::new();
        mock_secret_service
            .expect_list_secret()
            .withf(|_, path, _| path == "/")
            .times(1)
            .returning(move |_, _, _| Err(crate::domain::secret::Error::Anyhow(anyhow::anyhow!("some error"))));
        let mock_policy_service = MockPolicyService::new();

        let secret_usecase = SecretUseCaseImpl::new(
            "testworkspace".to_owned(),
            mock_connection,
            Arc::new(mock_secret_service),
            Arc::new(mock_policy_service),
        );

        let result = secret_usecase.list("/", &claim).await;

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "some error");
    }

    #[tokio::test]
    async fn when_getting_single_secret_data_is_successful_then_secret_usecase_returns_secret_ok() {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let identifier = "/test/path/TEST_KEY";
        let key = "TEST_KEY";
        let path = "/test/path";
        let applied_policy_ids = [
            Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap(),
            Ulid::from_str("01JACZ1FG1RYABQW2KB6YSEZ84").unwrap(),
        ];

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_secret_service = MockSecretService::new();
        mock_secret_service.expect_get_secret().withf(|_, identifier, _| identifier == identifier).times(1).returning(
            move |_, _, _| {
                Ok(SecretEntry::new(
                    key.to_owned(),
                    path.to_owned(),
                    vec![4, 5, 6],
                    vec![applied_policy_ids[0].to_owned()],
                ))
            },
        );
        let mock_policy_service = MockPolicyService::new();

        let secret_usecase = SecretUseCaseImpl::new(
            "testworkspace".to_owned(),
            mock_connection,
            Arc::new(mock_secret_service),
            Arc::new(mock_policy_service),
        );

        let result = secret_usecase.get(identifier, &claim).await.expect("creating workspace should be successful");

        assert_eq!(result.key, key);
        assert_eq!(result.path, path);
        assert_eq!(result.cipher, vec![4, 5, 6]);
        assert_eq!(result.access_condition_ids[0], applied_policy_ids[0]);
    }

    #[tokio::test]
    async fn when_registering_secret_is_successful_then_secret_usecase_returns_unit_ok() {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let key = "TEST_KEY";
        let path = "/test/path";
        let access_condition_ids = vec![Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap()];

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_secret_service = MockSecretService::new();
        mock_secret_service.expect_register_secret().times(1).returning(move |_, _, _, _, _, _| Ok(()));
        let mut mock_policy_service = MockPolicyService::new();
        mock_policy_service.expect_get().times(1).returning(move |_, _| {
            Ok(Some(AccessCondition::new(
                Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap(),
                "test policy".to_owned(),
                "(\"role=FRONTEND\")".to_owned(),
            )))
        });

        let secret_usecase = SecretUseCaseImpl::new(
            "testworkspace".to_owned(),
            mock_connection,
            Arc::new(mock_secret_service),
            Arc::new(mock_policy_service),
        );

        secret_usecase
            .register(
                SecretRegisterCommand {
                    path: path.to_owned(),
                    key: key.to_owned(),
                    cipher: vec![4, 5, 6],
                    access_condition_ids,
                },
                &claim,
            )
            .await
            .expect("creating workspace should be successful");
    }

    #[tokio::test]
    async fn when_registering_secret_with_not_existing_policy_then_secret_usecase_returns_policy_not_exists_err() {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let key = "TEST_KEY";
        let path = "/test/path";
        let access_condition_ids = vec![Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap()];

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mock_secret_service = MockSecretService::new();
        let mut mock_policy_service = MockPolicyService::new();
        mock_policy_service.expect_get().times(1).returning(move |_, _| Ok(None));

        let secret_usecase = SecretUseCaseImpl::new(
            "testworkspace".to_owned(),
            mock_connection,
            Arc::new(mock_secret_service),
            Arc::new(mock_policy_service),
        );

        let result = secret_usecase
            .register(
                SecretRegisterCommand {
                    path: path.to_owned(),
                    key: key.to_owned(),
                    cipher: vec![],
                    access_condition_ids,
                },
                &claim,
            )
            .await;

        assert!(matches!(result, Err(Error::PolicyNotExists { .. })))
    }
}
