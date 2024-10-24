use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, DatabaseTransaction};
use ulid::Ulid;

use crate::{
    database::OrganizationScopedTransaction,
    domain::{
        self,
        policy::{Policy, PolicyService},
        secret::{SecretEntry, SecretService},
    },
};

#[async_trait]
pub(crate) trait SecretUseCase {
    async fn list(&self, path: &str) -> Result<Vec<SecretData>>;
    async fn get(&self, secret_identifier: &str) -> Result<SecretData>;
    async fn register(&self, cmd: SecretRegisterCommand) -> Result<()>;
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

    async fn get_policies(&self, transaction: &DatabaseTransaction, ids: Vec<Ulid>) -> Result<Vec<Policy>> {
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
    async fn list(&self, path: &str) -> Result<Vec<SecretData>> {
        let transaction = self.database_connection.begin_with_organization_scope(&self.workspace_name).await?;
        let secrets = self.secret_service.list(&transaction, path).await?;
        transaction.commit().await?;

        Ok(secrets.into_iter().map(SecretData::from).collect())
    }

    async fn get(&self, secret_identifier: &str) -> Result<SecretData> {
        let transaction = self.database_connection.begin_with_organization_scope(&self.workspace_name).await?;
        let secret = self.secret_service.get(&transaction, secret_identifier).await?;
        transaction.commit().await?;

        Ok(secret.into())
    }

    async fn register(&self, cmd: SecretRegisterCommand) -> Result<()> {
        let transaction = self.database_connection.begin_with_organization_scope(&self.workspace_name).await?;

        let reader_policies = self.get_policies(&transaction, cmd.reader_policy_ids).await?;
        let writer_policies = self.get_policies(&transaction, cmd.writer_policy_ids).await?;

        self.secret_service.register(&transaction, cmd.path, cmd.key, reader_policies, writer_policies).await?;

        transaction.commit().await?;

        Ok(())
    }
}

pub(crate) struct SecretData {
    pub key: String,
    pub path: String,
    pub reader_policy_ids: Vec<Ulid>,
    pub writer_policy_ids: Vec<Ulid>,
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
            domain::secret::Error::PathNotExists { entered_path } => Error::PathNotExists { entered_path },
            domain::secret::Error::IdentifierConflicted { entered_identifier } => {
                Error::IdentifierConflicted { entered_identifier }
            }
        }
    }
}

impl From<domain::policy::Error> for Error {
    fn from(value: domain::policy::Error) -> Self {
        match value {
            domain::policy::Error::Anyhow(e) => Self::Anyhow(e),
        }
    }
}

impl From<SecretEntry> for SecretData {
    fn from(value: SecretEntry) -> Self {
        Self {
            key: value.key,
            path: value.path,
            reader_policy_ids: value.reader_policy_ids,
            writer_policy_ids: value.writer_policy_ids,
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

pub(crate) struct SecretRegisterCommand {
    pub path: String,
    pub key: String,
    pub reader_policy_ids: Vec<Ulid>,
    pub writer_policy_ids: Vec<Ulid>,
}

#[cfg(test)]
mod test {
    use std::{str::FromStr, sync::Arc};

    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    use ulid::Ulid;

    use crate::{
        application::secret::SecretRegisterCommand,
        domain::{
            policy::{MockPolicyService, Policy},
            secret::{MockSecretService, SecretEntry},
        },
    };

    use super::{Error, SecretUseCase, SecretUseCaseImpl};

    #[tokio::test]
    async fn when_getting_secret_data_is_successful_then_secret_usecase_returns_secrets_ok() {
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
        mock_secret_service.expect_list().withf(|_, path| path == "/").times(1).returning(move |_, _| {
            Ok(vec![SecretEntry {
                key: key.to_owned(),
                path: path.to_owned(),
                reader_policy_ids: vec![applied_policy_ids[0].to_owned()],
                writer_policy_ids: vec![applied_policy_ids[1].to_owned()],
            }])
        });
        let mock_policy_service = MockPolicyService::new();

        let secret_usecase = SecretUseCaseImpl::new(
            "test_workspace".to_owned(),
            mock_connection,
            Arc::new(mock_secret_service),
            Arc::new(mock_policy_service),
        );

        let result = secret_usecase.list("/").await.expect("creating workspace should be successful");

        assert_eq!(result[0].key, key);
        assert_eq!(result[0].path, path);
        assert_eq!(result[0].reader_policy_ids[0], applied_policy_ids[0]);
        assert_eq!(result[0].writer_policy_ids[0], applied_policy_ids[1]);
    }

    #[tokio::test]
    async fn when_getting_secret_is_failed_then_secret_usecase_returns_anyhow_err() {
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_secret_service = MockSecretService::new();
        mock_secret_service
            .expect_list()
            .withf(|_, path| path == "/")
            .times(1)
            .returning(move |_, _| Err(crate::domain::secret::Error::Anyhow(anyhow::anyhow!("some error"))));
        let mock_policy_service = MockPolicyService::new();

        let secret_usecase = SecretUseCaseImpl::new(
            "test_workspace".to_owned(),
            mock_connection,
            Arc::new(mock_secret_service),
            Arc::new(mock_policy_service),
        );

        let result = secret_usecase.list("/").await;

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "some error");
    }

    #[tokio::test]
    async fn when_getting_single_secret_data_is_successful_then_secret_usecase_returns_secret_ok() {
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
        mock_secret_service.expect_get().withf(|_, identifier| identifier == identifier).times(1).returning(
            move |_, _| {
                Ok(SecretEntry {
                    key: key.to_owned(),
                    path: path.to_owned(),
                    reader_policy_ids: vec![applied_policy_ids[0].to_owned()],
                    writer_policy_ids: vec![applied_policy_ids[1].to_owned()],
                })
            },
        );
        let mock_policy_service = MockPolicyService::new();

        let secret_usecase = SecretUseCaseImpl::new(
            "test_workspace".to_owned(),
            mock_connection,
            Arc::new(mock_secret_service),
            Arc::new(mock_policy_service),
        );

        let result = secret_usecase.get(identifier).await.expect("creating workspace should be successful");

        assert_eq!(result.key, key);
        assert_eq!(result.path, path);
        assert_eq!(result.reader_policy_ids[0], applied_policy_ids[0]);
        assert_eq!(result.writer_policy_ids[0], applied_policy_ids[1]);
    }

    #[tokio::test]
    async fn when_registering_secret_is_successful_then_secret_usecase_returns_unit_ok() {
        let key = "TEST_KEY";
        let path = "/test/path";
        let reader_policy_ids = vec![Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap()];
        let writer_policy_ids = vec![Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap()];

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_secret_service = MockSecretService::new();
        mock_secret_service.expect_register().times(1).returning(move |_, _, _, _, _| Ok(()));
        let mut mock_policy_service = MockPolicyService::new();
        mock_policy_service.expect_get().times(2).returning(move |_, _| {
            Ok(Some(Policy {
                id: Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap(),
                name: "test policy".to_owned(),
                expression: "(\"role=FRONTEND\")".to_owned(),
            }))
        });

        let secret_usecase = SecretUseCaseImpl::new(
            "test_workspace".to_owned(),
            mock_connection,
            Arc::new(mock_secret_service),
            Arc::new(mock_policy_service),
        );

        let result = secret_usecase
            .register(SecretRegisterCommand {
                path: path.to_owned(),
                key: key.to_owned(),
                reader_policy_ids,
                writer_policy_ids,
            })
            .await
            .expect("creating workspace should be successful");

        assert_eq!(result, ())
    }

    #[tokio::test]
    async fn when_registering_secret_with_not_existing_policy_then_secret_usecase_returns_policy_not_exists_err() {
        let key = "TEST_KEY";
        let path = "/test/path";
        let reader_policy_ids = vec![Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap()];
        let writer_policy_ids = vec![Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap()];

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mock_secret_service = MockSecretService::new();
        let mut mock_policy_service = MockPolicyService::new();
        mock_policy_service.expect_get().times(1).returning(move |_, _| Ok(None));

        let secret_usecase = SecretUseCaseImpl::new(
            "test_workspace".to_owned(),
            mock_connection,
            Arc::new(mock_secret_service),
            Arc::new(mock_policy_service),
        );

        let result = secret_usecase
            .register(SecretRegisterCommand {
                path: path.to_owned(),
                key: key.to_owned(),
                reader_policy_ids,
                writer_policy_ids,
            })
            .await;

        assert!(matches!(result, Err(Error::PolicyNotExists { .. })))
    }
}
