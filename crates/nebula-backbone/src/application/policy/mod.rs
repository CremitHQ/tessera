use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::DatabaseConnection;
use ulid::Ulid;

use crate::{
    database::{Persistable, WorkspaceScopedTransaction},
    domain::{self, policy::PolicyService},
};

#[async_trait]
pub(crate) trait PolicyUseCase {
    async fn get_all(&self) -> Result<Vec<PolicyData>>;
    async fn get_policy(&self, policy_id: Ulid) -> Result<PolicyData>;
    async fn register(&self, name: &str, expression: &str) -> Result<()>;
    async fn update(&self, policy_id: &Ulid, new_name: Option<&str>, new_expression: Option<&str>) -> Result<()>;
    async fn delete(&self, policy_id: &Ulid) -> Result<()>;
}

pub(crate) struct PolicyUseCaseImpl {
    workspace_name: String,
    database_connection: Arc<DatabaseConnection>,
    policy_service: Arc<dyn PolicyService + Sync + Send>,
}

impl PolicyUseCaseImpl {
    pub fn new(
        workspace_name: String,
        database_connection: Arc<DatabaseConnection>,
        policy_service: Arc<dyn PolicyService + Sync + Send>,
    ) -> Self {
        Self { workspace_name, database_connection, policy_service }
    }
}

#[async_trait]
impl PolicyUseCase for PolicyUseCaseImpl {
    async fn get_all(&self) -> Result<Vec<PolicyData>> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;

        let policies = self.policy_service.list(&transaction).await?;

        transaction.commit().await?;

        Ok(policies.into_iter().map(PolicyData::from).collect())
    }

    async fn get_policy(&self, policy_id: Ulid) -> Result<PolicyData> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;

        let policy = self
            .policy_service
            .get(&transaction, &policy_id)
            .await?
            .ok_or_else(|| Error::PolicyNotExists { entered_policy_id: policy_id })?;

        transaction.commit().await?;

        Ok(policy.into())
    }

    async fn register(&self, name: &str, expression: &str) -> Result<()> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;

        self.policy_service.register(&transaction, name, expression).await?;

        transaction.commit().await?;

        Ok(())
    }

    async fn update(&self, policy_id: &Ulid, new_name: Option<&str>, new_expression: Option<&str>) -> Result<()> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;

        let mut policy = self
            .policy_service
            .get(&transaction, policy_id)
            .await?
            .ok_or_else(|| Error::PolicyNotExists { entered_policy_id: policy_id.to_owned() })?;

        if let Some(new_name) = new_name {
            policy.update_name(new_name);
        }
        if let Some(new_expression) = new_expression {
            policy.update_expression(new_expression)?;
        }

        policy.persist(&transaction).await?;

        transaction.commit().await?;

        Ok(())
    }

    async fn delete(&self, policy_id: &Ulid) -> Result<()> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;

        let mut policy = self
            .policy_service
            .get(&transaction, policy_id)
            .await?
            .ok_or_else(|| Error::PolicyNotExists { entered_policy_id: policy_id.to_owned() })?;
        policy.delete();
        policy.persist(&transaction).await?;

        transaction.commit().await?;

        Ok(())
    }
}

pub(crate) struct PolicyData {
    pub id: Ulid,
    pub name: String,
    pub expression: String,
}

impl From<domain::policy::AccessCondition> for PolicyData {
    fn from(value: domain::policy::AccessCondition) -> Self {
        Self { id: value.id, name: value.name, expression: value.expression }
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("Entered policy name({entered_policy_name}) is already registered.")]
    PolicyNameDuplicated { entered_policy_name: String },
    #[error(transparent)]
    InvalidExpression(#[from] nebula_policy::error::PolicyParserError),
    #[error("Policy({entered_policy_id} is not exists)")]
    PolicyNotExists { entered_policy_id: Ulid },
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<sea_orm::DbErr> for Error {
    fn from(value: sea_orm::DbErr) -> Self {
        Error::Anyhow(value.into())
    }
}

impl From<domain::policy::Error> for Error {
    fn from(value: domain::policy::Error) -> Self {
        match value {
            domain::policy::Error::Anyhow(e) => Error::Anyhow(e),
            domain::policy::Error::InvalidExpression(e) => Error::InvalidExpression(e),
            domain::policy::Error::PolicyNameDuplicated { entered_policy_name } => {
                Error::PolicyNameDuplicated { entered_policy_name }
            }
        }
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test {
    use std::{str::FromStr, sync::Arc};

    use sea_orm::{DatabaseBackend, MockDatabase, MockExecResult};
    use ulid::Ulid;

    use crate::domain::policy::{AccessCondition, MockPolicyService};

    use super::{Error, PolicyUseCase, PolicyUseCaseImpl};

    #[tokio::test]
    async fn when_getting_policy_data_is_successful_then_policy_usecase_returns_policies_ok() {
        let policy_id = Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap();
        let policy_name = "test policy";
        let expression = "(\"role=FRONTEND\")";

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_policy_service = MockPolicyService::new();
        mock_policy_service.expect_list().withf(|_| true).times(1).returning(move |_| {
            Ok(vec![AccessCondition::new(policy_id.to_owned(), policy_name.to_owned(), expression.to_owned())])
        });

        let policy_usecase =
            PolicyUseCaseImpl::new("test_workspace".to_owned(), mock_connection, Arc::new(mock_policy_service));

        let result = policy_usecase.get_all().await.expect("creating workspace should be successful");

        assert_eq!(result[0].id, policy_id);
        assert_eq!(result[0].name, policy_name);
        assert_eq!(result[0].expression, expression);
    }

    #[tokio::test]
    async fn when_getting_secret_is_failed_then_secret_usecase_returns_anyhow_err() {
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_policy_service = MockPolicyService::new();
        mock_policy_service
            .expect_list()
            .withf(|_| true)
            .times(1)
            .returning(move |_| Err(crate::domain::policy::Error::Anyhow(anyhow::anyhow!("some error"))));
        let policy_usecase =
            PolicyUseCaseImpl::new("test_workspace".to_owned(), mock_connection, Arc::new(mock_policy_service));

        let result = policy_usecase.get_all().await;

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "some error");
    }

    #[tokio::test]
    async fn when_getting_single_policy_data_is_successful_then_policy_usecase_returns_policy_ok() {
        let policy_id = Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap();
        let policy_name = "test policy";
        let expression = "(\"role=FRONTEND\")";

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_policy_service = MockPolicyService::new();
        mock_policy_service.expect_get().times(1).returning(move |_, _| {
            Ok(Some(AccessCondition::new(policy_id.to_owned(), policy_name.to_owned(), expression.to_owned())))
        });

        let policy_usecase =
            PolicyUseCaseImpl::new("test_workspace".to_owned(), mock_connection, Arc::new(mock_policy_service));

        let result = policy_usecase.get_policy(policy_id).await.expect("getting policy data should be successful");

        assert_eq!(result.id, policy_id);
        assert_eq!(result.name, policy_name);
        assert_eq!(result.expression, expression);
    }

    #[tokio::test]
    async fn when_getting_not_existing_single_policy_data_then_policy_usecase_returns_policy_not_exists_err() {
        let policy_id = Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap();

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_policy_service = MockPolicyService::new();
        mock_policy_service.expect_get().times(1).returning(move |_, _| Ok(None));

        let policy_usecase =
            PolicyUseCaseImpl::new("test_workspace".to_owned(), mock_connection, Arc::new(mock_policy_service));

        let result = policy_usecase.get_policy(policy_id).await;

        assert!(matches!(result, Err(Error::PolicyNotExists { .. })));
    }

    #[tokio::test]
    async fn when_registering_policy_failed_with_invalid_expression_then_policy_usecase_returns_invalid_policy_err() {
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_exec_results([MockExecResult { last_insert_id: 0, rows_affected: 1 }]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let mut mock_policy_service = MockPolicyService::new();
        mock_policy_service.expect_register().times(1).returning(move |_, _, expression| {
            Err(crate::domain::policy::Error::InvalidExpression(nebula_policy::error::PolicyParserError::JsonPolicy(
                expression.to_owned(),
            )))
        });

        let policy_usecase =
            PolicyUseCaseImpl::new("test_workspace".to_owned(), mock_connection, Arc::new(mock_policy_service));

        let result = policy_usecase.register("test policy", "(\"role=FRONTEND@A\"").await;

        assert!(matches!(result, Err(Error::InvalidExpression { .. })));
    }
}
