use crate::database::policy;
use async_trait::async_trait;
use sea_orm::{DatabaseTransaction, EntityTrait};
use ulid::Ulid;

pub(crate) struct Policy {
    pub id: Ulid,
    pub name: String,
    pub expression: String,
}

impl From<policy::Model> for Policy {
    fn from(value: policy::Model) -> Self {
        Self { id: value.id.inner(), name: value.name, expression: value.expression }
    }
}

#[async_trait]
pub(crate) trait PolicyService {
    async fn list(&self, transaction: &DatabaseTransaction) -> Result<Vec<Policy>>;
}

pub(crate) struct PostgresPolicyService {}

#[async_trait]
impl PolicyService for PostgresPolicyService {
    async fn list(&self, transaction: &DatabaseTransaction) -> Result<Vec<Policy>> {
        let policies = policy::Entity::find().all(transaction).await?;

        Ok(policies.into_iter().map(Policy::from).collect())
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<sea_orm::DbErr> for Error {
    fn from(value: sea_orm::DbErr) -> Self {
        Error::Anyhow(value.into())
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test {
    use std::{str::FromStr, sync::Arc};

    use chrono::Utc;
    use sea_orm::{DatabaseBackend, DbErr, MockDatabase, TransactionTrait};
    use ulid::Ulid;

    use super::{Error, PolicyService, PostgresPolicyService};
    use crate::database::{policy, UlidId};

    #[tokio::test]
    async fn when_getting_policy_data_is_successful_then_secret_service_returns_policies_ok() {
        let now = Utc::now();
        let policy_id = UlidId::new(Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap());
        let policy_name = "test policy";
        let expression = "(\"role=FRONTEND\")";

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres).append_query_results([vec![policy::Model {
            id: policy_id.to_owned(),
            name: policy_name.to_owned(),
            expression: expression.to_owned(),
            created_at: now,
            updated_at: now,
        }]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let policy_service = PostgresPolicyService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = policy_service.list(&transaction).await.expect("creating workspace should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(result[0].id, Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap());
        assert_eq!(result[0].name, policy_name);
        assert_eq!(result[0].expression, expression);
    }

    #[tokio::test]
    async fn when_getting_secrets_is_failed_then_secret_service_returns_anyhow_err() {
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let policy_service = PostgresPolicyService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = policy_service.list(&transaction).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "Custom Error: some error");
    }

    #[tokio::test]
    async fn when_managed_policy_is_empty_then_secret_service_returns_empty_ok() {
        let mock_database =
            MockDatabase::new(DatabaseBackend::Postgres).append_query_results([Vec::<policy::Model>::new()]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let policy_service = PostgresPolicyService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = policy_service.list(&transaction).await.expect("creating workspace should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(result.is_empty())
    }
}
