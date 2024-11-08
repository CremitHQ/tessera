use crate::database::{policy, Persistable};
use async_trait::async_trait;
use chrono::Utc;
#[cfg(test)]
use mockall::automock;
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseTransaction, EntityTrait, PaginatorTrait, QueryFilter, Set};
use ulid::Ulid;

pub(crate) struct Policy {
    pub id: Ulid,
    pub name: String,
    pub expression: String,
    updated_name: Option<String>,
    updated_expression: Option<String>,
}

impl Policy {
    pub fn new(id: Ulid, name: String, expression: String) -> Self {
        Self { id, name, expression, updated_name: None, updated_expression: None }
    }

    pub fn update_name(&mut self, new_name: &str) {
        if self.name == new_name || self.updated_name.as_deref() == Some(new_name) {
            return;
        }

        self.updated_name = Some(new_name.to_owned());
    }

    pub fn update_expression(&mut self, new_expression: &str) -> Result<()> {
        validate_expression(new_expression)?;
        if self.expression == new_expression || self.updated_expression.as_deref() == Some(new_expression) {
            return Ok(());
        }

        self.updated_expression = Some(new_expression.to_owned());

        Ok(())
    }
}

impl From<policy::Model> for Policy {
    fn from(value: policy::Model) -> Self {
        Self::new(value.id.inner(), value.name, value.expression)
    }
}

#[async_trait]
impl Persistable for Policy {
    type Error = Error;

    async fn persist(self, transaction: &DatabaseTransaction) -> std::result::Result<(), Self::Error> {
        todo!()
    }
}

#[cfg_attr(test, automock)]
#[async_trait]
pub(crate) trait PolicyService {
    async fn list(&self, transaction: &DatabaseTransaction) -> Result<Vec<Policy>>;
    async fn get(&self, transaction: &DatabaseTransaction, id: &Ulid) -> Result<Option<Policy>>;
    async fn register(&self, transaction: &DatabaseTransaction, name: &str, expression: &str) -> Result<()>;
}

pub(crate) struct PostgresPolicyService {}

#[async_trait]
impl PolicyService for PostgresPolicyService {
    async fn list(&self, transaction: &DatabaseTransaction) -> Result<Vec<Policy>> {
        let policies = policy::Entity::find().all(transaction).await?;

        Ok(policies.into_iter().map(Policy::from).collect())
    }

    async fn get(&self, transaction: &DatabaseTransaction, id: &Ulid) -> Result<Option<Policy>> {
        let policy = policy::Entity::find_by_id(id).one(transaction).await?;

        Ok(policy.map(Policy::from))
    }

    async fn register(&self, transaction: &DatabaseTransaction, name: &str, expression: &str) -> Result<()> {
        validate_expression(expression)?;
        ensure_policy_name_not_duplicated(transaction, name).await?;

        let now = Utc::now();

        let active_model = policy::ActiveModel {
            id: Set(Ulid::new().into()),
            name: Set(name.to_owned()),
            expression: Set(expression.to_owned()),
            created_at: Set(now),
            updated_at: Set(now),
        };

        active_model.insert(transaction).await?;

        Ok(())
    }
}

async fn ensure_policy_name_not_duplicated(transaction: &DatabaseTransaction, policy_name: &str) -> Result<()> {
    if policy::Entity::find().filter(policy::Column::Name.eq(policy_name)).count(transaction).await? > 0 {
        return Err(Error::PolicyNameDuplicated { entered_policy_name: policy_name.to_owned() });
    }

    Ok(())
}

fn validate_expression(expression: &str) -> Result<()> {
    tessera_policy::pest::parse(expression, tessera_policy::pest::PolicyLanguage::HumanPolicy)?;

    Ok(())
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error(transparent)]
    InvalidExpression(#[from] tessera_policy::error::PolicyParserError),
    #[error("Entered policy name({entered_policy_name}) is already registered.")]
    PolicyNameDuplicated { entered_policy_name: String },
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
    use crate::{
        database::{policy, UlidId},
        domain::policy::Policy,
    };

    #[tokio::test]
    async fn when_getting_policy_data_is_successful_then_policy_service_returns_policies_ok() {
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
    async fn when_getting_policies_is_failed_then_policy_service_returns_anyhow_err() {
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
    async fn when_managed_policy_is_empty_then_policy_service_returns_empty_ok() {
        let mock_database =
            MockDatabase::new(DatabaseBackend::Postgres).append_query_results([Vec::<policy::Model>::new()]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let policy_service = PostgresPolicyService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = policy_service.list(&transaction).await.expect("creating workspace should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(result.is_empty())
    }

    #[tokio::test]
    async fn when_registering_policy_with_invalid_expression_then_policy_service_returns_invalid_policy_err() {
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres);

        let mock_connection = Arc::new(mock_database.into_connection());

        let policy_service = PostgresPolicyService {};

        let invalid_expressions = ["(\"role=FRONTEND@A\""];

        for invalid_expression in invalid_expressions {
            let transaction = mock_connection.begin().await.expect("begining transaction should be successful");
            let result = policy_service.register(&transaction, "test", invalid_expression).await;
            transaction.commit().await.expect("commiting transaction should be successful");
            assert!(matches!(result, Err(Error::InvalidExpression { .. })));
        }
    }

    #[tokio::test]
    async fn when_registering_policy_with_already_registered_name_then_policy_service_returns_policy_name_duplicated_err(
    ) {
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres).append_query_results([[maplit::btreemap! {
            "num_items" => sea_orm::Value::BigInt(Some(1))
        }]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let policy_service = PostgresPolicyService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");
        let result = policy_service.register(&transaction, "test", "(\"role=FRONTEND@A\")").await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::PolicyNameDuplicated { .. })));
    }

    #[tokio::test]
    async fn when_registering_policy_is_successful_then_policy_service_returns_unit_ok() {
        let now = Utc::now();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[maplit::btreemap! {
                "num_items" => sea_orm::Value::BigInt(Some(0))
            }]])
            .append_query_results([[policy::Model {
                id: Ulid::new().into(),
                name: "test".to_owned(),
                expression: "(\"role=FRONTEND@A\")".to_owned(),
                created_at: now,
                updated_at: now,
            }]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let policy_service = PostgresPolicyService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");
        policy_service
            .register(&transaction, "test", "(\"role=FRONTEND@A\")")
            .await
            .expect("registering policy should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");
    }

    #[tokio::test]
    async fn when_updating_name_then_updated_name_turns_into_new_name() {
        let mut policy = Policy::new(Ulid::new(), "test1".to_owned(), "(\"role=FRONTEND@A\")".to_owned());

        assert_eq!(policy.updated_name, None);

        policy.update_name("test2");

        assert_eq!(policy.updated_name, Some("test2".to_owned()));
    }

    #[tokio::test]
    async fn when_updating_name_with_same_name_then_updated_name_not_changed() {
        let mut policy = Policy::new(Ulid::new(), "test1".to_owned(), "(\"role=FRONTEND@A\")".to_owned());

        assert_eq!(policy.updated_name, None);

        policy.update_name("test1");

        assert_eq!(policy.updated_name, None);
    }

    #[tokio::test]
    async fn when_updating_expression_then_updated_expression_turns_into_new_expression() {
        let mut policy = Policy::new(Ulid::new(), "test1".to_owned(), "(\"role=FRONTEND@A\")".to_owned());

        assert_eq!(policy.updated_expression, None);

        policy.update_expression("(\"role=BACKEND@A\")").expect("updating expression should be successful");

        assert_eq!(policy.updated_expression, Some("(\"role=BACKEND@A\")".to_owned()));
    }

    #[tokio::test]
    async fn when_updating_expression_with_same_expression_then_updated_expression_not_changed() {
        let mut policy = Policy::new(Ulid::new(), "test1".to_owned(), "(\"role=FRONTEND@A\")".to_owned());

        assert_eq!(policy.updated_expression, None);

        policy.update_expression("(\"role=FRONTEND@A\")").expect("updating expression should be successful");

        assert_eq!(policy.updated_expression, None);
    }

    #[tokio::test]
    async fn when_updating_expression_with_invalid_expression_then_policy_returns_invalid_policy_err() {
        let mut policy = Policy::new(Ulid::new(), "test1".to_owned(), "(\"role=FRONTEND@A\")".to_owned());

        assert_eq!(policy.updated_expression, None);

        let result = policy.update_expression("(\"role=FRONTEND@A\"");

        assert!(matches!(result, Err(Error::InvalidExpression(_))));
    }
}
