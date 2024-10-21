use async_trait::async_trait;
use chrono::Utc;
#[cfg(test)]
use mockall::automock;
use rand::{rngs::OsRng, Rng};
use sea_orm::{
    ActiveModelTrait as _, ActiveValue, ColumnTrait, DatabaseTransaction, EntityTrait, PaginatorTrait, QueryFilter,
};
use ulid::Ulid;

use crate::database::parameter;
use tessera_abe::{
    curves::{bls24479::Bls24479Curve, PairingCurve},
    schemes::rw15::GlobalParams,
};

pub(crate) struct Parameter {
    pub version: i32,
    pub value: GlobalParams<Bls24479Curve>,
}

#[cfg_attr(test, automock)]
#[async_trait]
pub(crate) trait ParameterService {
    async fn create(&self, transaction: &DatabaseTransaction) -> Result<Parameter>;
}

pub(crate) struct PostgresParameterService;

pub const PARAMETER_VERSION: i32 = 1;

#[async_trait]
impl ParameterService for PostgresParameterService {
    async fn create(&self, transaction: &DatabaseTransaction) -> Result<Parameter> {
        let has_parameter = parameter::Entity::find()
            .filter(parameter::Column::Version.eq(PARAMETER_VERSION))
            .count(transaction)
            .await?
            > 0;
        if has_parameter {
            return Err(Error::ParameterAlreadyCreated(PARAMETER_VERSION));
        }

        let mut rng = <Bls24479Curve as PairingCurve>::Rng::new();
        let mut seed = [0u8; 64];
        OsRng.fill(&mut seed);
        rng.seed(&seed);

        let gp = GlobalParams::<Bls24479Curve>::new(&mut rng);
        let value = serde_json::to_value(&gp)?;
        let now = Utc::now();
        parameter::ActiveModel {
            id: ActiveValue::Set(Ulid::new().into()),
            version: ActiveValue::Set(PARAMETER_VERSION),
            value: ActiveValue::Set(value),
            created_at: ActiveValue::Set(now),
            updated_at: ActiveValue::Set(now),
        }
        .insert(transaction)
        .await?;

        Ok(Parameter { version: PARAMETER_VERSION, value: gp })
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("Parameter has already been created with version {0}")]
    ParameterAlreadyCreated(i32),

    #[error(transparent)]
    SerdeJson(#[from] serde_json::Error),

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
    use std::sync::Arc;

    use chrono::Utc;
    use sea_orm::{DatabaseBackend, DbErr, MockDatabase, TransactionTrait};
    use tessera_abe::{
        curves::{bls24479::Bls24479Curve, PairingCurve},
        schemes::rw15::GlobalParams,
    };
    use ulid::Ulid;

    use super::{ParameterService, PostgresParameterService};
    

    #[tokio::test]
    async fn when_insert_is_successful_then_parameter_service_returns_ok() {
        use crate::database::parameter::Model;
        let mut rng = <Bls24479Curve as PairingCurve>::Rng::new();
        let gp = GlobalParams::<Bls24479Curve>::new(&mut rng);
        let value = serde_json::to_value(&gp).expect("serializing global params should be successful");

        let now = Utc::now();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[maplit::btreemap! {
                "num_items" => sea_orm::Value::BigInt(Some(0))
            }]])
            .append_query_results([vec![Model {
                id: Ulid::new().into(),
                version: 1,
                value,
                created_at: now,
                updated_at: now,
            }]]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let parameter_service = PostgresParameterService;

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = parameter_service.create(&transaction).await;

        transaction.commit().await.expect("commiting transaction should be successful");

        result.expect("creating workspace should be successful");
    }

    #[tokio::test]
    async fn when_insert_is_failed_then_parameter_service_returns_error() {
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let parameter_service = PostgresParameterService;

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = parameter_service.create(&transaction).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), "Custom Error: some error");
    }
}
