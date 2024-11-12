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
use nebula_abe::{
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
    async fn get(&self, transaction: &DatabaseTransaction) -> Result<Parameter>;
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
        let value = rmp_serde::to_vec(&gp)?;
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

    async fn get(&self, transaction: &DatabaseTransaction) -> Result<Parameter> {
        let parameter = parameter::Entity::find()
            .filter(parameter::Column::Version.eq(PARAMETER_VERSION))
            .one(transaction)
            .await?
            .ok_or(Error::ParameterNotFound)?;
        let value = parameter.value;
        let gp: GlobalParams<Bls24479Curve> = rmp_serde::from_slice(&value)?;
        Ok(Parameter { version: PARAMETER_VERSION, value: gp })
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("Parameter has already been created with version {0}")]
    ParameterAlreadyCreated(i32),

    #[error("Parameter not found")]
    ParameterNotFound,

    #[error(transparent)]
    Serialization(#[from] rmp_serde::encode::Error),

    #[error(transparent)]
    Deserialization(#[from] rmp_serde::decode::Error),

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
    use std::{str::FromStr as _, sync::Arc};

    use chrono::Utc;
    use nebula_abe::{
        curves::{bls24479::Bls24479Curve, PairingCurve},
        schemes::rw15::GlobalParams,
    };
    use sea_orm::{DatabaseBackend, DbErr, MockDatabase, TransactionTrait};
    use ulid::Ulid;

    use crate::database::UlidId;

    use super::{ParameterService, PostgresParameterService, PARAMETER_VERSION};

    #[tokio::test]
    async fn when_creating_parameter_is_successful_then_parameter_service_returns_ok() {
        use crate::database::parameter::Model;
        let mut rng = <Bls24479Curve as PairingCurve>::Rng::new();
        let gp = GlobalParams::<Bls24479Curve>::new(&mut rng);
        let value = rmp_serde::to_vec(&gp).expect("serializing global params should be successful");

        let now = Utc::now();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[maplit::btreemap! {
                "num_items" => sea_orm::Value::BigInt(Some(0))
            }]])
            .append_query_results([vec![Model {
                id: Ulid::new().into(),
                version: PARAMETER_VERSION,
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
    async fn when_creating_parameter_is_failed_then_parameter_service_returns_error() {
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

    #[tokio::test]
    async fn when_getting_parameter_is_successful_then_parameter_service_returns_ok() {
        use crate::database::parameter::Model;
        let mut rng = <Bls24479Curve as PairingCurve>::Rng::new();
        let gp = GlobalParams::<Bls24479Curve>::new(&mut rng);
        let value = rmp_serde::to_vec(&gp).expect("serializing global params should be successful");

        let now = Utc::now();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres).append_query_results([vec![Model {
            id: UlidId::new(Ulid::from_str("01JACYVTYB4F2PEBFRG1BB7BFP").unwrap()),
            version: PARAMETER_VERSION,
            value: value.clone(),
            created_at: now,
            updated_at: now,
        }]]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let parameter_service = PostgresParameterService;

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = parameter_service.get(&transaction).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        let result = result.expect("getting workspace should be successful");
        assert_eq!(result.version, PARAMETER_VERSION);
        assert_eq!(
            rmp_serde::to_vec(&result.value).expect("serializing global params should be successful"),
            rmp_serde::to_vec(&gp).expect("serializing global params should be successful")
        );
    }

    #[tokio::test]
    async fn when_getting_parameter_is_failed_then_parameter_service_returns_error() {
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let parameter_service = PostgresParameterService;

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = parameter_service.get(&transaction).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(result.is_err());
        assert_eq!(result.err().unwrap().to_string(), "Custom Error: some error");
    }
}
