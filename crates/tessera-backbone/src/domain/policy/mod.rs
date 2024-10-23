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
