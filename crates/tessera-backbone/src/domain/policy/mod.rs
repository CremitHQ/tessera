use async_trait::async_trait;
use sea_orm::DatabaseTransaction;
use ulid::Ulid;

pub(crate) struct Policy {
    pub id: Ulid,
    pub name: String,
    pub expression: String,
}

#[async_trait]
pub(crate) trait PolicyService {
    async fn get_all(&self, transaction: &DatabaseTransaction) -> Result<Vec<Policy>>;
}

pub(crate) struct PostgresPolicyService {}

#[async_trait]
impl PolicyService for PostgresPolicyService {
    async fn get_all(&self, transaction: &DatabaseTransaction) -> Result<Vec<Policy>> {
        todo!()
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {}

pub(crate) type Result<T> = std::result::Result<T, Error>;
