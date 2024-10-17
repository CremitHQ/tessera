use async_trait::async_trait;
use sea_orm::DatabaseTransaction;
use ulid::Ulid;

pub(crate) struct Secret {
    pub key: String,
    pub path: String,
    pub reader_policy_ids: Vec<Ulid>,
    pub writer_policy_ids: Vec<Ulid>,
}

#[async_trait]
pub(crate) trait SecretService {
    async fn list(&self, transaction: &DatabaseTransaction, path_prefix: &str) -> Result<Vec<Secret>>;
}

pub(crate) struct PostgresSecretService {
}

#[async_trait]
impl SecretService for PostgresSecretService {
    async fn list(&self, _transaction: &DatabaseTransaction, _path_prefix: &str) -> Result<Vec<Secret>> {
        todo!()
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {}
pub(crate) type Result<T> = std::result::Result<T, Error>;
