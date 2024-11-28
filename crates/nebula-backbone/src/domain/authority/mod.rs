use crate::database::{authority, UlidId};
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseTransaction, DbErr, EntityTrait, PaginatorTrait, QueryFilter, Set,
};
use ulid::Ulid;

pub struct Authority {
    pub id: Ulid,
    pub name: String,
    pub host: String,
    pub public_key: Option<String>,
}

impl From<authority::Model> for Authority {
    fn from(value: authority::Model) -> Self {
        Self { id: value.id.inner(), name: value.name, host: value.host, public_key: value.public_key }
    }
}

#[async_trait]
pub trait AuthorityService {
    async fn register_authority(&self, transaction: &DatabaseTransaction, name: &str, host: &str) -> Result<()>;
    async fn get_authorities(&self, transaction: &DatabaseTransaction) -> Result<Vec<Authority>>;
    async fn get_authority(&self, transaction: &DatabaseTransaction, authority_id: &Ulid) -> Result<Option<Authority>>;
}

pub struct PostgresAuthorityService {}

#[async_trait]
impl AuthorityService for PostgresAuthorityService {
    async fn register_authority(&self, transaction: &DatabaseTransaction, name: &str, host: &str) -> Result<()> {
        let now = Utc::now();

        if authority::Entity::find().filter(authority::Column::Name.eq(name)).count(transaction).await? > 0 {
            return Err(Error::NameAlreadyInUse { entered_authority_name: name.to_owned() });
        }

        authority::ActiveModel {
            id: Set(UlidId::new(Ulid::new())),
            name: Set(name.to_owned()),
            host: Set(host.to_owned()),
            public_key: Set(None),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(transaction)
        .await?;

        Ok(())
    }

    async fn get_authorities(&self, transaction: &DatabaseTransaction) -> Result<Vec<Authority>> {
        Ok(authority::Entity::find().all(transaction).await?.into_iter().map(Into::into).collect())
    }

    async fn get_authority(&self, transaction: &DatabaseTransaction, authority_id: &Ulid) -> Result<Option<Authority>> {
        Ok(authority::Entity::find_by_id(UlidId::new(authority_id.to_owned())).one(transaction).await?.map(Into::into))
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Authority name is already in use")]
    NameAlreadyInUse { entered_authority_name: String },
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<DbErr> for Error {
    fn from(value: DbErr) -> Self {
        Self::Anyhow(value.into())
    }
}

pub type Result<T> = std::result::Result<T, Error>;
