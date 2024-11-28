use crate::database::{authority, UlidId};
use async_trait::async_trait;
use chrono::Utc;
use sea_orm::{
    ActiveModelTrait, ColumnTrait, DatabaseTransaction, DbErr, EntityTrait, PaginatorTrait, QueryFilter, Set,
};
use ulid::Ulid;

#[async_trait]
pub trait AuthorityService {
    async fn register_authority(&self, transaction: &DatabaseTransaction, name: &str, host: &str) -> Result<()>;
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
        todo!()
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
