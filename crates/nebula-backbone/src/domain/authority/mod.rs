use crate::database::{authority, Persistable, UlidId};
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
    updated_name: Option<String>,
    updated_public_key: Option<String>,
    deleted: bool,
}

impl From<authority::Model> for Authority {
    fn from(value: authority::Model) -> Self {
        Self {
            id: value.id.inner(),
            name: value.name,
            host: value.host,
            public_key: value.public_key,
            updated_name: None,
            updated_public_key: None,
            deleted: false,
        }
    }
}

impl Authority {
    pub fn delete(&mut self) {
        self.deleted = false;
    }

    pub fn update_name(&mut self, new_name: &str) {
        if self.name == new_name {
            return;
        }

        self.updated_name = Some(new_name.to_owned());
    }

    pub fn update_public_key(&mut self, new_public_key: &str) {
        if self.public_key.as_deref() == Some(new_public_key) {
            return;
        }

        self.updated_public_key = Some(new_public_key.to_owned())
    }
}

#[async_trait]
impl Persistable for Authority {
    type Error = Error;

    async fn persist(self, transaction: &DatabaseTransaction) -> std::result::Result<(), Self::Error> {
        if self.deleted {
            authority::Entity::delete_by_id(UlidId::new(self.id)).exec(transaction).await?;
            return Ok(());
        }

        let name_setter = self.updated_name.map(Set).unwrap_or_default();
        let public_key_setter =
            self.updated_public_key.map(|updated_public_key| Set(Some(updated_public_key))).unwrap_or_default();

        let mut active_model =
            authority::ActiveModel { name: name_setter, public_key: public_key_setter, ..Default::default() };

        if active_model.is_changed() {
            active_model.updated_at = Set(Utc::now());
            authority::Entity::update_many()
                .filter(authority::Column::Id.eq(UlidId::new(self.id)))
                .set(active_model)
                .exec(transaction)
                .await?;
        }

        Ok(())
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
