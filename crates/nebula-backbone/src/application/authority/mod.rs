use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, DatabaseTransaction, DbErr};
use ulid::Ulid;

use crate::{
    database::{Persistable, WorkspaceScopedTransaction},
    domain::{
        self,
        authority::{Authority, AuthorityService},
    },
};

pub struct AuthorityData {
    pub id: Ulid,
    pub name: String,
    pub host: String,
    pub public_key: Option<String>,
}

impl From<domain::authority::Authority> for AuthorityData {
    fn from(value: domain::authority::Authority) -> Self {
        Self { id: value.id, name: value.name, host: value.host, public_key: value.public_key }
    }
}

#[async_trait]
pub trait AuthorityUseCase {
    async fn register_authority(&self, name: &str, host: &str) -> Result<()>;
    async fn get_authorities(&self) -> Result<Vec<AuthorityData>>;
    async fn get_authority(&self, authority_id: &Ulid) -> Result<AuthorityData>;
    async fn update_authority(
        &self,
        authority_id: &Ulid,
        new_name: Option<&str>,
        new_public_key: Option<&str>,
    ) -> Result<()>;
    async fn delete_authority(&self, authority_id: &Ulid) -> Result<()>;
}

pub struct AuthorityUseCaseImpl {
    workspace_name: String,
    database_connection: Arc<DatabaseConnection>,
    authority_service: Arc<dyn AuthorityService + Sync + Send>,
}

impl AuthorityUseCaseImpl {
    pub fn new(
        workspace_name: String,
        database_connection: Arc<DatabaseConnection>,
        authority_service: Arc<dyn AuthorityService + Sync + Send>,
    ) -> Self {
        Self { workspace_name, database_connection, authority_service }
    }

    async fn get_authority_model(&self, transaction: &DatabaseTransaction, authority_id: &Ulid) -> Result<Authority> {
        self.authority_service
            .get_authority(transaction, authority_id)
            .await?
            .ok_or_else(|| Error::AuthorityNotExists { entered_authority_id: authority_id.to_owned() })
    }
}

#[async_trait]
impl AuthorityUseCase for AuthorityUseCaseImpl {
    async fn register_authority(&self, name: &str, host: &str) -> Result<()> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;
        self.authority_service.register_authority(&transaction, name, host).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn get_authorities(&self) -> Result<Vec<AuthorityData>> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;
        let authorities = self.authority_service.get_authorities(&transaction).await?;
        transaction.commit().await?;

        Ok(authorities.into_iter().map(Into::into).collect())
    }

    async fn get_authority(&self, authority_id: &Ulid) -> Result<AuthorityData> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;
        let authority = self.get_authority_model(&transaction, authority_id).await?;
        transaction.commit().await?;

        Ok(authority.into())
    }

    async fn update_authority(
        &self,
        authority_id: &Ulid,
        new_name: Option<&str>,
        new_public_key: Option<&str>,
    ) -> Result<()> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;

        let mut authority = self.get_authority_model(&transaction, authority_id).await?;
        if let Some(new_name) = new_name {
            authority.update_name(new_name)
        }
        if let Some(new_public_key) = new_public_key {
            authority.update_public_key(new_public_key)
        }
        authority.persist(&transaction).await?;

        transaction.commit().await?;

        Ok(())
    }

    async fn delete_authority(&self, authority_id: &Ulid) -> Result<()> {
        let transaction = self.database_connection.begin_with_workspace_scope(&self.workspace_name).await?;

        let mut authority = self.get_authority_model(&transaction, authority_id).await?;
        authority.delete();
        authority.persist(&transaction).await?;

        transaction.commit().await?;

        Ok(())
    }
}

#[derive(thiserror::Error, Debug)]
pub enum Error {
    #[error("Authority({entered_authority_id}) is not exists")]
    AuthorityNotExists { entered_authority_id: Ulid },
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

impl From<domain::authority::Error> for Error {
    fn from(value: domain::authority::Error) -> Self {
        match value {
            domain::authority::Error::NameAlreadyInUse { entered_authority_name } => {
                Self::NameAlreadyInUse { entered_authority_name }
            }
            domain::authority::Error::Anyhow(e) => Self::Anyhow(e),
        }
    }
}

pub type Result<T> = std::result::Result<T, Error>;
