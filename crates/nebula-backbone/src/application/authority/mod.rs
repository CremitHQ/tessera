use std::sync::Arc;

use async_trait::async_trait;
use sea_orm::{DatabaseConnection, DbErr};
use ulid::Ulid;

use crate::{
    database::OrganizationScopedTransaction,
    domain::{self, authority::AuthorityService},
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
}

#[async_trait]
impl AuthorityUseCase for AuthorityUseCaseImpl {
    async fn register_authority(&self, name: &str, host: &str) -> Result<()> {
        let transaction = self.database_connection.begin_with_organization_scope(&self.workspace_name).await?;
        self.authority_service.register_authority(&transaction, name, host).await?;
        transaction.commit().await?;
        Ok(())
    }

    async fn get_authorities(&self) -> Result<Vec<AuthorityData>> {
        let transaction = self.database_connection.begin_with_organization_scope(&self.workspace_name).await?;
        let authorities = self.authority_service.get_authorities(&transaction).await?;
        transaction.commit().await?;

        Ok(authorities.into_iter().map(Into::into).collect())
    }

    async fn get_authority(&self, authority_id: &Ulid) -> Result<AuthorityData> {
        let transaction = self.database_connection.begin_with_organization_scope(&self.workspace_name).await?;
        let authority = self
            .authority_service
            .get_authority(&transaction, authority_id)
            .await?
            .ok_or_else(|| Error::AuthorityNotExists { entered_authority_id: authority_id.to_owned() })?;
        transaction.commit().await?;

        Ok(authority.into())
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
