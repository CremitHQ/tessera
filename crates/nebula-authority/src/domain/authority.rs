use std::{path::PathBuf, str::FromStr, sync::Arc};

use anyhow::Result;

use nebula_abe::{curves::bn462::Bn462Curve, schemes::isabella24::GlobalParams};
use nebula_secret_sharing::shamir::Share;
use nebula_storage::backend::{file::FileStorage, postgres::PostgresStorage};
use sea_orm::DatabaseConnection;

use crate::{
    config::{ApplicationConfig, BackboneConfig, PostgresAuthMethod, PostgresConfig, StorageConfig},
    database::{connect_to_database, AuthMethod},
};

use super::{
    backbone::{BackboneService, WorkspaceBackboneService},
    key_pair::{FileKeyPairService, KeyPair, KeyVersion, PostgresKeyPairService, ShieldedKeyPairService},
};

pub struct Authority {
    pub name: String,
    pub backbone_service: Arc<dyn BackboneService + Send + Sync>,
    pub key_pair_service: Arc<dyn ShieldedKeyPairService + Send + Sync>,
}

impl Authority {
    pub async fn new(config: &ApplicationConfig) -> Result<Self> {
        let key_pair_service: Arc<dyn ShieldedKeyPairService + Send + Sync> = match &config.storage {
            StorageConfig::File { path } => {
                Arc::new(FileKeyPairService::new(FileStorage::new(PathBuf::from_str(path)?)))
            }
            StorageConfig::Postgres(auth_method) => {
                let database = init_database_connection(auth_method).await?;
                Arc::new(PostgresKeyPairService::new(
                    PostgresStorage::new(database.get_postgres_connection_pool().clone(), "nebula_key_pair_storage")
                        .await?,
                ))
            }
        };

        let backbone_service: Arc<dyn BackboneService + Send + Sync> = match &config.backbone {
            BackboneConfig::Workspace { host } => Arc::new(WorkspaceBackboneService::new(host.clone())),
        };

        Ok(Self { name: config.authority.name.clone(), key_pair_service, backbone_service })
    }

    pub async fn key_pair(&self, workspace_name: &str) -> Result<(KeyPair, KeyVersion)> {
        let gp = self.backbone_service.global_params(workspace_name).await?;
        let name = &format!("{}-{}", self.name, workspace_name);
        let key_pair = match self.key_pair_service.latest_key_pair(name).await? {
            Some(key_pair) => key_pair,
            None => self.key_pair_service.generate_latest_key_pair(&gp, name).await?,
        };

        Ok(key_pair)
    }

    pub async fn key_pair_by_version(&self, workspace_name: &str, version: KeyVersion) -> Result<KeyPair> {
        let name = &format!("{}-{}", self.name, workspace_name);
        let key_pair = match self.key_pair_service.key_pair_by_version(name, version).await? {
            Some(key_pair) => key_pair,
            None => {
                return Err(anyhow::anyhow!("Key pair with version {} not found", version));
            }
        };

        Ok(key_pair)
    }

    pub async fn key_pair_rolling(&self, gp: &GlobalParams<Bn462Curve>, workspace_name: &str) -> Result<KeyVersion> {
        let name = &format!("{}-{}", self.name, workspace_name);
        let (_, version) = self.key_pair_service.generate_latest_key_pair(gp, name).await?;
        Ok(version)
    }

    pub async fn init_key_pair_storage(&self, share: usize, threshold: usize) -> Result<Vec<Share>> {
        self.key_pair_service.shield_initialize(share, threshold).await
    }

    pub async fn armor_key_pair_storage(&self) -> Result<()> {
        self.key_pair_service.storage_armor().await
    }

    pub async fn disarm_key_pair_storage(&self, shares: &[Share]) -> Result<()> {
        self.key_pair_service.storage_disarm(shares).await
    }
}

async fn init_database_connection(config: &PostgresConfig) -> Result<Arc<DatabaseConnection>> {
    let database_host = &config.host;
    let database_port = config.port;
    let database_name = &config.database_name;
    let auth_method = create_database_auth_method(config);

    connect_to_database(database_host, database_port, database_name, &auth_method).await
}

fn create_database_auth_method(config: &PostgresConfig) -> AuthMethod {
    match &config.auth {
        PostgresAuthMethod::Credential { username, password } => {
            AuthMethod::Credential { username: username.to_owned(), password: password.to_owned() }
        }
        PostgresAuthMethod::RdsIamAuth { username } => {
            AuthMethod::RdsIamAuth { host: config.host.to_owned(), port: config.port, username: username.to_owned() }
        }
    }
}
