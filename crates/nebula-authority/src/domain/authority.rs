use std::{path::PathBuf, str::FromStr, sync::Arc};

use anyhow::Result;

use nebula_abe::{curves::bn462::Bn462Curve, schemes::isabella24::GlobalParams};
use nebula_secret_sharing::shamir::Share;
use nebula_storage::backend::file::FileStorage;
use zeroize::Zeroizing;

use crate::config::{ApplicationConfig, BackboneConfig, StorageConfig};

use super::{
    backbone::{BackboneService, WorkspaceBackboneClient, WorkspaceBackboneService},
    key_pair::{FileKeyPairService, KeyPair, ShieldedKeyPairService},
};

pub struct Authority {
    pub name: String,
    pub admin: Vec<String>,
    pub backbone_service: Arc<dyn BackboneService + Send + Sync>,
    key_pair_service: Arc<dyn ShieldedKeyPairService + Send + Sync>,
}

impl Authority {
    pub fn new(config: &ApplicationConfig) -> Result<Self> {
        let key_pair_service: Arc<dyn ShieldedKeyPairService + Send + Sync> = match &config.storage {
            StorageConfig::File { path } => {
                Arc::new(FileKeyPairService::new(FileStorage::new(PathBuf::from_str(path)?)))
            }
        };

        let backbone_service: Arc<dyn BackboneService + Send + Sync> = match &config.backbone {
            BackboneConfig::Workspace { host } => {
                let backbone_client = WorkspaceBackboneClient::new(host.clone());
                Arc::new(WorkspaceBackboneService::new(backbone_client))
            }
        };

        Ok(Self {
            name: config.authority.name.clone(),
            admin: config.authority.admin.clone(),
            key_pair_service,
            backbone_service,
        })
    }

    pub async fn key_pair(&self, workspace_name: &str) -> Result<KeyPair> {
        let gp = self.backbone_service.global_params(workspace_name).await?;
        let name = &format!("{}-{}", self.name, workspace_name);
        let key_pair = match self.key_pair_service.latest_key_pair(name).await? {
            Some(key_pair) => key_pair,
            None => {
                let key_pair = self.key_pair_service.generate_key_pair(&gp, name).await?;
                self.key_pair_service.store_latest_key_pair(&key_pair).await?;
                key_pair
            }
        };

        Ok(key_pair)
    }

    pub async fn key_pair_by_version(&self, workspace_name: &str, version: u64) -> Result<KeyPair> {
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

    pub async fn init_key_pair_storage(&self, share: usize, threshold: usize) -> Result<Zeroizing<Vec<Share>>> {
        self.key_pair_service.shield_initialize(share, threshold).await
    }

    pub async fn armor_key_pair_storage(&self) -> Result<()> {
        self.key_pair_service.storage_armor().await
    }

    pub async fn disarm_key_pair_storage(&self, shares: &[Share]) -> Result<()> {
        self.key_pair_service.storage_disarm(shares).await
    }
}
