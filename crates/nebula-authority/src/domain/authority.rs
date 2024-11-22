use std::{path::PathBuf, str::FromStr, sync::Arc};

use anyhow::Result;

use nebula_abe::{curves::bn462::Bn462Curve, schemes::isabella24::GlobalParams};
use nebula_secret_sharing::shamir::Share;
use nebula_storage::backend::file::FileStorage;

use crate::config::{ApplicationConfig, BackboneConfig, StorageConfig};

use super::{
    backbone::{BackboneService, WorkspaceBackboneService},
    key_pair::{FileKeyPairService, KeyPair, KeyVersion, ShieldedKeyPairService},
};

pub struct Authority {
    pub name: String,
    pub backbone_service: Arc<dyn BackboneService + Send + Sync>,
    pub key_pair_service: Arc<dyn ShieldedKeyPairService + Send + Sync>,
}

impl Authority {
    pub fn new(config: &ApplicationConfig) -> Result<Self> {
        let key_pair_service: Arc<dyn ShieldedKeyPairService + Send + Sync> = match &config.storage {
            StorageConfig::File { path } => {
                Arc::new(FileKeyPairService::new(FileStorage::new(PathBuf::from_str(path)?)))
            }
        };

        let backbone_service: Arc<dyn BackboneService + Send + Sync> = match &config.backbone {
            BackboneConfig::Workspace { host } => Arc::new(WorkspaceBackboneService::new(host)),
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
