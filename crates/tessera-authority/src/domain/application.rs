use std::{path::PathBuf, str::FromStr, sync::Arc};

use anyhow::Result;

use tessera_storage::backend::file::FileStorage;

use crate::config::{ApplicationConfig, BackboneConfig, StorageConfig};

use super::{
    backbone::{BackboneService, WorkspaceBackboneClient, WorkspaceBackboneService},
    key_pair::{FileKeyPairService, KeyPair, KeyPairService},
};

pub struct Application {
    key_pair_service: Arc<dyn KeyPairService + Send + Sync>,
    backbone_service: Arc<dyn BackboneService + Send + Sync>,
}

impl Application {
    pub fn new(config: &ApplicationConfig) -> Result<Self> {
        let key_pair_service: Arc<dyn KeyPairService + Send + Sync> = match &config.storage {
            StorageConfig::File { path } => {
                Arc::new(FileKeyPairService::new(FileStorage::new(PathBuf::from_str(path)?)))
            }
        };

        let backbone_service: Arc<dyn BackboneService + Send + Sync> = match &config.backbone {
            BackboneConfig::Workspace { workspace_name, host } => {
                let backbone_client = WorkspaceBackboneClient::new(workspace_name.clone(), host.clone());
                Arc::new(WorkspaceBackboneService::new(backbone_client))
            }
        };

        Ok(Self { key_pair_service, backbone_service })
    }

    pub async fn key_pair(&self, name: &str) -> Result<KeyPair> {
        let gp = self.backbone_service.global_params().await?;
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
}
