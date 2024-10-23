use std::{path::PathBuf, str::FromStr, sync::Arc};

use anyhow::Result;

use tessera_storage::backend::file::FileStorage;

use crate::config::{ApplicationConfig, BackboneConfig, StorageConfig};

use super::{
    backbone::{BackboneService, WorkspaceBackboneClient, WorkspaceBackboneService},
    key_pair::{FileKeyPairService, KeyPairService},
};

pub struct Application {
    pub key_pair_service: Arc<dyn KeyPairService + Send + Sync>,
    pub backbone_service: Arc<dyn BackboneService + Send + Sync>,
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
}
