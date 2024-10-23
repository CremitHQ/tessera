use anyhow::Result;
use async_trait::async_trait;
use serde::Deserialize;
use tessera_abe::{curves::bls24479::Bls24479Curve, schemes::rw15::GlobalParams};

#[async_trait]
pub trait BackboneService {
    async fn global_params(&self) -> Result<GlobalParams<Bls24479Curve>>;
}

#[async_trait]
pub trait BackboneClient {
    async fn get_global_params(&self) -> Result<GlobalParams<Bls24479Curve>>;
}

pub struct WorkspaceBackboneClient {
    client: reqwest::Client,
    workspace_name: String,
    host: String,
}

impl WorkspaceBackboneClient {
    pub fn new(workspace_name: String, host: String) -> Self {
        Self { workspace_name, host, client: reqwest::Client::new() }
    }

    pub fn client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    pub fn host(mut self, host: String) -> Self {
        self.host = host;
        self
    }

    pub fn workspace_name(mut self, workspace_name: String) -> Self {
        self.workspace_name = workspace_name;
        self
    }
}

#[derive(Deserialize)]
struct ParameterResponse {
    version: i32,
    parameter: GlobalParams<Bls24479Curve>,
}

#[async_trait]
impl BackboneClient for WorkspaceBackboneClient {
    async fn get_global_params(&self) -> Result<GlobalParams<Bls24479Curve>> {
        let url = format!("{}/workspaces/{}/parameter", self.host, self.workspace_name);
        let response = self.client.get(&url).send().await?;
        let parameter: ParameterResponse = response.json().await?;

        Ok(parameter.parameter)
    }
}

pub struct WorkspaceBackboneService {
    backbone_client: WorkspaceBackboneClient,
}

impl WorkspaceBackboneService {
    pub fn new(backbone_client: WorkspaceBackboneClient) -> Self {
        Self { backbone_client }
    }

    pub fn backbone_client(mut self, backbone_client: WorkspaceBackboneClient) -> Self {
        self.backbone_client = backbone_client;
        self
    }
}

#[async_trait]
impl BackboneService for WorkspaceBackboneService {
    async fn global_params(&self) -> Result<GlobalParams<Bls24479Curve>> {
        self.backbone_client.get_global_params().await
    }
}
