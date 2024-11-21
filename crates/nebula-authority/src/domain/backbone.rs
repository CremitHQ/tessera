use anyhow::Result;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use nebula_abe::{curves::bn462::Bn462Curve, schemes::isabella24::GlobalParams};
use serde::Deserialize;

#[async_trait]
pub trait BackboneService {
    async fn global_params(&self, workspace_name: &str) -> Result<GlobalParams<Bn462Curve>>;
}

#[async_trait]
pub trait BackboneClient {
    async fn get_global_params(&self, workspace_name: &str) -> Result<GlobalParams<Bn462Curve>>;
}

pub struct WorkspaceBackboneClient {
    client: reqwest::Client,
    host: String,
}

impl WorkspaceBackboneClient {
    pub fn new(host: String) -> Self {
        Self { host, client: reqwest::Client::new() }
    }

    pub fn client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    pub fn host(mut self, host: String) -> Self {
        self.host = host;
        self
    }
}

#[derive(Deserialize)]
struct ParameterResponse {
    version: i32,
    parameter: String,
}

#[async_trait]
impl BackboneClient for WorkspaceBackboneClient {
    async fn get_global_params(&self, workspace_name: &str) -> Result<GlobalParams<Bn462Curve>> {
        let url = format!("{}/workspaces/{}/parameter", self.host, workspace_name);
        let response = self.client.get(&url).send().await?;
        let parameter: ParameterResponse = response.json().await?;
        let parameter = STANDARD.decode(parameter.parameter)?;
        let parameter = rmp_serde::from_slice(&parameter)?;

        Ok(parameter)
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
    async fn global_params(&self, workspace_name: &str) -> Result<GlobalParams<Bn462Curve>> {
        self.backbone_client.get_global_params(workspace_name).await
    }
}
