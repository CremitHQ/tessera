use anyhow::Result;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use cached::proc_macro::cached;
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
    pub fn new(host: &str) -> Self {
        Self { host: host.to_string(), client: reqwest::Client::new() }
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
    backbone_host: String,
}

impl WorkspaceBackboneService {
    pub fn new(backbone_host: &str) -> Self {
        Self { backbone_host: backbone_host.to_string() }
    }
}

#[async_trait]
impl BackboneService for WorkspaceBackboneService {
    async fn global_params(&self, workspace_name: &str) -> Result<GlobalParams<Bn462Curve>> {
        get_global_params(&self.backbone_host, workspace_name).await
    }
}

#[cached(size = 32, result = true, key = "String", convert = r#"{ format!("{}{}", host, workspace_name) }"#)]
async fn get_global_params(host: &str, workspace_name: &str) -> Result<GlobalParams<Bn462Curve>> {
    let client = WorkspaceBackboneClient::new(host);
    client.get_global_params(workspace_name).await
}
