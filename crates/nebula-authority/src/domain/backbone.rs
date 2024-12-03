use anyhow::Result;
use async_trait::async_trait;
use base64::{engine::general_purpose::STANDARD, Engine as _};
use cached::proc_macro::cached;
use nebula_abe::{curves::bn462::Bn462Curve, schemes::isabella24::GlobalParams};
use reqwest::IntoUrl;
use serde::Deserialize;
use url::Url;

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
    host: Url,
}

impl WorkspaceBackboneClient {
    pub fn new(host: Url) -> Self {
        Self { host, client: reqwest::Client::new() }
    }

    pub fn client(mut self, client: reqwest::Client) -> Self {
        self.client = client;
        self
    }

    pub fn host(mut self, host: impl IntoUrl) -> anyhow::Result<Self> {
        self.host = host.into_url()?;
        Ok(self)
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
        let url = self.host.join(&format!("workspaces/{}/parameter", workspace_name))?;
        let response = self.client.get(url).send().await?;
        let parameter: ParameterResponse = response.json().await?;
        let parameter = STANDARD.decode(parameter.parameter)?;
        let parameter = rmp_serde::from_slice(&parameter)?;

        Ok(parameter)
    }
}

pub struct WorkspaceBackboneService {
    backbone_host: Url,
}

impl WorkspaceBackboneService {
    pub fn new(backbone_host: Url) -> Self {
        Self { backbone_host }
    }
}

#[async_trait]
impl BackboneService for WorkspaceBackboneService {
    async fn global_params(&self, workspace_name: &str) -> Result<GlobalParams<Bn462Curve>> {
        get_global_params(&self.backbone_host, workspace_name).await
    }
}

#[cached(size = 32, result = true, key = "String", convert = r#"{ format!("{}{}", host.as_str(), workspace_name) }"#)]
async fn get_global_params(host: &Url, workspace_name: &str) -> Result<GlobalParams<Bn462Curve>> {
    let client = WorkspaceBackboneClient::new(host.clone());
    client.get_global_params(workspace_name).await
}
