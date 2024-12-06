use cached::proc_macro::io_cached;
use reqwest::IntoUrl;
use serde::{Deserialize, Serialize};

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetPublicKeyResponse {
    pub public_key: String,
    pub version: u64,
}

#[io_cached(
    map_error = "|e| anyhow::anyhow!(e)",
    disk = true,
    time = 60,
    key = "String",
    convert = r#"{ format!("pk:{}/{}", authority_url.as_str(), workspace_name) }"#
)]
pub async fn get_public_key(authority_url: impl IntoUrl, workspace_name: &str) -> anyhow::Result<GetPublicKeyResponse> {
    let client = reqwest::Client::new();

    let url = authority_url.into_url()?.join(&format!("workspaces/{workspace_name}/public-key"))?;
    let response = client.get(url).send().await?.json::<GetPublicKeyResponse>().await?;

    Ok(response)
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GetUserKeyResponse {
    pub user_key: String,
    pub version: u64,
}

pub async fn get_user_key(
    authority_url: impl IntoUrl,
    workspace_name: &str,
    token: &str,
) -> anyhow::Result<GetUserKeyResponse> {
    let client = reqwest::Client::new();

    let url = authority_url.into_url()?.join(&format!("workspaces/{workspace_name}/user-key"))?;
    let response = client.get(url).bearer_auth(token).send().await?.json::<GetUserKeyResponse>().await?;

    Ok(response)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InitRequest {
    secret_shares: u8,
    secret_threshold: u8,
}

pub async fn init(authority_url: impl IntoUrl, secret_shares: u8, secret_threshold: u8) -> anyhow::Result<Vec<String>> {
    let client = reqwest::Client::new();

    let url = authority_url.into_url()?.join("init")?;
    let response =
        client.post(url).json(&InitRequest { secret_shares, secret_threshold }).send().await?.error_for_status()?;

    let shares: Vec<String> = response.json().await?;
    Ok(shares)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DisarmRequest {
    shares: Vec<String>,
}

pub async fn disarm(authority_url: impl IntoUrl, shares: Vec<String>) -> anyhow::Result<()> {
    let client = reqwest::Client::new();

    let url = authority_url.into_url()?.join("disarm")?;
    client.post(url).json(&DisarmRequest { shares }).send().await?.error_for_status()?;

    Ok(())
}
