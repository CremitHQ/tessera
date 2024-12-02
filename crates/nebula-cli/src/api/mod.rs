use anyhow::Result;
use reqwest::IntoUrl;
use serde::Deserialize;

const TOKEN_HEADER: &str = "Token";

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MachineIdentityTokenResponse {
    pub access_token: String,
}

pub async fn get_token_from_machine_identity_token(
    authz_url: impl IntoUrl,
    workspace_name: &str,
    token: &str,
) -> Result<String> {
    let client = reqwest::Client::new();

    let url = authz_url.into_url()?.join(&format!("workspaces/{workspace_name}/machine-identities/login"))?;
    let response =
        client.get(url).header(TOKEN_HEADER, token).send().await?.json::<MachineIdentityTokenResponse>().await?;

    Ok(response.access_token)
}
