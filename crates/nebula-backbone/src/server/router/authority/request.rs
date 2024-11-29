use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PostAuthorityRequest {
    pub name: String,
    pub host: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PatchAuthorityRequest {
    pub name: Option<String>,
    pub public_key: Option<String>,
}
