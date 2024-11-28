use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PostAuthorityRequest {
    pub name: String,
    pub host: String,
}
