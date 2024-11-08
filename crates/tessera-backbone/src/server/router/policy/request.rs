use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PostPolicyRequest {
    pub name: String,
    pub expression: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PatchPolicyRequest {
    pub name: Option<String>,
    pub expression: Option<String>,
}
