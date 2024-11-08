use serde::Deserialize;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PostPolicyRequest {
    pub name: String,
    pub expression: String,
}
