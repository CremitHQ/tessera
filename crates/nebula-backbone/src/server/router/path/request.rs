use serde::Deserialize;

use super::model::AppliedPolicy;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PostPathRequest {
    pub path: String,
    pub applied_policies: Vec<AppliedPolicy>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct PatchPathRequest {
    pub path: Option<String>,
    pub applied_policies: Option<Vec<AppliedPolicy>>,
}
