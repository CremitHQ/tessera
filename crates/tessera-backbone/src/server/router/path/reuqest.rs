use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct PostPathRequest {
    pub path: String,
}

#[derive(Deserialize)]
pub(super) struct PatchPathRequest {
    pub path: String,
}
