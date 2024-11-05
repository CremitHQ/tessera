use serde::Deserialize;

#[derive(Deserialize)]
pub(super) struct PostPathRequest {
    pub path: String,
}
