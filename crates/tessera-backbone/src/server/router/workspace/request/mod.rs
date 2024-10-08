use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub(crate) struct PostWorkspaceRequest {
    pub name: String,
}
