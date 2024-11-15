use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AppliedPolicy {
    expression: String,
    allowed_actions: Vec<AllowedAction>,
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AllowedAction {
    Read,
    Create,
    Update,
    Delete,
    Manage,
}
