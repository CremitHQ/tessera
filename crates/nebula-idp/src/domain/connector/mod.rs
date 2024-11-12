use serde::{Deserialize, Serialize};

pub mod saml;

#[derive(Serialize, Deserialize)]
pub struct Identity {
    pub user_id: String,
    pub user_name: String,
    pub email: String,
    pub email_verified: bool,
    pub groups: Vec<String>,
}
