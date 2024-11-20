use std::collections::HashMap;

use serde::{Deserialize, Serialize};

pub mod saml;

#[derive(Debug, Serialize, Deserialize)]
pub struct Identity {
    pub user_id: String,
    pub claims: HashMap<String, String>,
}
