use std::sync::Arc;

use nebula_token::auth::jwks_discovery::JwksDiscovery;

use crate::domain::authority::Authority;

pub struct Application {
    pub authority: Authority,
    pub jwks_discovery: Arc<dyn JwksDiscovery + Send + Sync>,
}

impl Application {
    pub fn new(authority: Authority, jwks_discovery: Arc<dyn JwksDiscovery + Send + Sync>) -> Self {
        Self { authority, jwks_discovery }
    }
}
