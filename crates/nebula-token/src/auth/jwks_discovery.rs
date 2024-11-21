use std::{sync::Arc, time::Duration};

use crate::jwk::jwk_set::JwkSet;
use reqwest::IntoUrl;
use tokio::sync::{Mutex, RwLock};

#[async_trait::async_trait]
pub trait JwksDiscovery {
    async fn jwks(&self) -> Result<JwkSet, super::error::AuthError>;
}

pub struct StaticJwksDiscovery {
    jwks: JwkSet,
}

impl StaticJwksDiscovery {
    pub fn new(jwks: JwkSet) -> Self {
        Self { jwks }
    }
}

#[async_trait::async_trait]
impl JwksDiscovery for StaticJwksDiscovery {
    async fn jwks(&self) -> Result<JwkSet, super::error::AuthError> {
        Ok(self.jwks.clone())
    }
}

pub struct CachedRemoteJwksDiscovery {
    jwks: Arc<RwLock<JwkSet>>,
    client: reqwest::Client,
    jwks_url: url::Url,
    refresh_interval: Duration,
    expiration: Arc<RwLock<std::time::Instant>>,
    is_refreshing: Mutex<()>,
}

impl CachedRemoteJwksDiscovery {
    pub async fn new(jwks_url: url::Url, refresh_interval: Duration) -> Result<Self, super::error::AuthError> {
        let client = reqwest::Client::new();
        let jwks = fetch_jwks(&client, jwks_url.clone()).await?;
        Ok(Self {
            jwks: Arc::new(RwLock::new(jwks)),
            client,
            jwks_url,
            refresh_interval,
            expiration: Arc::new(RwLock::new(std::time::Instant::now() + refresh_interval)),
            is_refreshing: Mutex::new(()),
        })
    }
}

pub async fn fetch_jwks(client: &reqwest::Client, jwks_url: impl IntoUrl) -> Result<JwkSet, super::error::AuthError> {
    let response = client.get(jwks_url).send().await?;
    let jwks = response.json::<JwkSet>().await?;
    Ok(jwks)
}

#[async_trait::async_trait]
impl JwksDiscovery for CachedRemoteJwksDiscovery {
    async fn jwks(&self) -> Result<JwkSet, super::error::AuthError> {
        let now = std::time::Instant::now();
        let expiration = self.expiration.read().await;

        if *expiration > now {
            return Ok(self.jwks.read().await.clone());
        } else {
            drop(expiration);
            if let Ok(_lock) = self.is_refreshing.try_lock() {
                let client = self.client.clone();
                let jwks_url = self.jwks_url.clone();
                let jwks_write = self.jwks.clone();
                let expiration_write = self.expiration.clone();
                let refresh_interval = self.refresh_interval;
                tokio::spawn(async move {
                    if let Ok(jwks) = fetch_jwks(&client, jwks_url).await {
                        *jwks_write.write().await = jwks;
                        *expiration_write.write().await = std::time::Instant::now() + refresh_interval;
                    }
                });
            }

            return Ok(self.jwks.read().await.clone());
        }
    }
}
