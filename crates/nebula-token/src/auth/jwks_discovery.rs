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
    jwks: Arc<RwLock<Option<JwkSet>>>,
    client: reqwest::Client,
    jwks_url: url::Url,
    refresh_interval: Duration,
    expiration: Arc<RwLock<std::time::Instant>>,
    is_refreshing: Mutex<()>,
    is_initialized: Mutex<bool>,
}

impl CachedRemoteJwksDiscovery {
    pub fn new(jwks_url: url::Url, refresh_interval: Duration) -> Self {
        let client = reqwest::Client::new();
        Self {
            jwks: Arc::new(RwLock::new(None)),
            client,
            jwks_url,
            refresh_interval,
            expiration: Arc::new(RwLock::new(std::time::Instant::now() - refresh_interval)),
            is_refreshing: Mutex::new(()),
            is_initialized: Mutex::new(false),
        }
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

        if *expiration <= now {
            drop(expiration);

            let mut is_initialized = self.is_initialized.lock().await;
            if !*is_initialized {
                *is_initialized = true;
                let jwks = fetch_jwks(&self.client, self.jwks_url.clone()).await?;
                *self.jwks.write().await = Some(jwks);
                *self.expiration.write().await = std::time::Instant::now() + self.refresh_interval;
            }
            drop(is_initialized);

            if let Ok(_lock) = self.is_refreshing.try_lock() {
                let client = self.client.clone();
                let jwks_url = self.jwks_url.clone();
                let jwks_write = self.jwks.clone();
                let expiration_write = self.expiration.clone();
                let refresh_interval = self.refresh_interval;
                tokio::spawn(async move {
                    if let Ok(jwks) = fetch_jwks(&client, jwks_url).await {
                        *jwks_write.write().await = Some(jwks);
                        *expiration_write.write().await = std::time::Instant::now() + refresh_interval;
                    }
                });
            }
        }
        match self.jwks.read().await.as_ref() {
            Some(jwks) => return Ok(jwks.clone()),
            None => return Err(super::error::AuthError::NoJwk),
        }
    }
}
