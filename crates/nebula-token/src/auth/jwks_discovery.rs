use std::{sync::atomic::AtomicBool, time::Duration};

use crate::jwk::jwk_set::JwkSet;
use reqwest::IntoUrl;
use tokio::sync::RwLock;

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
    jwks: RwLock<JwkSet>,
    client: reqwest::Client,
    jwks_url: url::Url,
    refresh_interval: Duration,
    expiration: RwLock<Option<std::time::Instant>>,
    is_refreshing: AtomicBool,
}

impl CachedRemoteJwksDiscovery {
    pub async fn new(jwks_url: url::Url, refresh_interval: Duration) -> Result<Self, super::error::AuthError> {
        let client = reqwest::Client::new();
        let jwks = fetch_jwks(&client, jwks_url.clone()).await?;
        Ok(Self {
            jwks: RwLock::new(jwks),
            client,
            jwks_url,
            refresh_interval,
            expiration: RwLock::new(None),
            is_refreshing: AtomicBool::new(false),
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
        {
            let expiration = self.expiration.read().await;
            if let Some(expiration) = *expiration {
                if expiration > std::time::Instant::now()
                    || self.is_refreshing.load(std::sync::atomic::Ordering::Acquire)
                {
                    return Ok(self.jwks.read().await.clone());
                }
            }
        }

        self.is_refreshing.store(true, std::sync::atomic::Ordering::Release);
        let jwks = fetch_jwks(&self.client, self.jwks_url.clone()).await?;
        *self.jwks.write().await = jwks.clone();
        *self.expiration.write().await = Some(std::time::Instant::now() + self.refresh_interval);
        self.is_refreshing.store(false, std::sync::atomic::Ordering::Release);
        Ok(jwks)
    }
}
