use std::ops::{Deref, DerefMut};

use super::Shield;
use crate::Storage;
use aes_gcm::{aead::Aead as _, Aes256Gcm, Key, KeyInit as _, Nonce};
use rand::{rngs::OsRng, Rng as _};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use tokio::sync::RwLock;
use zeroize::ZeroizeOnDrop;

const AES_GCM_VERSION: u8 = 1;
const AES_BLOCK_SIZE: usize = 32;
const SHIELD_KEY_PATH: &str = "/shield/key";

pub struct AESShieldStorage<S: Storage> {
    inner: S,
    shield_key: RwLock<Option<AESShieldKey>>,
}

#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct AESShieldKey {
    version: u8,
    key: ZeroizingKey,
}

#[derive(ZeroizeOnDrop, Serialize, Deserialize)]
pub struct ZeroizingKey(Vec<u8>);

impl ZeroizingKey {
    pub fn new(key: Vec<u8>) -> Self {
        Self(key)
    }
}

impl Deref for ZeroizingKey {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl DerefMut for ZeroizingKey {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[derive(Error, Debug)]
pub enum AESShieldError {
    #[error("error while generating shield key: {0}")]
    GenerateKey(#[from] GenerateKeyErrorKind),

    #[error("error while initializing shield key: {0}")]
    InitializeShieldKey(#[from] InitializationErrorKind),

    #[error("error while disarming shield key: {0}")]
    DisarmShieldKey(#[from] DisarmErrorKind),

    #[error("shield storage error: {0}")]
    StorageError(#[from] AESShieldStorageError),

    #[error("no shield key")]
    NoShieldKey,
}

#[derive(Error, Debug)]
pub enum InitializationErrorKind {
    #[error("invalid key size (expected: {0} bytes, got: {1} bytes)")]
    InvalidKeySize(usize, usize),

    #[error("failed to serialize shield key ({0})")]
    SerializeShieldKey(#[from] rmp_serde::encode::Error),

    #[error("failed to deserialize shield key ({0})")]
    DeserializeShieldKey(#[from] rmp_serde::decode::Error),

    #[error(transparent)]
    AESGCMError(#[from] AESGCMErrorKind),

    #[error("failed to read shield key ({0})")]
    ReadShieldKey(String),

    #[error("failed to write shield key ({0})")]
    WriteShieldKey(String),
}

#[derive(Error, Debug)]
pub enum DisarmErrorKind {
    #[error(transparent)]
    AESGCMError(#[from] AESGCMErrorKind),

    #[error("failed to read shield key ({0})")]
    ReadShieldKey(String),
}

#[derive(Error, Debug)]
pub enum GenerateKeyErrorKind {
    #[error("failed to fill random data ({0})")]
    FillRandomData(#[from] rand::Error),
}

#[derive(Error, Debug)]
pub enum AESGCMErrorKind {
    #[error("encryption error ({0})")]
    Encryption(aes_gcm::Error),

    #[error("decryption error ({0})")]
    Decryption(aes_gcm::Error),
}

impl<S: Storage> AESShieldStorage<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, shield_key: RwLock::new(None) }
    }
}

impl<S: Storage<Key = str, Value = [u8]> + Sync> Shield for AESShieldStorage<S> {
    type ShieldError = AESShieldError;
    type Key = <S as Storage>::Value;
    type ZeroizingKey = ZeroizingKey;

    async fn initialize(&self, master_key: &Self::Key) -> Result<(), Self::ShieldError> {
        let shield_key =
            self.inner.get(SHIELD_KEY_PATH).await.map_err(|e| InitializationErrorKind::ReadShieldKey(e.to_string()))?;

        // If shield_key is already set in the storage, we return `Ok(())` to maintain idempotency.
        // This is intentional—no need to throw an error here.
        if shield_key.is_some() {
            return Ok(());
        }

        let key_size = master_key.len();
        if key_size != AES_BLOCK_SIZE {
            return Err(InitializationErrorKind::InvalidKeySize(AES_BLOCK_SIZE, key_size).into());
        }
        let storage_key = self.generate_key().await?;
        let shield_key = AESShieldKey { version: AES_GCM_VERSION, key: storage_key };
        let shield_key = rmp_serde::to_vec(&shield_key).map_err(InitializationErrorKind::SerializeShieldKey)?;
        let shield_key = self.encrypt(master_key, &shield_key).map_err(InitializationErrorKind::AESGCMError)?;
        self.inner
            .set(SHIELD_KEY_PATH, &shield_key)
            .await
            .map_err(|e| InitializationErrorKind::WriteShieldKey(e.to_string()))?;

        Ok(())
    }

    async fn armor(&self) -> Result<(), Self::ShieldError> {
        let mut shield_key = self.shield_key.write().await;
        let shield_key = shield_key.deref_mut();
        *shield_key = None;
        Ok(())
    }

    async fn disarm(&self, master_key: &Self::Key) -> Result<(), Self::ShieldError> {
        if !self.is_armored().await {
            return Ok(());
        }

        let armored_shield_key = self
            .inner
            .get(SHIELD_KEY_PATH)
            .await
            .map_err(|e| DisarmErrorKind::ReadShieldKey(e.to_string()))?
            .ok_or(AESShieldError::NoShieldKey)?;

        // We manually zeroize `shield_key` to make sure it doesn't linger in memory.
        let shield_key =
            ZeroizingKey::new(self.decrypt(master_key, &armored_shield_key).map_err(DisarmErrorKind::AESGCMError)?);
        let shield_key: AESShieldKey =
            rmp_serde::from_slice(&shield_key).map_err(InitializationErrorKind::DeserializeShieldKey)?;

        let mut shield = self.shield_key.write().await;
        let shield = shield.deref_mut();
        *shield = Some(shield_key);

        Ok(())
    }

    async fn generate_key(&self) -> Result<ZeroizingKey, Self::ShieldError> {
        let mut buf = vec![0; AES_BLOCK_SIZE];
        OsRng.fill(buf.deref_mut());
        Ok(ZeroizingKey::new(buf))
    }
}

impl<S: Storage> AESShieldStorage<S> {
    async fn is_armored(&self) -> bool {
        self.shield_key.read().await.is_none()
    }

    fn encrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, AESGCMErrorKind> {
        debug_assert!(key.len() == AES_BLOCK_SIZE);
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let mut nonce_vec = [0u8; 12];
        OsRng.fill(&mut nonce_vec);

        let nonce = Nonce::from_slice(nonce_vec.as_ref());
        let mut ct = cipher.encrypt(nonce, data.as_ref()).map_err(AESGCMErrorKind::Encryption)?;
        ct.splice(0..0, nonce.iter().cloned()); // first 12 bytes are nonce i.e. [nonce|ciphertext]
        Ok(ct)
    }

    fn decrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, AESGCMErrorKind> {
        debug_assert!(key.len() == AES_BLOCK_SIZE);
        let nonce = data[..12].as_ref();
        let ciphertext = data.to_vec().split_off(12);
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);
        let result = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(AESGCMErrorKind::Decryption)?;
        Ok(result)
    }
}

impl<S: Storage<Key = str, Value = [u8]> + Sync> Storage for AESShieldStorage<S> {
    type StorageError = AESShieldStorageError;
    type Key = <S as Storage>::Key;
    type Value = <S as Storage>::Value;

    async fn get(&self, key: &str) -> Result<Option<Vec<u8>>, Self::StorageError> {
        if self.is_armored().await {
            return Err(AESShieldStorageError::ShieldArmored);
        }
        let shield_key = self.shield_key.read().await;
        let shield_key = shield_key.as_ref().unwrap(); // Since we've already validated this earlier with is_armored(), it's safe to use unwrap() here.
        debug_assert!(shield_key.key.len() == AES_BLOCK_SIZE);
        let ciphertext = self.inner.get(key).await.map_err(|e| AESShieldStorageError::StorageError(e.to_string()))?;

        match ciphertext {
            Some(ciphertext) => {
                let plaintext = self.decrypt(&shield_key.key, &ciphertext)?;
                Ok(Some(plaintext))
            }
            None => Ok(None),
        }
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<(), Self::StorageError> {
        if self.is_armored().await {
            return Err(AESShieldStorageError::ShieldArmored);
        }
        let shield_key = self.shield_key.read().await;
        let shield_key = shield_key.as_ref().unwrap(); // Since we've already validated this earlier with is_armored(), it's safe to use unwrap() here.
        debug_assert!(shield_key.key.len() == AES_BLOCK_SIZE);
        let ciphertext = self.encrypt(&shield_key.key, value)?;
        self.inner.set(key, &ciphertext).await.map_err(|e| AESShieldStorageError::StorageError(e.to_string()))
    }

    async fn delete(&self, key: &str) -> Result<(), Self::StorageError> {
        if self.is_armored().await {
            return Err(AESShieldStorageError::ShieldArmored);
        }

        self.inner.delete(key).await.map_err(|e| AESShieldStorageError::StorageError(e.to_string()))
    }

    async fn list(&self, prefix: &str) -> Result<impl IntoIterator<Item = String>, Self::StorageError> {
        if self.is_armored().await {
            return Err(AESShieldStorageError::ShieldArmored);
        }

        self.inner.list(prefix).await.map_err(|e| AESShieldStorageError::StorageError(e.to_string()))
    }
}

#[derive(Error, Debug)]
pub enum AESShieldStorageError {
    #[error("shield has already been armored")]
    ShieldArmored,

    #[error("storage error occurred ({0})")]
    StorageError(String),

    #[error(transparent)]
    AESGCMError(#[from] AESGCMErrorKind),
}
