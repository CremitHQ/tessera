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
    #[error("Key generation error: {0}")]
    KeyGenerationError(#[from] KeyGenerationError),

    #[error("Initialization error: {0}")]
    InitializationError(#[from] InitializationError),

    #[error(transparent)]
    StorageError(#[from] AESShieldStorageError),

    #[error("AES GCM error: {0}")]
    AESGCMError(#[from] AESGCMError),
}

#[derive(Error, Debug)]
pub enum AESShieldStorageError {
    #[error("Shield has been sealed. Cannot perform operation.")]
    ShieldSealed,

    #[error("Storage error: {}", 0)]
    StorageError(String),

    #[error(transparent)]
    AESGCMError(#[from] AESGCMError),
}

#[derive(Error, Debug)]
pub enum InitializationError {
    #[error("Invalid key size: {0}")]
    InvalidKeySize(usize),

    #[error("Failed to serialize/deserialize shield key: {0}")]
    SerializationError(Box<bincode::ErrorKind>),
}

#[derive(Error, Debug)]
pub enum KeyGenerationError {
    #[error("Failed to fill random data: {0}")]
    FillRandomDataError(#[from] rand::Error),
}

#[derive(Error, Debug)]
pub enum AESGCMError {
    #[error("Encryption error: {0}")]
    EncryptionError(aes_gcm::Error),

    #[error("Decryption error: {0}")]
    DecryptionError(aes_gcm::Error),
}

impl<S: Storage> AESShieldStorage<S> {
    pub fn new(inner: S) -> Self {
        Self { inner, shield_key: RwLock::new(None) }
    }
}

impl<S: Storage<Key = str, Value = [u8]>> Shield for AESShieldStorage<S> {
    type ShieldError = AESShieldError;
    type Key = <S as Storage>::Value;
    type ZeroizingKey = ZeroizingKey;

    async fn initialize(&self, master_key: &Self::Key) -> Result<(), Self::ShieldError> {
        let shield_key =
            self.inner.get(SHIELD_KEY_PATH).await.map_err(|e| AESShieldStorageError::StorageError(e.to_string()))?;

        // If shield_key is empty, we return `Ok(())` to maintain idempotency.
        // This is intentional—no need to throw an error here.
        if !shield_key.is_empty() {
            return Ok(());
        }

        let key_size = master_key.len();
        if key_size != AES_BLOCK_SIZE {
            return Err(InitializationError::InvalidKeySize(key_size).into());
        }
        let storage_key = self.generate_key().await?;
        let shield_key = AESShieldKey { version: AES_GCM_VERSION, key: storage_key };
        let shield_key = bincode::serialize(&shield_key).map_err(InitializationError::SerializationError)?;
        let shield_key = self.encrypt(master_key, &shield_key)?;
        self.inner
            .set(SHIELD_KEY_PATH, &shield_key)
            .await
            .map_err(|e| AESShieldStorageError::StorageError(e.to_string()))?;

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

        let armored_shield_key =
            self.inner.get(SHIELD_KEY_PATH).await.map_err(|e| AESShieldStorageError::StorageError(e.to_string()))?;

        // We manually zeroize `shield_key` to make sure it doesn't linger in memory.
        let shield_key = ZeroizingKey::new(self.decrypt(master_key, &armored_shield_key)?);
        let shield_key: AESShieldKey =
            bincode::deserialize(&shield_key).map_err(InitializationError::SerializationError)?;
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

    fn encrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, AESGCMError> {
        debug_assert!(key.len() == AES_BLOCK_SIZE);
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let mut nonce_vec = [0u8; 12];
        OsRng.fill(&mut nonce_vec);

        let nonce = Nonce::from_slice(nonce_vec.as_ref());
        let mut ct = cipher.encrypt(nonce, data.as_ref()).map_err(AESGCMError::EncryptionError)?;
        ct.splice(0..0, nonce.iter().cloned()); // first 12 bytes are nonce i.e. [nonce|ciphertext]
        Ok(ct)
    }

    fn decrypt(&self, key: &[u8], data: &[u8]) -> Result<Vec<u8>, AESGCMError> {
        debug_assert!(key.len() == AES_BLOCK_SIZE);
        let nonce = data[..12].as_ref();
        let ciphertext = data.to_vec().split_off(12);
        let key = Key::<Aes256Gcm>::from_slice(key);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(nonce);
        let result = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(AESGCMError::DecryptionError)?;
        Ok(result)
    }
}

impl<S: Storage<Key = str, Value = [u8]>> Storage for AESShieldStorage<S> {
    type StorageError = AESShieldStorageError;
    type Key = <S as Storage>::Key;
    type Value = <S as Storage>::Value;

    async fn get(&self, key: &str) -> Result<Vec<u8>, Self::StorageError> {
        if self.is_armored().await {
            return Err(AESShieldStorageError::ShieldSealed);
        }
        let shield_key = self.shield_key.read().await;
        let shield_key = shield_key.as_ref().unwrap(); // Since we've already validated this earlier with is_armored(), it's safe to use unwrap() here.
        debug_assert!(shield_key.key.len() == AES_BLOCK_SIZE);
        let ciphertext = self.inner.get(key).await.map_err(|e| AESShieldStorageError::StorageError(e.to_string()))?;
        let plaintext = self.decrypt(&shield_key.key, &ciphertext)?;

        Ok(plaintext)
    }

    async fn set(&self, key: &str, value: &[u8]) -> Result<(), Self::StorageError> {
        if self.is_armored().await {
            return Err(AESShieldStorageError::ShieldSealed);
        }
        let shield_key = self.shield_key.read().await;
        let shield_key = shield_key.as_ref().unwrap(); // Since we've already validated this earlier with is_armored(), it's safe to use unwrap() here.
        debug_assert!(shield_key.key.len() == AES_BLOCK_SIZE);
        let ciphertext = self.encrypt(&shield_key.key, value)?;
        self.inner.set(key, &ciphertext).await.map_err(|e| AESShieldStorageError::StorageError(e.to_string()))
    }

    async fn delete(&self, key: &str) -> Result<(), Self::StorageError> {
        if self.is_armored().await {
            return Err(AESShieldStorageError::ShieldSealed);
        }

        self.inner.delete(key).await.map_err(|e| AESShieldStorageError::StorageError(e.to_string()))
    }

    async fn list(&self, prefix: &str) -> Result<impl IntoIterator<Item = String>, Self::StorageError> {
        if self.is_armored().await {
            return Err(AESShieldStorageError::ShieldSealed);
        }

        self.inner.list(prefix).await.map_err(|e| AESShieldStorageError::StorageError(e.to_string()))
    }
}
