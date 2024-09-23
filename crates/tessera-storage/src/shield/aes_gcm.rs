use std::ops::{Deref, DerefMut};
use std::sync::Arc;

use anyhow::anyhow;
use async_trait::async_trait;
use openssl::{
    cipher::{Cipher, CipherRef},
    cipher_ctx::CipherCtx,
};
use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use super::ShieldStorage;
use crate::errors::{ProtectorError, StorageError};
use crate::{Storage, STORAGE_INIT_PATH};
use zeroize::{Zeroize, Zeroizing};

const EPOCH_SIZE: usize = 4;
const KEY_EPOCH: u8 = 1;
const AES_GCM_VERSION: u8 = 0x1;
const AES_BLOCK_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct AESGCMShieldInit {
    version: u32,
    key: Vec<u8>,
}

struct AESGCMShieldState {
    sealed: bool,
    key: Option<Vec<u8>>,
    cipher: Option<&'static CipherRef>,
    cipher_ctx: Option<RwLock<CipherCtx>>,
}

pub struct AESGCMShieldStorage {
    shield_info: Arc<RwLock<AESGCMShieldState>>,
    storage: Arc<dyn Storage>,
}

#[async_trait]
impl Storage for AESGCMShieldStorage {
    async fn get(&self, path: &str) -> Result<Vec<u8>, StorageError> {
        self.storage.get(path).await
    }

    async fn set(&self, path: &str, value: &[u8]) -> Result<(), StorageError> {
        self.storage.set(path, value).await
    }

    async fn delete(&self, path: &str) -> Result<(), StorageError> {
        self.storage.delete(path).await
    }

    async fn list(&self) -> Result<Vec<String>, StorageError> {
        self.storage.list().await
    }
}

#[async_trait]
impl ShieldStorage for AESGCMShieldStorage {
    async fn initialized(&self) -> Result<bool, ProtectorError> {
        let res = self.storage.get(STORAGE_INIT_PATH).await;
        match res {
            Ok(_) => Ok(true),
            Err(StorageError::KeyNotFound) => Ok(false),
            Err(e) => Err(ProtectorError::Storage(e)),
        }
    }

    async fn initialize(&self, kek: &[u8]) -> Result<(), ProtectorError> {
        let (min, max) = self.key_length();
        if kek.len() < min || kek.len() > max {
            return Err(ProtectorError::KeySizeInvalid);
        }

        // Check if already initialized
        let inited = self.initialized().await?;
        if inited {
            return Err(ProtectorError::AlreadyInitialized);
        }

        // the encrypt_key variable will be zeroized automatically on drop
        let encrypt_key = self.generate_key()?;

        let shield_int = AESGCMShieldInit { version: 1, key: encrypt_key.to_vec() };

        let serialized_shield_init = serde_json::to_string(&shield_int)?;

        self.init_cipher(kek).await?;

        let value = self.encrypt(serialized_shield_init.as_bytes()).await?;

        self.storage.set(STORAGE_INIT_PATH, &value).await?;

        self.reset_cipher().await?;

        Ok(())
    }

    fn generate_key(&self) -> Result<Zeroizing<Vec<u8>>, ProtectorError> {
        let key_size = 2 * AES_BLOCK_SIZE;
        // will be zeroized on drop
        let mut buf = Zeroizing::new(vec![0u8; key_size]);

        thread_rng().fill(buf.deref_mut().as_mut_slice());
        Ok(buf)
    }

    fn key_length(&self) -> (usize, usize) {
        (AES_BLOCK_SIZE, 2 * AES_BLOCK_SIZE)
    }

    async fn armored(&self) -> Result<bool, ProtectorError> {
        let shield_info = self.shield_info.read().await;
        Ok(shield_info.sealed)
    }

    async fn disarm(&self, kek: &[u8]) -> Result<(), ProtectorError> {
        let sealed = self.armored().await?;
        if !sealed {
            return Ok(());
        }

        let value = self.storage.get(STORAGE_INIT_PATH).await?;
        self.init_cipher(kek).await?;

        let value = self.decrypt(value.as_slice()).await?;
        let shield_init: AESGCMShieldInit = serde_json::from_slice(value.as_slice())?;

        self.init_cipher(shield_init.key.as_slice()).await?;

        let mut shield_info = self.shield_info.write().await;
        shield_info.sealed = false;

        Ok(())
    }

    async fn armor(&self) -> Result<(), ProtectorError> {
        self.reset_cipher().await?;
        let mut shield_info = self.shield_info.write().await;
        shield_info.sealed = true;
        Ok(())
    }
}

impl AESGCMShieldStorage {
    pub fn new(physical: Arc<dyn Storage>) -> Self {
        Self {
            storage: physical,
            shield_info: Arc::new(RwLock::new(AESGCMShieldState {
                sealed: true,
                key: None,
                cipher: None,
                cipher_ctx: None,
            })),
        }
    }

    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        let shield_info = self.shield_info.read().await;
        if shield_info.key.is_none() || shield_info.cipher_ctx.is_none() || shield_info.cipher.is_none() {
            return Err(ProtectorError::NotInitialized);
        }

        let cipher = shield_info.cipher.unwrap();
        let mut cipher_ctx = shield_info.cipher_ctx.as_ref().unwrap().write().await;
        let key = Zeroizing::new(shield_info.key.clone().unwrap());

        // Assuming nonce size is the same as IV size
        let nonce_size = cipher.iv_length();

        // Generate a random nonce
        let mut nonce = Zeroizing::new(vec![0u8; nonce_size]);
        thread_rng().fill(nonce.deref_mut().as_mut_slice());

        // Encrypt
        let mut ciphertext = vec![0u8; plaintext.len()];
        cipher_ctx
            .encrypt_init(Some(cipher), Some(key.deref().as_slice()), Some(nonce.deref().as_slice()))
            .map_err(|e| ProtectorError::Other(anyhow!(e)))?;
        cipher_ctx.set_padding(false);
        let len = cipher_ctx
            .cipher_update(plaintext, Some(&mut ciphertext))
            .map_err(|e| ProtectorError::Other(anyhow!(e)))?;
        let _final_len =
            cipher_ctx.cipher_final(&mut ciphertext[len..]).map_err(|e| ProtectorError::Other(anyhow!(e)))?;

        let tag_size = cipher_ctx.tag_length();
        let mut tag = vec![0u8; tag_size];
        cipher_ctx.tag(tag.as_mut_slice()).map_err(|e| ProtectorError::Other(anyhow!(e)))?;

        let size: usize = EPOCH_SIZE + 1 + nonce_size + ciphertext.len() + tag_size;
        let mut out = vec![0u8; size];

        out[3] = KEY_EPOCH;
        out[4] = AES_GCM_VERSION;
        out[5..5 + nonce_size].copy_from_slice(nonce.deref().as_slice());
        out[5 + nonce_size..5 + nonce_size + ciphertext.len()].copy_from_slice(ciphertext.as_slice());
        out[5 + nonce_size + ciphertext.len()..size].copy_from_slice(tag.as_slice());

        Ok(out)
    }

    async fn decrypt(&self, ciphertext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        let shield_info = self.shield_info.read().await;
        if shield_info.key.is_none() || shield_info.cipher_ctx.is_none() || shield_info.cipher.is_none() {
            return Err(ProtectorError::NotInitialized);
        }

        if ciphertext[0] != 0 || ciphertext[1] != 0 || ciphertext[2] != 0 || ciphertext[3] != KEY_EPOCH {
            return Err(ProtectorError::Other(anyhow!("Invalid key epoch in ciphertext")));
        }

        let cipher = shield_info.cipher.unwrap();
        let mut cipher_ctx = shield_info.cipher_ctx.as_ref().unwrap().write().await;
        let key = Zeroizing::new(shield_info.key.clone().unwrap());
        let nonce_size = cipher.iv_length();

        if ciphertext[4] != AES_GCM_VERSION {
            return Err(ProtectorError::Other(anyhow!("Invalid AES-GCM version in ciphertext")));
        }

        let nonce = &ciphertext[5..5 + nonce_size];

        cipher_ctx
            .decrypt_init(Some(cipher), Some(key.deref().as_slice()), Some(nonce))
            .map_err(|e| ProtectorError::Other(anyhow!(e)))?;
        cipher_ctx.set_padding(false);

        let tag_size = cipher_ctx.tag_length();
        let raw = &ciphertext[5 + nonce_size..ciphertext.len() - tag_size];
        let tag = &ciphertext[ciphertext.len() - tag_size..ciphertext.len()];
        let size = ciphertext.len() - 5 - nonce_size - tag_size;
        let mut out = vec![0u8; size];

        cipher_ctx.set_tag(tag).map_err(|e| ProtectorError::Other(anyhow!(e)))?;
        let len = cipher_ctx.cipher_update(raw, Some(&mut out)).map_err(|e| ProtectorError::Other(anyhow!(e)))?;
        let final_len = cipher_ctx.cipher_final(&mut out[len..]).map_err(|e| ProtectorError::Other(anyhow!(e)))?;
        out.truncate(len + final_len);

        Ok(out)
    }

    async fn init_cipher(&self, key: &[u8]) -> Result<(), ProtectorError> {
        let cipher_ctx = CipherCtx::new().map_err(|e| ProtectorError::Other(anyhow!(e)))?;
        let mut shield_info = self.shield_info.write().await;
        shield_info.key = Some(key.to_vec());
        shield_info.cipher = Some(Cipher::aes_256_gcm());
        shield_info.cipher_ctx = Some(RwLock::new(cipher_ctx));
        Ok(())
    }

    async fn reset_cipher(&self) -> Result<(), ProtectorError> {
        let mut shield_info = self.shield_info.write().await;
        // Zeroize it explicitly
        shield_info.key.zeroize();
        shield_info.key = None;
        shield_info.cipher = None;
        shield_info.cipher_ctx = None;
        Ok(())
    }
}
