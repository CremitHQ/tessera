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

use super::Protector;
use crate::errors::{ProtectorError, StorageError};
use crate::{Storage, STORAGE_INIT_PATH};
use zeroize::{Zeroize, Zeroizing};

const EPOCH_SIZE: usize = 4;
const KEY_EPOCH: u8 = 1;
const AES_GCM_VERSION: u8 = 0x1;
const AES_BLOCK_SIZE: usize = 16;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, Zeroize)]
#[zeroize(drop)]
struct ProtectorInit {
    version: u32,
    key: Vec<u8>,
}

struct ProtectorState {
    sealed: bool,
    key: Option<Vec<u8>>,
    cipher: Option<&'static CipherRef>,
    cipher_ctx: Option<RwLock<CipherCtx>>,
}

pub struct AESGCMProtector {
    barrier_info: Arc<RwLock<ProtectorState>>,
    backend: Arc<dyn Storage>,
}

#[async_trait]
impl Protector for AESGCMProtector {
    async fn initialized(&self) -> Result<bool, ProtectorError> {
        let res = self.backend.get(STORAGE_INIT_PATH).await;
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

        let barrier_init = ProtectorInit { version: 1, key: encrypt_key.to_vec() };

        let serialized_barrier_init = serde_json::to_string(&barrier_init)?;

        self.init_cipher(kek).await?;

        let value = self.encrypt(serialized_barrier_init.as_bytes()).await?;

        self.backend.set(STORAGE_INIT_PATH, &value).await?;

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

    async fn protected(&self) -> Result<bool, ProtectorError> {
        let barrier_info = self.barrier_info.read().await;
        Ok(barrier_info.sealed)
    }

    async fn release(&self, kek: &[u8]) -> Result<(), ProtectorError> {
        let sealed = self.protected().await?;
        if !sealed {
            return Ok(());
        }

        let value = self.backend.get(STORAGE_INIT_PATH).await?;
        self.init_cipher(kek).await?;

        let value = self.decrypt(value.as_slice()).await?;
        let barrier_init: ProtectorInit = serde_json::from_slice(value.as_slice())?;

        // the barrier_init.key is the real encryption key generated in init().
        // the whole barrier_init will be zeroized on drop, so there is no special
        // zeroizing logic on barrier_init.key.
        self.init_cipher(barrier_init.key.as_slice()).await?;

        let mut barrier_info = self.barrier_info.write().await;
        barrier_info.sealed = false;

        Ok(())
    }

    async fn protect(&self) -> Result<(), ProtectorError> {
        self.reset_cipher().await?;
        let mut barrier_info = self.barrier_info.write().await;
        barrier_info.sealed = true;
        Ok(())
    }
}

impl AESGCMProtector {
    pub fn new(physical: Arc<dyn Storage>) -> Self {
        Self {
            backend: physical,
            barrier_info: Arc::new(RwLock::new(ProtectorState {
                sealed: true,
                key: None,
                cipher: None,
                cipher_ctx: None,
            })),
        }
    }

    async fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>, ProtectorError> {
        let barrier_info = self.barrier_info.read().await;
        if barrier_info.key.is_none() || barrier_info.cipher_ctx.is_none() || barrier_info.cipher.is_none() {
            return Err(ProtectorError::NotInitialized);
        }

        let cipher = barrier_info.cipher.unwrap();
        let mut cipher_ctx = barrier_info.cipher_ctx.as_ref().unwrap().write().await;
        let key = Zeroizing::new(barrier_info.key.clone().unwrap());

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
        let barrier_info = self.barrier_info.read().await;
        if barrier_info.key.is_none() || barrier_info.cipher_ctx.is_none() || barrier_info.cipher.is_none() {
            return Err(ProtectorError::NotInitialized);
        }

        if ciphertext[0] != 0 || ciphertext[1] != 0 || ciphertext[2] != 0 || ciphertext[3] != KEY_EPOCH {
            return Err(ProtectorError::Other(anyhow!("Invalid key epoch in ciphertext")));
        }

        let cipher = barrier_info.cipher.unwrap();
        let mut cipher_ctx = barrier_info.cipher_ctx.as_ref().unwrap().write().await;
        let key = Zeroizing::new(barrier_info.key.clone().unwrap());
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
        let mut barrier_info = self.barrier_info.write().await;
        barrier_info.key = Some(key.to_vec());
        barrier_info.cipher = Some(Cipher::aes_256_gcm());
        barrier_info.cipher_ctx = Some(RwLock::new(cipher_ctx));
        Ok(())
    }

    async fn reset_cipher(&self) -> Result<(), ProtectorError> {
        let mut barrier_info = self.barrier_info.write().await;
        // Zeroize it explicitly
        barrier_info.key.zeroize();
        barrier_info.key = None;
        barrier_info.cipher = None;
        barrier_info.cipher_ctx = None;
        Ok(())
    }
}
