use crate::{errors::ProtectorError, Storage};
use async_trait::async_trait;
use zeroize::Zeroizing;
pub mod aes_gcm;

#[async_trait]
pub trait ShieldStorage: Storage + Send + Sync {
    async fn initialized(&self) -> Result<bool, ProtectorError>;
    async fn initialize(&self, key: &[u8]) -> Result<(), ProtectorError>;
    fn key_length(&self) -> (usize, usize);
    async fn armored(&self) -> Result<bool, ProtectorError>;
    async fn armor(&self) -> Result<(), ProtectorError>;
    async fn disarm(&self, key: &[u8]) -> Result<(), ProtectorError>;
    fn generate_key(&self) -> Result<Zeroizing<Vec<u8>>, ProtectorError>;
}
