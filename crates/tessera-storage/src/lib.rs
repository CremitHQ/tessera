use async_trait::async_trait;
pub mod errors;
pub mod shield;

pub const STORAGE_INIT_PATH: &str = "storage/init";
type Value = Vec<u8>;

#[async_trait]
pub trait Storage: Send + Sync {
    async fn get(&self, key: &str) -> Result<Value, errors::StorageError>;
    async fn set(&self, key: &str, value: &[u8]) -> Result<(), errors::StorageError>;
    async fn delete(&self, key: &str) -> Result<(), errors::StorageError>;
    async fn list(&self) -> Result<Vec<String>, errors::StorageError>;
}
