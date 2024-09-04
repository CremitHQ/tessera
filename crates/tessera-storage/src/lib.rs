use async_trait::async_trait;
pub mod errors;

type Value = Vec<u8>;

#[async_trait]
pub trait Storage {
    async fn get(&self, key: &str) -> Result<Value, errors::StorageError>;
    async fn set(&self, key: &str, value: Value) -> Result<(), errors::StorageError>;
    async fn delete(&self, key: &str) -> Result<(), errors::StorageError>;
    async fn list(&self) -> Result<Vec<String>, errors::StorageError>;
}
