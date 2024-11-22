pub mod backend;

#[cfg(feature = "shield")]
pub mod shield;

#[trait_variant::make(Storage: Send)]
pub trait LocalStorage {
    type Key: ToOwned + ?Sized;
    type Value: ToOwned + ?Sized;
    type StorageError: std::error::Error;
    async fn get(&self, key: &Self::Key) -> Result<Option<<Self::Value as ToOwned>::Owned>, Self::StorageError>;
    async fn set(&self, key: &Self::Key, value: &Self::Value) -> Result<(), Self::StorageError>;
    async fn delete(&self, key: &Self::Key) -> Result<(), Self::StorageError>;
    async fn list(
        &self,
        prefix: &Self::Key,
    ) -> Result<impl IntoIterator<Item = <Self::Key as ToOwned>::Owned>, Self::StorageError>;
}
