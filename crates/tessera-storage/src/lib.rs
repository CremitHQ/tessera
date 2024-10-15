pub mod shield;
pub mod storages;

#[trait_variant::make(Storage: Send + Sync)]
pub trait LocalStorage {
    type Key: ToOwned + ?Sized + Sync;
    type Value: ToOwned + ?Sized + Sync;
    type StorageError: std::error::Error;
    async fn get(&self, key: &Self::Key) -> Result<<Self::Value as ToOwned>::Owned, Self::StorageError>;
    async fn set(&self, key: &Self::Key, value: &Self::Value) -> Result<(), Self::StorageError>;
    async fn delete(&self, key: &Self::Key) -> Result<(), Self::StorageError>;
    async fn list(
        &self,
        prefix: &Self::Key,
    ) -> Result<impl IntoIterator<Item = <Self::Key as ToOwned>::Owned>, Self::StorageError>;
}
