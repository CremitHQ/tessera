pub mod aes;

#[trait_variant::make(Shield: Send)]
pub trait LocalShield {
    type ShieldError: std::error::Error;
    type Key: ?Sized;
    type Value: ToOwned + ?Sized;
    async fn initialize(&self, key: &Self::Key) -> Result<(), Self::ShieldError>;
    async fn armor(&self) -> Result<(), Self::ShieldError>;
    async fn disarm(&self, key: &Self::Key) -> Result<(), Self::ShieldError>;
    async fn generate_key(&self) -> Result<<Self::Value as ToOwned>::Owned, Self::ShieldError>;
}
