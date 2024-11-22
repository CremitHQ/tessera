use zeroize::ZeroizeOnDrop;

pub mod aes;

#[trait_variant::make(Shield: Send)]
pub trait LocalShield {
    type ShieldError: std::error::Error;
    type Key: ToOwned + ?Sized;
    type ZeroizingKey: ZeroizeOnDrop;
    async fn is_initialized(&self) -> Result<bool, Self::ShieldError>;
    async fn initialize(&self, master_key: &Self::Key) -> Result<(), Self::ShieldError>;
    async fn armor(&self) -> Result<(), Self::ShieldError>;
    async fn disarm(&self, master_key: &Self::Key) -> Result<(), Self::ShieldError>;
    async fn generate_key(&self) -> Result<Self::ZeroizingKey, Self::ShieldError>;
}
