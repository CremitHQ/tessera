use zeroize::ZeroizeOnDrop;

pub mod aes;

#[trait_variant::make(Shield: Send)]
pub trait LocalShield {
    type ShieldError<'error>: std::error::Error;
    type Key: ToOwned + ?Sized;
    type ZeroizingKey: ZeroizeOnDrop;
    async fn initialize<'a>(&self, master_key: &Self::Key) -> Result<(), Self::ShieldError<'a>>;
    async fn armor<'a>(&self) -> Result<(), Self::ShieldError<'a>>;
    async fn disarm<'a>(&self, master_key: &Self::Key) -> Result<(), Self::ShieldError<'a>>;
    async fn generate_key<'a>(&self) -> Result<Self::ZeroizingKey, Self::ShieldError<'a>>;
}
