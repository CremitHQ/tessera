use rand_core::{CryptoRng, RngCore};
pub mod miracl;

pub trait Random {
    type Rng: RngCore + CryptoRng;
    fn random(rng: &mut Self::Rng) -> Self;
}
