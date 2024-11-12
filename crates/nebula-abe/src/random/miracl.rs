use nebula_miracl::rand::RAND;
use rand_core::{CryptoRng, RngCore};

pub struct MiraclRng {
    pub inner: RAND,
}

impl CryptoRng for MiraclRng {}

impl Default for MiraclRng {
    fn default() -> Self {
        Self::new()
    }
}

impl MiraclRng {
    pub fn new() -> Self {
        Self { inner: RAND::new() }
    }

    pub fn seed(&mut self, seed: &[u8]) {
        self.inner.seed(seed.len(), seed);
    }

    pub fn get_byte(&mut self) -> u8 {
        self.inner.getbyte()
    }
}

impl RngCore for MiraclRng {
    fn next_u32(&mut self) -> u32 {
        let mut bytes = [0u8; 4];
        self.fill_bytes(&mut bytes);
        u32::from_le_bytes(bytes)
    }

    fn next_u64(&mut self) -> u64 {
        let mut bytes = [0u8; 8];
        self.fill_bytes(&mut bytes);
        u64::from_le_bytes(bytes)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for d in dest {
            *d = self.inner.getbyte();
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest); // MIRACL RNG never fails
        Ok(())
    }
}
