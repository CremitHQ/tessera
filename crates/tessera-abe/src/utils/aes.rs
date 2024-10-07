use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};

use crate::error::ABEError;
use rand::thread_rng;
use rand::Rng;
use std::convert::TryInto;

/// Key Encapsulation Mechanism (AES-256 Encryption Function)
pub fn encrypt_symmetric<G: std::convert::Into<Vec<u8>>>(msg: G, data: &[u8]) -> Result<Vec<u8>, ABEError> {
    let mut rng = thread_rng();
    // 256bit key hashed/derived from _msg G
    let kdf = kdf(msg);
    let key = Key::<Aes256Gcm>::from_slice(kdf.as_slice());
    let cipher = Aes256Gcm::new(key);
    // 96bit random noise
    let nonce_vec: Vec<u8> = (0..12).into_iter().map(|_| rng.gen()).collect(); // 12*u8 = 96 Bit
    let nonce = Nonce::from_slice(nonce_vec.as_ref());
    match cipher.encrypt(nonce, data.as_ref()) {
        Ok(mut ct) => {
            ct.splice(0..0, nonce.iter().cloned()); // first 12 bytes are nonce i.e. [nonce|ciphertext]
            Ok(ct)
        }
        Err(e) => Err(ABEError::new(&format!("encryption error: {:?}", e.to_string()))),
    }
}

/// Key Encapsulation Mechanism (AES-256 Decryption Function)
pub fn decrypt_symmetric<G: std::convert::Into<Vec<u8>>>(msg: G, _nonce_ct: &[u8]) -> Result<Vec<u8>, ABEError> {
    let ciphertext = _nonce_ct.to_vec().split_off(12); // 12*u8 = 96 Bit
    let nonce_vec: [u8; 12] = match _nonce_ct[..12].try_into() {
        // first 12 bytes are nonce i.e. [nonce|ciphertext]
        Ok(iv) => iv,
        Err(_) => return Err(ABEError::new("Error extracting IV from ciphertext: Expected an IV of 16 bytes")), // this REALLY shouldn't happen.
    };
    // 256bit key hashed/derived from _msg G
    let kdf = kdf(msg);
    let key = Key::<Aes256Gcm>::from_slice(kdf.as_slice());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_vec.as_ref());
    match cipher.decrypt(nonce, ciphertext.as_ref()) {
        Ok(data) => Ok(data),
        Err(e) => Err(ABEError::new(&format!("decryption error: {:?}", e.to_string()))),
    }
}

/// Key derivation function - turns anything implementing the `Into<Vec<u8>` trait into a key for AES-256
fn kdf<T: std::convert::Into<Vec<u8>>>(data: T) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::default();
    hasher.update(data.into());
    hasher.finalize().to_vec()
}
