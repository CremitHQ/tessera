use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use rand_core::RngCore as _;

use crate::curves::PairingCurve;
use crate::error::{ABEError, AESGCMError};
use std::convert::TryInto;

/// Key Encapsulation Mechanism (AES-256 Encryption Function)
pub fn encrypt_symmetric<'a, T: PairingCurve, G: std::convert::Into<Vec<u8>>>(
    rng: &mut T::Rng,
    msg: G,
    data: &[u8],
) -> Result<Vec<u8>, ABEError<'a>> {
    // 256bit key hashed/derived from _msg G
    let kdf = kdf(msg);
    let key = Key::<Aes256Gcm>::from_slice(kdf.as_slice());
    let cipher = Aes256Gcm::new(key);

    // 96bit random noise
    let mut nonce_vec = [0u8; 12];
    rng.fill_bytes(&mut nonce_vec);

    let nonce = Nonce::from_slice(nonce_vec.as_ref());
    let mut ct = cipher.encrypt(nonce, data.as_ref()).map_err(AESGCMError::EncryptionError)?;
    ct.splice(0..0, nonce.iter().cloned()); // first 12 bytes are nonce i.e. [nonce|ciphertext]
    Ok(ct)
}

/// Key Encapsulation Mechanism (AES-256 Decryption Function)
pub fn decrypt_symmetric<'a, G: std::convert::Into<Vec<u8>>>(msg: G, nonce_ct: &[u8]) -> Result<Vec<u8>, ABEError<'a>> {
    let ciphertext = nonce_ct.to_vec().split_off(12); // 12*u8 = 96 Bit
    let nonce_vec: [u8; 12] =
        nonce_ct[..12].try_into().map_err(|_| ABEError::AESGCMError(AESGCMError::NonceSizeMismatch))?;
    // 256bit key hashed/derived from _msg G
    let kdf = kdf(msg);
    let key = Key::<Aes256Gcm>::from_slice(kdf.as_slice());
    let cipher = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(nonce_vec.as_ref());
    let result = cipher.decrypt(nonce, ciphertext.as_ref()).map_err(AESGCMError::DecryptionError)?;
    Ok(result)
}

/// Key derivation function - turns anything implementing the `Into<Vec<u8>` trait into a key for AES-256
fn kdf<T: std::convert::Into<Vec<u8>>>(data: T) -> Vec<u8> {
    use sha3::{Digest, Sha3_256};
    let mut hasher = Sha3_256::default();
    hasher.update(data.into());
    hasher.finalize().to_vec()
}
