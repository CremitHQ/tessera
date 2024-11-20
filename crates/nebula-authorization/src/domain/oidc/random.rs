use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use rand::{rngs::OsRng, RngCore as _};

pub fn random_code() -> String {
    random(16)
}

pub fn random(size: usize) -> String {
    let mut bytes = vec![0u8; size];
    OsRng.fill_bytes(&mut bytes);

    let first = bytes[0] % 26 + b'a';
    let encoded = URL_SAFE_NO_PAD.encode(&bytes);
    format!("{}{}", first as char, encoded)
}
