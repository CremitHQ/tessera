use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, Eq, PartialEq)]
pub struct Nonce(String);

impl From<Nonce> for String {
    fn from(nonce: Nonce) -> Self {
        nonce.0
    }
}

impl Nonce {
    pub fn new<T: Into<String>>(value: T) -> Self {
        Self(value.into())
    }
}
