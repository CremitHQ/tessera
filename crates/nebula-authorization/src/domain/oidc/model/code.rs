use serde::{Deserialize, Serialize};
use std::ops::Deref;

use crate::domain::oidc::random::random_code;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Deserialize, Serialize)]
pub struct Code(String);

impl Code {
    pub fn random() -> Self {
        Code::default()
    }
}

impl<T: Into<String>> From<T> for Code {
    fn from(c: T) -> Self {
        Self(c.into())
    }
}

impl AsRef<str> for Code {
    fn as_ref(&self) -> &str {
        self.0.as_str()
    }
}

impl Deref for Code {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl Default for Code {
    fn default() -> Self {
        Self(random_code())
    }
}
