use std::convert::TryInto;
use std::fmt::Debug;

use serde::{Deserialize, Serialize};
use url::Url;

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Issuer(Url);

impl Issuer {
    pub fn new<I: TryInto<Url, Error = E>, E: Debug>(identifier: I) -> Result<Self, E> {
        Ok(Self(identifier.try_into()?))
    }

    pub fn inner(&self) -> &Url {
        &self.0
    }
}

impl TryFrom<&str> for Issuer {
    type Error = url::ParseError;

    fn try_from(iss: &str) -> Result<Self, Self::Error> {
        Issuer::new(iss)
    }
}

impl TryFrom<String> for Issuer {
    type Error = url::ParseError;

    fn try_from(iss: String) -> Result<Self, Self::Error> {
        Issuer::new(iss.as_str())
    }
}

impl From<Issuer> for String {
    fn from(iss: Issuer) -> Self {
        iss.0.to_string()
    }
}

impl From<&Issuer> for String {
    fn from(iss: &Issuer) -> Self {
        iss.0.to_string()
    }
}
