use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Serialize)]
pub struct Amr(
    #[serde(
        serialize_with = "crate::domain::oidc::utils::serde::space_delimited_serializer",
        deserialize_with = "crate::domain::oidc::utils::serde::space_delimited_deserializer"
    )]
    Vec<String>,
);

impl From<String> for Amr {
    fn from(s: String) -> Self {
        Amr(s.split(' ').map(|s| s.to_owned()).collect())
    }
}
