use serde::{Deserialize, Serialize};
use serde_json::Value;

pub const CLAIM_KEY: &str = "acr";

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Acr(
    #[serde(
        serialize_with = "crate::domain::oidc::utils::serde::space_delimited_serializer",
        deserialize_with = "crate::domain::oidc::utils::serde::space_delimited_deserializer"
    )]
    Vec<String>,
);

impl Acr {
    pub fn new(values: Vec<String>) -> Self {
        Self(values)
    }

    pub fn iter(&self) -> impl Iterator<Item = &String> {
        self.0.iter()
    }

    pub fn contains(&self, v: &String) -> bool {
        self.0.contains(v)
    }

    pub fn to_values(&self) -> (Option<Value>, Option<Vec<Value>>) {
        match self.0.len() {
            0 => (None, None),
            1 => (Some(Value::String(self.0.first().expect("Must have at least 1 value").clone())), None),
            _ => (None, Some(self.0.iter().map(|it| Value::String(it.clone())).collect())),
        }
    }
}

impl From<String> for Acr {
    fn from(s: String) -> Self {
        Acr(s.split(' ').map(|s| s.to_owned()).collect())
    }
}
