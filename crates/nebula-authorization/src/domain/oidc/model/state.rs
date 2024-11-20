use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct State(String);

impl State {
    pub fn new<T: Into<String>>(value: T) -> Self {
        Self(value.into())
    }
}
