use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CodeChallengeMethod {
    Plain,
    S256,
}
