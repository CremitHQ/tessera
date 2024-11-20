use std::ops::Deref;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Scope(String);
#[derive(Debug, Clone, Eq, PartialEq, Serialize, Deserialize)]
pub struct Scopes(Vec<Scope>);

impl From<&str> for Scope {
    fn from(scope: &str) -> Self {
        Scope(scope.to_string())
    }
}

impl From<String> for Scope {
    fn from(scope: String) -> Self {
        Scope(scope)
    }
}

impl Deref for Scope {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.0.as_str()
    }
}

impl Deref for Scopes {
    type Target = Vec<Scope>;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl Scopes {
    pub fn new<I: Into<Scopes>>(values: I) -> Self {
        values.into()
    }

    pub fn get(&self, idx: usize) -> Option<&Scope> {
        self.0.get(idx)
    }

    pub fn contains(&self, scope: &Scope) -> bool {
        self.0.contains(scope)
    }

    pub fn contains_all(&self, scope: &Scopes) -> bool {
        scope.iter().all(|item| self.contains(item))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Scope> {
        self.0.iter()
    }
}
