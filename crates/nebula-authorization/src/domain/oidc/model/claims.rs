use std::collections::HashMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::acr::{Acr, CLAIM_KEY};

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct ClaimOptions {
    essential: bool,
    value: Option<Value>,
    values: Option<Vec<Value>>,
}

impl ClaimOptions {
    pub fn voluntary(value: Option<Value>, values: Option<Vec<Value>>) -> ClaimOptions {
        Self { essential: false, value, values }
    }

    pub fn essential(value: Option<Value>, values: Option<Vec<Value>>) -> ClaimOptions {
        Self { essential: true, value, values }
    }

    pub fn validate(&self, value: &Value) -> bool {
        if self.essential {
            if let Some(expected) = &self.value {
                if expected != value {
                    return false;
                }
            }

            if let Some(expected_values) = &self.values {
                if !expected_values.contains(value) {
                    return false;
                }
            }
        }
        true
    }

    pub fn is_essential(&self) -> bool {
        self.essential
    }

    pub fn value(&self) -> Option<&Value> {
        self.value.as_ref()
    }

    pub fn values(&self) -> Option<&Vec<Value>> {
        self.values.as_ref()
    }
}

#[derive(Debug, Clone, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Claims {
    #[serde(default)]
    pub userinfo: HashMap<String, Option<ClaimOptions>>,
    #[serde(default)]
    pub id_token: HashMap<String, Option<ClaimOptions>>,
}

impl Claims {
    pub fn handle_acr_values_parameter(&mut self, param: Option<&Acr>) {
        if let Some(acr_values) = param {
            if !self.id_token.contains_key(CLAIM_KEY) {
                let (value, values) = acr_values.to_values();
                let co = ClaimOptions::voluntary(value, values);
                self.id_token.insert(CLAIM_KEY.to_owned(), Some(co));
            }
            if !self.userinfo.contains_key(CLAIM_KEY) {
                let (value, values) = acr_values.to_values();
                let co = ClaimOptions::voluntary(value, values);
                self.userinfo.insert(CLAIM_KEY.to_owned(), Some(co));
            }
        }
    }
}
