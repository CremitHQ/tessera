use std::collections::HashMap;

use self::human::HumanPolicyParser;
use self::json::JSONPolicyParser;
use crate::error::PolicyParserError;
use pest::Parser;
use serde::{Deserialize, Serialize};

pub(crate) mod human;
pub(crate) mod json;

#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PolicyLanguage {
    JsonPolicy,
    HumanPolicy,
}

#[derive(Debug, Clone)]
pub enum PolicyNode<'a> {
    And((Box<PolicyNode<'a>>, Box<PolicyNode<'a>>)),
    Or((Box<PolicyNode<'a>>, Box<PolicyNode<'a>>)),
    Leaf((&'a str, usize)),
}

/// Parses a &str in a give [PolicyLanguage] to a PolicyValue tree
pub fn parse(policy: &str, language: PolicyLanguage) -> Result<PolicyNode, PolicyParserError> {
    match language {
        PolicyLanguage::JsonPolicy => {
            use crate::pest::json::Rule;
            let mut result = JSONPolicyParser::parse(Rule::content, policy)?;
            let result = result.next().ok_or(PolicyParserError::Empty)?;
            let mut attributes: HashMap<&str, usize> = HashMap::new();
            json::parse(result, &mut attributes)
        }
        PolicyLanguage::HumanPolicy => {
            use crate::pest::human::Rule;
            let mut result = HumanPolicyParser::parse(Rule::content, policy)?;
            let result = result.next().ok_or(PolicyParserError::Empty)?;
            let mut attribute_index: HashMap<&str, usize> = HashMap::new();
            human::parse(result, &mut attribute_index)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn serialize_policy(val: &PolicyNode, language: PolicyLanguage) -> String {
        match language {
            PolicyLanguage::JsonPolicy => match val {
                PolicyNode::And((left, right)) => {
                    format!(
                        "{{\"name\": \"and\", \"children\": [{}, {}]}}",
                        serialize_policy(right, language),
                        serialize_policy(left, language),
                    )
                }
                PolicyNode::Or((left, right)) => {
                    format!(
                        "{{\"name\": \"or\", \"children\": [{}, {}]}}",
                        serialize_policy(right, language),
                        serialize_policy(left, language),
                    )
                }
                PolicyNode::Leaf((name, _)) => {
                    format!("{{\"name\": \"{}\"}}", name)
                }
            },
            PolicyLanguage::HumanPolicy => match val {
                PolicyNode::And((left, right)) => {
                    format!("({} and {})", serialize_policy(right, language), serialize_policy(left, language))
                }
                PolicyNode::Or((left, right)) => {
                    format!("({} or {})", serialize_policy(right, language), serialize_policy(left, language))
                }
                PolicyNode::Leaf((name, _)) => name.to_string(),
            },
        }
    }

    #[test]
    fn test_single_parsing() {
        let pol = String::from(r#"{"name": "A"}"#);
        let human = String::from("A");
        let json = parse(&pol, PolicyLanguage::JsonPolicy).expect("unsuccessful parse");
        let serialized_json = serialize_policy(&json, PolicyLanguage::JsonPolicy);
        let serialized_human = serialize_policy(&json, PolicyLanguage::HumanPolicy);
        assert_eq!(serialized_json, pol);
        assert_eq!(serialized_human, human);
    }

    #[test]
    fn test_children_parsing() {
        let pol = String::from(r#"{"name": "and", "children": [{"name": "B"}, {"name": "C"}]}"#);
        let human = String::from("(B and C)");
        let json = parse(&pol, PolicyLanguage::JsonPolicy).expect("unsuccessful parse");
        let serialized_json = serialize_policy(&json, PolicyLanguage::JsonPolicy);
        let serialized_human = serialize_policy(&json, PolicyLanguage::HumanPolicy);
        assert_eq!(serialized_json, pol);
        assert_eq!(serialized_human, human);
    }

    #[test]
    fn test_sub_children_parsing() {
        let pol = String::from(
            r#"{"name": "or", "children": [{"name": "A"}, {"name": "and", "children": [{"name": "B"}, {"name": "C"}]}]}"#,
        );
        let human = String::from(r#"(A or (B and C))"#);
        let json = parse(&pol, PolicyLanguage::JsonPolicy).expect("unsuccessful parse");
        let serialized_json = serialize_policy(&json, PolicyLanguage::JsonPolicy);
        let serialized_human = serialize_policy(&json, PolicyLanguage::HumanPolicy);

        assert_eq!(serialized_json, pol);
        assert_eq!(serialized_human, human);
    }
}
