use self::human::HumanPolicyParser;
use self::json::JSONPolicyParser;
use crate::error::PolicyError;
use pest::Parser;
use serde::{Deserialize, Serialize};
use std::string::String;

pub(crate) mod human;
pub(crate) mod json;

/// Policy Language Type. Currently two types are available:
#[derive(Copy, Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum PolicyLanguage {
    /// A JSON policy language
    JsonPolicy,
    /// A natural human language
    HumanPolicy,
}

/// Internally there are only three types of nodes: AND, OR and LEAF nodes
pub enum PolicyType {
    And,
    Or,
    Leaf,
}

/// The value of a node may either be a String (with a position stored in a u8), and Array of values oder a child with value
pub enum PolicyValue<'a> {
    Object((PolicyType, Box<PolicyValue<'a>>)),
    Array(Vec<PolicyValue<'a>>),
    String((&'a str, usize)),
}

/// Parses a &str in a give [PolicyLanguage] to a PolicyValue tree
pub fn parse(policy: &str, language: PolicyLanguage) -> Result<PolicyValue, PolicyError> {
    match language {
        PolicyLanguage::JsonPolicy => {
            use crate::pest::json::Rule;
            let mut result = JSONPolicyParser::parse(Rule::content, policy)?;
            let result = result.next().ok_or(PolicyError::Empty)?;
            json::parse(result)
        }
        PolicyLanguage::HumanPolicy => {
            use crate::pest::human::Rule;
            let mut result = HumanPolicyParser::parse(Rule::content, policy)?;
            let result = result.next().ok_or(PolicyError::Empty)?;
            human::parse(result)
        }
    }
}
/// Serializes a [PolicyValue] to a String in a specific [PolicyLanguage]
pub fn serialize_policy(val: &PolicyValue, language: PolicyLanguage, parent: Option<PolicyType>) -> String {
    use self::PolicyValue::*;
    match language {
        PolicyLanguage::JsonPolicy => match val {
            Object(obj) => match obj.0 {
                PolicyType::And => {
                    format!("{{\"name\": \"and\", {}}}", serialize_policy(obj.1.as_ref(), language, None))
                }
                PolicyType::Or => format!("{{\"name\": \"or\", {}}}", serialize_policy(obj.1.as_ref(), language, None)),
                PolicyType::Leaf => serialize_policy(&obj.1.as_ref(), language, None),
            },
            Array(a) => {
                let contents: Vec<_> = a.iter().map(|val| serialize_policy(val, language, None)).collect();
                format!("\"children\": [{}]", contents.join(", "))
            }
            String(s) => format!("{{\"name\": \"{}\"}}", s.0),
        },
        PolicyLanguage::HumanPolicy => match val {
            Object(obj) => match obj.0 {
                PolicyType::And => format!("{}", serialize_policy(obj.1.as_ref(), language, Some(PolicyType::And))),
                PolicyType::Or => format!("{}", serialize_policy(obj.1.as_ref(), language, Some(PolicyType::Or))),
                PolicyType::Leaf => serialize_policy(&obj.1.as_ref(), language, Some(PolicyType::Leaf)),
            },
            Array(a) => {
                let contents: Vec<_> = a.iter().map(|val| serialize_policy(val, language, None)).collect();
                match parent {
                    Some(PolicyType::And) => format!("({})", contents.join(" and ")),
                    Some(PolicyType::Or) => format!("({})", contents.join(" or ")),
                    _ => panic!("children without parent"),
                }
            }
            String(s) => format!("{}", s.0),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_single_parsing() {
        let pol = String::from(r#"{"name": "A"}"#);
        let human = String::from("A");
        let json: PolicyValue = parse(&pol, PolicyLanguage::JsonPolicy).expect("unsuccessful parse");
        let serialized_json = serialize_policy(&json, PolicyLanguage::JsonPolicy, None);
        let serialized_human = serialize_policy(&json, PolicyLanguage::HumanPolicy, None);
        assert_eq!(serialized_json, pol);
        assert_eq!(serialized_human, human);
    }

    #[test]
    fn test_children_parsing() {
        let pol = String::from(r#"{"name": "and", "children": [{"name": "B"}, {"name": "C"}]}"#);
        let human = String::from("(B and C)");
        let json: PolicyValue = parse(&pol, PolicyLanguage::JsonPolicy).expect("unsuccessful parse");
        let serialized_json = serialize_policy(&json, PolicyLanguage::JsonPolicy, None);
        let serialized_human = serialize_policy(&json, PolicyLanguage::HumanPolicy, None);
        assert_eq!(serialized_json, pol);
        assert_eq!(serialized_human, human);
    }

    #[test]
    fn test_sub_children_parsing() {
        let pol = String::from(
            r#"{"name": "or", "children": [{"name": "A"}, {"name": "and", "children": [{"name": "B"}, {"name": "C"}]}]}"#,
        );
        let human = String::from(r#"(A or (B and C))"#);
        let json: PolicyValue = parse(&pol, PolicyLanguage::JsonPolicy).expect("unsuccessful parse");
        let serialized_json = serialize_policy(&json, PolicyLanguage::JsonPolicy, None);
        let serialized_human = serialize_policy(&json, PolicyLanguage::HumanPolicy, None);
        assert_eq!(serialized_json, pol);
        assert_eq!(serialized_human, human);
    }
}
