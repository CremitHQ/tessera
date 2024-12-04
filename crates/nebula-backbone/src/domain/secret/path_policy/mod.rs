use std::str::FromStr;

use ::pest::{error::LineColLocation, Parser};

use self::pest::{PolicyParser, Rule};

mod pest;

#[derive(Debug, Clone)]
pub enum PolicyNode<'a> {
    And((Box<PolicyNode<'a>>, Box<PolicyNode<'a>>)),
    Or((Box<PolicyNode<'a>>, Box<PolicyNode<'a>>)),
    Leaf { key: &'a str, operator: Operator, value: &'a str },
}

impl PolicyNode<'_> {
    pub fn is_attribute_matched(&self, attributes: &[(&str, &str)]) -> bool {
        match self {
            PolicyNode::And((node1, node2)) => {
                node1.is_attribute_matched(attributes) && node2.is_attribute_matched(attributes)
            }
            PolicyNode::Or((node1, node2)) => {
                node1.is_attribute_matched(attributes) || node2.is_attribute_matched(attributes)
            }
            PolicyNode::Leaf { key, operator, value, .. } => {
                attributes.iter().any(|(attribute_key, attribute_value)| {
                    if attribute_key != key {
                        return false;
                    }
                    match operator {
                        Operator::Equal => attribute_value == value,
                        Operator::NotEqual => attribute_value != value,
                    }
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub enum Operator {
    Equal,
    NotEqual,
}

impl FromStr for Operator {
    type Err = Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "equal" => Ok(Self::Equal),
            "not_equal" => Ok(Self::NotEqual),
            _ => Err(Error::InvalidOperator(s.to_owned())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("Parse error: {0}")]
    ParseFailed(String),
    #[error("provided policy was empty")]
    Empty,
    #[error("Invalid Operator: {0}")]
    InvalidOperator(String),
    #[error("invalid policy type")]
    InvalidPolicyType,
}

pub fn parse(policy: &str) -> Result<PolicyNode, Error> {
    let mut result = PolicyParser::parse(Rule::Content, policy)?;
    let result = result.next().ok_or(Error::Empty)?;
    pest::parse(result)
}

impl From<::pest::error::Error<pest::Rule>> for Error {
    fn from(error: ::pest::error::Error<pest::Rule>) -> Self {
        let line = match error.line_col.to_owned() {
            LineColLocation::Pos((line, _)) => line,
            LineColLocation::Span((start_line, _), (end_line, _)) => std::cmp::max(start_line, end_line),
        };
        Error::ParseFailed(format!("Human Policy Error in line {}\n", line))
    }
}
