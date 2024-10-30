use crate::pest::human::Rule as HumanRule;
use crate::pest::json::Rule as JsonRule;
use pest::error::{Error as PestError, LineColLocation};
use std::cmp;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyParserError {
    #[error("json policy error: {0}")]
    JsonPolicy(String),
    #[error("human policy error: {0}")]
    HumanPolicy(String),
    #[error("provided policy was empty")]
    Empty,
    #[error("invalid policy type")]
    InvalidPolicyType,
}

impl From<PestError<JsonRule>> for PolicyParserError {
    fn from(error: PestError<JsonRule>) -> Self {
        let line = match error.line_col.to_owned() {
            LineColLocation::Pos((line, _)) => line,
            LineColLocation::Span((start_line, _), (end_line, _)) => cmp::max(start_line, end_line),
        };
        PolicyParserError::JsonPolicy(format!("Json Policy Error in line {}\n", line))
    }
}

impl From<PestError<HumanRule>> for PolicyParserError {
    fn from(error: PestError<HumanRule>) -> Self {
        let line = match error.line_col.to_owned() {
            LineColLocation::Pos((line, _)) => line,
            LineColLocation::Span((start_line, _), (end_line, _)) => cmp::max(start_line, end_line),
        };
        PolicyParserError::HumanPolicy(format!("Human Policy Error in line {}\n", line))
    }
}
