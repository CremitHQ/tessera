use crate::pest::human::Rule as HumanRule;
use crate::pest::json::Rule as JsonRule;
use pest::error::{Error as PestError, LineColLocation};
use std::cmp;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum PolicyError {
    #[error("Json Policy Error: {0}")]
    JsonPolicy(String),
    #[error("Human Policy Error: {0}")]
    HumanPolicy(String),
    #[error("Empty Policy Error")]
    Empty,
    #[error("Invalid Policy Type")]
    InvalidPolicyType,
}

impl From<PestError<JsonRule>> for PolicyError {
    fn from(error: PestError<JsonRule>) -> Self {
        let line = match error.line_col.to_owned() {
            LineColLocation::Pos((line, _)) => line,
            LineColLocation::Span((start_line, _), (end_line, _)) => cmp::max(start_line, end_line),
        };
        PolicyError::JsonPolicy(format!("Json Policy Error in line {}\n", line))
    }
}

impl From<PestError<HumanRule>> for PolicyError {
    fn from(error: PestError<HumanRule>) -> Self {
        let line = match error.line_col.to_owned() {
            LineColLocation::Pos((line, _)) => line,
            LineColLocation::Span((start_line, _), (end_line, _)) => cmp::max(start_line, end_line),
        };
        PolicyError::HumanPolicy(format!("Human Policy Error in line {}\n", line))
    }
}
