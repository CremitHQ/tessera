use crate::pest::human::Rule as HumanRule;
use crate::pest::json::Rule as JsonRule;
use pest::error::{Error as PestError, LineColLocation};
use std::cmp;

#[derive(Clone, PartialEq, Debug)]
pub struct PolicyError {
    details: String,
}

impl PolicyError {
    /// Creates a new Error
    pub fn new(msg: &str) -> PolicyError {
        PolicyError { details: msg.to_string() }
    }
}

impl From<PestError<JsonRule>> for PolicyError {
    fn from(error: PestError<JsonRule>) -> Self {
        let line = match error.line_col.to_owned() {
            LineColLocation::Pos((line, _)) => line,
            LineColLocation::Span((start_line, _), (end_line, _)) => cmp::max(start_line, end_line),
        };
        PolicyError::new(format!("Json Policy Error in line {}\n", line).as_ref())
    }
}

impl From<PestError<HumanRule>> for PolicyError {
    fn from(error: PestError<HumanRule>) -> Self {
        let line = match error.line_col.to_owned() {
            LineColLocation::Pos((line, _)) => line,
            LineColLocation::Span((start_line, _), (end_line, _)) => cmp::max(start_line, end_line),
        };
        PolicyError::new(format!("Human Policy Error in line {}\n", line).as_ref())
    }
}
