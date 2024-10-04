#[derive(Clone, PartialEq, Debug)]
pub struct ABEError {
    details: String,
}

impl ABEError {
    /// Creates a new Error
    pub fn new(msg: &str) -> ABEError {
        ABEError { details: msg.to_string() }
    }
}
