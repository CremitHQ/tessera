use std::io;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("IO error: {0:?}")]
    IO(#[from] io::Error),
    #[error("Serde error: {0:?}")]
    Serde(#[from] serde_json::Error),
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error("Unknown error")]
    Unknown,
}
