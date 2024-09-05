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
    #[error("Key not found")]
    KeyNotFound,
}

#[derive(Error, Debug)]
pub enum ProtectorError {
    #[error("IO error: {0:?}")]
    IO(#[from] io::Error),
    #[error("Serde error: {0:?}")]
    Serde(#[from] serde_json::Error),
    #[error("Storage error: {0:?}")]
    Storage(#[from] StorageError),
    #[error("Key size is invalid")]
    KeySizeInvalid,
    #[error("Protector is already initialized")]
    AlreadyInitialized,
    #[error("Protector is not initialized")]
    NotInitialized,
    #[error(transparent)]
    Other(#[from] anyhow::Error),
    #[error("Unknown error")]
    Unknown,
}
