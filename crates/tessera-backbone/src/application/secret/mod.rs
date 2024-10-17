use async_trait::async_trait;
use ulid::Ulid;

#[async_trait]
pub(crate) trait SecretUseCase {
    async fn list(&self, path: &str) -> Result<Vec<SecretData>>;
}

pub(crate) struct SecretUseCaseImpl {
    workspace_name: String,
}

impl SecretUseCaseImpl {
    pub fn new(workspace_name: String) -> Self {
        Self { workspace_name }
    }
}

#[async_trait]
impl SecretUseCase for SecretUseCaseImpl {
    async fn list(&self, _path: &str) -> Result<Vec<SecretData>> {
        todo!()
    }
}

pub(crate) struct SecretData {
    pub key: String,
    pub path: String,
    pub reader_policy_ids: Vec<Ulid>,
    pub writer_policy_ids: Vec<Ulid>,
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {}
pub(crate) type Result<T> = std::result::Result<T, Error>;
