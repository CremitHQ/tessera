use async_trait::async_trait;
use ulid::Ulid;

#[async_trait]
pub(crate) trait PolicyUseCase {
    async fn get_all(&self) -> Result<Vec<PolicyData>>;
}

pub(crate) struct PolicyUseCaseImpl {}

impl PolicyUseCaseImpl {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl PolicyUseCase for PolicyUseCaseImpl {
    async fn get_all(&self) -> Result<Vec<PolicyData>> {
        todo!()
    }
}

pub(crate) struct PolicyData {
    pub id: Ulid,
    pub name: String,
    pub expression: String,
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {}

pub(crate) type Result<T> = std::result::Result<T, Error>;
