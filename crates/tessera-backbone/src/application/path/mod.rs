use async_trait::async_trait;

pub(crate) struct PathData {
    pub path: String,
}

#[async_trait]
pub(crate) trait PathUseCase {
    async fn get_all(&self) -> Result<Vec<PathData>>;
}

pub(crate) struct PathUseCaseImpl {}

impl PathUseCaseImpl {
    pub fn new() -> Self {
        Self {}
    }
}

#[async_trait]
impl PathUseCase for PathUseCaseImpl {
    async fn get_all(&self) -> Result<Vec<PathData>> {
        todo!()
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {}

pub(crate) type Result<T> = std::result::Result<T, Error>;
