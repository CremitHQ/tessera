mod workspace_service;

#[cfg(test)]
pub(crate) use workspace_service::MockWorkspaceService;
pub(crate) use workspace_service::{WorkspaceService, WorkspaceServiceImpl};

pub(crate) struct Workspace {
    pub name: String,
}

impl Workspace {
    pub fn new(name: String) -> Self {
        Self { name }
    }

    pub(crate) async fn delete(self) -> Result<()> {
        todo!()
    }
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("workspace name already exists")]
    WorkspaceNameConflicted,
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

pub(crate) type Result<T> = std::result::Result<T, Error>;
