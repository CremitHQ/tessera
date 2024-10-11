mod workspace_service;

#[cfg(test)]
pub(crate) use workspace_service::MockWorkspaceService;
pub(crate) use workspace_service::{Error, WorkspaceService, WorkspaceServiceImpl};

pub(crate) struct Workspace {
    pub name: String
}

