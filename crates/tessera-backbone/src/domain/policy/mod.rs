use async_trait::async_trait;

#[async_trait]
pub(crate) trait PolicyService {}

pub(crate) struct PostgresPolicyService {}

#[async_trait]
impl PolicyService for PostgresPolicyService {}
