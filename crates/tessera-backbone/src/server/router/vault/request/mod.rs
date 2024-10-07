use serde::Deserialize;

#[derive(Deserialize, Debug)]
pub(crate) struct PostVaultRequest {
    pub name: String,
}
