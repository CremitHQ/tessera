use serde::Deserialize;
use ulid::Ulid;

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PostSecretRequest {
    pub path: String,
    pub key: String,
    pub cipher: String,
    pub reader_policy_ids: Vec<Ulid>,
    pub writer_policy_ids: Vec<Ulid>,
}
