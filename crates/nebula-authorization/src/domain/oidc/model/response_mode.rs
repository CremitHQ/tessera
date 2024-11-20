use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Debug, Eq, PartialEq, Clone, Copy)]
#[serde(rename_all = "snake_case")]
pub enum ResponseMode {
    FormPost,
    Fragment,
    Query,
    Jwt,
    #[serde(rename = "query.jwt")]
    QueryJwt,
    #[serde(rename = "fragment.jwt")]
    FragmentJwt,
    #[serde(rename = "form_post.jwt")]
    FormPostJwt,
}
