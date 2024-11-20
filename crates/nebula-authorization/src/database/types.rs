use sea_orm::prelude::*;

#[derive(EnumIter, DeriveActiveEnum, Clone, Debug, PartialEq)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)", rename_all = "snake_case")]
pub enum ResponseType {
    Code,
    Token,
    IdToken,
}

#[derive(EnumIter, DeriveActiveEnum, Clone, Debug, PartialEq)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)", rename_all = "snake_case")]
pub enum CodeChallengeMethod {
    Plain,
    S256,
}
