use chrono::{DateTime, Utc};
use sea_orm::prelude::*;

use super::UlidId;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "applied_path_policy_allowed_action")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: UlidId,
    pub applied_path_policy_id: UlidId,
    pub action: AllowedAction,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(EnumIter, DeriveActiveEnum, Clone, Debug, PartialEq)]
#[sea_orm(rs_type = "String", db_type = "String(StringLen::None)", rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AllowedAction {
    Create,
    Update,
    Delete,
    Manage,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::applied_path_policy::Entity",
        from = "Column::AppliedPathPolicyId",
        to = "super::applied_path_policy::Column::Id"
    )]
    AppliedPathPolicy,
}

impl ActiveModelBehavior for ActiveModel {}

impl Related<super::applied_path_policy::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AppliedPathPolicy.def()
    }
}
