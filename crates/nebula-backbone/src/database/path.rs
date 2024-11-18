use chrono::{DateTime, Utc};
use sea_orm::prelude::*;

use super::UlidId;

#[derive(Clone, Debug, PartialEq, DeriveEntityModel)]
#[sea_orm(table_name = "path")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: UlidId,
    pub path: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(has_many = "super::applied_path_policy::Entity")]
    AppliedPathPolicy,
}

impl ActiveModelBehavior for ActiveModel {}

impl Related<super::applied_path_policy::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::AppliedPathPolicy.def()
    }
}
