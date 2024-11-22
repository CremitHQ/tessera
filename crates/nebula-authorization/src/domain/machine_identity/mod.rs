use std::collections::HashSet;

use axum::async_trait;
use chrono::Utc;
use rand::{distributions::Alphanumeric, Rng};
use sea_orm::{ActiveModelTrait, ColumnTrait, DatabaseTransaction, DbErr, EntityTrait, LoaderTrait, QueryFilter, Set};
use thiserror::Error;
use ulid::Ulid;

use crate::database::{machine_identity, machine_identity_attribute, machine_identity_token, Persistable, UlidId};

pub struct MachineIdentity {
    pub id: Ulid,
    pub label: String,
    pub attributes: Vec<(String, String)>,
    updated_attributes: Option<Vec<(String, String)>>,
    deleted: bool,
}

impl MachineIdentity {
    pub(crate) fn update_attributes(&mut self, attributes: &[(&str, &str)]) {
        let current_attributes: HashSet<(&str, &str)> =
            self.attributes.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect();

        if current_attributes == attributes.iter().map(|(key, value)| (*key, *value)).collect::<HashSet<_>>() {
            return;
        }

        self.updated_attributes =
            Some(attributes.iter().map(|(key, value)| (key.to_string(), value.to_string())).collect());
    }

    pub(crate) fn delete(&mut self) {
        self.deleted = true
    }
}

#[async_trait]
impl Persistable for MachineIdentity {
    type Error = Error;

    async fn persist(self, transaction: &DatabaseTransaction) -> std::result::Result<(), Self::Error> {
        if self.deleted {
            machine_identity_attribute::Entity::delete_many()
                .filter(machine_identity_attribute::Column::MachineIdentityId.eq(UlidId::new(self.id)))
                .exec(transaction)
                .await?;
            machine_identity::Entity::delete_by_id(UlidId::new(self.id)).exec(transaction).await?;
            return Ok(());
        }

        if let Some(updated_attributes) = self.updated_attributes {
            machine_identity_attribute::Entity::delete_many()
                .filter(machine_identity_attribute::Column::MachineIdentityId.eq(UlidId::new(self.id)))
                .exec(transaction)
                .await?;
            if !updated_attributes.is_empty() {
                let now = Utc::now();
                let attributes_active_models =
                    updated_attributes.into_iter().map(|(key, value)| machine_identity_attribute::ActiveModel {
                        id: Set(UlidId::new(Ulid::new())),
                        machine_identity_id: Set(UlidId::new(self.id)),
                        key: Set(key),
                        value: Set(value),
                        created_at: Set(now),
                        updated_at: Set(now),
                    });

                machine_identity_attribute::Entity::insert_many(attributes_active_models).exec(transaction).await?;
            }
        }

        Ok(())
    }
}

pub struct MachineIdentityToken {
    pub id: Ulid,
    pub token: String,
    deleted: bool,
}

impl From<machine_identity_token::Model> for MachineIdentityToken {
    fn from(value: machine_identity_token::Model) -> Self {
        Self { id: value.id.inner(), token: value.token, deleted: false }
    }
}

impl MachineIdentityToken {
    pub fn delete(&mut self) {
        self.deleted = true
    }
}

#[async_trait]
impl Persistable for MachineIdentityToken {
    type Error = Error;

    async fn persist(self, transaction: &DatabaseTransaction) -> std::result::Result<(), Self::Error> {
        if self.deleted {
            machine_identity_token::Entity::delete_by_id(UlidId::new(self.id)).exec(transaction).await?;
        }

        Ok(())
    }
}

pub struct MachineIdentityService {}

impl From<(machine_identity::Model, Vec<machine_identity_attribute::Model>)> for MachineIdentity {
    fn from(
        (machine_identity_model, machine_identity_attribute_models): (
            machine_identity::Model,
            Vec<machine_identity_attribute::Model>,
        ),
    ) -> Self {
        Self {
            id: machine_identity_model.id.inner(),
            label: machine_identity_model.label,
            attributes: machine_identity_attribute_models
                .into_iter()
                .map(|attribute| (attribute.key, attribute.value))
                .collect(),
            updated_attributes: None,
            deleted: false,
        }
    }
}

impl MachineIdentityService {
    pub async fn register_machine_identity(
        &self,
        transaction: &DatabaseTransaction,
        label: &str,
        attributes: &[(&str, &str)],
    ) -> Result<()> {
        let machine_identity_id = UlidId::new(Ulid::new());
        let now = Utc::now();
        machine_identity::ActiveModel {
            id: Set(machine_identity_id),
            label: Set(label.to_owned()),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(transaction)
        .await?;

        if !attributes.is_empty() {
            let attributes_active_models =
                attributes.iter().map(|(key, value)| machine_identity_attribute::ActiveModel {
                    id: Set(UlidId::new(Ulid::new())),
                    machine_identity_id: Set(machine_identity_id),
                    key: Set(key.to_string()),
                    value: Set(value.to_string()),
                    created_at: Set(now),
                    updated_at: Set(now),
                });

            machine_identity_attribute::Entity::insert_many(attributes_active_models).exec(transaction).await?;
        }

        Ok(())
    }

    pub async fn get_machine_identities(&self, transaction: &DatabaseTransaction) -> Result<Vec<MachineIdentity>> {
        let machine_identities = machine_identity::Entity::find().all(transaction).await?;
        let attributes = machine_identities.load_many(machine_identity_attribute::Entity, transaction).await?;

        Ok(machine_identities.into_iter().zip(attributes.into_iter()).map(MachineIdentity::from).collect())
    }

    pub async fn get_machine_identity(
        &self,
        transaction: &DatabaseTransaction,
        machine_identity_id: &Ulid,
    ) -> Result<Option<MachineIdentity>> {
        let machine_identity = if let Some(machine_identity) =
            machine_identity::Entity::find_by_id(UlidId::new(*machine_identity_id)).one(transaction).await?
        {
            machine_identity
        } else {
            return Ok(None);
        };
        let attributes = machine_identity_attribute::Entity::find()
            .filter(machine_identity_attribute::Column::MachineIdentityId.eq(machine_identity.id))
            .all(transaction)
            .await?;

        Ok(Some((machine_identity, attributes).into()))
    }

    pub async fn get_machine_identity_tokens(
        &self,
        transaction: &DatabaseTransaction,
        machine_identity: &MachineIdentity,
    ) -> Result<Vec<MachineIdentityToken>> {
        let tokens = machine_identity_token::Entity::find()
            .filter(machine_identity_token::Column::MachineIdentityId.eq(UlidId::new(machine_identity.id)))
            .all(transaction)
            .await?;

        Ok(tokens.into_iter().map(MachineIdentityToken::from).collect())
    }

    pub async fn create_new_machine_identity_token(
        &self,
        transaction: &DatabaseTransaction,
        machine_identity: &MachineIdentity,
    ) -> Result<()> {
        let now = Utc::now();

        machine_identity_token::ActiveModel {
            id: Set(UlidId::new(Ulid::new())),
            machine_identity_id: Set(UlidId::new(machine_identity.id)),
            token: Set(create_new_machine_identity_token()),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(transaction)
        .await?;

        Ok(())
    }

    pub async fn get_machine_identity_token(
        &self,
        transaction: &DatabaseTransaction,
        machine_identity: &MachineIdentity,
        machine_identity_token_id: &Ulid,
    ) -> Result<Option<MachineIdentityToken>> {
        let token = machine_identity_token::Entity::find_by_id(UlidId::new(machine_identity_token_id.to_owned()))
            .filter(machine_identity_token::Column::MachineIdentityId.eq(UlidId::new(machine_identity.id)))
            .one(transaction)
            .await?;

        Ok(token.map(MachineIdentityToken::from))
    }
}

// example: nmit_n12Aj0aa6ZkaA4RBp1fhYJcOTJnLHxAM
fn create_new_machine_identity_token() -> String {
    let random_part: String = rand::thread_rng().sample_iter(&Alphanumeric).take(32).map(char::from).collect();
    format!("nmit_{random_part}")
}

#[derive(Error, Debug)]
pub enum Error {
    #[error("Error occurrred by database")]
    DatabaseError(#[from] DbErr),
}

pub type Result<T> = std::result::Result<T, Error>;
