use std::collections::{HashMap, HashSet};

use async_trait::async_trait;
use chrono::Utc;
use lazy_static::lazy_static;
#[cfg(test)]
use mockall::automock;
use nebula_token::claim::NebulaClaim;
use regex::Regex;
use sea_orm::{
    ActiveModelTrait, ActiveValue, ColumnTrait, DatabaseTransaction, EntityTrait, IntoActiveModel, LoaderTrait,
    PaginatorTrait, QueryFilter, QuerySelect, QueryTrait, Set,
};
use tracing::warn;
use ulid::Ulid;

use crate::database::{
    applied_path_policy, applied_path_policy_allowed_action, applied_policy, path, policy, secret_metadata,
    secret_value, Persistable, UlidId,
};

use super::policy::AccessCondition;

mod path_policy;

pub(crate) struct SecretEntry {
    pub key: String,
    pub path: String,
    pub cipher: Vec<u8>,
    pub access_condition_ids: Vec<Ulid>,
    deleted: bool,
    updated_path: Option<String>,
    updated_cipher: Option<Vec<u8>>,
    updated_access_condition_ids: Option<Vec<Ulid>>,
}

impl SecretEntry {
    #[cfg(test)]
    pub(crate) fn new(key: String, path: String, cipher: Vec<u8>, access_condition_ids: Vec<Ulid>) -> Self {
        Self {
            key,
            path,
            cipher,
            access_condition_ids,
            deleted: false,
            updated_path: None,
            updated_cipher: None,
            updated_access_condition_ids: None,
        }
    }

    pub async fn delete(&mut self, transaction: &DatabaseTransaction, claim: &NebulaClaim) -> Result<()> {
        self.ensure_path_accessible(transaction, AllowedAction::Delete, claim).await?;

        self.deleted = true;

        Ok(())
    }

    pub async fn update_path(
        &mut self,
        transaction: &DatabaseTransaction,
        new_path: String,
        claim: &NebulaClaim,
    ) -> Result<()> {
        if self.path == new_path {
            return Ok(());
        }

        self.ensure_path_accessible(transaction, AllowedAction::Update, claim).await?;

        self.updated_path = Some(new_path);

        Ok(())
    }

    pub async fn update_cipher(
        &mut self,
        transaction: &DatabaseTransaction,
        new_cipher: Vec<u8>,
        claim: &NebulaClaim,
    ) -> Result<()> {
        if self.cipher == new_cipher {
            return Ok(());
        }
        self.ensure_path_accessible(transaction, AllowedAction::Update, claim).await?;
        self.updated_cipher = Some(new_cipher);

        Ok(())
    }

    pub async fn update_access_conditions(
        &mut self,
        transaction: &DatabaseTransaction,
        new_access_conditions: Vec<AccessCondition>,
        claim: &NebulaClaim,
    ) -> Result<()> {
        let new_access_condition_ids: Vec<_> = new_access_conditions.into_iter().map(|policy| policy.id).collect();

        if self.access_condition_ids.iter().collect::<HashSet<_>>()
            == new_access_condition_ids.iter().collect::<HashSet<_>>()
        {
            return Ok(());
        }

        self.ensure_path_accessible(transaction, AllowedAction::Update, claim).await?;

        self.updated_access_condition_ids = Some(new_access_condition_ids);

        Ok(())
    }

    async fn ensure_path_accessible(
        &self,
        transaction: &DatabaseTransaction,
        allowed_action: AllowedAction,
        claim: &NebulaClaim,
    ) -> Result<()> {
        let parent_path = self.get_parent_path(transaction).await?;
        parent_path.ensure_accessible(allowed_action, claim)?;
        for parent_path in get_all_parent_paths(transaction, &self.path).await? {
            parent_path.ensure_accessible(allowed_action, claim)?;
        }

        Ok(())
    }

    async fn get_parent_path(&self, transaction: &DatabaseTransaction) -> Result<Path> {
        get_path(transaction, &self.path)
            .await?
            .ok_or_else(|| Error::ParentPathNotExists { entered_path: self.path.to_owned() })
    }
}

#[derive(PartialEq, Eq, Hash, Clone)]
pub(crate) struct AppliedPolicy {
    pub expression: String,
    pub allowed_actions: Vec<AllowedAction>,
}

impl AppliedPolicy {
    fn check_accessible(&self, allowed_action: AllowedAction, claim: &NebulaClaim) -> Result<bool> {
        if !self.allowed_actions.contains(&allowed_action) {
            return Ok(true);
        }

        let parsed_expression = path_policy::parse(&self.expression)?;

        if parsed_expression.is_attribute_matched(
            &claim.attributes.iter().map(|(key, value)| (key.as_str(), value.as_str())).collect::<Vec<_>>(),
        ) {
            Ok(true)
        } else {
            Ok(false)
        }
    }
}

impl From<(applied_path_policy::Model, Vec<applied_path_policy_allowed_action::Model>)> for AppliedPolicy {
    fn from(
        (policy_model, allowed_action_models): (
            applied_path_policy::Model,
            Vec<applied_path_policy_allowed_action::Model>,
        ),
    ) -> Self {
        Self {
            expression: policy_model.expression,
            allowed_actions: allowed_action_models.into_iter().map(|aa| aa.action.into()).collect(),
        }
    }
}

#[derive(PartialEq, Eq, Hash, Clone, Copy)]
pub(crate) enum AllowedAction {
    Create,
    Update,
    Delete,
    Manage,
}

impl From<applied_path_policy_allowed_action::AllowedAction> for AllowedAction {
    fn from(value: applied_path_policy_allowed_action::AllowedAction) -> Self {
        match value {
            applied_path_policy_allowed_action::AllowedAction::Create => AllowedAction::Create,
            applied_path_policy_allowed_action::AllowedAction::Update => AllowedAction::Update,
            applied_path_policy_allowed_action::AllowedAction::Delete => AllowedAction::Delete,
            applied_path_policy_allowed_action::AllowedAction::Manage => AllowedAction::Manage,
        }
    }
}

impl From<&AllowedAction> for applied_path_policy_allowed_action::AllowedAction {
    fn from(value: &AllowedAction) -> Self {
        match value {
            AllowedAction::Create => applied_path_policy_allowed_action::AllowedAction::Create,
            AllowedAction::Update => applied_path_policy_allowed_action::AllowedAction::Update,
            AllowedAction::Delete => applied_path_policy_allowed_action::AllowedAction::Delete,
            AllowedAction::Manage => applied_path_policy_allowed_action::AllowedAction::Manage,
        }
    }
}

#[async_trait]
impl Persistable for SecretEntry {
    type Error = Error;

    async fn persist(self, transaction: &DatabaseTransaction) -> std::result::Result<(), Self::Error> {
        if self.deleted {
            secret_value::Entity::delete_many()
                .filter(secret_value::Column::Identifier.eq(create_identifier(&self.path, &self.key)))
                .exec(transaction)
                .await?;
            applied_policy::Entity::delete_many()
                .filter(
                    applied_policy::Column::SecretMetadataId.in_subquery(
                        secret_metadata::Entity::find()
                            .select_only()
                            .column(secret_metadata::Column::Id)
                            .filter(secret_metadata::Column::Path.eq(&self.path))
                            .filter(secret_metadata::Column::Key.eq(&self.key))
                            .into_query(),
                    ),
                )
                .exec(transaction)
                .await?;
            secret_metadata::Entity::delete_many()
                .filter(secret_metadata::Column::Path.eq(self.path))
                .filter(secret_metadata::Column::Key.eq(self.key))
                .exec(transaction)
                .await?;

            return Ok(());
        }

        let now = Utc::now();

        // update applied polciies
        if let Some(updated_access_condition_ids) = self.updated_access_condition_ids {
            let metadata_id: UlidId = if let Some(metadata_id) = secret_metadata::Entity::find()
                .select_only()
                .column(secret_metadata::Column::Id)
                .filter(secret_metadata::Column::Path.eq(&self.path))
                .filter(secret_metadata::Column::Key.eq(&self.key))
                .into_tuple()
                .one(transaction)
                .await?
            {
                metadata_id
            } else {
                return Ok(());
            };
            applied_policy::Entity::delete_many()
                .filter(applied_policy::Column::SecretMetadataId.eq(metadata_id.clone()))
                .exec(transaction)
                .await?;

            if !updated_access_condition_ids.is_empty() {
                let applied_access_policies =
                    updated_access_condition_ids.into_iter().map(|policy_id| applied_policy::ActiveModel {
                        id: Set(UlidId::new(Ulid::new())),
                        secret_metadata_id: Set(metadata_id.clone()),
                        policy_id: Set(UlidId::new(policy_id)),
                        created_at: Set(now),
                        updated_at: Set(now),
                    });

                applied_policy::Entity::insert_many(applied_access_policies).exec(transaction).await?;
            }
        }

        // update secret metadata
        let path_setter = self.updated_path.clone().map(Set).unwrap_or_default();

        let active_model = secret_metadata::ActiveModel { path: path_setter, ..Default::default() };

        if active_model.is_changed() {
            secret_metadata::Entity::update_many()
                .set(active_model)
                .filter(secret_metadata::Column::Path.eq(&self.path))
                .filter(secret_metadata::Column::Key.eq(&self.key))
                .exec(transaction)
                .await?;
        }

        // update secret value
        let identifier_setter = if self.updated_path.as_deref().is_some() {
            let new_identifier = create_identifier(self.updated_path.as_deref().unwrap_or(&self.path), &self.key);
            Set(new_identifier)
        } else {
            ActiveValue::default()
        };
        let cipher_setter = self.updated_cipher.map(Set).unwrap_or_default();

        let active_model =
            secret_value::ActiveModel { identifier: identifier_setter, cipher: cipher_setter, ..Default::default() };

        if active_model.is_changed() {
            secret_value::Entity::update_many()
                .set(active_model)
                .filter(secret_value::Column::Identifier.eq(create_identifier(&self.path, &self.key)))
                .exec(transaction)
                .await?;
        }

        Ok(())
    }
}

impl From<(secret_metadata::Model, Vec<applied_policy::Model>, Vec<u8>)> for SecretEntry {
    fn from(
        (metadata, applied_policies, cipher): (secret_metadata::Model, Vec<applied_policy::Model>, Vec<u8>),
    ) -> Self {
        let access_condition_ids = applied_policies.into_iter().map(|ap| ap.policy_id.inner()).collect();

        SecretEntry {
            key: metadata.key,
            cipher,
            path: metadata.path,
            access_condition_ids,
            deleted: false,
            updated_path: None,
            updated_cipher: None,
            updated_access_condition_ids: None,
        }
    }
}

pub(crate) struct Path {
    pub path: String,
    pub applied_policies: Vec<AppliedPolicy>,
    deleted: bool,
    updated_path: Option<String>,
    updated_policies: Option<Vec<AppliedPolicy>>,
}

impl Path {
    pub(crate) fn new(path: String, applied_policies: Vec<AppliedPolicy>) -> Self {
        Self { path, applied_policies, deleted: false, updated_path: None, updated_policies: None }
    }

    pub(crate) async fn delete(&mut self, transaction: &DatabaseTransaction, claim: &NebulaClaim) -> Result<()> {
        self.ensure_accessible(AllowedAction::Manage, claim)?;
        for parent_path in get_all_parent_paths(transaction, &self.path).await? {
            parent_path.ensure_accessible(AllowedAction::Manage, claim)?;
        }

        self.deleted = true;
        Ok(())
    }

    pub(crate) async fn update_path(
        &mut self,
        transaction: &DatabaseTransaction,
        new_path: &str,
        claim: &NebulaClaim,
    ) -> Result<()> {
        self.ensure_accessible(AllowedAction::Manage, claim)?;
        for parent_path in get_all_parent_paths(transaction, &self.path).await? {
            parent_path.ensure_accessible(AllowedAction::Manage, claim)?;
        }

        validate_path(new_path)?;
        if self.path == new_path {
            self.updated_path = None;
            return Ok(());
        }

        self.updated_path = Some(new_path.to_owned());
        Ok(())
    }

    pub(crate) async fn update_policies(
        &mut self,
        transaction: &DatabaseTransaction,
        new_policies: &[AppliedPolicy],
        claim: &NebulaClaim,
    ) -> Result<()> {
        self.ensure_accessible(AllowedAction::Manage, claim)?;
        for parent_path in get_all_parent_paths(transaction, &self.path).await? {
            parent_path.ensure_accessible(AllowedAction::Manage, claim)?;
        }

        if self.applied_policies.iter().collect::<HashSet<_>>() == new_policies.iter().collect::<HashSet<_>>() {
            return Ok(());
        }

        self.updated_policies = Some(new_policies.to_vec());

        Ok(())
    }

    async fn ensure_child_path_not_exists(&self, transaction: &DatabaseTransaction) -> Result<()> {
        if path::Entity::find()
            .filter(path::Column::Path.like(&self.path))
            .filter(path::Column::Path.ne(&self.path))
            .count(transaction)
            .await?
            > 0
        {
            return Err(Error::PathIsInUse { entered_path: self.path.to_owned() });
        }

        Ok(())
    }

    async fn ensure_child_secret_not_exists(&self, transaction: &DatabaseTransaction) -> Result<()> {
        if secret_metadata::Entity::find()
            .filter(secret_metadata::Column::Path.like(&self.path))
            .count(transaction)
            .await?
            > 0
        {
            return Err(Error::PathIsInUse { entered_path: self.path.to_owned() });
        }

        Ok(())
    }

    async fn delete_from_database(self, transaction: &DatabaseTransaction) -> Result<()> {
        self.clear_policies(transaction).await?;

        path::Entity::delete_many().filter(path::Column::Path.eq(self.path)).exec(transaction).await?;
        Ok(())
    }

    async fn clear_policies(&self, transaction: &DatabaseTransaction) -> Result<()> {
        let path = if let Some(path) =
            path::Entity::find().filter(path::Column::Path.eq(self.path.clone())).one(transaction).await?
        {
            path
        } else {
            return Ok(());
        };

        let applied_path_policies = applied_path_policy::Entity::find()
            .filter(applied_path_policy::Column::PathId.eq(path.id.clone()))
            .all(transaction)
            .await?;

        if applied_path_policies.is_empty() {
            return Ok(());
        }

        applied_path_policy_allowed_action::Entity::delete_many()
            .filter(
                applied_path_policy_allowed_action::Column::AppliedPathPolicyId
                    .is_in(applied_path_policies.iter().map(|app| app.id.clone())),
            )
            .exec(transaction)
            .await?;

        for path_policy in applied_path_policies {
            applied_path_policy::Entity::delete(path_policy.into_active_model()).exec(transaction).await?;
        }

        Ok(())
    }

    fn ensure_accessible(&self, allowed_action: AllowedAction, claim: &NebulaClaim) -> Result<()> {
        for applied_policy in &self.applied_policies {
            if !applied_policy.check_accessible(allowed_action, claim)? {
                return Err(Error::AccessDenied);
            }
        }

        Ok(())
    }
}

impl From<(path::Model, Vec<AppliedPolicy>)> for Path {
    fn from((path_model, applied_policies): (path::Model, Vec<AppliedPolicy>)) -> Self {
        Self::new(path_model.path, applied_policies)
    }
}

#[async_trait]
impl Persistable for Path {
    type Error = Error;

    async fn persist(self, transaction: &DatabaseTransaction) -> std::result::Result<(), Self::Error> {
        if self.deleted {
            self.ensure_child_path_not_exists(transaction).await?;
            self.ensure_child_secret_not_exists(transaction).await?;
            self.delete_from_database(transaction).await?;
            return Ok(());
        }

        let now = Utc::now();
        if let Some(ref updated_path) = self.updated_path {
            ensure_path_not_duplicated(transaction, updated_path).await?;

            let child_paths = path::Entity::find()
                .filter(path::Column::Path.like(format!("{}%", &self.path)))
                .all(transaction)
                .await?;

            for child_path in child_paths {
                let new_path = child_path.path.replacen(&self.path, updated_path, 1);
                let mut active_model = child_path.into_active_model();
                active_model.path = Set(new_path);
                active_model.update(transaction).await?;
            }

            let child_secrets = secret_metadata::Entity::find()
                .filter(secret_metadata::Column::Path.like(format!("{}%", &self.path)))
                .all(transaction)
                .await?;

            for child_secret in child_secrets {
                let new_path = child_secret.path.replacen(&self.path, updated_path, 1);
                let mut active_model = child_secret.into_active_model();
                active_model.path = Set(new_path);
                active_model.update(transaction).await?;
            }

            let child_secret_values = secret_value::Entity::find()
                .filter(secret_value::Column::Identifier.like(format!("{}%", &self.path)))
                .all(transaction)
                .await?;

            for child_secret_value in child_secret_values {
                let new_identifier = child_secret_value.identifier.replacen(&self.path, updated_path, 1);
                let mut active_model = child_secret_value.into_active_model();
                active_model.identifier = Set(new_identifier);
                active_model.update(transaction).await?;
            }
        }

        if let Some(ref updated_policies) = self.updated_policies {
            let path = if let Some(path) =
                path::Entity::find().filter(path::Column::Path.eq(self.path.clone())).one(transaction).await?
            {
                path
            } else {
                return Ok(());
            };

            self.clear_policies(transaction).await?;

            let mut applied_path_policy_models: Vec<applied_path_policy::ActiveModel> = vec![];
            let mut allowed_action_models: Vec<applied_path_policy_allowed_action::ActiveModel> = vec![];

            for updated_policy in updated_policies {
                let policy_id = Ulid::new();

                applied_path_policy_models.push(applied_path_policy::ActiveModel {
                    id: Set(policy_id.into()),
                    path_id: Set(path.id.clone()),
                    expression: Set(updated_policy.expression.clone()),
                    created_at: Set(now),
                    updated_at: Set(now),
                });

                for allowed_action in &updated_policy.allowed_actions {
                    allowed_action_models.push(applied_path_policy_allowed_action::ActiveModel {
                        id: Set(Ulid::new().into()),
                        applied_path_policy_id: Set(policy_id.into()),
                        action: Set(allowed_action.into()),
                        created_at: Set(now),
                        updated_at: Set(now),
                    });
                }
            }

            applied_path_policy::Entity::insert_many(applied_path_policy_models).exec(transaction).await?;
            applied_path_policy_allowed_action::Entity::insert_many(allowed_action_models).exec(transaction).await?;
        }

        Ok(())
    }
}

#[cfg_attr(test, automock)]
#[async_trait]
pub(crate) trait SecretService {
    async fn list_secret(
        &self,
        transaction: &DatabaseTransaction,
        path_prefix: &str,
        claim: &NebulaClaim,
    ) -> Result<Vec<SecretEntry>>;

    async fn get_secret(
        &self,
        transaction: &DatabaseTransaction,
        secret_identifier: &str,
        claim: &NebulaClaim,
    ) -> Result<SecretEntry>;

    async fn get_paths(&self, transaction: &DatabaseTransaction) -> Result<Vec<Path>>;

    async fn register_secret(
        &self,
        transaction: &DatabaseTransaction,
        path: String,
        key: String,
        cipher: Vec<u8>,
        access_conditions: Vec<AccessCondition>,
        claim: &NebulaClaim,
    ) -> Result<()>;

    async fn register_path(
        &self,
        transaction: &DatabaseTransaction,
        path: &str,
        policies: &[AppliedPolicy],
        claim: &NebulaClaim,
    ) -> Result<()>;

    async fn get_path(&self, transaction: &DatabaseTransaction, path: &str) -> Result<Option<Path>>;
}

lazy_static! {
    static ref IDENTIFIER_PATTERN: Regex =
        Regex::new(r"^((?:/[^/]+)*)/([^/]+)$").expect("IDENTIFIER_PATTERN should be compiled successfully");
    static ref PATH_PATTERN: Regex =
        Regex::new(r"^((?:/[^/]+)*)/([^/]+)$").expect("PATH_PATTERN should be compiled successfully");
    static ref SECRET_POLICY_VALUE_PATTERN: Regex =
        Regex::new(r"^([^=]+)=([^@]+)@([^#]+)").expect("SECRET_POLICY_VALUE_PATTERN should be compiled successfully");
}

fn parse_identifier(full_path: &str) -> Option<(String, String)> {
    let mut capture = IDENTIFIER_PATTERN.captures_iter(full_path);
    let (_, [path, key]) = capture.next().map(|c| c.extract())?;

    let path = if path.is_empty() { "/".to_owned() } else { path.to_owned() };

    Some((path.to_owned(), key.to_owned()))
}

fn create_identifier(path: &str, key: &str) -> String {
    if path == "/" || path.is_empty() {
        format!("/{key}")
    } else {
        format!("{path}/{key}")
    }
}

fn validate_path(path: &str) -> Result<()> {
    if path == "/" {
        return Ok(());
    }
    if PATH_PATTERN.is_match(path) {
        return Ok(());
    }

    Err(Error::InvalidPath { entered_path: path.to_owned() })
}

pub(crate) struct PostgresSecretService {}

fn check_secret_accessible(secret_policy: &policy::Model, claim: &NebulaClaim) -> Result<bool> {
    let (parsed_policy, _) =
        nebula_policy::pest::parse(&secret_policy.expression, nebula_policy::pest::PolicyLanguage::HumanPolicy)?;

    check_node_accessiblity(&parsed_policy, claim)
}

fn check_node_accessiblity(node: &nebula_policy::pest::PolicyNode, claim: &NebulaClaim) -> Result<bool> {
    match node {
        nebula_policy::pest::PolicyNode::And((left, right)) => {
            Ok(check_node_accessiblity(left, claim)? && check_node_accessiblity(right, claim)?)
        }
        nebula_policy::pest::PolicyNode::Or((left, right)) => {
            Ok(check_node_accessiblity(left, claim)? || check_node_accessiblity(right, claim)?)
        }
        nebula_policy::pest::PolicyNode::Leaf((val, _)) => check_leaf_node_accessiblity(val, claim),
    }
}

fn check_leaf_node_accessiblity(val: &str, claim: &NebulaClaim) -> Result<bool> {
    let mut capture = SECRET_POLICY_VALUE_PATTERN.captures_iter(val);
    let (key, value) = if let Some((_, [key, value, _])) = capture.next().map(|c| c.extract()) {
        (key, value)
    } else {
        return Err(Error::InvalidSecretPolicy);
    };

    Ok(claim.attributes.get(key).map(|attribute_value| attribute_value == value).unwrap_or(false))
}

#[async_trait]
impl SecretService for PostgresSecretService {
    async fn list_secret(
        &self,
        transaction: &DatabaseTransaction,
        path: &str,
        claim: &NebulaClaim,
    ) -> Result<Vec<SecretEntry>> {
        let metadata =
            secret_metadata::Entity::find().filter(secret_metadata::Column::Path.eq(path)).all(transaction).await?;
        let applied_policies = metadata.load_many(applied_policy::Entity, transaction).await?;
        let mut ciphers: HashMap<String, Vec<u8>> = secret_value::Entity::find()
            .filter(
                secret_value::Column::Identifier
                    .is_in(metadata.iter().map(|metadata| create_identifier(&metadata.path, &metadata.key))),
            )
            .all(transaction)
            .await?
            .into_iter()
            .map(|secret_value| (secret_value.identifier, secret_value.cipher))
            .collect();

        let policies_by_id: HashMap<_, _> = policy::Entity::find()
            .filter(
                policy::Column::Id
                    .is_in(applied_policies.iter().flatten().map(|applied_policy| applied_policy.policy_id.clone())),
            )
            .all(transaction)
            .await?
            .into_iter()
            .map(|policy| (policy.id.clone(), policy))
            .collect();

        Ok(metadata
            .into_iter()
            .zip(applied_policies.into_iter())
            .filter_map(|(metadata, applied_policies)| {
                let cipher = ciphers.remove(&create_identifier(&metadata.path, &metadata.key)).unwrap_or_default();

                let policies: Vec<_> = applied_policies
                    .iter()
                    .map(|applied_policy| &applied_policy.policy_id)
                    .filter_map(|policy_id| policies_by_id.get(policy_id))
                    .collect();

                let accessible = if policies.is_empty() {
                    true
                } else {
                    let mut accessible = false;
                    for policy in policies {
                        match check_secret_accessible(policy, claim) {
                            Ok(check_result) => accessible |= check_result,
                            Err(e) => {
                                warn!(
                                    "failed to check accessibility for secret({}): {:?}",
                                    create_identifier(&metadata.path, &metadata.key),
                                    e
                                );
                                return None;
                            }
                        }
                    }

                    accessible
                };

                if accessible {
                    Some(SecretEntry::from((metadata, applied_policies, cipher)))
                } else {
                    None
                }
            })
            .collect())
    }

    async fn get_secret(
        &self,
        transaction: &DatabaseTransaction,
        secret_identifier: &str,
        claim: &NebulaClaim,
    ) -> Result<SecretEntry> {
        let (path, key) = parse_identifier(secret_identifier)
            .ok_or_else(|| Error::InvalidSecretIdentifier { entered_identifier: secret_identifier.to_owned() })?;

        let metadata = secret_metadata::Entity::find()
            .filter(secret_metadata::Column::Path.eq(path))
            .filter(secret_metadata::Column::Key.eq(key))
            .one(transaction)
            .await?
            .ok_or_else(|| Error::SecretNotExists)?;
        let applied_policies = applied_policy::Entity::find()
            .filter(applied_policy::Column::SecretMetadataId.eq(metadata.id.to_owned()))
            .all(transaction)
            .await?;
        let cipher = secret_value::Entity::find()
            .filter(secret_value::Column::Identifier.eq(create_identifier(&metadata.path, &metadata.key)))
            .one(transaction)
            .await?
            .map(|secret_value| secret_value.cipher)
            .unwrap_or_default();

        let policies = policy::Entity::find()
            .filter(
                policy::Column::Id
                    .is_in(applied_policies.iter().map(|applied_policy| applied_policy.policy_id.clone())),
            )
            .all(transaction)
            .await?;

        let accessible = if policies.is_empty() {
            true
        } else {
            let mut accessible = false;
            for policy in policies {
                match check_secret_accessible(&policy, claim) {
                    Ok(check_result) => accessible |= check_result,
                    Err(e) => {
                        warn!(
                            "failed to check accessibility for secret({}): {:?}",
                            create_identifier(&metadata.path, &metadata.key),
                            e
                        );
                        return Err(Error::InvalidSecretPolicy);
                    }
                }
            }
            accessible
        };

        if !accessible {
            return Err(Error::AccessDenied);
        }
        Ok(SecretEntry::from((metadata, applied_policies, cipher)))
    }

    async fn get_paths(&self, transaction: &DatabaseTransaction) -> Result<Vec<Path>> {
        let paths = path::Entity::find().all(transaction).await?;
        let applied_path_policies = paths.load_many(applied_path_policy::Entity, transaction).await?;

        let applied_path_poilicy_ids =
            applied_path_policies.iter().flat_map(|apps| apps.iter().map(|app| app.id.clone())).collect::<Vec<_>>();

        let mut allowed_actions_map = if !applied_path_poilicy_ids.is_empty() {
            let mut allowed_actions_map = HashMap::<UlidId, Vec<applied_path_policy_allowed_action::Model>>::new();
            let allowed_actions = applied_path_policy_allowed_action::Entity::find()
                .filter(applied_path_policy_allowed_action::Column::AppliedPathPolicyId.is_in(applied_path_poilicy_ids))
                .all(transaction)
                .await?;

            for allowed_action in allowed_actions {
                let allowed_actions =
                    allowed_actions_map.entry(allowed_action.applied_path_policy_id.clone()).or_default();
                allowed_actions.push(allowed_action);
            }

            allowed_actions_map
        } else {
            HashMap::new()
        };

        Ok(paths
            .into_iter()
            .zip(applied_path_policies.into_iter())
            .map(|(path, path_policies)| {
                let aapplied_path_policies = path_policies
                    .into_iter()
                    .map(|pp| {
                        let allowed_actions = allowed_actions_map.remove(&pp.id).unwrap_or_default();
                        AppliedPolicy::from((pp, allowed_actions))
                    })
                    .collect::<Vec<_>>();

                (path, aapplied_path_policies).into()
            })
            .collect())
    }

    async fn register_secret(
        &self,
        transaction: &DatabaseTransaction,
        path: String,
        key: String,
        cipher: Vec<u8>,
        access_conditions: Vec<AccessCondition>,
        claim: &NebulaClaim,
    ) -> Result<()> {
        let parent_path = get_path(transaction, &path)
            .await?
            .ok_or_else(|| Error::ParentPathNotExists { entered_path: path.to_owned() })?;
        parent_path.ensure_accessible(AllowedAction::Create, claim)?;
        for parent_path in get_all_parent_paths(transaction, &path).await? {
            parent_path.ensure_accessible(AllowedAction::Create, claim)?;
        }

        let identifier = create_identifier(&path, &key);

        if secret_metadata::Entity::find()
            .filter(secret_metadata::Column::Path.eq(&path))
            .filter(secret_metadata::Column::Key.eq(&key))
            .count(transaction)
            .await?
            > 0
        {
            return Err(Error::IdentifierConflicted { entered_identifier: identifier });
        }

        let now = Utc::now();

        let secret_metadata_id = UlidId::new(Ulid::new());
        secret_metadata::ActiveModel {
            id: Set(secret_metadata_id.clone()),
            key: Set(key),
            path: Set(path),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(transaction)
        .await?;

        let applied_access_policies = access_conditions.into_iter().map(|access_policy| applied_policy::ActiveModel {
            id: Set(UlidId::new(Ulid::new())),
            secret_metadata_id: Set(secret_metadata_id.clone()),
            policy_id: Set(UlidId::new(access_policy.id)),
            created_at: Set(now),
            updated_at: Set(now),
        });

        applied_policy::Entity::insert_many(applied_access_policies).exec(transaction).await?;

        secret_value::ActiveModel {
            id: Set(UlidId::new(Ulid::new())),
            identifier: Set(identifier),
            cipher: Set(cipher),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(transaction)
        .await?;

        Ok(())
    }

    async fn register_path(
        &self,
        transaction: &DatabaseTransaction,
        path: &str,
        policies: &[AppliedPolicy],
        claim: &NebulaClaim,
    ) -> Result<()> {
        validate_path(path)?;
        for parent_path in get_all_parent_paths(transaction, path).await? {
            parent_path.ensure_accessible(AllowedAction::Manage, claim)?;
        }
        self.ensure_path_not_duplicated(transaction, path).await?;

        let path_id = Ulid::new();
        let now = Utc::now();

        path::ActiveModel {
            id: Set(path_id.into()),
            path: Set(path.to_owned()),
            created_at: Set(now),
            updated_at: Set(now),
        }
        .insert(transaction)
        .await?;

        if !policies.is_empty() {
            let mut applied_path_policy_models: Vec<applied_path_policy::ActiveModel> = vec![];
            let mut allowed_action_models: Vec<applied_path_policy_allowed_action::ActiveModel> = vec![];

            for policy in policies {
                let policy_id = Ulid::new();

                applied_path_policy_models.push(applied_path_policy::ActiveModel {
                    id: Set(policy_id.into()),
                    path_id: Set(path_id.into()),
                    expression: Set(policy.expression.clone()),
                    created_at: Set(now),
                    updated_at: Set(now),
                });

                for allowed_action in &policy.allowed_actions {
                    allowed_action_models.push(applied_path_policy_allowed_action::ActiveModel {
                        id: Set(Ulid::new().into()),
                        applied_path_policy_id: Set(policy_id.into()),
                        action: Set(allowed_action.into()),
                        created_at: Set(now),
                        updated_at: Set(now),
                    });
                }
            }

            applied_path_policy::Entity::insert_many(applied_path_policy_models).exec(transaction).await?;
            applied_path_policy_allowed_action::Entity::insert_many(allowed_action_models).exec(transaction).await?;
        }

        Ok(())
    }

    async fn get_path(&self, transaction: &DatabaseTransaction, path: &str) -> Result<Option<Path>> {
        get_path(transaction, path).await
    }
}

impl PostgresSecretService {
    async fn ensure_path_not_duplicated(&self, transaction: &DatabaseTransaction, path: &str) -> Result<()> {
        ensure_path_not_duplicated(transaction, path).await
    }
}

async fn ensure_path_not_duplicated(transaction: &DatabaseTransaction, path: &str) -> Result<()> {
    if path == "/" {
        return Err(Error::PathDuplicated { entered_path: path.to_owned() });
    }

    if path::Entity::find().filter(path::Column::Path.eq(path)).count(transaction).await? > 0 {
        return Err(Error::PathDuplicated { entered_path: path.to_owned() });
    }

    Ok(())
}

fn get_all_raw_parent_paths(path: &str) -> Vec<String> {
    let mut result = Vec::new();
    let mut current_path = std::path::Path::new(path);

    while let Some(parent) = current_path.parent() {
        result.push(parent.to_string_lossy().to_string());
        current_path = parent;
    }

    result
}

async fn get_all_parent_paths(transaction: &DatabaseTransaction, path: &str) -> Result<Vec<Path>> {
    let raw_paths = get_all_raw_parent_paths(path);

    let mut paths = vec![];

    for raw_path in raw_paths {
        let path = get_path(transaction, &raw_path)
            .await?
            .ok_or_else(|| Error::ParentPathNotExists { entered_path: raw_path })?;
        paths.push(path);
    }

    Ok(paths)
}

async fn get_path(transaction: &DatabaseTransaction, path: &str) -> Result<Option<Path>> {
    validate_path(path)?;
    let path = if let Some(path) = path::Entity::find().filter(path::Column::Path.eq(path)).one(transaction).await? {
        path
    } else {
        return Ok(None);
    };

    let applied_path_policies = applied_path_policy::Entity::find()
        .filter(applied_path_policy::Column::PathId.eq(path.id.clone()))
        .all(transaction)
        .await?;

    let mut allowed_actions_map = if !applied_path_policies.is_empty() {
        let mut allowed_actions_map = HashMap::<UlidId, Vec<applied_path_policy_allowed_action::Model>>::new();
        let allowed_actions = applied_path_policy_allowed_action::Entity::find()
            .filter(
                applied_path_policy_allowed_action::Column::AppliedPathPolicyId
                    .is_in(applied_path_policies.iter().map(|app| app.id.clone())),
            )
            .all(transaction)
            .await?;

        for allowed_action in allowed_actions {
            let allowed_actions = allowed_actions_map.entry(allowed_action.applied_path_policy_id.clone()).or_default();
            allowed_actions.push(allowed_action);
        }
        allowed_actions_map
    } else {
        HashMap::new()
    };

    let applied_path_policies = applied_path_policies
        .into_iter()
        .map(|pp| {
            let allowed_actions = allowed_actions_map.remove(&pp.id).unwrap_or_default();
            AppliedPolicy::from((pp, allowed_actions))
        })
        .collect::<Vec<_>>();

    Ok(Some(Path::from((path, applied_path_policies))))
}

#[derive(thiserror::Error, Debug)]
pub(crate) enum Error {
    #[error("Path({entered_path}) is in use")]
    PathIsInUse { entered_path: String },
    #[error("Entered path({entered_path}) is already registered")]
    PathDuplicated { entered_path: String },
    #[error("Entered identifier conflicted with existing secret")]
    IdentifierConflicted { entered_identifier: String },
    #[error("Invalid secret identifier({entered_identifier}) is entered")]
    InvalidSecretIdentifier { entered_identifier: String },
    #[error("Secret Not exists")]
    SecretNotExists,
    #[error("Parent path for path({entered_path}) is not registered")]
    ParentPathNotExists { entered_path: String },
    #[error("Invalid path({entered_path}) is entered")]
    InvalidPath { entered_path: String },
    #[error("Invalid path policy expression is entered")]
    InvalidPathPolicy,
    #[error(" path policy expression is entered")]
    InvalidSecretPolicy,
    #[error("Access denied")]
    AccessDenied,
    #[error(transparent)]
    Anyhow(#[from] anyhow::Error),
}

impl From<nebula_policy::error::PolicyParserError> for Error {
    fn from(_: nebula_policy::error::PolicyParserError) -> Self {
        Self::InvalidSecretPolicy
    }
}

impl From<sea_orm::DbErr> for Error {
    fn from(value: sea_orm::DbErr) -> Self {
        Self::Anyhow(value.into())
    }
}

impl From<path_policy::Error> for Error {
    fn from(_: path_policy::Error) -> Self {
        Self::InvalidPathPolicy
    }
}

pub(crate) type Result<T> = std::result::Result<T, Error>;

#[cfg(test)]
mod test {
    use std::{collections::HashMap, str::FromStr, sync::Arc};

    use chrono::Utc;
    use nebula_token::claim::{NebulaClaim, Role};
    use sea_orm::{DatabaseBackend, DbErr, MockDatabase, TransactionTrait};
    use ulid::Ulid;

    use super::{Error, PostgresSecretService, SecretService};
    use crate::{
        database::{
            applied_path_policy, applied_path_policy_allowed_action, applied_policy, path, policy, secret_metadata,
            secret_value, UlidId,
        },
        domain::{
            policy::AccessCondition,
            secret::{Path, SecretEntry},
        },
    };

    #[tokio::test]
    async fn when_getting_secret_data_is_successful_then_secret_service_returns_secrets_ok() {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let now = Utc::now();
        let metadata_id = UlidId::new(Ulid::from_str("01JACYVTYB4F2PEBFRG1BB7BKP").unwrap());
        let key = "TEST_KEY";
        let path = "/test/path";
        let applied_policy_ids = [
            UlidId::new(Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap()),
            UlidId::new(Ulid::from_str("01JACZ1FG1RYABQW2KB6YSEZ84").unwrap()),
        ];
        let policy_id = UlidId::new(Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap());

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![secret_metadata::Model {
                id: metadata_id.to_owned(),
                key: key.to_owned(),
                path: path.to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([vec![applied_policy::Model {
                id: applied_policy_ids[0].to_owned(),
                secret_metadata_id: metadata_id.to_owned(),
                policy_id: policy_id.to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([vec![secret_value::Model {
                id: UlidId::new(Ulid::new()),
                identifier: "/test/path/TEST_KEY".to_owned(),
                cipher: vec![1, 2, 3],
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<policy::Model>::new()]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service
            .list_secret(&transaction, "/", &claim)
            .await
            .expect("creating workspace should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(result[0].key, key);
        assert_eq!(result[0].path, path);
        assert_eq!(result[0].cipher, vec![1, 2, 3]);
        assert_eq!(result[0].access_condition_ids[0], Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap());
    }

    #[tokio::test]
    async fn when_getting_secrets_is_failed_then_secret_service_returns_anyhow_err() {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.list_secret(&transaction, "/", &claim).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "Custom Error: some error");
    }

    #[tokio::test]
    async fn when_getting_secret_data_is_successful_then_secret_service_returns_secret_ok() {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let now = Utc::now();
        let identifier = "/test/path/TEST_KEY";
        let metadata_id = UlidId::new(Ulid::from_str("01JACYVTYB4F2PEBFRG1BB7BKP").unwrap());
        let key = "TEST_KEY";
        let path = "/test/path";
        let applied_policy_ids = [
            UlidId::new(Ulid::from_str("01JACZ1B5W5Z3D9R1CVYB7JJ8S").unwrap()),
            UlidId::new(Ulid::from_str("01JACZ1FG1RYABQW2KB6YSEZ84").unwrap()),
        ];
        let policy_id = UlidId::new(Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap());

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![secret_metadata::Model {
                id: metadata_id.to_owned(),
                key: key.to_owned(),
                path: path.to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([vec![applied_policy::Model {
                id: applied_policy_ids[0].to_owned(),
                secret_metadata_id: metadata_id.to_owned(),
                policy_id: policy_id.to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([vec![secret_value::Model {
                id: UlidId::new(Ulid::new()),
                identifier: "/test/path/TEST_KEY".to_owned(),
                cipher: vec![1, 2, 3],
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<policy::Model>::new()]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service
            .get_secret(&transaction, identifier, &claim)
            .await
            .expect("creating workspace should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(result.key, key);
        assert_eq!(result.path, path);
        assert_eq!(result.cipher, vec![1, 2, 3]);
        assert_eq!(result.access_condition_ids[0], Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap());
    }

    #[tokio::test]
    async fn when_getting_secret_is_failed_then_secret_service_returns_anyhow_err() {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let identifier = "/some/secret";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get_secret(&transaction, identifier, &claim).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "Custom Error: some error");
    }

    #[tokio::test]
    async fn when_getting_secret_path_without_slash_then_secret_service_returns_invalid_secret_identifier_error() {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let identifier = "just_key";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get_secret(&transaction, identifier, &claim).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::InvalidSecretIdentifier { .. })));
    }

    #[tokio::test]
    async fn when_getting_secret_path_without_leading_slash_then_secret_service_returns_invalid_secret_identifier_error(
    ) {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let identifier = "some/secret";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get_secret(&transaction, identifier, &claim).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::InvalidSecretIdentifier { .. })));
    }

    #[tokio::test]
    async fn when_getting_secret_path_contains_empty_segment_then_secret_service_returns_invalid_secret_identifier_error(
    ) {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let identifier = "/some//secret";
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get_secret(&transaction, identifier, &claim).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::InvalidSecretIdentifier { .. })));
    }

    #[tokio::test]
    async fn when_getting_not_existing_secret_then_secret_service_returns_secret_not_exists_error() {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let identifier = "/some/secret";
        let mock_database =
            MockDatabase::new(DatabaseBackend::Postgres).append_query_results([Vec::<secret_metadata::Model>::new()]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get_secret(&transaction, identifier, &claim).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::SecretNotExists { .. })));
    }

    #[tokio::test]
    async fn when_getting_paths_from_database_is_successful_then_secret_service_returns_paths_ok() {
        let now = Utc::now();
        let path_id = UlidId::new(Ulid::from_str("01JACYVTYB4F2PEBFRG1BB7BKP").unwrap());
        let path = "/test/path";

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([vec![path::Model {
                id: path_id.to_owned(),
                path: path.to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get_paths(&transaction).await.expect("creating workspace should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(result[0].path, path);
    }

    #[tokio::test]
    async fn when_getting_paths_from_database_is_failed_then_secret_service_returns_anyhow_err() {
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_errors(vec![DbErr::Custom("some error".to_owned())]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get_paths(&transaction).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::Anyhow(_))));
        assert_eq!(result.err().unwrap().to_string(), "Custom Error: some error");
    }

    #[tokio::test]
    async fn when_registering_secret_is_successful_then_secret_service_returns_unit_ok() {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let now = Utc::now();
        let path = "/test/path";
        let key = "TEST_KEY";
        let access_conditions = vec![AccessCondition::new(
            Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap(),
            "test policy".to_owned(),
            "(\"role=FRONTEND\")".to_owned(),
        )];

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test/path".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[maplit::btreemap! {
                "num_items" => sea_orm::Value::BigInt(Some(0))
            }]])
            .append_query_results([[secret_metadata::Model {
                id: UlidId::new(Ulid::new()),
                key: key.to_owned(),
                path: path.to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([vec![applied_policy::Model {
                id: UlidId::new(Ulid::new()),
                secret_metadata_id: UlidId::new(Ulid::new()),
                policy_id: UlidId::new(Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap()),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([vec![secret_value::Model {
                id: UlidId::new(Ulid::new()),
                identifier: "/test/path/TEST_KEY".to_owned(),
                cipher: vec![1, 2, 3],
                created_at: now,
                updated_at: now,
            }]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        secret_service
            .register_secret(&transaction, path.to_owned(), key.to_owned(), vec![1, 2, 3], access_conditions, &claim)
            .await
            .expect("creating workspace should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");
    }

    #[tokio::test]
    async fn when_registering_secret_with_not_existing_path_then_secret_service_returns_path_not_exists_err() {
        let now = Utc::now();
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let path = "/test/path";
        let key = "TEST_KEY";
        let access_conditions = vec![AccessCondition::new(
            Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap(),
            "test policy".to_owned(),
            "(\"role=FRONTEND\")".to_owned(),
        )];

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test/path".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([Vec::<path::Model>::new()])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[maplit::btreemap! {
                "num_items" => sea_orm::Value::BigInt(Some(0))
            }]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service
            .register_secret(&transaction, path.to_owned(), key.to_owned(), vec![], access_conditions, &claim)
            .await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::ParentPathNotExists { .. })));
    }

    #[tokio::test]
    async fn when_registering_secret_with_already_used_key_then_secret_service_returns_identifier_conflicted_err() {
        let now = Utc::now();
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let path = "/test/path";
        let key = "TEST_KEY";
        let access_conditions = vec![AccessCondition::new(
            Ulid::from_str("01JACZ44MJDY5GD21X2W910CFV").unwrap(),
            "test policy".to_owned(),
            "(\"role=FRONTEND\")".to_owned(),
        )];

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test/path".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[maplit::btreemap! {
                "num_items" => sea_orm::Value::BigInt(Some(1))
            }]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service
            .register_secret(&transaction, path.to_owned(), key.to_owned(), vec![], access_conditions, &claim)
            .await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::IdentifierConflicted { .. })));
    }

    #[tokio::test]
    async fn when_delete_secret_entry_then_delete_property_turns_into_true() {
        let now = Utc::now();
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test/path".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()]);

        let mock_connection = Arc::new(mock_database.into_connection());
        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let mut secret_entry = SecretEntry {
            key: "TEST_KEY".to_owned(),
            path: "/test/path".to_owned(),
            cipher: vec![1, 2, 3],
            access_condition_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            deleted: false,
            updated_path: None,
            updated_cipher: None,
            updated_access_condition_ids: None,
        };

        secret_entry.delete(&transaction, &claim).await.expect("deleting secret should be successful");

        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(secret_entry.deleted)
    }

    #[tokio::test]
    async fn when_update_path_of_secret_entry_then_write_new_path_to_field() {
        let now = Utc::now();
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test/path".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()]);

        let mock_connection = Arc::new(mock_database.into_connection());
        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let mut secret_entry = SecretEntry {
            key: "TEST_KEY".to_owned(),
            path: "/test/path".to_owned(),
            cipher: vec![1, 2, 3],
            access_condition_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            deleted: false,
            updated_path: None,
            updated_cipher: None,
            updated_access_condition_ids: None,
        };

        secret_entry
            .update_path(&transaction, "/test/path/2".to_owned(), &claim)
            .await
            .expect("updating secret should be successful");

        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(secret_entry.updated_path.as_deref(), Some("/test/path/2"));
    }

    #[tokio::test]
    async fn when_update_cipher_of_secret_entry_then_write_new_cipher_to_field() {
        let now = Utc::now();
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test/path".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()]);

        let mock_connection = Arc::new(mock_database.into_connection());
        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let mut secret_entry = SecretEntry {
            key: "TEST_KEY".to_owned(),
            path: "/test/path".to_owned(),
            cipher: vec![1, 2, 3],
            access_condition_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            deleted: false,
            updated_path: None,
            updated_cipher: None,
            updated_access_condition_ids: None,
        };

        secret_entry
            .update_cipher(&transaction, vec![4, 5, 6], &claim)
            .await
            .expect("updating secre tshould be successful");

        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(secret_entry.updated_cipher, Some(vec![4, 5, 6]));
    }

    #[tokio::test]
    async fn when_update_access_policies_of_secret_entry_then_write_new_access_policy_ids_to_field() {
        let now = Utc::now();
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let mut secret_entry = SecretEntry {
            key: "TEST_KEY".to_owned(),
            path: "/test/path".to_owned(),
            cipher: vec![1, 2, 3],
            access_condition_ids: vec![Ulid::from_string("01JACZ44MJDY5GD21X2W910CFV").unwrap()],
            deleted: false,
            updated_path: None,
            updated_cipher: None,
            updated_access_condition_ids: None,
        };

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test/path".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()]);

        let mock_connection = Arc::new(mock_database.into_connection());
        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        secret_entry
            .update_access_conditions(
                &transaction,
                vec![AccessCondition::new(
                    Ulid::from_str("01JBS3ATPE50HBBFENKJDDBM08").unwrap(),
                    "test policy2".to_owned(),
                    "(\"role=BACKEND\")".to_owned(),
                )],
                &claim,
            )
            .await
            .expect("updating secret should be successful");

        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(
            secret_entry.updated_access_condition_ids,
            Some(vec![Ulid::from_str("01JBS3ATPE50HBBFENKJDDBM08").unwrap()])
        );
    }

    #[tokio::test]
    async fn when_path_insertion_is_successful_then_secret_service_returns_unit_ok() {
        let now = Utc::now();
        let path = "/test/path";

        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[maplit::btreemap! {
                "num_items" => sea_orm::Value::BigInt(Some(0))
            }]])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: path.to_owned(),
                created_at: now,
                updated_at: now,
            }]]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        secret_service
            .register_path(&transaction, path, &[], &claim)
            .await
            .expect("registering path should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");
    }

    #[tokio::test]
    async fn when_path_is_invalid_then_secret_service_returns_invalid_path_err() {
        let invalid_paths = ["//", "", "/a//b", "a/b/c", "/a/b/c/"];

        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let secret_service = PostgresSecretService {};
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres);
        let mock_connection = Arc::new(mock_database.into_connection());
        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        for invalid_path in invalid_paths {
            let result = secret_service.register_path(&transaction, invalid_path, &[], &claim).await;

            assert!(matches!(result, Err(Error::InvalidPath { .. })));
        }

        transaction.commit().await.expect("commiting transaction should be successful");
    }

    #[tokio::test]
    async fn when_parent_path_is_not_exists_then_secret_service_returns_parent_path_not_exists_err() {
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let path = "/test/path";

        let mock_database =
            MockDatabase::new(DatabaseBackend::Postgres).append_query_results([Vec::<path::Model>::new()]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.register_path(&transaction, path, &[], &claim).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::ParentPathNotExists { .. })));
    }

    #[tokio::test]
    async fn when_path_is_already_registered_then_secret_service_returns_path_duplicated_err() {
        let now = Utc::now();
        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let path = "/test/path";

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([
                [maplit::btreemap! {
                    "num_items" => sea_orm::Value::BigInt(Some(1))
                }],
                [maplit::btreemap! {
                    "num_items" => sea_orm::Value::BigInt(Some(1))
                }],
            ]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.register_path(&transaction, path, &[], &claim).await;
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Err(Error::PathDuplicated { .. })));
    }

    #[tokio::test]
    async fn when_getting_existing_path_then_secret_service_returns_path_ok() {
        let now = Utc::now();
        let path = "/test/path";

        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: path.to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([Vec::<applied_path_policy_allowed_action::Model>::new()]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let secret_service = PostgresSecretService {};

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let result = secret_service.get_path(&transaction, path).await.expect("getting path should be successful");
        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(matches!(result, Some(..)));
        let returned_path = result.unwrap();

        assert_eq!(returned_path.path, path);
    }

    #[tokio::test]
    async fn when_deleting_path_then_deleted_field_turns_into_true() {
        let now = Utc::now();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()]);

        let mock_connection = Arc::new(mock_database.into_connection());

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let mut path = Path::new("/test/path".to_owned(), vec![]);

        assert!(!path.deleted);

        path.delete(&transaction, &claim).await.expect("deleting path should be successful");

        transaction.commit().await.expect("commiting transaction should be successful");

        assert!(path.deleted);
    }

    #[tokio::test]
    async fn when_updating_path_then_updated_path_field_turns_into_new_path() {
        let now = Utc::now();
        let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/test".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()])
            .append_query_results([[path::Model {
                id: UlidId::new(Ulid::new()),
                path: "/".to_owned(),
                created_at: now,
                updated_at: now,
            }]])
            .append_query_results([Vec::<applied_path_policy::Model>::new()]);
        let mock_connection = Arc::new(mock_database.into_connection());

        let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        let mut path = Path::new("/test/path".to_owned(), vec![]);

        assert!(path.updated_path.is_none());

        path.update_path(&transaction, "/test/path/new", &claim).await.expect("updating path should be successful");

        transaction.commit().await.expect("commiting transaction should be successful");

        assert_eq!(path.updated_path, Some("/test/path/new".to_owned()))
    }

    #[tokio::test]
    async fn when_updating_path_with_invalid_path_then_path_returns_invalid_path_err() {
        let now = Utc::now();
        let invalid_paths = ["//", "", "/a//b", "a/b/c", "/a/b/c/"];

        let claim = NebulaClaim {
            gid: "test@cremit.io".to_owned(),
            workspace_name: "cremit".to_owned(),
            attributes: HashMap::new(),
            role: Role::Member,
        };

        for invalid_path in invalid_paths {
            let mock_database = MockDatabase::new(DatabaseBackend::Postgres)
                .append_query_results([[path::Model {
                    id: UlidId::new(Ulid::new()),
                    path: "/test/path".to_owned(),
                    created_at: now,
                    updated_at: now,
                }]])
                .append_query_results([Vec::<applied_path_policy::Model>::new()])
                .append_query_results([[path::Model {
                    id: UlidId::new(Ulid::new()),
                    path: "/test".to_owned(),
                    created_at: now,
                    updated_at: now,
                }]])
                .append_query_results([Vec::<applied_path_policy::Model>::new()])
                .append_query_results([[path::Model {
                    id: UlidId::new(Ulid::new()),
                    path: "/".to_owned(),
                    created_at: now,
                    updated_at: now,
                }]])
                .append_query_results([Vec::<applied_path_policy::Model>::new()]);
            let mock_connection = Arc::new(mock_database.into_connection());

            let transaction = mock_connection.begin().await.expect("begining transaction should be successful");

            let mut path = Path::new("/test/path".to_owned(), vec![]);
            let result = path.update_path(&transaction, invalid_path, &claim).await;

            transaction.commit().await.expect("commiting transaction should be successful");

            assert!(matches!(result, Err(Error::InvalidPath { .. })));
        }
    }
}
