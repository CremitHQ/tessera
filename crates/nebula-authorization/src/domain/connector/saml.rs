use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bon::Builder;
use nebula_token::claim::Role;
use samael::{
    metadata::{Endpoint, EntityDescriptor, IdpSsoDescriptor, NameIdFormat, HTTP_POST_BINDING, HTTP_REDIRECT_BINDING},
    schema::{AttributeStatement, AuthnRequest},
    service_provider::{ServiceProvider, ServiceProviderBuilder},
};
use thiserror::Error;

use crate::config::{AttributesConfig, WorkspaceConfig};

use super::Identity;

#[derive(Builder)]
#[builder(on(String, into))]
pub struct SAMLConnertorConfig {
    entity_id: Option<String>,
    redirect_uri: String,
    idp_issuer: String,
    sso_url: String,
    #[builder(default = NameIdFormat::PersistentNameIDFormat)]
    name_id_policy_format: NameIdFormat,
    ca: openssl::x509::X509,
    attributes_config: AttributesConfig,
    workspace_config: WorkspaceConfig,
    group_attribute: String,
    admin_groups: Vec<String>,
}

pub struct SAMLConnector {
    sso_url: String,
    pub(crate) redirect_uri: String,
    service_provider: ServiceProvider,
    attributes_config: AttributesConfig,
    workspace_config: WorkspaceConfig,
    group_attribute: String,
    admin_groups: Vec<String>,
}

#[derive(Error, Debug)]
pub enum SAMLHandlerError {
    #[error(transparent)]
    DecodeBase64(#[from] base64::DecodeError),

    #[error("failed to stringify SAML response")]
    StringifySAMLResponse(#[from] std::string::FromUtf8Error),

    #[error(transparent)]
    ServiceProvider(#[from] samael::service_provider::Error),

    #[error(transparent)]
    BuildServiceProvider(#[from] samael::service_provider::ServiceProviderBuilderError),

    #[error("attribute statement not found")]
    AttributeStatementNotFound,

    #[error("subject not found")]
    SubjectNotFound,

    #[error("name id not found")]
    NameIdNotFound,

    #[error("attribute not found")]
    AttributeNotFound,

    #[error("failed to make SAML authentication request")]
    MakeSAMLAuthRequest,
}

impl SAMLConnector {
    pub fn new(config: SAMLConnertorConfig) -> Result<Self, SAMLHandlerError> {
        let service_provider = ServiceProviderBuilder::default()
            .entity_id(config.entity_id)
            .idp_metadata(EntityDescriptor {
                entity_id: Some(config.idp_issuer),
                idp_sso_descriptors: Some(vec![IdpSsoDescriptor {
                    single_sign_on_services: vec![
                        Endpoint {
                            binding: HTTP_POST_BINDING.to_string(),
                            location: config.sso_url.clone(),
                            response_location: None,
                        },
                        Endpoint {
                            binding: HTTP_REDIRECT_BINDING.to_string(),
                            location: config.sso_url.clone(),
                            response_location: None,
                        },
                    ],
                    id: None,
                    valid_until: None,
                    cache_duration: None,
                    protocol_support_enumeration: None,
                    error_url: None,
                    signature: None,
                    key_descriptors: vec![],
                    organization: None,
                    contact_people: vec![],
                    artifact_resolution_service: vec![],
                    single_logout_services: vec![],
                    manage_name_id_services: vec![],
                    name_id_formats: vec![],
                    want_authn_requests_signed: None,
                    name_id_mapping_services: vec![],
                    assertion_id_request_services: vec![],
                    attribute_profiles: vec![],
                    attributes: vec![],
                }]),
                ..Default::default()
            })
            .acs_url(config.redirect_uri.clone())
            .allow_idp_initiated(true)
            .certificate(config.ca)
            .build()?;
        Ok(Self {
            service_provider,
            sso_url: config.sso_url,
            redirect_uri: config.redirect_uri,
            attributes_config: config.attributes_config,
            workspace_config: config.workspace_config,
            group_attribute: config.group_attribute,
            admin_groups: config.admin_groups,
        })
    }

    pub fn authentication_request(&self) -> Result<AuthnRequest, SAMLHandlerError> {
        self.service_provider
            .make_authentication_request(&self.sso_url)
            .map_err(|_| SAMLHandlerError::MakeSAMLAuthRequest)
    }

    pub fn identity(&self, response: &str, request_id: &str) -> Result<Identity, SAMLHandlerError> {
        let raw_response = STANDARD.decode(response.as_bytes())?;
        let response = String::from_utf8(raw_response)?;
        let assertion = self.service_provider.parse_xml_response(&response, Some(&[request_id]))?;
        let user_id = assertion
            .subject
            .ok_or(SAMLHandlerError::SubjectNotFound)?
            .name_id
            .ok_or(SAMLHandlerError::NameIdNotFound)?
            .value;
        let attributes = assertion.attribute_statements.ok_or(SAMLHandlerError::AttributeStatementNotFound)?;
        let claims = match self.attributes_config {
            AttributesConfig::Mapping(ref mapping) => mapping
                .iter()
                .map(|(key, mapped_key)| {
                    let value = get_attribute(&attributes, key)?;
                    Ok((mapped_key.clone(), value))
                })
                .collect::<Result<HashMap<_, _>, SAMLHandlerError>>(),
            AttributesConfig::All => Ok(attributes
                .iter()
                .flat_map(|statement| &statement.attributes)
                .filter_map(|attribute| {
                    let key = attribute.name.as_ref()?;
                    let value = attribute.values.first().and_then(|value| value.value.clone());
                    value.map(|value| (key.clone(), value))
                })
                .collect::<HashMap<_, _>>()),
        }?;
        let workspace_name = match self.workspace_config {
            WorkspaceConfig::Static(ref config) => config.name.clone(),
            WorkspaceConfig::Claim(ref config) => get_attribute(&attributes, &config.claim)?,
        };

        let role = get_all_attribute(&attributes, &self.group_attribute)?
            .iter()
            .find_map(|group| if self.admin_groups.contains(group) { Some(Role::Admin) } else { None })
            .unwrap_or(Role::Member);

        Ok(Identity { user_id, claims, workspace_name, role })
    }
}

fn get_attribute(attribute_statements: &[AttributeStatement], name: &str) -> Result<String, SAMLHandlerError> {
    attribute_statements
        .iter()
        .flat_map(|statement| &statement.attributes)
        .find(|attribute| attribute.name.as_ref().is_some_and(|n| n == name))
        .and_then(|attribute| attribute.values.first())
        .and_then(|attribute_value| attribute_value.value.clone())
        .ok_or(SAMLHandlerError::AttributeNotFound)
}

fn get_all_attribute(attribute_statements: &[AttributeStatement], name: &str) -> Result<Vec<String>, SAMLHandlerError> {
    let values: Vec<String> = attribute_statements
        .iter()
        .flat_map(|statement| &statement.attributes)
        .filter(|attribute| attribute.name.as_ref().is_some_and(|n| n == name))
        .flat_map(|attribute| &attribute.values)
        .filter_map(|attribute_value| attribute_value.value.clone())
        .collect();

    if values.is_empty() {
        Err(SAMLHandlerError::AttributeNotFound)
    } else {
        Ok(values)
    }
}
