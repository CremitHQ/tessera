use std::collections::HashMap;

use base64::{engine::general_purpose::STANDARD, Engine as _};
use bon::Builder;
use samael::{
    metadata::{Endpoint, EntityDescriptor, IdpSsoDescriptor, NameIdFormat, HTTP_POST_BINDING, HTTP_REDIRECT_BINDING},
    schema::AttributeStatement,
    service_provider::{ServiceProvider, ServiceProviderBuilder},
};
use thiserror::Error;

use super::Identity;

#[derive(Builder)]
#[builder(on(String, into))]
pub struct SAMLConnertorConfig {
    entity_id: String,
    idp_url: String,
    acs_url: String,
    sso_url: String,
    user_name_attr: String,
    email_attr: String,
    groups_attr: String,
    groups_separator: Option<String>,
    #[builder(default = NameIdFormat::PersistentNameIDFormat)]
    name_id_policy_format: NameIdFormat,
    ca: openssl::x509::X509,
    attribute_mapping: Vec<(String, String)>,
}

pub struct SAMLConnector {
    service_provider: ServiceProvider,
    user_name_attr: String,
    email_attr: String,
    groups_attr: String,
    groups_separator: Option<String>,
    attribute_mapping: Vec<(String, String)>,
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
}

impl SAMLConnector {
    pub fn new(config: SAMLConnertorConfig) -> Result<Self, SAMLHandlerError> {
        let service_provider = ServiceProviderBuilder::default()
            .entity_id(config.entity_id)
            .idp_metadata(EntityDescriptor {
                entity_id: Some(config.idp_url),
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
            .acs_url(config.acs_url)
            .allow_idp_initiated(true)
            .certificate(config.ca)
            .build()?;
        Ok(Self {
            service_provider,
            user_name_attr: config.user_name_attr,
            email_attr: config.email_attr,
            groups_attr: config.groups_attr,
            groups_separator: config.groups_separator,
            attribute_mapping: config.attribute_mapping,
        })
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
        let user_name = get_attribute(&attributes, &self.user_name_attr)?;
        let email = get_attribute(&attributes, &self.email_attr)?;
        let groups = if let Some(separator) = &self.groups_separator {
            let raw_groups = get_attribute(&attributes, &self.groups_attr)?;
            raw_groups.split(separator).map(String::from).collect::<Vec<_>>()
        } else {
            get_all_attribute(&attributes, &self.groups_attr)?
        };

        let custom_claims = self
            .attribute_mapping
            .iter()
            .map(|(key, value)| {
                let val = get_attribute(&attributes, value)?;
                Ok((key.clone(), val))
            })
            .collect::<Result<HashMap<_, _>, SAMLHandlerError>>()?;

        // SAML does not provide a way to verify the email address of the user
        Ok(Identity { user_id, user_name, email, email_verified: true, groups, custom_claims })
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
