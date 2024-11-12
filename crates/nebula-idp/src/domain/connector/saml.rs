use base64::{engine::general_purpose::STANDARD, Engine as _};
use bon::Builder;
use samael::{
    metadata::NameIdFormat,
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
    user_name_attr: String,
    email_attr: String,
    groups_attr: String,
    groups_separator: Option<String>,
    #[builder(default = NameIdFormat::PersistentNameIDFormat)]
    name_id_policy_format: NameIdFormat,
}

pub struct SAMLConnector {
    service_provider: ServiceProvider,
    user_name_attr: String,
    email_attr: String,
    groups_attr: String,
    groups_separator: Option<String>,
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
        let service_provider =
            ServiceProviderBuilder::default().entity_id(config.entity_id).acs_url(config.acs_url).build()?;
        Ok(Self {
            service_provider,
            user_name_attr: config.user_name_attr,
            email_attr: config.email_attr,
            groups_attr: config.groups_attr,
            groups_separator: config.groups_separator,
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

        // SAML does not provide a way to verify the email address of the user
        Ok(Identity { user_id, user_name, email, email_verified: true, groups })
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
