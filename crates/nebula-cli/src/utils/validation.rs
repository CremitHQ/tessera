use inquire::validator::Validation;
use url::Url;

use crate::config::has_profile;

type Error = Box<dyn std::error::Error + Send + Sync + 'static>;

pub fn validate_url(url: &str) -> Result<Validation, Error> {
    if Url::parse(url).is_ok() {
        Ok(Validation::Valid)
    } else {
        Ok(Validation::Invalid("Invalid url".into()))
    }
}

pub fn validate_workspace_name(value: &str) -> Result<Validation, Error> {
    if value.is_empty() {
        Ok(Validation::Invalid("Workspace name is empty".into()))
    } else if value.len() > 50 {
        Ok(Validation::Invalid("Workspace name is too long".into()))
    } else {
        Ok(Validation::Valid)
    }
}

pub fn validate_new_profile(config: Option<String>) -> impl Fn(&str) -> Result<Validation, Error> + Clone {
    let config = config.map(Into::into);
    move |value: &str| {
        if has_profile(value, config.clone()).unwrap_or(false) {
            Ok(Validation::Invalid("Profile already exists".into()))
        } else {
            Ok(Validation::Valid)
        }
    }
}
