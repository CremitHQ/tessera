use thiserror::Error;

pub struct Attribute {
    pub name: String,
    pub authority: String,
    pub index: usize,
}

#[derive(Debug, Error)]
pub enum ParseAttributeError {
    #[error("the attribute is not in the correct format (expected: <attribute>@<authority>#<version>_<index>)")]
    AttributeFormatError,
}

pub fn unpack_attribute(attribute: &str) -> Result<Attribute, ParseAttributeError> {
    let (name, rest) = attribute.split_once('@').ok_or(ParseAttributeError::AttributeFormatError)?;
    let mut parts: Vec<_> = rest.split('_').collect();
    let index: usize = if parts.len() > 1 {
        parts.pop().unwrap().parse().map_err(|_| ParseAttributeError::AttributeFormatError)?
    } else {
        0
    };
    let authority = parts.join("_");

    Ok(Attribute { name: name.to_string(), authority, index })
}

#[cfg(test)]
mod test {

    #[test]
    fn test_unpack_attribute() {
        let attribute = "test@authority#1_0";
        let result = super::unpack_attribute(attribute);
        assert!(result.is_ok());
        let result = result.unwrap();
        assert_eq!(result.name, "test");
        assert_eq!(result.authority, "authority#1");
        assert_eq!(result.index, 0);
    }
}
