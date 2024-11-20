use std::fmt;
use std::fmt::Formatter;

use serde::de::{Error, Visitor};
use serde::{Deserializer, Serializer};

#[macro_export]
macro_rules! serialize_to_str {
    ($t:ty) => {
        impl serde::Serialize for $t {
            fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
            where
                S: Serializer,
            {
                serializer.serialize_str(&self.to_string())
            }
        }
    };
}

pub(crate) fn space_delimited_deserializer<'de, D>(deserializer: D) -> Result<Vec<String>, D::Error>
where
    D: Deserializer<'de>,
{
    struct SpaceDelimitedVisitor;

    impl<'de> Visitor<'de> for SpaceDelimitedVisitor {
        type Value = Vec<String>;

        fn expecting(&self, formatter: &mut Formatter) -> fmt::Result {
            formatter.write_str("a space separated string")
        }

        fn visit_str<E>(self, v: &str) -> Result<Self::Value, E>
        where
            E: Error,
        {
            Ok(v.split(' ').map(|s| s.to_owned()).collect::<Vec<String>>())
        }
    }
    deserializer.deserialize_str(SpaceDelimitedVisitor)
}

pub(crate) fn space_delimited_serializer<T, S>(data: &T, serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
    T: AsRef<[String]>,
{
    let s = data.as_ref().join(" ");
    serializer.serialize_str(s.as_str())
}
