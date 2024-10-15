use crate::utils::secret_shares::node_index;
use std::collections::HashSet;
use tessera_policy::pest::{PolicyType, PolicyValue};

pub fn is_negative(attr: &String) -> bool {
    let first_char = &attr[..1];
    first_char == '!'.to_string()
}

#[inline]
pub fn contains(data: &Vec<String>, value: &String) -> bool {
    return data.iter().any(|x| x == value);
}

// used to check if a set of attributes is a subset of another
pub fn is_subset(subset: &[&str], attr: &[&str]) -> bool {
    let super_set: HashSet<_> = attr.iter().cloned().collect();
    let sub_set: HashSet<_> = subset.iter().cloned().collect();
    sub_set.is_subset(&super_set)
}

// used to traverse / check policy tree
pub fn traverse_policy(attr: &Vec<String>, policy_value: &PolicyValue, policy_type: PolicyType) -> bool {
    return (!attr.is_empty())
        && match policy_value {
            PolicyValue::String(node) => attr.iter().any(|x| x == node.0),
            PolicyValue::Object(obj) => {
                return match obj.0 {
                    PolicyType::And => traverse_policy(attr, obj.1.as_ref(), PolicyType::And),
                    PolicyType::Or => traverse_policy(attr, obj.1.as_ref(), PolicyType::Or),
                    _ => true,
                }
            }
            PolicyValue::Array(arrayref) => {
                return match policy_type {
                    PolicyType::And => {
                        let mut ret = true;
                        for obj in arrayref.iter() {
                            ret &= traverse_policy(attr, obj, PolicyType::Leaf)
                        }
                        ret
                    }
                    PolicyType::Or => {
                        let mut ret = false;
                        for obj in arrayref.iter() {
                            ret |= traverse_policy(attr, obj, PolicyType::Leaf)
                        }
                        ret
                    }
                    PolicyType::Leaf => false,
                };
            }
        };
}

pub fn get_value(json: &PolicyValue) -> String {
    match json {
        PolicyValue::String(node) => node_index(node),
        _ => "".to_string(),
    }
}
