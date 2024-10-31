use crate::utils::secret_shares::node_index;
use std::collections::HashSet;
use tessera_policy::pest::PolicyNode;

pub fn is_negative(attr: &str) -> bool {
    let first_char = &attr[..1];
    first_char == '!'.to_string()
}

#[inline]
pub fn contains(data: &[String], value: &str) -> bool {
    return data.iter().any(|x| x == value);
}

pub fn is_subset(subset: &[&str], attr: &[&str]) -> bool {
    let super_set: HashSet<_> = attr.iter().cloned().collect();
    let sub_set: HashSet<_> = subset.iter().cloned().collect();
    sub_set.is_subset(&super_set)
}

pub fn get_value(json: &PolicyNode) -> String {
    match json {
        PolicyNode::Leaf(node) => node_index(node),
        _ => "".to_string(),
    }
}
