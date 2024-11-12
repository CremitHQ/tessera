use crate::pest::PolicyNode;
use std::collections::HashSet;

pub fn node_index(node: &(&str, usize)) -> String {
    format!("{}_{}", node.0, node.1)
}
pub fn remove_index(node: &str) -> String {
    let mut parts: Vec<_> = node.split('_').collect();
    if parts.len() > 1 {
        parts.pop();
    }
    parts.join("_")
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
