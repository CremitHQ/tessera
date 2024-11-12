use std::collections::HashMap;

use crate::{error::PolicyParserError, pest::PolicyNode};
use pest::iterators::Pair;

#[derive(Parser)]
#[grammar = "human.policy.pest"]
pub(crate) struct HumanPolicyParser;

pub(crate) fn parse<'a>(
    pair: Pair<'a, Rule>,
    attribute_index: &mut HashMap<&'a str, usize>,
) -> Result<PolicyNode<'a>, PolicyParserError> {
    match pair.as_rule() {
        Rule::string | Rule::number => {
            let p = pair.into_inner().next().unwrap();
            let index = attribute_index.entry(p.as_str()).and_modify(|i| *i += 1).or_insert(0);
            Ok(PolicyNode::Leaf((p.as_str(), *index)))
        }
        Rule::and => {
            let mut vec = Vec::new();
            for child in pair.into_inner() {
                vec.push(parse(child, attribute_index)?);
            }
            debug_assert!(vec.len() > 1);
            let rest = vec.split_off(1);
            Ok(rest.into_iter().fold(vec[0].clone(), |acc, x| PolicyNode::And((Box::new(acc), Box::new(x)))))
        }
        Rule::or => {
            let mut vec = Vec::new();
            for child in pair.into_inner() {
                vec.push(parse(child, attribute_index)?);
            }
            debug_assert!(vec.len() > 1);
            let rest = vec.split_off(1);
            Ok(rest.into_iter().fold(vec[0].clone(), |acc, x| PolicyNode::Or((Box::new(acc), Box::new(x)))))
        }
        _ => Err(PolicyParserError::InvalidPolicyType),
    }
}
