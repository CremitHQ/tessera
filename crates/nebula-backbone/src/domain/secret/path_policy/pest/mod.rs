use pest::iterators::Pair;
use pest_derive::Parser;

use super::{Error, PolicyNode};

#[derive(Parser)]
#[grammar = "domain/secret/path_policy/pest/policy.pest"]
pub(crate) struct PolicyParser;

pub(crate) fn parse(pair: Pair<'_, Rule>) -> Result<PolicyNode<'_>, Error> {
    match pair.as_rule() {
        Rule::Condition => {
            let p = pair.into_inner().next().unwrap();
            let mut inner = p.into_inner();
            let next = inner.next().unwrap();
            if next.as_rule() == Rule::Condition {
                return parse(next);
            }
            let key = next.as_str();
            let operator = inner.next().unwrap().as_str().parse()?;
            let value = inner.next().unwrap().as_str();

            Ok(PolicyNode::Leaf { key, operator, value })
        }
        Rule::And => {
            let mut vec = Vec::new();
            for child in pair.into_inner() {
                vec.push(parse(child)?);
            }
            debug_assert!(vec.len() > 1);
            let rest = vec.split_off(1);
            Ok(rest.into_iter().fold(vec[0].clone(), |acc, x| PolicyNode::And((Box::new(acc), Box::new(x)))))
        }
        Rule::Or => {
            let mut vec = Vec::new();
            for child in pair.into_inner() {
                vec.push(parse(child)?);
            }
            debug_assert!(vec.len() > 1);
            let rest = vec.split_off(1);
            Ok(rest.into_iter().fold(vec[0].clone(), |acc, x| PolicyNode::Or((Box::new(acc), Box::new(x)))))
        }
        _ => Err(Error::InvalidPolicyType),
    }
}
