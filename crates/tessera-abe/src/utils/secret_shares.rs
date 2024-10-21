use std::collections::HashMap;

use crate::curves::{Field, PairingCurve, RefAdd as _, RefMul as _, RefNeg as _, RefPow as _, RefSub as _};
use crate::error::ABEError;
use crate::random::Random;
use crate::utils::tools::{contains, get_value};
use tessera_policy::pest::{parse, PolicyLanguage, PolicyType, PolicyValue};

pub fn calc_coefficients<T: PairingCurve>(
    policy_value: &PolicyValue,
    coeff: T::Field,
    coeff_list: &mut HashMap<String, T::Field>,
    policy_type: Option<PolicyType>,
) {
    match policy_value {
        PolicyValue::Object(obj) => match obj.0 {
            PolicyType::And => calc_coefficients::<T>(obj.1.as_ref(), coeff, coeff_list, Some(PolicyType::And)),
            PolicyType::Or => calc_coefficients::<T>(obj.1.as_ref(), coeff, coeff_list, Some(PolicyType::Or)),
            _ => {
                coeff_list.insert(get_value(&obj.1), coeff);
            }
        },
        PolicyValue::Array(children) => match policy_type {
            Some(PolicyType::And) => {
                let mut this_coeff_vec = vec![T::Field::one()];
                for i in 1..children.len() {
                    this_coeff_vec.push(T::Field::one().ref_add(&this_coeff_vec[i - 1]));
                }
                let this_coeff = recover_coefficients::<T>(this_coeff_vec);
                for (i, child) in children.iter().enumerate() {
                    calc_coefficients::<T>(child, coeff.ref_mul(&this_coeff[i]), coeff_list, None);
                }
            }
            Some(PolicyType::Or) => {
                let this_coeff = recover_coefficients::<T>(vec![T::Field::one()]);
                for child in children.iter() {
                    calc_coefficients::<T>(child, coeff.ref_mul(&this_coeff[0]), coeff_list, None);
                }
            }
            _ => (),
        },
        PolicyValue::String(node) => {
            coeff_list.insert(node_index(node), coeff);
        }
    }
}

// lagrange interpolation
pub fn recover_coefficients<T: PairingCurve>(list: Vec<T::Field>) -> Vec<T::Field> {
    let mut coeff = vec![];
    for i in list.iter() {
        let mut result = T::Field::one();
        for j in list.iter() {
            if i != j {
                let p = j.ref_neg();
                let q = i.ref_sub(j);
                let t = p / q;
                result = result * t;
            }
        }
        coeff.push(result);
    }
    coeff
}

pub fn node_index(node: &(&str, usize)) -> String {
    format!("{}_{}", node.0, node.1)
}
pub fn remove_index(node: &str) -> String {
    let parts: Vec<_> = node.split('_').collect();
    parts[0].to_string()
}

pub fn gen_shares_policy<T: PairingCurve>(
    rng: &mut T::Rng,
    secret: &T::Field,
    policy_value: &PolicyValue,
    policy_type: Option<PolicyType>,
) -> HashMap<String, T::Field> {
    let mut result: HashMap<String, T::Field> = HashMap::new();
    let k;
    let n;
    match policy_value {
        PolicyValue::String(node) => {
            result.insert(node_index(node), secret.clone());
            result
        }
        PolicyValue::Object(obj) => match obj.0 {
            PolicyType::And => gen_shares_policy::<T>(rng, secret, obj.1.as_ref(), Some(PolicyType::And)),
            PolicyType::Or => gen_shares_policy::<T>(rng, secret, obj.1.as_ref(), Some(PolicyType::Or)),
            _ => gen_shares_policy::<T>(rng, secret, obj.1.as_ref(), Some(PolicyType::Leaf)),
        },
        PolicyValue::Array(children) => {
            n = children.len();
            match policy_type {
                Some(PolicyType::And) => {
                    k = n;
                }
                Some(PolicyType::Or) => {
                    k = 1;
                }
                _ => panic!("this should not happen =( Array is always AND or OR."),
            }
            let shares = gen_shares::<T>(rng, secret, k, n);
            for i in 0..n {
                let items = gen_shares_policy::<T>(rng, &shares[i + 1], &children[i], None);
                result.extend(items.into_iter());
            }
            result
        }
    }
}

pub fn gen_shares<T: PairingCurve>(rng: &mut T::Rng, secret: &T::Field, k: usize, n: usize) -> Vec<T::Field> {
    let mut shares: Vec<T::Field> = Vec::new();
    if k <= n {
        // polynomial coefficients
        let mut a: Vec<T::Field> = Vec::new();
        a.push(secret.clone());
        for _ in 1..k {
            a.push(<T::Field as Random>::random(rng));
        }
        for i in 0..(n + 1) {
            let polynom = polynomial::<T>(a.clone(), T::Field::new_int(i.try_into().unwrap_or_default()));
            shares.push(polynom);
        }
    }
    shares
}

pub fn calc_pruned<'a>(
    attr: &Vec<String>,
    policy_value: &PolicyValue,
    policy_type: Option<PolicyType>,
) -> Result<(bool, Vec<(String, String)>), ABEError<'a>> {
    let mut matched_nodes: Vec<(String, String)> = vec![];
    match policy_value {
        PolicyValue::Object(obj) => match obj.0 {
            PolicyType::And => calc_pruned(attr, obj.1.as_ref(), Some(PolicyType::And)),
            PolicyType::Or => calc_pruned(attr, obj.1.as_ref(), Some(PolicyType::Or)),
            _ => calc_pruned(attr, obj.1.as_ref(), Some(PolicyType::Leaf)),
        },
        PolicyValue::Array(children) => {
            let len = children.len();
            match policy_type {
                Some(PolicyType::And) => {
                    let mut policy_match: bool = true;
                    if len >= 2 {
                        for child in children.iter().take(len) {
                            let (found, list) = calc_pruned(attr, child, None)?;
                            policy_match = policy_match && found;
                            if policy_match {
                                matched_nodes.extend(list);
                            }
                        }
                    } else {
                        return Err(ABEError::InvalidPolicy("AND with just a single child.".into()));
                    }
                    if !policy_match {
                        matched_nodes = vec![];
                    }
                    Ok((policy_match, matched_nodes))
                }
                Some(PolicyType::Or) => {
                    let mut policy_match: bool = false;
                    if len >= 2 {
                        for child in children.iter().take(len) {
                            let (found, list) = calc_pruned(attr, child, None).unwrap();
                            policy_match = policy_match || found;
                            if policy_match {
                                matched_nodes.extend(list);
                                break;
                            }
                        }
                        Ok((policy_match, matched_nodes))
                    } else {
                        Err(ABEError::InvalidPolicy("OR with just a single child.".into()))
                    }
                }
                _ => Err(ABEError::InvalidPolicy("unknown array type!".into())),
            }
        }
        PolicyValue::String(node) => {
            if contains(attr, node.0) {
                Ok((true, vec![(node.0.to_string(), node_index(node))]))
            } else {
                Ok((false, matched_nodes))
            }
        }
    }
}

#[allow(dead_code)]
pub fn recover_secret<T: PairingCurve>(shares: HashMap<String, T::Field>, _policy: &str) -> T::Field {
    let policy = parse(_policy, PolicyLanguage::JsonPolicy).unwrap();
    let mut coeff_list: HashMap<String, T::Field> = HashMap::new();
    calc_coefficients::<T>(&policy, T::Field::one(), &mut coeff_list, None);
    let mut secret = T::Field::new();
    for (i, share) in shares {
        let coeff = coeff_list.get(&i).unwrap();
        secret = secret + share.ref_mul(coeff);
    }
    secret
}

pub fn polynomial<T: PairingCurve>(coeff: Vec<T::Field>, x: T::Field) -> T::Field {
    let mut share = coeff[0].clone();
    for (i, c) in coeff.iter().enumerate().skip(1) {
        let x_pow = x.ref_pow(&T::Field::new_int(i.try_into().unwrap_or_default()));
        share = share.ref_add(&x_pow.ref_mul(c));
    }
    share
}

#[cfg(test)]
mod tests {

    use crate::{
        curves::bls24479::{Bls24479Curve, Bls24479Field},
        random::miracl::MiraclRng,
    };

    use super::*;
    use rand::Rng;

    #[test]
    fn test_secret_sharing_or() {
        let mut rng = MiraclRng::new();
        let secret = Bls24479Field::random(&mut rng);
        let shares = gen_shares::<Bls24479Curve>(&mut rng, &secret, 1, 2);

        let mut input: HashMap<String, Bls24479Field> = HashMap::new();
        input.insert("A_38".to_string(), shares[1].clone());
        // input.insert("B_53".to_string(), shares[2]);
        let reconstruct = recover_secret::<Bls24479Curve>(
            input,
            &String::from(r#"{"name":"or", "children": [{"name": "A"}, {"name": "B"}]}"#),
        );
        assert!(secret == reconstruct);
    }

    #[test]
    fn test_gen_shares_json() {
        let mut rng = MiraclRng::new();
        let secret = Bls24479Field::random(&mut rng);
        let policy = String::from(
            r#"{"name": "and", "children": [{"name": "A"}, {"name": "B"}, {"name": "C"}, {"name": "D"}]}"#,
        );
        match parse(&policy, PolicyLanguage::JsonPolicy) {
            Ok(pol) => {
                let shares = gen_shares_policy::<Bls24479Curve>(&mut rng, &secret, &pol, None);
                let mut coeff_list: HashMap<String, Bls24479Field> = HashMap::new();
                let coeff = Bls24479Field::one();
                calc_coefficients::<Bls24479Curve>(&pol, coeff, &mut coeff_list, None);
                assert_eq!(coeff_list.len(), shares.len());
            }
            Err(e) => println!("test_gen_shares_json: could not parse policy {:?}", e),
        }
    }

    #[test]
    fn test_secret_sharing_and() {
        // AND
        let mut rng = MiraclRng::new();
        let mut thread_rng = rand::thread_rng();
        let mut seed = [0u8; 128];
        thread_rng.fill(&mut seed);
        rng.seed(&seed);

        let secret = Bls24479Field::random(&mut rng);
        let shares = gen_shares::<Bls24479Curve>(&mut rng, &secret, 5, 5);
        let k = shares[0].clone();
        let mut input: HashMap<String, Bls24479Field> = HashMap::new();
        input.insert("A_40".to_string(), shares[1].clone());
        input.insert("B_55".to_string(), shares[2].clone());
        input.insert("C_70".to_string(), shares[3].clone());
        input.insert("D_85".to_string(), shares[4].clone());
        input.insert("E_100".to_string(), shares[5].clone());

        let reconstruct = recover_secret::<Bls24479Curve>(
            input,
            &String::from(
                r#"{"name": "and", "children": [{"name": "A"}, {"name": "B"}, {"name": "C"}, {"name": "D"}, {"name": "E"}]}"#,
            ),
        );

        assert!(k == reconstruct);
    }

    #[test]
    fn test_pruning() {
        // a set of two attributes
        let mut _attributes: Vec<String> = vec![String::from("A"), String::from("B"), String::from("C")];

        let pol1 = String::from(
            r#"{"name": "or", "children": [{"name": "and", "children": [{"name": "A"}, {"name": "B"}]}, {"name": "and", "children": [{"name": "C"}, {"name": "D"}]}]}"#,
        );
        let pol2 = String::from(
            r#"{"name": "or", "children": [{"name": "C"}, {"name": "and", "children": [{"name": "A"}, {"name": "E"}]}]}"#,
        );
        let pol3 = String::from(
            r#"{"name": "or", "children": [{"name": "and", "children": [{"name": "A"}, {"name": "C"}]}, {"name": "and", "children": [{"name": "C"}, {"name": "A"}]}]}"#,
        );

        let _result1 = calc_pruned(&_attributes, &parse(pol1.as_ref(), PolicyLanguage::JsonPolicy).unwrap(), None);
        let _result2 = calc_pruned(&_attributes, &parse(pol2.as_ref(), PolicyLanguage::JsonPolicy).unwrap(), None);
        let _result3 = calc_pruned(&_attributes, &parse(pol3.as_ref(), PolicyLanguage::JsonPolicy).unwrap(), None);

        let (_match1, _list1) = _result1.unwrap();
        assert!(_match1);
        assert!(_list1 == vec![("A".to_string(), "A_68".to_string()), ("B".to_string(), "B_83".to_string())]);

        let (_match2, _list2) = _result2.unwrap();
        assert!(_match2);
        assert!(_list2 == vec![("C".to_string(), "C_39".to_string())]);

        let (_match3, _list3) = _result3.unwrap();
        assert!(_match3);
        assert!(_list3 == vec![("A".to_string(), "A_68".to_string()), ("C".to_string(), "C_83".to_string())]);
    }
}
