use std::collections::HashMap;

use crate::error::ABEError;
use crate::utils::tools::{contains, get_value};

use rand::RngCore as _;
use tessera_miracl::bls48556::big::BIG;
use tessera_miracl::bls48556::rom::CURVE_ORDER as MODULUS;
use tessera_miracl::rand::RAND;
use tessera_policy::pest::{parse, PolicyLanguage, PolicyType, PolicyValue};

pub fn calc_coefficients(
    policy_value: &PolicyValue,
    coeff: BIG,
    mut coeff_list: HashMap<String, BIG>,
    policy_type: Option<PolicyType>,
) -> Option<HashMap<String, BIG>> {
    let q = BIG::new_ints(&MODULUS);
    return match policy_value {
        PolicyValue::Object(obj) => {
            match obj.0 {
                PolicyType::And => calc_coefficients(&obj.1.as_ref(), coeff, coeff_list, Some(PolicyType::And)),
                PolicyType::Or => calc_coefficients(&obj.1.as_ref(), coeff, coeff_list, Some(PolicyType::Or)),
                _ => {
                    // Single attribute policy use case
                    coeff_list.insert(get_value(&obj.1), coeff);
                    return Some(coeff_list);
                }
            }
        }
        PolicyValue::Array(children) => match policy_type.unwrap() {
            PolicyType::And => {
                let mut this_coeff_vec = vec![BIG::new_int(1)];
                for i in 1..children.len() {
                    this_coeff_vec.push(BIG::modadd(&this_coeff_vec[i - 1], &BIG::new_int(1), &q));
                }
                let this_coeff = recover_coefficients(this_coeff_vec);
                for (i, child) in children.iter().enumerate() {
                    match calc_coefficients(&child, BIG::modmul(&coeff, &this_coeff[i], &q), coeff_list.clone(), None) {
                        None => return None,
                        Some(res) => coeff_list = res,
                    }
                }
                Some(coeff_list)
            }
            PolicyType::Or => {
                let this_coeff = recover_coefficients(vec![BIG::new_int(1)]);
                for child in children.iter() {
                    match calc_coefficients(&child, BIG::modmul(&coeff, &this_coeff[0], &q), coeff_list.clone(), None) {
                        None => return None,
                        Some(res) => coeff_list = res,
                    }
                }
                Some(coeff_list)
            }
            _ => None,
        },
        PolicyValue::String(node) => {
            coeff_list.insert(node_index(node), coeff);
            Some(coeff_list)
        }
    };
}

// lagrange interpolation
pub fn recover_coefficients(list: Vec<BIG>) -> Vec<BIG> {
    let mut coeff = vec![];
    let modulus = BIG::new_ints(&MODULUS);
    for i in list.clone() {
        let mut result = BIG::new_int(1);
        for j in list.clone() {
            if BIG::comp(&i, &j) != 0 {
                let mut q = BIG::modadd(&i, &BIG::modneg(&j, &modulus), &modulus);
                q.invmodp(&modulus);
                let p = BIG::modneg(&j, &modulus);
                result = BIG::modmul(&result, &BIG::modmul(&q, &p, &modulus), &modulus);
            }
        }
        coeff.push(result);
    }
    return coeff;
}

pub fn node_index(node: &(&str, usize)) -> String {
    format!("{}_{}", node.0, node.1)
}
pub fn remove_index(node: &String) -> String {
    let parts: Vec<_> = node.split('_').collect();
    parts[0].to_string()
}

pub fn gen_shares_policy(
    secret: BIG,
    policy_value: &PolicyValue,
    policy_type: Option<PolicyType>,
) -> Option<HashMap<String, BIG>> {
    let q = BIG::new_ints(&MODULUS);
    let mut result: HashMap<String, BIG> = HashMap::new();
    let k;
    let n;
    match policy_value {
        PolicyValue::String(node) => {
            result.insert(node_index(node), secret);
            Some(result)
        }
        PolicyValue::Object(obj) => match obj.0 {
            PolicyType::And => gen_shares_policy(secret, &obj.1.as_ref(), Some(PolicyType::And)),
            PolicyType::Or => gen_shares_policy(secret, &obj.1.as_ref(), Some(PolicyType::Or)),
            _ => gen_shares_policy(secret, &obj.1.as_ref(), Some(PolicyType::Leaf)),
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
            let shares = gen_shares(secret, k, n);
            for i in 0..n {
                match gen_shares_policy(shares[i + 1], &children[i], None) {
                    None => panic!("Error in gen_shares_policy: Returned None."),
                    Some(items) => {
                        result.extend(items.into_iter());
                    }
                }
            }
            Some(result)
        }
    }
}

pub fn gen_shares(secret: BIG, k: usize, n: usize) -> Vec<BIG> {
    let mut shares: Vec<BIG> = Vec::new();
    if k <= n {
        let mut rng = RAND::new();
        let mut seed: [u8; 128] = [0; 128];
        let mut thread_rng = rand::thread_rng();
        thread_rng.fill_bytes(&mut seed);
        rng.seed(128, &seed);

        // polynomial coefficients
        let mut a: Vec<BIG> = Vec::new();
        a.push(secret);
        for _i in 1..k {
            a.push(BIG::random(&mut rng));
        }
        for i in 0..(n + 1) {
            let polynom = polynomial(a.clone(), BIG::new_int(i as isize));
            shares.push(polynom);
        }
    }
    return shares;
}

pub fn calc_pruned(
    attr: &Vec<String>,
    policy_value: &PolicyValue,
    policy_type: Option<PolicyType>,
) -> Result<(bool, Vec<(String, String)>), ABEError> {
    let mut matched_nodes: Vec<(String, String)> = vec![];
    match policy_value {
        PolicyValue::Object(obj) => match obj.0 {
            PolicyType::And => calc_pruned(attr, &obj.1.as_ref(), Some(PolicyType::And)),
            PolicyType::Or => calc_pruned(attr, &obj.1.as_ref(), Some(PolicyType::Or)),
            _ => calc_pruned(attr, &obj.1.as_ref(), Some(PolicyType::Leaf)),
        },
        PolicyValue::Array(children) => {
            let len = children.len();
            match policy_type {
                Some(PolicyType::And) => {
                    let mut policy_match: bool = true;
                    if len >= 2 {
                        for i in 0usize..len {
                            let (found, list) = calc_pruned(attr, &children[i], None).unwrap();
                            policy_match = policy_match && found;
                            if policy_match {
                                matched_nodes.extend(list);
                            }
                        }
                    } else {
                        panic!("Error: Invalid policy (AND with just a single child).");
                    }
                    if !policy_match {
                        matched_nodes = vec![];
                    }
                    return Ok((policy_match, matched_nodes));
                }
                Some(PolicyType::Or) => {
                    let mut policy_match: bool = false;
                    if len >= 2 {
                        for _i in 0usize..len {
                            let (found, list) = calc_pruned(attr, &children[_i], None).unwrap();
                            policy_match = policy_match || found;
                            if policy_match {
                                matched_nodes.extend(list);
                                break;
                            }
                        }
                        return Ok((policy_match, matched_nodes));
                    } else {
                        panic!("Error: Invalid policy (OR with just a single child).")
                    }
                }
                _ => Err(ABEError::new("Error in calc_pruned: unknown array type!")),
            }
        }
        PolicyValue::String(node) => {
            if contains(attr, &node.0.to_string()) {
                Ok((true, vec![(node.0.to_string(), node_index(node))]))
            } else {
                Ok((false, matched_nodes))
            }
        }
    }
}

#[allow(dead_code)]
pub fn recover_secret(shares: HashMap<String, BIG>, _policy: &String) -> BIG {
    let q = BIG::new_ints(&MODULUS);
    let policy = parse(_policy, PolicyLanguage::JsonPolicy).unwrap();
    let mut coeff_list: HashMap<String, BIG> = HashMap::new();
    coeff_list = calc_coefficients(&policy, BIG::new_int(1), coeff_list, None).unwrap();
    let mut secret = BIG::new();
    for (i, share) in shares {
        let coeff = coeff_list.get(&i).unwrap();
        secret = BIG::modadd(&secret, &BIG::modmul(&coeff, &share, &q), &q);
    }
    return secret;
}

pub fn polynomial(coeff: Vec<BIG>, x: BIG) -> BIG {
    let mut share = coeff[0].clone();

    let modulus = BIG::new_ints(&MODULUS);
    for i in 1usize..coeff.len() {
        let mut x_pow = x.clone();
        x_pow.powmod(&BIG::new_int(i as isize), &modulus);
        // share.add(&BIG::modmul(&coeff[i], &x_pow, &modulus));
        share = BIG::modadd(&share, &BIG::modmul(&coeff[i], &x_pow, &modulus), &modulus);
    }
    return share;
}

#[cfg(test)]
mod tests {

    use rand::Rng;
    use tessera_miracl::bls48556::big::BIG;

    use super::*;

    #[test]
    fn test_secret_sharing_or() {
        let mut rng = RAND::new();
        let secret: BIG = BIG::random(&mut rng);
        let shares = gen_shares(secret, 1, 2);
        let k = shares[0];

        let mut input: HashMap<String, BIG> = HashMap::new();
        input.insert("A_38".to_string(), shares[1]);
        // input.insert("B_53".to_string(), shares[2]);
        let reconstruct =
            recover_secret(input, &String::from(r#"{"name":"or", "children": [{"name": "A"}, {"name": "B"}]}"#));
        assert!(BIG::comp(&k, &reconstruct) == 0);
    }

    #[test]
    fn test_gen_shares_json() {
        let mut rng = RAND::new();
        let _secret = BIG::random(&mut rng);
        let _policy = String::from(
            r#"{"name": "and", "children": [{"name": "A"}, {"name": "B"}, {"name": "C"}, {"name": "D"}]}"#,
        );
        match parse(&_policy, PolicyLanguage::JsonPolicy) {
            Ok(pol) => {
                let _shares = gen_shares_policy(_secret, &pol, None).unwrap();
                let coeff_list: HashMap<String, BIG> = HashMap::new();
                let mut coeff = BIG::new();
                coeff.one();
                let _coeff = calc_coefficients(&pol, coeff, coeff_list, None).unwrap();
                assert_eq!(_coeff.len(), _shares.len());
            }
            Err(e) => println!("test_gen_shares_json: could not parse policy {:?}", e),
        }
    }

    #[test]
    fn test_secret_sharing_and() {
        // AND
        let mut rng = RAND::new();
        let mut thread_rng = rand::thread_rng();
        let mut seed = [0u8; 128];
        thread_rng.fill(&mut seed);
        rng.seed(128, &seed);

        let secret = BIG::random(&mut rng);
        // let secret = BIG::new();
        let shares = gen_shares(secret, 5, 5);
        let k = shares[0];
        let mut input: HashMap<String, BIG> = HashMap::new();
        input.insert("A_40".to_string(), shares[1]);
        input.insert("B_55".to_string(), shares[2]);
        input.insert("C_70".to_string(), shares[3]);
        input.insert("D_85".to_string(), shares[4]);
        input.insert("E_100".to_string(), shares[5]);

        let reconstruct = recover_secret(
            input,
            &String::from(
                r#"{"name": "and", "children": [{"name": "A"}, {"name": "B"}, {"name": "C"}, {"name": "D"}, {"name": "E"}]}"#,
            ),
        );

        assert!(BIG::comp(&k, &reconstruct) == 0);
    }

    #[test]
    fn test_pruning() {
        // a set of two attributes
        let mut _attributes: Vec<String> = Vec::new();
        _attributes.push(String::from("A"));
        _attributes.push(String::from("B"));
        _attributes.push(String::from("C"));

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
        assert_eq!(_match1, true);
        assert!(_list1 == vec![("A".to_string(), "A_68".to_string()), ("B".to_string(), "B_83".to_string())]);

        let (_match2, _list2) = _result2.unwrap();
        assert_eq!(_match2, true);
        assert!(_list2 == vec![("C".to_string(), "C_39".to_string())]);

        let (_match3, _list3) = _result3.unwrap();
        assert_eq!(_match3, true);
        assert!(_list3 == vec![("A".to_string(), "A_68".to_string()), ("C".to_string(), "C_83".to_string())]);
    }
}
