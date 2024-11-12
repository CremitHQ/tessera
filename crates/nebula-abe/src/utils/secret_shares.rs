use std::collections::HashMap;

use crate::curves::{Field, PairingCurve, RefAdd as _, RefMul as _, RefNeg as _, RefPow as _, RefSub as _};
use crate::random::Random;
use nebula_policy::pest::PolicyNode;
use nebula_policy::utils::{contains, node_index};

pub fn calc_coefficients<T: PairingCurve>(
    policy_value: &PolicyNode,
    coeff: T::Field,
    coeff_list: &mut HashMap<String, T::Field>,
) {
    match policy_value {
        PolicyNode::And((left, right)) => {
            let mut new_coeff = vec![T::Field::one()];
            new_coeff.push(T::Field::one().ref_add(&new_coeff[0]));
            let new_coeff = recover_coefficients::<T>(new_coeff);
            calc_coefficients::<T>(left, coeff.ref_mul(&new_coeff[0]), coeff_list);
            calc_coefficients::<T>(right, coeff.ref_mul(&new_coeff[1]), coeff_list);
        }
        PolicyNode::Or((left, right)) => {
            let new_coeff = recover_coefficients::<T>(vec![T::Field::one()]);
            calc_coefficients::<T>(left, coeff.ref_mul(&new_coeff[0]), coeff_list);
            calc_coefficients::<T>(right, coeff.ref_mul(&new_coeff[0]), coeff_list);
        }
        PolicyNode::Leaf(node) => {
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

pub fn gen_shares_policy<T: PairingCurve>(
    rng: &mut T::Rng,
    secret: &T::Field,
    policy_value: &PolicyNode,
) -> HashMap<String, T::Field> {
    let mut result: HashMap<String, T::Field> = HashMap::new();
    match policy_value {
        PolicyNode::Leaf(node) => {
            result.insert(node_index(node), secret.clone());
            result
        }
        PolicyNode::And((left, right)) => {
            let shares = gen_shares::<T>(rng, secret, 2, 2);
            result.extend(gen_shares_policy::<T>(rng, &shares[1], left));
            result.extend(gen_shares_policy::<T>(rng, &shares[2], right));
            result
        }
        PolicyNode::Or((left, right)) => {
            let shares = gen_shares::<T>(rng, secret, 1, 2);
            result.extend(gen_shares_policy::<T>(rng, &shares[1], left));
            result.extend(gen_shares_policy::<T>(rng, &shares[2], right));
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
            let polynom = polynomial::<T>(a.clone(), T::Field::from(i as u64));
            shares.push(polynom);
        }
    }
    shares
}

pub fn calc_pruned(attr: &[String], policy_value: &PolicyNode) -> (bool, Vec<(String, String)>) {
    let mut matched_nodes: Vec<(String, String)> = vec![];
    match policy_value {
        PolicyNode::Leaf(node) => {
            if contains(attr, node.0) {
                (true, vec![(node.0.to_string(), node_index(node))])
            } else {
                (false, matched_nodes)
            }
        }
        PolicyNode::And((left, right)) => {
            let (left_match, left_list) = calc_pruned(attr, left);
            let (right_match, right_list) = calc_pruned(attr, right);
            if left_match && right_match {
                matched_nodes.extend(left_list);
                matched_nodes.extend(right_list);
                (true, matched_nodes)
            } else {
                (false, matched_nodes)
            }
        }
        PolicyNode::Or((left, right)) => {
            let (left_match, left_list) = calc_pruned(attr, left);
            let (right_match, right_list) = calc_pruned(attr, right);
            if left_match {
                matched_nodes.extend(left_list);
                return (true, matched_nodes);
            }
            if right_match {
                matched_nodes.extend(right_list);
                return (true, matched_nodes);
            }
            (false, matched_nodes)
        }
    }
}

pub fn polynomial<T: PairingCurve>(coeff: Vec<T::Field>, x: T::Field) -> T::Field {
    let mut share = coeff[0].clone();
    for (i, c) in coeff.iter().enumerate().skip(1) {
        let x_pow = x.ref_pow(&T::Field::from(i as u64));
        share = share.ref_add(&x_pow.ref_mul(c));
    }
    share
}

#[cfg(test)]
mod tests {

    use crate::{
        curves::{
            bls24479::{Bls24479Curve, Bls24479Field},
            FieldWithOrder,
        },
        random::miracl::MiraclRng,
    };

    use super::*;
    use nebula_policy::pest::{parse, PolicyLanguage};
    use rand::Rng;

    fn recover_secret<T: PairingCurve>(shares: HashMap<String, T::Field>, policy: &str) -> T::Field {
        let policy = parse(policy, PolicyLanguage::JsonPolicy).unwrap().0;
        let mut coeff_list: HashMap<String, T::Field> = HashMap::new();
        calc_coefficients::<T>(&policy, T::Field::one(), &mut coeff_list);

        let mut secret = T::Field::new();
        for (i, share) in shares {
            let coeff = coeff_list.get(&i).unwrap();
            secret = secret + share.ref_mul(coeff);
        }
        secret
    }

    #[test]
    fn test_secret_sharing_or() {
        let mut rng = MiraclRng::new();
        let mut thread_rng = rand::thread_rng();
        let mut seed = [0u8; 128];
        thread_rng.fill(&mut seed);
        rng.seed(&seed);
        let secret = Bls24479Field::random_within_order(&mut rng);
        let shares = gen_shares::<Bls24479Curve>(&mut rng, &secret, 1, 2);

        let mut input: HashMap<String, Bls24479Field> = HashMap::new();
        input.insert("B_0".to_string(), shares[1].clone());
        let reconstruct = recover_secret::<Bls24479Curve>(
            input,
            &String::from(r#"{"name":"or", "children": [{"name": "A"}, {"name": "B"}]}"#),
        );

        assert!(secret == reconstruct);
    }

    #[test]
    fn test_gen_shares_json() {
        let mut rng = MiraclRng::new();
        let mut thread_rng = rand::thread_rng();
        let mut seed = [0u8; 128];
        thread_rng.fill(&mut seed);
        rng.seed(&seed);
        let secret = Bls24479Field::random(&mut rng);
        let policy = String::from(
            r#"{"name": "and", "children": [{"name": "A"}, {"name": "B"}, {"name": "C"}, {"name": "D"}]}"#,
        );
        match parse(&policy, PolicyLanguage::JsonPolicy) {
            Ok((pol, _)) => {
                let shares = gen_shares_policy::<Bls24479Curve>(&mut rng, &secret, &pol);
                let mut coeff_list: HashMap<String, Bls24479Field> = HashMap::new();
                let coeff = Bls24479Field::one();
                calc_coefficients::<Bls24479Curve>(&pol, coeff, &mut coeff_list);
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
        let shares = gen_shares::<Bls24479Curve>(&mut rng, &secret, 2, 2);

        let k = shares[0].clone();
        let mut input: HashMap<String, Bls24479Field> = HashMap::new();
        input.insert("A_0".to_string(), shares[1].clone());
        input.insert("B_0".to_string(), shares[2].clone());

        let reconstruct = recover_secret::<Bls24479Curve>(
            input,
            &String::from(r#"{"name": "and", "children": [{"name": "A"}, {"name": "B"}]}"#),
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

        let _result1 = calc_pruned(&_attributes, &parse(pol1.as_ref(), PolicyLanguage::JsonPolicy).unwrap().0);
        let _result2 = calc_pruned(&_attributes, &parse(pol2.as_ref(), PolicyLanguage::JsonPolicy).unwrap().0);
        let _result3 = calc_pruned(&_attributes, &parse(pol3.as_ref(), PolicyLanguage::JsonPolicy).unwrap().0);

        let (_match1, mut _list1) = _result1;
        assert!(_match1);
        _list1.sort();
        assert!(_list1 == vec![("A".to_string(), "A_0".to_string()), ("B".to_string(), "B_0".to_string())]);

        let (_match2, mut _list2) = _result2;
        assert!(_match2);
        _list2.sort();
        assert!(_list2 == vec![("C".to_string(), "C_0".to_string())]);

        let (_match3, mut _list3) = _result3;
        assert!(_match3);
        assert!(_list3 == vec![("A".to_string(), "A_0".to_string()), ("C".to_string(), "C_0".to_string())]);
    }
}
