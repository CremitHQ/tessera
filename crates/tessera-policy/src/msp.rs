use crate::{pest::PolicyNode, utils::node_index};
use std::collections::HashMap;

const ZERO: i8 = 0;
const PLUS: i8 = 1;
const MINUS: i8 = -1;

pub struct MonotoneSpanProgram {
    pub matrix: HashMap<String, Vec<i8>>,
    pub column_size: usize,
}

impl MonotoneSpanProgram {
    pub fn new() -> Self {
        MonotoneSpanProgram { matrix: HashMap::new(), column_size: 1 }
    }

    pub fn construct(&mut self, node: &PolicyNode, current_vector: &[i8]) {
        match node {
            PolicyNode::Leaf(attr) => {
                self.matrix.insert(node_index(attr), current_vector.to_vec());
            }
            PolicyNode::Or((left, right)) => {
                self.construct(left, current_vector);
                self.construct(right, current_vector);
            }
            PolicyNode::And((left, right)) => {
                let mut left_vector = current_vector.to_vec();
                left_vector.resize(self.column_size, ZERO);
                left_vector.push(PLUS);
                let mut right_vector = vec![];
                right_vector.resize(self.column_size, ZERO);
                right_vector.push(MINUS);

                self.column_size += 1;
                self.construct(left, &left_vector);
                self.construct(right, &right_vector);
            }
        }
    }
}

impl<'a> From<PolicyNode<'a>> for MonotoneSpanProgram {
    fn from(value: PolicyNode<'a>) -> Self {
        MonotoneSpanProgram::from(&value)
    }
}

impl<'a> From<&'a PolicyNode<'a>> for MonotoneSpanProgram {
    fn from(value: &'a PolicyNode<'a>) -> Self {
        let mut v: Vec<i8> = Vec::new();
        let mut msp = MonotoneSpanProgram::new();
        v.push(PLUS);
        msp.construct(&value, &v);
        for val in msp.matrix.values_mut() {
            val.resize(msp.column_size, ZERO);
        }
        msp
    }
}

#[cfg(test)]
mod tests {
    use crate::pest::{parse, PolicyLanguage};

    use super::*;

    #[test]
    fn test_msp_simple_version() {
        let policy = r#"("X@A" OR "A@B") AND ("A@B" OR "C@B")"#;
        let policy = parse(policy, PolicyLanguage::HumanPolicy).expect("unsuccessful parse").0;
        let msp: MonotoneSpanProgram = policy.into();

        let mut matrix = HashMap::new();
        matrix.insert("X@A_0".to_string(), vec![1, 1]);
        matrix.insert("A@B_0".to_string(), vec![1, 1]);
        matrix.insert("A@B_1".to_string(), vec![0, -1]);
        matrix.insert("C@B_0".to_string(), vec![0, -1]);

        assert_eq!(msp.matrix, matrix);
    }

    #[test]
    fn test_msp_complicated_version() {
        let policy = r#"("X@A" OR "A@B") AND (("X@A" AND "Y@A" AND "Z@A") AND ("A@B" OR "C@B"))"#;
        let policy = parse(policy, PolicyLanguage::HumanPolicy).expect("unsuccessful parse").0;
        let msp = MonotoneSpanProgram::from(&policy);

        let mut matrix = HashMap::new();
        matrix.insert("X@A_0".to_string(), vec![1, 1, 0, 0, 0]);
        matrix.insert("X@A_1".to_string(), vec![0, -1, 1, 1, 1]);
        matrix.insert("Y@A_0".to_string(), vec![0, 0, 0, 0, -1]);
        matrix.insert("Z@A_0".to_string(), vec![0, 0, 0, -1, 0]);
        matrix.insert("A@B_0".to_string(), vec![1, 1, 0, 0, 0]);
        matrix.insert("A@B_1".to_string(), vec![0, 0, -1, 0, 0]);
        matrix.insert("C@B_0".to_string(), vec![0, 0, -1, 0, 0]);

        assert_eq!(msp.matrix, matrix);
    }
}
