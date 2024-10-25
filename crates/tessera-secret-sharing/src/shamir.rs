use crate::gf256::GF256;

pub struct Polynomial {
    pub coefficients: Vec<GF256>,
}

impl Polynomial {
    pub fn new(coefficients: Vec<GF256>) -> Self {
        Self { coefficients }
    }

    pub fn evaluate(&self, x: GF256) -> GF256 {
        let mut result = GF256::new(0);
        let mut x_power = GF256::new(1);

        for coeff in &self.coefficients {
            result += x_power * *coeff;
            x_power *= x;
        }
        result
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Share {
    pub x: GF256,
    pub points: Vec<GF256>,
}

impl Share {
    pub fn new(x: GF256) -> Self {
        Self { x, points: vec![] }
    }

    pub fn add_point(&mut self, point: GF256) {
        self.points.push(point);
    }

    pub fn get_point(&self, i: usize) -> GF256 {
        debug_assert!(i < self.points.len());
        self.points[i]
    }

    pub fn set_point(&mut self, i: usize, point: GF256) {
        debug_assert!(i < self.points.len());
        self.points[i] = point;
    }
}

pub fn split(secret: &[u8], threshold: usize, shares: usize) -> Vec<Share> {
    debug_assert!(threshold <= shares);
    debug_assert!(shares > 0 && shares < 256);
    let mut shares = (1..=shares).map(|i| Share::new(GF256::new(i as u8))).collect::<Vec<_>>();

    for &byte in secret {
        let p =
            Polynomial::new(std::iter::once(GF256::new(byte)).chain((1..threshold).map(|_| GF256::random())).collect());

        for share in shares.iter_mut() {
            share.add_point(p.evaluate(share.x));
        }
    }

    shares
}

pub fn combine(shares: &[Share]) -> Vec<u8> {
    debug_assert!(!shares.is_empty());
    debug_assert!(shares.iter().all(|share| share.points.len() == shares[0].points.len()));
    let secret_size = shares[0].points.len();

    let mut secret = Vec::with_capacity(secret_size);

    for i in 0..secret_size {
        let points = shares.iter().map(|share| (share.x, share.get_point(i))).collect::<Vec<_>>();
        secret.push(interpolate(&points).0);
    }

    secret
}

pub fn interpolate(points: &[(GF256, GF256)]) -> GF256 {
    let mut result = GF256::new(0);

    for (i, &(x_i, y_i)) in points.iter().enumerate() {
        let mut term = y_i;
        for (j, &(x_j, _)) in points.iter().enumerate() {
            if i == j {
                continue;
            }
            term *= -x_j;
            term /= x_i - x_j;
        }
        result += term;
    }

    result
}

pub fn refresh(shares: &mut [Share]) {
    debug_assert!(!shares.is_empty());
    debug_assert!(shares.iter().all(|share| share.points.len() == shares[0].points.len()));

    let threshold = shares.len();
    let secret_size = shares[0].points.len();
    for i in 0..secret_size {
        let p =
            Polynomial::new(std::iter::once(GF256::new(0)).chain((1..threshold).map(|_| GF256::random())).collect());
        for share in shares.iter_mut() {
            let previous = share.get_point(i);
            share.set_point(i, p.evaluate(share.x) + previous);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_combine() {
        let secret_data = b"secret data";
        let threshold = 5;
        let shares = 10;
        let shares = split(secret_data, threshold, shares);
        let not_work = combine(&shares[..4]);
        let secret = combine(&shares);

        assert_ne!(not_work, secret_data);
        assert_eq!(secret, secret_data);
    }

    #[test]
    fn test_refresh() {
        let secret_data = b"secret data";
        let threshold = 5;
        let shares = 10;
        let mut shares = split(secret_data, threshold, shares);
        refresh(&mut shares[1..6]);
        let secret = combine(&shares[1..6]);

        assert_eq!(secret, secret_data);
    }
}
