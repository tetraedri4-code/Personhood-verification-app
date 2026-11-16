//! Shamir sharing over the scalar field F_q of BLS12-381 (q is the prime order of G1 and G2, about
//! 2^255). Every operation is arithmetic modulo q, so nothing can overflow.
//!
//! The key K is the constant term of a secret polynomial f of degree t-1; operator i holds f(i).
//! Any t operators recover f(0) = Σ λ_i f(i), and since exponentiation is linear,
//! a^K = Π (a^{f(i)})^{λ_i}: the operators evaluate without ever putting K together.
use ark_ec::{CurveGroup, Group};
use ark_ff::{Field, One, Zero};
use pop_crypto::params::{Fr, G2, G2A};

/// f(x) for coefficients c_0, c_1, ... (Horner).
pub fn eval_poly(coeffs: &[Fr], x: u32) -> Fr {
    let x = Fr::from(x as u64);
    coeffs.iter().rev().fold(Fr::zero(), |acc, c| acc * x + c)
}

/// Lagrange coefficient λ_i at 0 for the point set `indices`: Π_{j≠i} j / (j - i).
/// Indices must be distinct and non-zero.
pub fn lagrange_at_zero(indices: &[u32], i: u32) -> Fr {
    let xi = Fr::from(i as u64);
    let (mut num, mut den) = (Fr::one(), Fr::one());
    for &j in indices.iter().filter(|j| **j != i) {
        let xj = Fr::from(j as u64);
        num *= xj;
        den *= xj - xi;
    }
    num * den.inverse().expect("distinct indices")
}

/// Feldman commitments g2^{c_k} to the coefficients of a polynomial.
pub fn commit(coeffs: &[Fr]) -> Vec<G2A> {
    coeffs.iter().map(|c| (G2::generator() * c).into_affine()).collect()
}

/// g2^{f(x)} from the commitments to f: Π C_k^{x^k}.
pub fn commitment_at(commitments: &[G2A], x: u32) -> G2 {
    let x = Fr::from(x as u64);
    commitments.iter().rev().fold(G2::zero(), |acc, c| acc * x + c)
}

pub fn distinct_nonzero(indices: &[u32]) -> bool {
    let mut v = indices.to_vec();
    v.sort_unstable();
    v.dedup();
    v.len() == indices.len() && !indices.contains(&0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::UniformRand;

    fn poly(t: usize, c0: Fr) -> Vec<Fr> {
        let mut rng = rand::thread_rng();
        std::iter::once(c0).chain((1..t).map(|_| Fr::rand(&mut rng))).collect()
    }

    fn recover(points: &[(u32, Fr)]) -> Fr {
        let idx: Vec<u32> = points.iter().map(|p| p.0).collect();
        points.iter().map(|(i, v)| lagrange_at_zero(&idx, *i) * v).sum()
    }

    #[test]
    fn share_and_recover() {
        let k = Fr::rand(&mut rand::thread_rng());
        let f = poly(3, k);
        let sh: Vec<(u32, Fr)> = [1u32, 2, 3, 4, 5].iter().map(|i| (*i, eval_poly(&f, *i))).collect();
        assert_eq!(recover(&sh[..3]), k);
        assert_eq!(recover(&[sh[4], sh[1], sh[3]]), k);
        assert_eq!(recover(&sh), k);
        assert_ne!(recover(&sh[..2]), k, "t-1 shares do not give the key");
    }

    #[test]
    fn commitments_match_shares() {
        let f = poly(3, Fr::from(7u64));
        let c = commit(&f);
        for i in [1u32, 2, 9] {
            assert_eq!(commitment_at(&c, i), G2::generator() * eval_poly(&f, i));
        }
    }

    /// Refresh: add shares of a polynomial with constant term 0. The key stays, every share changes.
    #[test]
    fn refresh_keeps_key() {
        let k = Fr::rand(&mut rand::thread_rng());
        let f = poly(2, k);
        let z = poly(2, Fr::zero());
        let old: Vec<(u32, Fr)> = [1u32, 2, 3].iter().map(|i| (*i, eval_poly(&f, *i))).collect();
        let new: Vec<(u32, Fr)> = old.iter().map(|(i, v)| (*i, *v + eval_poly(&z, *i))).collect();
        assert_eq!(recover(&new[..2]), k);
        assert!(old.iter().zip(&new).all(|(a, b)| a.1 != b.1));
        // an old share and a new share together are useless
        assert_ne!(recover(&[old[0], new[1]]), k);
    }

    /// Resharing: each old holder shares its own share with the new set; a new member adds up what it
    /// received, weighted by the old holders' Lagrange coefficients.
    #[test]
    fn reshare_to_other_set_and_threshold() {
        let k = Fr::rand(&mut rand::thread_rng());
        let f = poly(2, k);
        let dealers = [1u32, 3];
        let new_set = [2u32, 4, 5, 6];
        let subs: Vec<Vec<Fr>> = dealers.iter().map(|i| poly(3, eval_poly(&f, *i))).collect();
        let new: Vec<(u32, Fr)> = new_set
            .iter()
            .map(|j| (*j, dealers.iter().zip(&subs).map(|(i, h)| lagrange_at_zero(&dealers, *i) * eval_poly(h, *j)).sum()))
            .collect();
        assert_eq!(recover(&new[..3]), k);
        assert_eq!(recover(&new[1..]), k);
        assert_ne!(recover(&new[..2]), k);
    }
}
