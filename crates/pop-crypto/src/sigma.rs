//! Linear-relation Schnorr proofs in G1 with one shared challenge (compact form:
//! the proof carries only the challenge and responses; the verifier recomputes the commitments).
//! Equal witness indices across relations give equality proofs for free.
use crate::params::*;
use ark_ec::{CurveGroup, VariableBaseMSM};

/// target = sum_j bases[j] * w[idx[j]]
pub struct LinRel {
    pub target: G1,
    pub terms: Vec<(G1A, usize)>,
}

impl LinRel {
    pub fn new(target: G1, terms: Vec<(G1A, usize)>) -> Self {
        LinRel { target, terms }
    }
}

/// Prover commitments: T_k = sum bases * blind[idx]
pub fn commit(rels: &[LinRel], blind: &[Fr]) -> Vec<G1A> {
    let t: Vec<G1> = rels
        .iter()
        .map(|r| {
            let b: Vec<G1A> = r.terms.iter().map(|x| x.0).collect();
            let s: Vec<Fr> = r.terms.iter().map(|x| blind[x.1]).collect();
            G1::msm(&b, &s).unwrap()
        })
        .collect();
    G1::normalize_batch(&t)
}

/// Verifier recomputation: T_k = sum bases * z[idx] - c * target
pub fn recompute(rels: &[LinRel], z: &[Fr], c: Fr) -> Vec<G1A> {
    let t: Vec<G1> = rels
        .iter()
        .map(|r| {
            let mut b: Vec<G1A> = r.terms.iter().map(|x| x.0).collect();
            let mut s: Vec<Fr> = r.terms.iter().map(|x| z[x.1]).collect();
            b.push(r.target.into_affine());
            s.push(-c);
            G1::msm(&b, &s).unwrap()
        })
        .collect();
    G1::normalize_batch(&t)
}

/// Debug helper: check that the witness satisfies every relation.
pub fn check(rels: &[LinRel], w: &[Fr]) -> Option<usize> {
    for (k, r) in rels.iter().enumerate() {
        let b: Vec<G1A> = r.terms.iter().map(|x| x.0).collect();
        let s: Vec<Fr> = r.terms.iter().map(|x| w[x.1]).collect();
        if G1::msm(&b, &s).unwrap() != r.target {
            return Some(k);
        }
    }
    None
}
