//! Pairing-based accumulator of revoked handles with non-membership witnesses and batch
//! updates (positive accumulator V = P^{prod (y_i + alpha)}, as in Nguyen 2005 / Vitto–Biryukov 2022).
//! Non-membership witness (C, d), d != 0:  C^{y+alpha} * P^d = V,
//! checked as e(C, Q * g2^y) * e(P^d, g2) = e(V, g2), Q = g2^alpha.
//! Each fresh generation starts at V0 = P^{alpha + z} for a public dummy z, so a holder's initial
//! witness is (P, z - y) and needs no secret.
//! Batch update data per added handle y_k: the handle (8 bytes) and the accumulator value before it (48 bytes).
//! Holder update: C' = C * prod(y_k - y) + sum_k V_{k-1} * prod_{j>k}(y_j - y), d' = d * prod(y_k - y).
use crate::params::*;
use ark_ec::{pairing::Pairing, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One};

#[derive(Clone, Copy)]
pub struct NonMemWit {
    pub c: G1A,
    pub d: Fr,
}

pub fn dummy() -> Fr {
    hash_to_fr(b"EUPC-ACC-DUMMY", b"z")
}

pub fn initial_value(g: &Gens, alpha: Fr) -> G1A {
    (g.p_acc * (alpha + dummy())).into_affine()
}

pub fn initial_witness(g: &Gens, y: Fr) -> NonMemWit {
    NonMemWit { c: g.p_acc, d: dummy() - y }
}

/// Manager: add handles; returns the value before each addition (published update data) and the final value.
pub fn manager_add(v: G1A, alpha: Fr, ys: &[Fr]) -> (Vec<G1A>, G1A) {
    let mut cur: G1 = v.into();
    let mut before = Vec::with_capacity(ys.len());
    for y in ys {
        before.push(cur);
        cur = cur * (*y + alpha);
    }
    (G1::normalize_batch(&before), cur.into_affine())
}

/// Holder: apply a batch update.
pub fn holder_update(w: &NonMemWit, y: Fr, ys: &[Fr], before: &[G1A]) -> NonMemWit {
    let m = ys.len();
    // suffix products prod_{j>k}(y_j - y)
    let mut suffix = vec![Fr::one(); m + 1];
    for k in (0..m).rev() {
        suffix[k] = suffix[k + 1] * (ys[k] - y);
    }
    let mut bases = Vec::with_capacity(m + 1);
    let mut sc = Vec::with_capacity(m + 1);
    bases.push(w.c);
    sc.push(suffix[0]);
    for k in 0..m {
        bases.push(before[k]);
        sc.push(suffix[k + 1]);
    }
    let c = G1::msm(&bases, &sc).unwrap().into_affine();
    NonMemWit { c, d: w.d * suffix[0] }
}

pub fn verify_witness(g: &Gens, q: &G2A, v: &G1A, w: &NonMemWit, y: Fr) -> bool {
    if w.d == Fr::from(0u64) {
        return false;
    }
    let lhs = E::multi_pairing(
        [w.c, (g.p_acc * w.d).into_affine()],
        [(*q + g.g2 * y).into_affine(), g.g2],
    );
    lhs == E::pairing(*v, g.g2)
}

#[allow(dead_code)]
pub fn inv(x: Fr) -> Fr {
    x.inverse().unwrap()
}
