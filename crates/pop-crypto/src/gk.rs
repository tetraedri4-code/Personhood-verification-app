//! Groth–Kohlweiss one-out-of-many proof (Eurocrypt 2015), base 2, over Pedersen commitments in G1.
//! List: c_i = K - V_i (i < N = 2^m). The prover knows l and rho with c_l = H*rho (a commitment to 0).
//! Bit commitments c_{l_k} = B*l_k + H*r_k are supplied from outside (the R1CS commitments to the low
//! bits of the handle r), so one set serves every generation and also binds the shard to H(r) = r mod N.
use crate::params::*;
use ark_ec::{CurveGroup, VariableBaseMSM};
use ark_ff::{One, UniformRand, Zero};
use ark_std::rand::RngCore;

pub struct GkProof {
    pub ca: Vec<G1A>,
    pub cb: Vec<G1A>,
    pub cd: Vec<G1A>,
    pub f: Vec<Fr>,
    pub za: Vec<Fr>,
    pub zb: Vec<Fr>,
    pub zd: Fr,
}

pub struct GkState {
    a: Vec<Fr>,
    s: Vec<Fr>,
    t: Vec<Fr>,
    rho_k: Vec<Fr>,
    pub ca: Vec<G1A>,
    pub cb: Vec<G1A>,
    pub cd: Vec<G1A>,
}

/// Coefficients p_{i,k} of p_i(x) = prod_k f_{k,i_k}(x); returns polys[i][k], k = 0..=m.
fn polys(m: usize, l_bits: &[Fr], a: &[Fr]) -> Vec<Vec<Fr>> {
    let mut ps: Vec<Vec<Fr>> = vec![vec![Fr::one()]];
    for k in 0..m {
        let f1 = [a[k], l_bits[k]]; // l_k x + a_k
        let f0 = [-a[k], Fr::one() - l_bits[k]]; // x - f1
        let n = ps.len();
        let mut next = vec![Vec::new(); 2 * n];
        for (b, f) in [(0usize, f0), (1usize, f1)] {
            for i in 0..n {
                let p = &ps[i];
                let mut q = vec![Fr::zero(); p.len() + 1];
                for (j, c) in p.iter().enumerate() {
                    q[j] += *c * f[0];
                    q[j + 1] += *c * f[1];
                }
                next[i + b * n] = q;
            }
        }
        ps = next;
    }
    ps
}

pub fn commit<R: RngCore>(
    rng: &mut R,
    g: &Gens,
    vals: &[G1A],
    l: usize,
    m: usize,
) -> GkState {
    let l_bits: Vec<Fr> = (0..m).map(|k| Fr::from(((l >> k) & 1) as u64)).collect();
    let a: Vec<Fr> = (0..m).map(|_| Fr::rand(rng)).collect();
    let s: Vec<Fr> = (0..m).map(|_| Fr::rand(rng)).collect();
    let t: Vec<Fr> = (0..m).map(|_| Fr::rand(rng)).collect();
    let rho_k: Vec<Fr> = (0..m).map(|_| Fr::rand(rng)).collect();
    let ca: Vec<G1> = (0..m).map(|k| g.ped_b * a[k] + g.ped_h * s[k]).collect();
    let cb: Vec<G1> = (0..m).map(|k| g.ped_b * (l_bits[k] * a[k]) + g.ped_h * t[k]).collect();
    let ps = polys(m, &l_bits, &a);
    // c_d_k = -MSM(V, p_{.,k}) + H rho_k  (the K terms cancel because sum_i p_{i,k} = 0 for k < m)
    let cd: Vec<G1> = (0..m)
        .map(|k| {
            let sc: Vec<Fr> = ps.iter().map(|p| -p[k]).collect();
            G1::msm(vals, &sc).unwrap() + g.ped_h * rho_k[k]
        })
        .collect();
    GkState {
        a,
        s,
        t,
        rho_k,
        ca: G1::normalize_batch(&ca),
        cb: G1::normalize_batch(&cb),
        cd: G1::normalize_batch(&cd),
    }
}

pub fn respond(st: GkState, l: usize, m: usize, r_k: &[Fr], rho: Fr, x: Fr) -> GkProof {
    let mut f = Vec::with_capacity(m);
    let mut za = Vec::with_capacity(m);
    let mut zb = Vec::with_capacity(m);
    for k in 0..m {
        let lk = Fr::from(((l >> k) & 1) as u64);
        let fk = lk * x + st.a[k];
        f.push(fk);
        za.push(r_k[k] * x + st.s[k]);
        zb.push(r_k[k] * (x - fk) + st.t[k]);
    }
    let mut xp = Fr::one();
    let mut zd = Fr::zero();
    for k in 0..m {
        zd -= st.rho_k[k] * xp;
        xp *= x;
    }
    zd += rho * xp;
    GkProof { ca: st.ca, cb: st.cb, cd: st.cd, f, za, zb, zd }
}

pub fn verify(g: &Gens, vals: &[G1A], k_pt: &G1A, cl: &[G1A], m: usize, pr: &GkProof, x: Fr) -> bool {
    for k in 0..m {
        if (g.ped_b * pr.f[k] + g.ped_h * pr.za[k]) != (cl[k] * x + pr.ca[k]) {
            return false;
        }
        if (g.ped_h * pr.zb[k]) != (cl[k] * (x - pr.f[k]) + pr.cb[k]) {
            return false;
        }
    }
    // P_i = prod_k f_{k,i_k}(x)
    let mut pv = vec![Fr::one()];
    for k in 0..m {
        let f1 = pr.f[k];
        let f0 = x - f1;
        let n = pv.len();
        let mut next = vec![Fr::zero(); 2 * n];
        for i in 0..n {
            next[i] = pv[i] * f0;
            next[i + n] = pv[i] * f1;
        }
        pv = next;
    }
    let mut xm = Fr::one();
    let mut bases: Vec<G1A> = Vec::with_capacity(vals.len() + m + 2);
    let mut sc: Vec<Fr> = Vec::with_capacity(vals.len() + m + 2);
    for k in 0..m {
        bases.push(pr.cd[k]);
        sc.push(-xm);
        xm *= x;
    }
    bases.extend_from_slice(vals);
    sc.extend(pv.iter().map(|p| -*p));
    bases.push(*k_pt);
    sc.push(xm);
    bases.push(g.ped_h);
    sc.push(-pr.zd);
    G1::msm(&bases, &sc).unwrap().is_zero()
}

/// Compact form (BM7): the verifier recomputes c_a, c_b and c_d[0] from the responses and the claimed
/// challenge, as the paper's simulator does; the proof then omits them. The recomputed values feed the
/// Fiat–Shamir hash, so a wrong response changes the challenge and the proof fails.
pub fn recompute(g: &Gens, vals: &[G1A], k_pt: &G1A, cl: &[G1A], m: usize, pr: &GkProof, x: Fr) -> (Vec<G1A>, Vec<G1A>, G1A) {
    let ca: Vec<G1> = (0..m).map(|k| g.ped_b * pr.f[k] + g.ped_h * pr.za[k] - cl[k] * x).collect();
    let cb: Vec<G1> = (0..m).map(|k| g.ped_h * pr.zb[k] - cl[k] * (x - pr.f[k])).collect();
    let mut pv = vec![Fr::one()];
    for k in 0..m {
        let f1 = pr.f[k];
        let f0 = x - f1;
        let n = pv.len();
        let mut next = vec![Fr::zero(); 2 * n];
        for i in 0..n {
            next[i] = pv[i] * f0;
            next[i + n] = pv[i] * f1;
        }
        pv = next;
    }
    // c_d0 = x^m K - MSM(V, P) - sum_{k>=1} x^k c_dk - H z_d
    let mut bases: Vec<G1A> = Vec::with_capacity(vals.len() + m + 2);
    let mut sc: Vec<Fr> = Vec::with_capacity(vals.len() + m + 2);
    let mut xp = Fr::one();
    for k in 0..m {
        if k > 0 {
            bases.push(pr.cd[k]);
            sc.push(-xp);
        }
        xp *= x;
    }
    bases.extend_from_slice(vals);
    sc.extend(pv.iter().map(|p| -*p));
    bases.push(*k_pt);
    sc.push(xp);
    bases.push(g.ped_h);
    sc.push(-pr.zd);
    let cd0 = G1::msm(&bases, &sc).unwrap().into_affine();
    (G1::normalize_batch(&ca), G1::normalize_batch(&cb), cd0)
}
