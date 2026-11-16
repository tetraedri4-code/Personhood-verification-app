//! Design v2 §4.6: each month's revoked handles form a sorted Poseidon hash tree. A leaf holds two
//! neighbouring revoked handles (a, b); a holder proves inside the circuit that its handle r lies strictly
//! between them (a < r < b) and that the leaf is in the tree with the month's public root.
//! Binary tree: nodes = Poseidon width 3 (2 inputs). 4-ary tree: nodes = Poseidon width 5 (4 inputs).
//! Leaves always use width 3: leaf = Hp_leaf(a, b).
use crate::params::*;
use crate::poseidon::{Lc, Poseidon};
use ark_bulletproofs::r1cs::{ConstraintSystem, Variable};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::{ConstraintSystemRef, SynthesisError};
use ark_std::rand::RngCore;

#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct TreeShape {
    pub arity: usize, // 2 or 4
    pub depth: usize,
}

impl TreeShape {
    /// Smallest depth whose capacity holds `leaves`.
    pub fn for_leaves(arity: usize, leaves: u64) -> Self {
        let mut depth = 0;
        let mut cap: u64 = 1;
        while cap < leaves {
            cap *= arity as u64;
            depth += 1;
        }
        TreeShape { arity, depth }
    }
}

#[derive(Clone)]
pub struct TreePath {
    pub a: u64,
    pub b: u64,
    pub sib: Vec<Vec<Fr>>, // per level, arity-1 siblings in slot order
    pub pos: Vec<usize>,   // per level, the position of the running node
    pub root: Fr,
}

pub fn dom_leaf() -> Fr {
    hash_to_fr(b"EUPC-HP-DOM", b"rev-leaf")
}
pub fn dom_node() -> Fr {
    hash_to_fr(b"EUPC-HP-DOM", b"rev-node")
}

/// Insert `cur` at position p among the siblings.
pub fn arrange(cur: Fr, sib: &[Fr], p: usize) -> Vec<Fr> {
    let mut v = sib.to_vec();
    v.insert(p, cur);
    v
}

pub fn node_hash(pos3: &Poseidon, pos5: &Poseidon, children: &[Fr]) -> Fr {
    match children.len() {
        2 => pos3.hash_dom(dom_node(), children),
        4 => pos5.hash_dom(dom_node(), children),
        _ => panic!("arity"),
    }
}

/// A path for handle r in a month's tree. The siblings are random field elements: proving and verifying
/// cost the same as for a real tree of this depth, and the root is computed from the path.
pub fn make_path<R: RngCore>(rng: &mut R, r: u64, shape: TreeShape, pos3: &Poseidon, pos5: &Poseidon) -> TreePath {
    let gap = 1u64 << 20;
    let a = r.saturating_sub(1 + rng.next_u64() % gap);
    let b = r.saturating_add(1 + rng.next_u64() % gap);
    assert!(a < r && r < b);
    let mut cur = pos3.hash_dom(dom_leaf(), &[Fr::from(a), Fr::from(b)]);
    let mut sib = vec![];
    let mut pos = vec![];
    for _ in 0..shape.depth {
        let p = (rng.next_u32() as usize) % shape.arity;
        let s: Vec<Fr> = (0..shape.arity - 1).map(|_| Fr::rand(rng)).collect();
        cur = node_hash(pos3, pos5, &arrange(cur, &s, p));
        sib.push(s);
        pos.push(p);
    }
    TreePath { a, b, sib, pos, root: cur }
}

/// Multipliers of one month's non-membership in the Bulletproofs R1CS.
pub fn multipliers(shape: TreeShape, pos3: &Poseidon, pos5: &Poseidon) -> usize {
    let per_level = match shape.arity {
        2 => 1 + 1 + pos3.constraints(),
        4 => 3 + 6 + pos5.constraints(),
        _ => panic!(),
    };
    1 + 2 * 64 + pos3.constraints() + shape.depth * per_level
}

// ---------------- Bulletproofs gadget ----------------

pub fn alloc_bit<CS: ConstraintSystem<Fr>>(cs: &mut CS, v: Option<bool>) -> Variable<Fr> {
    let asg = v.map(|b| {
        let x = if b { Fr::one() } else { Fr::zero() };
        (x, Fr::one() - x)
    });
    let (l, r, o) = cs.allocate_multiplier(asg).expect("alloc");
    cs.constrain(o.into());
    cs.constrain(Lc { terms: vec![(l, Fr::one()), (r, Fr::one())], constant: -Fr::one() }.to_lc());
    l
}

/// Constrain lc to a 64-bit value.
pub fn range64<CS: ConstraintSystem<Fr>>(cs: &mut CS, lc: Lc, v: Option<u64>) {
    let mut d = lc;
    let mut p = Fr::one();
    for k in 0..64 {
        let b = alloc_bit(cs, v.map(|x| (x >> k) & 1 == 1));
        d.add_term(b, -p);
        p.double_in_place();
    }
    cs.constrain(d.to_lc());
}

fn mul<CS: ConstraintSystem<Fr>>(cs: &mut CS, x: &Lc, y: &Lc) -> Lc {
    let (_, _, o) = cs.multiply(x.to_lc(), y.to_lc());
    Lc::var(o)
}

fn sub(x: &Lc, y: &Lc) -> Lc {
    let mut d = x.clone();
    d.add_scaled(y, -Fr::one());
    d
}

fn add(x: &Lc, y: &Lc) -> Lc {
    let mut d = x.clone();
    d.add_scaled(y, Fr::one());
    d
}

/// r ∉ revoked set of one month: a < r < b, leaf (a, b) under `root`.
pub fn gadget<CS: ConstraintSystem<Fr>>(
    cs: &mut CS,
    shape: TreeShape,
    pos3: &Poseidon,
    pos5: &Poseidon,
    r: &Lc,
    r_val: Option<u64>,
    root: Fr,
    w: Option<&TreePath>,
) {
    let (va, vb) = (cs.allocate(w.map(|p| Fr::from(p.a))).unwrap(), cs.allocate(w.map(|p| Fr::from(p.b))).unwrap());
    let (a, b) = (Lc::var(va), Lc::var(vb));
    // r - a - 1 and b - r - 1 in [0, 2^64)
    let mut d1 = sub(r, &a);
    d1.add_const(-Fr::one());
    range64(cs, d1, w.zip(r_val).map(|(p, r)| r - p.a - 1));
    let mut d2 = sub(&b, r);
    d2.add_const(-Fr::one());
    range64(cs, d2, w.zip(r_val).map(|(p, r)| p.b - r - 1));
    let mut cur = pos3.gadget_dom(cs, dom_leaf(), vec![a, b]);
    for lvl in 0..shape.depth {
        let p = w.map(|t| t.pos[lvl]);
        let s: Vec<Lc> = (0..shape.arity - 1)
            .map(|j| Lc::var(cs.allocate(w.map(|t| t.sib[lvl][j])).unwrap()))
            .collect();
        match shape.arity {
            2 => {
                let beta = Lc::var(alloc_bit(cs, p.map(|p| p == 1)));
                let t = mul(cs, &beta, &sub(&s[0], &cur));
                let left = add(&cur, &t);
                let right = sub(&s[0], &t);
                cur = pos3.gadget_dom(cs, dom_node(), vec![left, right]);
            }
            4 => {
                let b0 = Lc::var(alloc_bit(cs, p.map(|p| p & 1 == 1)));
                let b1 = Lc::var(alloc_bit(cs, p.map(|p| p & 2 == 2)));
                let e3 = mul(cs, &b0, &b1);
                let e1 = sub(&b0, &e3);
                let e2 = sub(&b1, &e3);
                let mut e0 = sub(&e3, &add(&b0, &b1));
                e0.add_const(Fr::one());
                let x0 = add(&s[0], &mul(cs, &e0, &sub(&cur, &s[0])));
                let x1 = add(&add(&s[1], &mul(cs, &e0, &sub(&s[0], &s[1]))), &mul(cs, &e1, &sub(&cur, &s[1])));
                let x2 = add(&add(&s[2], &mul(cs, &add(&e0, &e1), &sub(&s[1], &s[2]))), &mul(cs, &e2, &sub(&cur, &s[2])));
                let x3 = add(&s[2], &mul(cs, &e3, &sub(&cur, &s[2])));
                cur = pos5.gadget_dom(cs, dom_node(), vec![x0, x1, x2, x3]);
            }
            _ => panic!("arity"),
        }
    }
    cur.add_const(-root);
    cs.constrain(cur.to_lc());
}

// ---------------- ark-r1cs-std gadget (LegoGroth16) ----------------

fn range64_fp(cs: ConstraintSystemRef<Fr>, x: &FpVar<Fr>, v: Option<u64>) -> Result<(), SynthesisError> {
    let mut acc = FpVar::constant(Fr::zero());
    let mut p = Fr::one();
    for k in 0..64 {
        let b = Boolean::new_witness(cs.clone(), || v.map(|x| (x >> k) & 1 == 1).ok_or(SynthesisError::AssignmentMissing))?;
        acc += FpVar::from(b) * p;
        p.double_in_place();
    }
    acc.enforce_equal(x)
}

pub fn gadget_fp(
    cs: ConstraintSystemRef<Fr>,
    shape: TreeShape,
    pos3: &Poseidon,
    pos5: &Poseidon,
    r: &FpVar<Fr>,
    r_val: Option<u64>,
    root: &FpVar<Fr>,
    w: Option<&TreePath>,
) -> Result<(), SynthesisError> {
    let miss = SynthesisError::AssignmentMissing;
    let a = FpVar::new_witness(cs.clone(), || w.map(|p| Fr::from(p.a)).ok_or(miss))?;
    let b = FpVar::new_witness(cs.clone(), || w.map(|p| Fr::from(p.b)).ok_or(miss))?;
    let one = FpVar::constant(Fr::one());
    range64_fp(cs.clone(), &(r - &a - &one), w.zip(r_val).map(|(p, r)| r - p.a - 1))?;
    range64_fp(cs.clone(), &(&b - r - &one), w.zip(r_val).map(|(p, r)| p.b - r - 1))?;
    let mut cur = pos3.gadget_fp_dom(dom_leaf(), vec![a, b])?;
    for lvl in 0..shape.depth {
        let p = w.map(|t| t.pos[lvl]);
        let mut s = vec![];
        for j in 0..shape.arity - 1 {
            s.push(FpVar::new_witness(cs.clone(), || w.map(|t| t.sib[lvl][j]).ok_or(miss))?);
        }
        match shape.arity {
            2 => {
                let beta = FpVar::from(Boolean::new_witness(cs.clone(), || p.map(|p| p == 1).ok_or(miss))?);
                let t = &beta * (&s[0] - &cur);
                let left = &cur + &t;
                let right = &s[0] - &t;
                cur = pos3.gadget_fp_dom(dom_node(), vec![left, right])?;
            }
            4 => {
                let b0 = FpVar::from(Boolean::new_witness(cs.clone(), || p.map(|p| p & 1 == 1).ok_or(miss))?);
                let b1 = FpVar::from(Boolean::new_witness(cs.clone(), || p.map(|p| p & 2 == 2).ok_or(miss))?);
                let e3 = &b0 * &b1;
                let e1 = &b0 - &e3;
                let e2 = &b1 - &e3;
                let e0 = &one - &b0 - &b1 + &e3;
                let x0 = &s[0] + &e0 * (&cur - &s[0]);
                let x1 = &s[1] + &e0 * (&s[0] - &s[1]) + &e1 * (&cur - &s[1]);
                let x2 = &s[2] + (&e0 + &e1) * (&s[1] - &s[2]) + &e2 * (&cur - &s[2]);
                let x3 = &s[2] + &e3 * (&cur - &s[2]);
                cur = pos5.gadget_fp_dom(dom_node(), vec![x0, x1, x2, x3])?;
            }
            _ => panic!("arity"),
        }
    }
    cur.enforce_equal(root)
}
