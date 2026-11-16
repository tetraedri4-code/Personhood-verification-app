//! Composite presentation proofs of the final design, version 2 (§4.3, §4.4, §4.5, §4.6):
//!   BBS proof of knowledge (IETF draft structure, all 10 hidden values)
//! + Poseidon hash proofs x = Hp(tag; P, s, i, j|E) in a Bulletproofs R1CS, with nym / tag outputs
//!   (later quarters' badge tags as Pedersen commitments)
//! + revocation, v2: per month, a < r < b for a leaf (a, b) of the month's sorted Poseidon tree, in the R1CS;
//!   or the fallback of §4.6 (threshold-keyed pairing accumulator), as in the earlier design:
//! + PS proof of the witnesses' signature on the hidden handle r
//! + per Rev generation: accumulator non-membership with the shard hidden by a GK one-out-of-many proof,
//!   the shard bound to the low bits of r
//! + range proofs (dates) and the 64-bit handle decomposition, inside the same R1CS
//! + distrust-list inequality proofs
//! + optional blind re-issuance commitment (renewal).
use crate::acc::NonMemWit;
use crate::gk;
use crate::params::*;
use crate::poseidon::{Lc, Poseidon};
use crate::sigma::{self, LinRel};
use crate::tree::{self, TreePath, TreeShape};
use ark_bulletproofs::r1cs::{ConstraintSystem, Prover, R1CSProof, Verifier, Variable};
use ark_r1cs_std::{alloc::AllocVar, boolean::Boolean, eq::EqGadget, fields::fp::FpVar, fields::FieldVar};
use ark_relations::r1cs::{ConstraintSynthesizer, ConstraintSystemRef, SynthesisError};
use ark_serialize::CanonicalDeserialize;
use std::sync::Arc;
use ark_bulletproofs::{BulletproofGens, PedersenGens};
use ark_ec::{pairing::Pairing, pairing::PairingOutput, AffineRepr, CurveGroup, VariableBaseMSM};
use ark_ff::{Field, One, UniformRand, Zero};
use ark_serialize::CanonicalSerialize;
use ark_std::rand::RngCore;
use merlin::Transcript;
use sha2::{Digest, Sha256};

pub const HANDLE_BITS: usize = 64;

use std::cell::RefCell;
thread_local! {
    /// Time split of the last prove() call: (r1cs_ms, gk_commit_ms, total_ms)
    pub static SPLIT: RefCell<(f64, f64, f64)> = RefCell::new((0.0, 0.0, 0.0));
}
pub const RANGE_BITS: usize = 16;

#[derive(Clone)]
pub struct Keys {
    pub x_iss: Fr,
    pub w_iss: G2A,
    pub ps_x: Fr,
    pub ps_y: Fr,
    pub ps_xt: G2A,
    pub ps_yt: G2A,
    pub acc_alpha: Fr,
    pub acc_q: G2A,
}

impl Keys {
    pub fn gen<R: RngCore>(rng: &mut R, g: &Gens) -> Self {
        let x_iss = Fr::rand(rng);
        let ps_x = Fr::rand(rng);
        let ps_y = Fr::rand(rng);
        let acc_alpha = Fr::rand(rng);
        Keys {
            x_iss,
            w_iss: (g.g2 * x_iss).into_affine(),
            ps_x,
            ps_y,
            ps_xt: (g.g2 * ps_x).into_affine(),
            ps_yt: (g.g2 * ps_y).into_affine(),
            acc_alpha,
            acc_q: (g.g2 * acc_alpha).into_affine(),
        }
    }
}

#[derive(Clone)]
pub struct Credential {
    pub a: G1A,
    pub e: Fr,
    pub m: [Fr; N_ATTR],
    pub mv: [u64; N_ATTR], // small integer values where meaningful (dates etc.)
}

pub fn bbs_b(g: &Gens, m: &[Fr; N_ATTR]) -> G1 {
    let mut b: G1 = g.p1 + g.q1 * domain();
    b += G1::msm(&g.h, m).unwrap();
    b
}

pub fn domain() -> Fr {
    hash_to_fr(b"EUPC-BBS-DOMAIN", b"quarter key t")
}

/// Issuer signs (direct form; blind issuance signs the same B computed from a commitment).
pub fn bbs_sign<R: RngCore>(rng: &mut R, g: &Gens, k: &Keys, m: &[Fr; N_ATTR]) -> (G1A, Fr) {
    let e = Fr::rand(rng);
    let a = (bbs_b(g, m) * (k.x_iss + e).inverse().unwrap()).into_affine();
    (a, e)
}

pub fn bbs_verify(g: &Gens, w: &G2A, a: &G1A, e: Fr, b: &G1) -> bool {
    E::multi_pairing([*a, (-*b).into_affine()], [(*w + g.g2 * e).into_affine(), g.g2]).is_zero()
}

/// Witnesses' PS signature on r.
pub fn ps_sign<R: RngCore>(rng: &mut R, g: &Gens, k: &Keys, r: Fr) -> (G1A, G1A) {
    let h = (g.p1 * Fr::rand(rng)).into_affine();
    (h, (h * (k.ps_x + k.ps_y * r)).into_affine())
}

#[derive(Clone)]
pub struct HashUse {
    pub label: &'static str,
    pub tag: Fr,   // domain, in the capacity element
    pub ctx: Fr,   // P
    pub slot: Fr,  // i
    pub extra: Fr, // j (nym) or quarter E (badge tag)
    pub bases: Vec<G1A>, // outputs = base * x
    pub hidden: Vec<bool>, // per base: true = sent as a Pedersen commitment base*x + h*rho (later quarters)
}

/// sum coeff * attr + constant in [0, 2^16)
#[derive(Clone)]
pub struct Range {
    pub label: &'static str,
    pub terms: Vec<(usize, i64)>,
    pub constant: i64,
}

#[derive(Clone)]
pub struct Generation {
    pub vals: Vec<G1A>, // shard accumulator values, len = 2^m
    pub m: usize,
}

#[derive(Clone)]
pub struct Cfg {
    pub name: String,
    pub context: Vec<u8>, // nonce, origin, account id, month ... bound into both transcripts
    pub hashes: Vec<HashUse>,
    pub n_gens: usize,            // fallback: accumulator generations (GK one-out-of-many)
    pub tree: Option<TreeShape>,  // v2: revocation tree shape
    pub roots: Vec<Fr>,           // v2: one public root per month checked
    pub ranges: Vec<Range>,
    pub d_entries: Vec<(u64, u64)>, // (state c*, quarter gamma0*)
    pub reissue: bool,
    /// attributes the holder shows in the clear: (attribute index, value). The proof then says the
    /// credential's attribute equals that value.
    pub reveal: Vec<(usize, Fr)>,
    pub backend: Backend,
    pub width: usize,     // Poseidon width: 5 = Hp(tag, P, s, i); 3 = Hp(c, s) with c = H(tag, P, i) public
    pub compact: bool,    // BM7 savings: compact one-out-of-many, one-phase Bulletproofs encoding
    pub lego: Option<Arc<LegoKeys>>,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, serde::Serialize, serde::Deserialize)]
pub enum Backend {
    Bulletproofs,
    LegoGroth16,
}

pub struct LegoKeys {
    pub pk: legogroth16::ProvingKey<E>,
    pub pvk: legogroth16::PreparedVerifyingKey<E>,
}

pub struct GenProof {
    pub k: G1A,
    pub cp: G1A,
    pub e: G1A,
    pub cma: G1A,
    pub gk: gk::GkProof,
}

pub struct Proof {
    pub abar: G1A,
    pub bbar: G1A,
    pub d: G1A,
    pub s1: G1A,
    pub s2: G1A,
    pub vcoms: Vec<G1A>,
    pub r1cs: Option<R1CSProof<G1A>>,
    pub lego: Option<legogroth16::Proof<E>>,
    pub clcoms: Vec<G1A>, // LegoGroth16 only: Pedersen commitments to the shard bits for GK
    pub gens: Vec<GenProof>,
    pub dcoms: Vec<G1A>,
    pub cnew: Option<G1A>,
    pub outputs: Vec<G1A>, // nyms / tags (public outputs of the presentation)
    pub c: Fr,
    pub z: Vec<Fr>,
}

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct SizeBreakdown {
    pub bbs: usize,
    pub ps: usize,
    pub r1cs_proof: usize,
    pub r1cs_commitments: usize,
    pub r1cs_multipliers: usize,
    pub per_generation: usize,
    pub generations: usize,
    pub distrust: usize,
    pub reissue: usize,
    pub outputs: usize,
    pub other_responses: usize,
    pub challenge: usize,
    pub total: usize,
}

/// Witness-index layout shared by prover and verifier.
struct Layout {
    e_neg: usize,
    r1: usize,
    r3: usize,
    ps_k: usize,
    // committed values in the R1CS: (value-index or None for raw bits, blinding index)
    v_s: Option<usize>,
    v_x: Vec<usize>,              // vcom position of each hash output
    x_idx: Vec<usize>,            // witness idx of each hash exponent
    range_attrs: Vec<usize>,      // distinct attributes used in ranges
    v_range: Vec<usize>,          // vcom position per range attr
    v_r: Option<usize>,
    v_bits: Vec<usize>,           // vcom positions of the low bits of r
    out_blind: Vec<Vec<Option<usize>>>, // per hash, per base: blinding witness of a hidden output
    vblind: Vec<usize>,           // blinding witness idx per vcom (usize::MAX for bit commitments)
    vval: Vec<Option<usize>>,     // value witness idx per vcom
    gen_idx: Vec<[usize; 4]>,     // u', bbar, a', t'
    d_idx: Vec<[usize; 3]>,       // t, u, v
    rho_new: Option<usize>,
    bit_val: Vec<usize>,   // LegoGroth16: witness idx of each shard bit
    bit_blind: Vec<usize>, // LegoGroth16: witness idx of each GK bit-commitment blinding
    lego_v: Option<usize>, // LegoGroth16: blinding of the witness commitment D
    n: usize,
    m_max: usize,
}

fn layout(cfg: &Cfg, m_max: usize) -> Layout {
    let mut n = N_ATTR;
    let mut take = || {
        let i = n;
        n += 1;
        i
    };
    let e_neg = take();
    let r1 = take();
    let r3 = take();
    let ps_k = take();
    let mut vblind = vec![];
    let mut vval: Vec<Option<usize>> = vec![];
    let mut v_s = None;
    let mut v_x = vec![];
    let mut x_idx = vec![];
    if !cfg.hashes.is_empty() {
        v_s = Some(vval.len());
        vval.push(Some(A_S));
        vblind.push(take());
        for _ in &cfg.hashes {
            let xi = take();

            x_idx.push(xi);
            v_x.push(vval.len());
            vval.push(Some(xi));
            vblind.push(take());
        }
    }
    let mut range_attrs: Vec<usize> = vec![];
    for r in &cfg.ranges {
        for (a, _) in &r.terms {
            if !range_attrs.contains(a) {
                range_attrs.push(*a);
            }
        }
    }
    let mut v_range = vec![];
    for a in &range_attrs {
        v_range.push(vval.len());
        vval.push(Some(*a));
        vblind.push(take());
    }
    let mut v_r = None;
    let mut v_bits = vec![];
    if cfg.n_gens > 0 || !cfg.roots.is_empty() {
        v_r = Some(vval.len());
        vval.push(Some(A_R));
        vblind.push(take());
    }
    if cfg.n_gens > 0 {
        for _ in 0..m_max {
            v_bits.push(vval.len());
            vval.push(None);
            vblind.push(usize::MAX);
        }
    }
    let mut bit_val = vec![];
    let mut bit_blind = vec![];
    let mut lego_v = None;
    if cfg.backend == Backend::LegoGroth16 {
        lego_v = Some(take());
        for k in 0..v_bits.len() {
            let bv = take();
            bit_val.push(bv);
            bit_blind.push(take());
            vval[v_bits[k]] = Some(bv);
        }
    }
    let mut gen_idx = vec![];
    for _ in 0..cfg.n_gens {
        gen_idx.push([take(), take(), take(), take()]);
    }
    let mut d_idx = vec![];
    for _ in &cfg.d_entries {
        d_idx.push([take(), take(), take()]);
    }
    let rho_new = if cfg.reissue { Some(take()) } else { None };
    let out_blind = cfg.hashes.iter().map(|hu| hu.hidden.iter().map(|h| if *h { Some(take()) } else { None }).collect()).collect();
    Layout {
        out_blind,
        e_neg,
        r1,
        r3,
        ps_k,
        v_s,
        v_x,
        x_idx,
        range_attrs,
        v_range,
        v_r,
        v_bits,
        vblind,
        vval,
        gen_idx,
        d_idx,
        rho_new,
        bit_val,
        bit_blind,
        lego_v,
        n,
        m_max,
    }
}

fn fi(x: i64) -> Fr {
    if x >= 0 {
        Fr::from(x as u64)
    } else {
        -Fr::from((-x) as u64)
    }
}

/// Public prefix for the width-3 variant: c = H(tag, P, i), hashed outside the circuit.
pub fn c_pub(hu: &HashUse) -> Fr {
    let mut b = vec![];
    for x in [hu.tag, hu.ctx, hu.slot, hu.extra] {
        x.serialize_compressed(&mut b).unwrap();
    }
    hash_to_fr(b"EUPC-HP-PREFIX", &b)
}

/// Hash inputs in order; None marks the secret s.
pub fn hash_layout(hu: &HashUse, width: usize) -> Vec<Option<Fr>> {
    match width {
        5 => vec![Some(hu.ctx), None, Some(hu.slot), Some(hu.extra)],
        3 => vec![Some(c_pub(hu)), None],
        _ => panic!("width"),
    }
}

pub fn hash_value(pos: &Poseidon, hu: &HashUse, width: usize, s: Fr) -> Fr {
    let inp: Vec<Fr> = hash_layout(hu, width).into_iter().map(|c| c.unwrap_or(s)).collect();
    pos.hash_dom(hu.tag, &inp)
}

/// Public inputs of the LegoGroth16 circuit: the hash constants, then the range constants.
fn lego_public_inputs(cfg: &Cfg) -> Vec<Fr> {
    let mut v = vec![];
    for hu in &cfg.hashes {
        for c in hash_layout(hu, cfg.width).into_iter().flatten() {
            v.push(c);
        }
    }
    for rg in &cfg.ranges {
        v.push(fi(rg.constant));
    }
    v.extend_from_slice(&cfg.roots);
    v
}

/// The same relation as `circuit`, for LegoGroth16. The committed witnesses come first, in the order of
/// `Layout::vval`, so proof.d commits to them.
pub struct LegoCircuit<'a> {
    pub cfg: &'a Cfg,
    pub pos: &'a Poseidon,
    pub committed: Vec<Option<Fr>>, // per vval entry
    pub range_values: Vec<Option<u64>>,
    pub r_u64: Option<u64>,
    pub pos3: &'a Poseidon,
    pub pos5: &'a Poseidon,
    pub paths: Option<Vec<TreePath>>,
    m_max: usize,
    v_s: Option<usize>,
    v_x: Vec<usize>,
    range_attrs: Vec<usize>,
    v_range: Vec<usize>,
    v_r: Option<usize>,
    v_bits: Vec<usize>,
}

impl<'a> LegoCircuit<'a> {
    fn new(cfg: &'a Cfg, pos: &'a Poseidon, pos3: &'a Poseidon, pos5: &'a Poseidon, paths: Option<Vec<TreePath>>, lay: &Layout, committed: Vec<Option<Fr>>, range_values: Vec<Option<u64>>, r_u64: Option<u64>) -> Self {
        LegoCircuit {
            cfg,
            pos,
            pos3,
            pos5,
            paths,
            committed,
            range_values,
            r_u64,
            m_max: lay.m_max,
            v_s: lay.v_s,
            v_x: lay.v_x.clone(),
            range_attrs: lay.range_attrs.clone(),
            v_range: lay.v_range.clone(),
            v_r: lay.v_r,
            v_bits: lay.v_bits.clone(),
        }
    }
}

/// Setup-time circuit (no values) for a statement shape; returns the keys.
pub fn lego_setup<R: RngCore>(rng: &mut R, cfg: &Cfg, pos: &Poseidon, pos3: &Poseidon, pos5: &Poseidon, m_max: usize) -> LegoKeys {
    let lay = layout(cfg, m_max);
    let n = lay.vval.len();
    let circ = LegoCircuit::new(cfg, pos, pos3, pos5, None, &lay, vec![None; n], vec![None; cfg.ranges.len()], None);
    let pk = legogroth16::generate_random_parameters::<E, _, _>(circ, n as u32, rng).expect("setup");
    let pvk = legogroth16::prepare_verifying_key(&pk.vk);
    LegoKeys { pk, pvk }
}

impl<'a> ConstraintSynthesizer<Fr> for LegoCircuit<'a> {
    fn generate_constraints(self, cs: ConstraintSystemRef<Fr>) -> Result<(), SynthesisError> {
        let mut com = vec![];
        for v in &self.committed {
            com.push(FpVar::new_witness(cs.clone(), || v.ok_or(SynthesisError::AssignmentMissing))?);
        }
        let pubs = lego_public_inputs(self.cfg);
        let mut pv = vec![];
        for p in &pubs {
            pv.push(FpVar::new_input(cs.clone(), || Ok(*p))?);
        }
        let mut pi = 0;
        for (h, hu) in self.cfg.hashes.iter().enumerate() {
            let mut inp = vec![];
            for c in hash_layout(hu, self.cfg.width) {
                match c {
                    Some(_) => {
                        inp.push(pv[pi].clone());
                        pi += 1;
                    }
                    None => inp.push(com[self.v_s.unwrap()].clone()),
                }
            }
            let out = self.pos.gadget_fp_dom(hu.tag, inp)?;
            out.enforce_equal(&com[self.v_x[h]])?;
        }
        let bits = |value: Option<u64>, nbits: usize| -> Result<Vec<Boolean<Fr>>, SynthesisError> {
            (0..nbits)
                .map(|k| Boolean::new_witness(cs.clone(), || value.map(|v| (v >> k) & 1 == 1).ok_or(SynthesisError::AssignmentMissing)))
                .collect()
        };
        let sum = |bs: &[Boolean<Fr>]| -> FpVar<Fr> {
            let mut acc = FpVar::constant(Fr::zero());
            let mut p = Fr::one();
            for b in bs {
                acc += FpVar::from(b.clone()) * p;
                p.double_in_place();
            }
            acc
        };
        for (ri, rg) in self.cfg.ranges.iter().enumerate() {
            let mut val = pv[pi].clone();
            pi += 1;
            for (a, c) in &rg.terms {
                let p = self.range_attrs.iter().position(|x| x == a).unwrap();
                val += &com[self.v_range[p]] * fi(*c);
            }
            let bs = bits(self.range_values[ri], RANGE_BITS)?;
            sum(&bs).enforce_equal(&val)?;
        }
        if self.cfg.n_gens > 0 {
            let bs = bits(self.r_u64, HANDLE_BITS)?;
            sum(&bs).enforce_equal(&com[self.v_r.unwrap()])?;
            for k in 0..self.m_max {
                FpVar::from(bs[k].clone()).enforce_equal(&com[self.v_bits[k]])?;
            }
        }
        if let Some(shape) = self.cfg.tree {
            for (mi, _) in self.cfg.roots.iter().enumerate() {
                let root = pv[pi].clone();
                pi += 1;
                let w = self.paths.as_ref().map(|p| &p[mi]);
                tree::gadget_fp(cs.clone(), shape, self.pos3, self.pos5, &com[self.v_r.unwrap()], self.r_u64, &root, w)?;
            }
        }
        Ok(())
    }
}

/// The R1CS: Poseidon hashes, ranges, handle decomposition. `vals` = Some(...) for the prover.
fn circuit<CS: ConstraintSystem<Fr>>(
    cs: &mut CS,
    cfg: &Cfg,
    lay: &Layout,
    pos: &Poseidon,
    pos3: &Poseidon,
    pos5: &Poseidon,
    vars: &[Variable<Fr>],
    vals: Option<(&Credential, u64, &[TreePath])>,
) {
    // hashes
    for (h, hu) in cfg.hashes.iter().enumerate() {
        let inp: Vec<Lc> = hash_layout(hu, cfg.width)
            .into_iter()
            .map(|c| match c {
                Some(c) => Lc::constant(c),
                None => Lc::var(vars[lay.v_s.unwrap()]),
            })
            .collect();
        let out = pos.gadget_dom(cs, hu.tag, inp);
        let mut diff = out;
        diff.add_term(vars[lay.v_x[h]], -Fr::one());
        cs.constrain(diff.to_lc());
    }
    let bits = |cs: &mut CS, value: Option<u64>, nbits: usize| -> Vec<Variable<Fr>> {
        (0..nbits)
            .map(|k| {
                let asg = value.map(|v| {
                    let b = Fr::from((v >> k) & 1);
                    (b, Fr::one() - b)
                });
                let (l, r, o) = cs.allocate_multiplier(asg).expect("alloc");
                cs.constrain(o.into());
                cs.constrain(Lc { terms: vec![(l, Fr::one()), (r, Fr::one())], constant: -Fr::one() }.to_lc());
                l
            })
            .collect()
    };
    for rg in &cfg.ranges {
        let value = vals.map(|(cr, _, _)| {
            let mut v = rg.constant;
            for (a, c) in &rg.terms {
                v += *c * cr.mv[*a] as i64;
            }
            assert!(v >= 0 && v < (1 << RANGE_BITS), "range {} out of range: {}", rg.label, v);
            v as u64
        });
        let bs = bits(cs, value, RANGE_BITS);
        let mut lc = Lc::constant(fi(rg.constant));
        for (a, c) in &rg.terms {
            let p = lay.range_attrs.iter().position(|x| x == a).unwrap();
            lc.add_term(vars[lay.v_range[p]], fi(*c));
        }
        for (k, b) in bs.iter().enumerate() {
            lc.add_term(*b, -Fr::from(1u64 << k));
        }
        cs.constrain(lc.to_lc());
    }
    if cfg.n_gens > 0 {
        let value = vals.map(|(_, r, _)| r);
        let bs = bits(cs, value, HANDLE_BITS);
        let mut lc = Lc::var(vars[lay.v_r.unwrap()]);
        for (k, b) in bs.iter().enumerate() {
            lc.add_term(*b, -Fr::from(2u64).pow([k as u64]));
        }
        cs.constrain(lc.to_lc());
        for k in 0..lay.m_max {
            let mut d = Lc::var(vars[lay.v_bits[k]]);
            d.add_term(bs[k], -Fr::one());
            cs.constrain(d.to_lc());
        }
    }
    if let Some(shape) = cfg.tree {
        let r = Lc::var(vars[lay.v_r.unwrap()]);
        for (mi, root) in cfg.roots.iter().enumerate() {
            let w = vals.map(|(_, _, p)| &p[mi]);
            tree::gadget(cs, shape, pos3, pos5, &r, vals.map(|(_, r, _)| r), *root, w);
        }
    }
}

pub struct Public<'a> {
    pub g: &'a Gens,
    pub w_iss: G2A,
    pub ps_xt: G2A,
    pub ps_yt: G2A,
    pub acc_q: G2A,
    pub gens: &'a [Generation],
    pub pc: PedersenGens<G1A>,
    pub bp: &'a BulletproofGens<G1A>,
    pub pos5: &'a Poseidon,
    pub pos3: &'a Poseidon,
}

impl<'a> Public<'a> {
    pub fn pos(&self, width: usize) -> &'a Poseidon {
        if width == 3 { self.pos3 } else { self.pos5 }
    }
}

pub struct Holder {
    pub cred: Credential,
    pub r_u64: u64,
    pub ps: (G1A, G1A),
    pub wits: Vec<NonMemWit>, // one per generation (fallback)
    pub paths: Vec<TreePath>, // one per month (v2 tree)
    /// renewal: the new blinding rho' the holder chose for the re-issued credential (drawn if None)
    pub rho_new: Option<Fr>,
}

pub fn m_max_of(gens: &[Generation], n_gens: usize) -> usize {
    gens.iter().take(n_gens).map(|g| g.m).max().unwrap_or(0)
}

fn m_max(p: &Public, cfg: &Cfg) -> usize {
    m_max_of(p.gens, cfg.n_gens)
}

/// Bases of the LegoGroth16 witness commitment proof.d: one per committed witness, then eta.
fn lego_bases(cfg: &Cfg) -> (Vec<G1A>, G1A) {
    let k = cfg.lego.as_ref().expect("lego keys");
    let vk = &k.pk.vk;
    let npub = lego_public_inputs(cfg).len();
    let n = vk.commit_witness_count as usize;
    (vk.gamma_abc_g1[1 + npub..1 + npub + n].to_vec(), vk.eta_gamma_inv_g1)
}

fn linear_relations(p: &Public, cfg: &Cfg, lay: &Layout, pr: &Proof) -> Vec<LinRel> {
    let g = p.g;
    let mut rels = vec![];
    // BBS: Bbar = Abar*(-e) + D*r1 ;  P1 + Q1*dom = D*r3 - sum H_j m_j
    rels.push(LinRel::new(pr.bbar.into(), vec![(pr.abar, lay.e_neg), (pr.d, lay.r1)]));
    let mut t = vec![(pr.d, lay.r3)];
    for j in 0..N_ATTR {
        t.push(((-g.h[j].into_group()).into_affine(), j));
    }
    rels.push(LinRel::new(g.p1 + g.q1 * domain(), t));
    match cfg.backend {
        Backend::Bulletproofs => {
            // each R1CS commitment opens to the hidden value
            for (vi, v) in pr.vcoms.iter().enumerate() {
                if let Some(val) = lay.vval[vi] {
                    rels.push(LinRel::new((*v).into(), vec![(g.ped_b, val), (g.ped_h, lay.vblind[vi])]));
                }
            }
        }
        Backend::LegoGroth16 => {
            if let Some(lp) = &pr.lego {
                let (bases, eta) = lego_bases(cfg);
                let mut terms: Vec<(G1A, usize)> = lay.vval.iter().enumerate().map(|(j, v)| (bases[j], v.unwrap())).collect();
                terms.push((eta, lay.lego_v.unwrap()));
                rels.push(LinRel::new(lp.d.into(), terms));
            }
            // GK bit commitments open to the same bits as in proof.d
            for (k, c) in pr.clcoms.iter().enumerate() {
                rels.push(LinRel::new((*c).into(), vec![(g.ped_b, lay.bit_val[k]), (g.ped_h, lay.bit_blind[k])]));
            }
        }
    }
    // hash outputs
    let mut o = 0;
    for (h, hu) in cfg.hashes.iter().enumerate() {
        for (bi, b) in hu.bases.iter().enumerate() {
            let mut t = vec![(*b, lay.x_idx[h])];
            if let Some(bl) = lay.out_blind[h][bi] {
                t.push((g.ped_h, bl));
            }
            rels.push(LinRel::new(pr.outputs[o].into(), t));
            o += 1;
        }
    }
    // generations
    for (gi, gp) in pr.gens.iter().enumerate() {
        let [u_, bb, a_, t_] = lay.gen_idx[gi];
        rels.push(LinRel::new(
            gp.e.into_group() - gp.cma,
            vec![(gp.cp, A_R), (gp.k, u_), (g.ped_h, bb)],
        ));
        rels.push(LinRel::new(g.p_acc.into(), vec![(gp.cma, a_), (g.ped_h, t_)]));
    }
    // distrust inequalities: L = c + 2^16 gamma0 - z* != 0
    let b16 = (g.ped_b * Fr::from(1u64 << 16)).into_affine();
    for (di, (c_, g0)) in cfg.d_entries.iter().enumerate() {
        let [t_, u_, v_] = lay.d_idx[di];
        let zs = Fr::from(*c_ + (*g0 << 16));
        rels.push(LinRel::new(
            pr.dcoms[di] + g.ped_b * zs,
            vec![(g.ped_b, A_C), (b16, A_GAMMA0), (g.ped_h, t_)],
        ));
        rels.push(LinRel::new(g.ped_b.into(), vec![(pr.dcoms[di], u_), (g.ped_h, v_)]));
    }
    if let (Some(cn), Some(rn)) = (pr.cnew, lay.rho_new) {
        let mut t = vec![(g.h[A_RHO], rn)];
        for j in 0..N_ATTR {
            if j != A_RHO && j != A_TAU {
                t.push((g.h[j], j));
            }
        }
        rels.push(LinRel::new(cn.into(), t));
    }
    for (j, v) in &cfg.reveal {
        // h_j^v = h_j^{m_j}: the response for m_j is shared with every other relation, so this pins it
        rels.push(LinRel::new(g.h[*j] * v, vec![(g.h[*j], *j)]));
    }
    rels
}

fn challenge(cfg: &Cfg, pr: &Proof, ts: &[G1A], ps_t: &PairingOutput<E>, snark_bytes: &[u8]) -> Fr {
    let mut h = Sha256::new();
    h.update(b"EUPC-V1-PRESENTATION");
    h.update(cfg.name.as_bytes());
    h.update(&cfg.context);
    let mut buf = vec![];
    for p in [pr.abar, pr.bbar, pr.d, pr.s1, pr.s2] {
        p.serialize_compressed(&mut buf).unwrap();
    }
    for p in pr.vcoms.iter().chain(pr.clcoms.iter()).chain(pr.dcoms.iter()).chain(pr.outputs.iter()).chain(ts.iter()) {
        p.serialize_compressed(&mut buf).unwrap();
    }
    for gp in &pr.gens {
        for p in [gp.k, gp.cp, gp.e, gp.cma] {
            p.serialize_compressed(&mut buf).unwrap();
        }
        for p in gp.gk.ca.iter().chain(gp.gk.cb.iter()).chain(gp.gk.cd.iter()) {
            p.serialize_compressed(&mut buf).unwrap();
        }
    }
    if let Some(c) = pr.cnew {
        c.serialize_compressed(&mut buf).unwrap();
    }
    ps_t.serialize_compressed(&mut buf).unwrap();
    h.update(&buf);
    h.update(snark_bytes);
    let d = h.finalize();
    hash_to_fr(b"EUPC-CHALLENGE", &d)
}

fn snark_bytes(pr: &Proof) -> Vec<u8> {
    let mut b = vec![];
    if let Some(pf) = &pr.r1cs {
        pf.serialize_compressed(&mut b).unwrap();
    }
    if let Some(lp) = &pr.lego {
        lp.serialize_compressed(&mut b).unwrap();
    }
    b
}

/// BM7: one-phase Bulletproofs proofs carry A_I2, A_O2, S2 = identity; the compact encoding drops them.
pub fn bp_strip(pf: &R1CSProof<G1A>) -> Vec<u8> {
    let mut b = vec![];
    pf.serialize_compressed(&mut b).unwrap();
    let mut id = vec![];
    G1A::zero().serialize_compressed(&mut id).unwrap();
    for k in 3..6 {
        assert_eq!(&b[k * 48..(k + 1) * 48], &id[..], "second-phase point not identity");
    }
    let mut out = b[..3 * 48].to_vec();
    out.extend_from_slice(&b[6 * 48..]);
    out
}

pub fn bp_unstrip(b: &[u8]) -> R1CSProof<G1A> {
    let mut id = vec![];
    G1A::zero().serialize_compressed(&mut id).unwrap();
    let mut full = b[..3 * 48].to_vec();
    for _ in 0..3 {
        full.extend_from_slice(&id);
    }
    full.extend_from_slice(&b[3 * 48..]);
    R1CSProof::<G1A>::deserialize_compressed(&full[..]).expect("decode")
}

pub fn prove<R: RngCore + ark_std::rand::CryptoRng>(
    rng: &mut R,
    p: &Public,
    cfg: &Cfg,
    hd: &Holder,
) -> Proof {
    let t_all = std::time::Instant::now();
    let g = p.g;
    let pos = p.pos(cfg.width);
    let mm = m_max(p, cfg);
    let lay = layout(cfg, mm);
    let cr = &hd.cred;
    let mut w = vec![Fr::zero(); lay.n];
    w[..N_ATTR].copy_from_slice(&cr.m);
    // BBS randomisation
    let r1 = Fr::rand(rng);
    let r2 = Fr::rand(rng);
    let b = bbs_b(g, &cr.m);
    let d = b * r2;
    let abar = cr.a * (r1 * r2);
    let bbar = d * r1 - abar * cr.e;
    w[lay.e_neg] = -cr.e;
    w[lay.r1] = r1;
    w[lay.r3] = r2.inverse().unwrap();
    // PS randomisation
    let tt = Fr::rand(rng);
    let kk = Fr::rand(rng);
    let s1 = hd.ps.0 * tt;
    let s2 = (hd.ps.1.into_group() + hd.ps.0 * kk) * tt;
    w[lay.ps_k] = kk;
    // hashes
    let mut outputs = vec![];
    for (h, hu) in cfg.hashes.iter().enumerate() {
        let x = hash_value(pos, hu, cfg.width, cr.m[A_S]);
        w[lay.x_idx[h]] = x;
        for (bi, bse) in hu.bases.iter().enumerate() {
            match lay.out_blind[h][bi] {
                Some(bl) => {
                    let rho = Fr::rand(rng);
                    w[bl] = rho;
                    outputs.push((*bse * x + g.ped_h * rho).into_affine());
                }
                None => outputs.push((*bse * x).into_affine()),
            }
        }
    }
    // committed values (R1CS commitments / LegoGroth16 committed witnesses)
    let nv = lay.vval.len();
    let mut vvals = vec![Fr::zero(); nv];
    let mut vbl = vec![Fr::zero(); nv];
    for vi in 0..nv {
        vbl[vi] = Fr::rand(rng);
        if lay.vblind[vi] != usize::MAX {
            w[lay.vblind[vi]] = vbl[vi];
        }
        vvals[vi] = if lay.v_bits.contains(&vi) {
            let k = vi - lay.v_bits[0];
            Fr::from((hd.r_u64 >> k) & 1)
        } else {
            w[lay.vval[vi].unwrap()]
        };
        if let Some(ix) = lay.vval[vi] {
            w[ix] = vvals[vi];
        }
    }
    let range_values: Vec<u64> = cfg
        .ranges
        .iter()
        .map(|rg| {
            let mut v = rg.constant;
            for (a, c) in &rg.terms {
                v += *c * cr.mv[*a] as i64;
            }
            assert!(v >= 0 && v < (1 << RANGE_BITS), "range {} out of range: {}", rg.label, v);
            v as u64
        })
        .collect();
    let t_snark = std::time::Instant::now();
    let mut vcoms = vec![];
    let mut clcoms = vec![];
    let mut r1cs = None;
    let mut lego = None;
    let mut rk: Vec<Fr> = vec![]; // blindings of the GK bit commitments
    if nv > 0 {
        match cfg.backend {
            Backend::Bulletproofs => {
                let mut tr = Transcript::new(b"EUPC-R1CS");
                tr.append_message(b"ctx", &cfg.context);
                let mut prover = Prover::new(&p.pc, &mut tr);
                let mut vars = vec![];
                for vi in 0..nv {
                    let (c, v) = prover.commit(vvals[vi], vbl[vi]);
                    vcoms.push(c);
                    vars.push(v);
                }
                circuit(&mut prover, cfg, &lay, pos, p.pos3, p.pos5, &vars, Some((cr, hd.r_u64, &hd.paths)));
                r1cs = Some(prover.prove(rng, p.bp).expect("r1cs prove"));
                rk = lay.v_bits.iter().map(|vi| vbl[*vi]).collect();
            }
            Backend::LegoGroth16 => {
                let keys = cfg.lego.as_ref().expect("lego keys");
                let v = Fr::rand(rng);
                w[lay.lego_v.unwrap()] = v;
                let circ = LegoCircuit::new(cfg, pos, p.pos3, p.pos5, Some(hd.paths.clone()), &lay, vvals.iter().map(|x| Some(*x)).collect(), range_values.iter().map(|x| Some(*x)).collect(), Some(hd.r_u64));
                lego = Some(legogroth16::create_random_proof(circ, v, &keys.pk, rng).expect("lego prove"));
                for k in 0..lay.v_bits.len() {
                    let rkk = Fr::rand(rng);
                    w[lay.bit_blind[k]] = rkk;
                    rk.push(rkk);
                    clcoms.push((g.ped_b * vvals[lay.v_bits[k]] + g.ped_h * rkk).into_affine());
                }
            }
        }
    }
    let snark_ms = t_snark.elapsed().as_secs_f64() * 1000.0;
    let mut gk_ms = 0.0;
    // generations
    let r_fr = cr.m[A_R];
    let mut gen_states = vec![];
    let mut gens_pf = vec![];
    for gi in 0..cfg.n_gens {
        let gen = &p.gens[gi];
        let l = (hd.r_u64 as usize) & ((1 << gen.m) - 1);
        let wit = &hd.wits[gi];
        let rho = Fr::rand(rng);
        let kp = (gen.vals[l].into_group() + g.ped_h * rho).into_affine();
        let u = Fr::rand(rng);
        let cp = (wit.c * u).into_affine();
        let a = wit.d * u;
        let t = Fr::rand(rng);
        let cma = (g.p_acc * a + g.ped_h * t).into_affine();
        let e = (cp * r_fr + g.p_acc * a - kp * u + g.ped_h * (rho * u)).into_affine();
        let [u_, bb, a_, t_] = lay.gen_idx[gi];
        w[u_] = -u;
        w[bb] = rho * u - t;
        w[a_] = a.inverse().unwrap();
        w[t_] = -t * a.inverse().unwrap();
        let t_gk = std::time::Instant::now();
        let st = gk::commit(rng, g, &gen.vals, l, gen.m);
        gk_ms += t_gk.elapsed().as_secs_f64() * 1000.0;
        gen_states.push((st, l, rho));
        gens_pf.push((kp, cp, e, cma));
    }
    // distrust
    let mut dcoms = vec![];
    for (di, (c_, g0)) in cfg.d_entries.iter().enumerate() {
        let lval = cr.m[A_C] + cr.m[A_GAMMA0] * Fr::from(1u64 << 16) - Fr::from(*c_ + (*g0 << 16));
        let t = Fr::rand(rng);
        dcoms.push((g.ped_b * lval + g.ped_h * t).into_affine());
        let [t_, u_, v_] = lay.d_idx[di];
        let li = lval.inverse().expect("credential is in a distrusted group");
        w[t_] = t;
        w[u_] = li;
        w[v_] = -t * li;
    }
    let mut cnew = None;
    if let Some(rn) = lay.rho_new {
        let rho2 = hd.rho_new.unwrap_or_else(|| Fr::rand(rng));
        w[rn] = rho2;
        let mut c = g.h[A_RHO] * rho2;
        for j in 0..N_ATTR {
            if j != A_RHO && j != A_TAU {
                c += g.h[j] * cr.m[j];
            }
        }
        cnew = Some(c.into_affine());
    }
    let mut pr = Proof {
        abar: abar.into_affine(),
        bbar: bbar.into_affine(),
        d: d.into_affine(),
        s1: s1.into_affine(),
        s2: s2.into_affine(),
        vcoms,
        r1cs,
        lego,
        clcoms,
        gens: vec![],
        dcoms,
        cnew,
        outputs,
        c: Fr::zero(),
        z: vec![],
    };
    for (gi, (kp, cp, e, cma)) in gens_pf.iter().enumerate() {
        let st = &gen_states[gi].0;
        pr.gens.push(GenProof {
            k: *kp,
            cp: *cp,
            e: *e,
            cma: *cma,
            gk: gk::GkProof { ca: st.ca.clone(), cb: st.cb.clone(), cd: st.cd.clone(), f: vec![], za: vec![], zb: vec![], zd: Fr::zero() },
        });
    }
    let rels = linear_relations(p, cfg, &lay, &pr);
    debug_assert!(sigma::check(&rels, &w).is_none(), "relation {:?} fails", sigma::check(&rels, &w));
    let blind: Vec<Fr> = (0..lay.n).map(|_| Fr::rand(rng)).collect();
    let ts = sigma::commit(&rels, &blind);
    let ps_t = E::pairing(pr.s1, (p.ps_yt * blind[A_R] + g.g2 * blind[lay.ps_k]).into_affine());
    let c = challenge(cfg, &pr, &ts, &ps_t, &snark_bytes(&pr));
    pr.z = (0..lay.n).map(|i| blind[i] + c * w[i]).collect();
    pr.c = c;
    for (gi, (st, l, rho)) in gen_states.into_iter().enumerate() {
        let m = p.gens[gi].m;
        pr.gens[gi].gk = gk::respond(st, l, m, &rk, rho, c);
    }
    let tot = t_all.elapsed().as_secs_f64() * 1000.0;
    SPLIT.with(|s| *s.borrow_mut() = (snark_ms, gk_ms, tot));
    pr
}

pub fn verify(p: &Public, cfg: &Cfg, pr_in: &Proof) -> bool {
    let g = p.g;
    let pos = p.pos(cfg.width);
    let mm = m_max(p, cfg);
    let lay = layout(cfg, mm);
    // Compact encoding: rebuild what the sender left out, as a real receiver would.
    let mut rebuilt;
    let pr: &Proof = if cfg.compact {
        rebuilt = Proof {
            abar: pr_in.abar, bbar: pr_in.bbar, d: pr_in.d, s1: pr_in.s1, s2: pr_in.s2,
            vcoms: pr_in.vcoms.clone(),
            r1cs: pr_in.r1cs.as_ref().map(|pf| bp_unstrip(&bp_strip(pf))),
            lego: pr_in.lego.clone(),
            clcoms: pr_in.clcoms.clone(),
            gens: vec![],
            dcoms: pr_in.dcoms.clone(), cnew: pr_in.cnew, outputs: pr_in.outputs.clone(),
            c: pr_in.c, z: pr_in.z.clone(),
        };
        let cl: Vec<G1A> = match cfg.backend {
            Backend::Bulletproofs => lay.v_bits.iter().map(|vi| pr_in.vcoms[*vi]).collect(),
            Backend::LegoGroth16 => pr_in.clcoms.clone(),
        };
        for (gi, gp) in pr_in.gens.iter().enumerate() {
            let gen = &p.gens[gi];
            // the received proof has no c_a, c_b, c_d[0]
            let mut cd = gp.gk.cd.clone();
            cd[0] = G1A::zero();
            let recv = gk::GkProof { ca: vec![], cb: vec![], cd, f: gp.gk.f.clone(), za: gp.gk.za.clone(), zb: gp.gk.zb.clone(), zd: gp.gk.zd };
            let (ca, cb, cd0) = gk::recompute(g, &gen.vals, &gp.k, &cl[..gen.m], gen.m, &recv, pr_in.c);
            let mut cd = recv.cd.clone();
            cd[0] = cd0;
            rebuilt.gens.push(GenProof { k: gp.k, cp: gp.cp, e: gp.e, cma: gp.cma, gk: gk::GkProof { ca, cb, cd, f: recv.f, za: recv.za, zb: recv.zb, zd: recv.zd } });
        }
        &rebuilt
    } else {
        pr_in
    };
    if pr.abar.is_zero() || pr.s1.is_zero() {
        return false;
    }
    // pairing checks: BBS, and per generation e(E, g2) e(C', Q) = 1
    if !E::multi_pairing([pr.abar, (-pr.bbar.into_group()).into_affine()], [p.w_iss, g.g2]).is_zero() {
        return false;
    }
    for gp in &pr.gens {
        if gp.cp.is_zero() || !E::multi_pairing([gp.e, gp.cp], [g.g2, p.acc_q]).is_zero() {
            return false;
        }
    }
    // SNARK
    match cfg.backend {
        Backend::Bulletproofs => {
            if let Some(pf) = &pr.r1cs {
                let mut tr = Transcript::new(b"EUPC-R1CS");
                tr.append_message(b"ctx", &cfg.context);
                let mut ver = Verifier::new(&mut tr);
                let vars: Vec<Variable<Fr>> = pr.vcoms.iter().map(|v| ver.commit(*v)).collect();
                circuit(&mut ver, cfg, &lay, pos, p.pos3, p.pos5, &vars, None);
                if ver.verify(pf, &p.pc, p.bp).is_err() {
                    return false;
                }
            }
        }
        Backend::LegoGroth16 => {
            if let Some(lp) = &pr.lego {
                let keys = cfg.lego.as_ref().unwrap();
                if legogroth16::verify_proof(&keys.pvk, lp, &lego_public_inputs(cfg)).is_err() {
                    return false;
                }
            }
        }
    }
    // sigma relations
    let rels = linear_relations(p, cfg, &lay, pr);
    let ts = sigma::recompute(&rels, &pr.z, pr.c);
    let ps_t = E::multi_pairing(
        [pr.s1, (pr.s2 * (-pr.c)).into_affine()],
        [(p.ps_yt * pr.z[A_R] + g.g2 * pr.z[lay.ps_k] + p.ps_xt * pr.c).into_affine(), g.g2],
    );
    if challenge(cfg, pr, &ts, &ps_t, &snark_bytes(pr)) != pr.c {
        return false;
    }
    if !cfg.compact {
        let cl: Vec<G1A> = match cfg.backend {
            Backend::Bulletproofs => lay.v_bits.iter().map(|vi| pr.vcoms[*vi]).collect(),
            Backend::LegoGroth16 => pr.clcoms.clone(),
        };
        for (gi, gp) in pr.gens.iter().enumerate() {
            let gen = &p.gens[gi];
            if !gk::verify(g, &gen.vals, &gp.k, &cl[..gen.m], gen.m, &gp.gk, pr.c) {
                return false;
            }
        }
    }
    true
}

pub fn sizes(pr: &Proof, compact: bool) -> SizeBreakdown {
    let mut s = SizeBreakdown::default();
    s.bbs = 3 * G1_BYTES + 3 * FR_BYTES + N_ATTR * FR_BYTES; // Abar,Bbar,D + e^,r1^,r3^ + hidden m^
    s.ps = 2 * G1_BYTES + FR_BYTES; // sigma1', sigma2' + k^
    s.r1cs_proof = match (&pr.r1cs, &pr.lego) {
        (Some(p), _) => if compact { bp_strip(p).len() } else { p.compressed_size() },
        (_, Some(l)) => l.compressed_size(),
        _ => 0,
    };
    s.r1cs_commitments = (pr.vcoms.len() + pr.clcoms.len()) * G1_BYTES;
    s.generations = pr.gens.len();
    if let Some(gp) = pr.gens.first() {
        let m = gp.gk.f.len();
        let g_elems = if compact { m - 1 } else { 3 * m };
        s.per_generation = 4 * G1_BYTES + 4 * FR_BYTES + g_elems * G1_BYTES + (3 * m + 1) * FR_BYTES;
    }
    s.distrust = pr.dcoms.len() * (G1_BYTES + 3 * FR_BYTES);
    s.reissue = if pr.cnew.is_some() { G1_BYTES + FR_BYTES } else { 0 };
    s.outputs = pr.outputs.len() * G1_BYTES;
    let accounted = N_ATTR + 3 + 1 + pr.gens.len() * 4 + pr.dcoms.len() * 3 + if pr.cnew.is_some() { 1 } else { 0 };
    s.other_responses = (pr.z.len() - accounted) * FR_BYTES; // commitment-link blindings, hash exponents, bits
    s.challenge = FR_BYTES;
    s.total = s.bbs + s.ps + s.r1cs_proof + s.r1cs_commitments + s.per_generation * s.generations
        + s.distrust + s.reissue + s.outputs + s.other_responses + s.challenge;
    s
}
