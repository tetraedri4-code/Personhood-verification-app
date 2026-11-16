//! Poseidon over the BLS12-381 scalar field, S-box x^5 (Grassi et al., USENIX Security 2021, Table 2:
//! POSEIDON-128 with t = 3: R_F = 8, R_P = 57; t = 5: R_F = 8, R_P = 60).
//! Constants from the reference Grain LFSR generator (ark-crypto-primitives).
//! Native evaluation, a Bulletproofs R1CS gadget and an ark-r1cs-std gadget (for LegoGroth16).
//! hash(inputs) = state[1] after the permutation of [0, inputs...] (capacity 1, rate t-1).
use crate::params::Fr;
use ark_bulletproofs::r1cs::{ConstraintSystem, LinearCombination, Variable};
use ark_crypto_primitives::sponge::poseidon::find_poseidon_ark_and_mds;
use ark_ff::{Field, One, Zero};
use ark_r1cs_std::fields::fp::FpVar;
use ark_r1cs_std::fields::FieldVar;
use ark_relations::r1cs::SynthesisError;

pub const RF: usize = 8;

pub struct Poseidon {
    pub width: usize,
    pub rp: usize,
    pub ark: Vec<Vec<Fr>>,
    pub mds: Vec<Vec<Fr>>,
}

impl Poseidon {
    pub fn new(width: usize) -> Self {
        let rp = match width {
            3 => 57,
            5 => 60,
            _ => panic!("unsupported width"),
        };
        let (ark, mds) = find_poseidon_ark_and_mds::<Fr>(255, width - 1, RF as u64, rp as u64, 0);
        Poseidon { width, rp, ark, mds }
    }

    fn is_full(&self, r: usize) -> bool {
        r < RF / 2 || r >= RF / 2 + self.rp
    }

    /// Multipliers (R1CS constraints) per hash: 3 per S-box.
    pub fn constraints(&self) -> usize {
        3 * (RF * self.width + self.rp)
    }

    pub fn hash(&self, inp: &[Fr]) -> Fr {
        self.hash_dom(Fr::zero(), inp)
    }

    /// Hash with a domain-separation constant in the capacity element (e.g. "nym", "pub", "rev-node").
    pub fn hash_dom(&self, dom: Fr, inp: &[Fr]) -> Fr {
        assert_eq!(inp.len(), self.width - 1);
        let w = self.width;
        let mut st = vec![dom];
        st.extend_from_slice(inp);
        for r in 0..RF + self.rp {
            for j in 0..w {
                st[j] += self.ark[r][j];
            }
            if self.is_full(r) {
                for j in 0..w {
                    st[j] = st[j].pow([5u64]);
                }
            } else {
                st[0] = st[0].pow([5u64]);
            }
            let mut n = vec![Fr::zero(); w];
            for i in 0..w {
                for j in 0..w {
                    n[i] += self.mds[i][j] * st[j];
                }
            }
            st = n;
        }
        st[1]
    }

    /// Bulletproofs gadget.
    pub fn gadget<CS: ConstraintSystem<Fr>>(&self, cs: &mut CS, inp: Vec<Lc>) -> Lc {
        self.gadget_dom(cs, Fr::zero(), inp)
    }

    pub fn gadget_dom<CS: ConstraintSystem<Fr>>(&self, cs: &mut CS, dom: Fr, inp: Vec<Lc>) -> Lc {
        let w = self.width;
        let mut st: Vec<Lc> = vec![Lc::constant(dom)];
        st.extend(inp);
        for r in 0..RF + self.rp {
            for j in 0..w {
                st[j].add_const(self.ark[r][j]);
            }
            let sbox = |cs: &mut CS, x: &Lc| -> Lc {
                let (_, _, x2) = cs.multiply(x.to_lc(), x.to_lc());
                let (_, _, x4) = cs.multiply(x2.into(), x2.into());
                let (_, _, x5) = cs.multiply(x4.into(), x.to_lc());
                Lc::var(x5)
            };
            if self.is_full(r) {
                for j in 0..w {
                    st[j] = sbox(cs, &st[j]);
                }
            } else {
                st[0] = sbox(cs, &st[0]);
            }
            let mut n = Vec::with_capacity(w);
            for i in 0..w {
                let mut acc = Lc::default();
                for j in 0..w {
                    acc.add_scaled(&st[j], self.mds[i][j]);
                }
                n.push(acc);
            }
            st = n;
        }
        st[1].clone()
    }

    /// ark-r1cs-std gadget (LegoGroth16 / Groth16).
    pub fn gadget_fp(&self, inp: Vec<FpVar<Fr>>) -> Result<FpVar<Fr>, SynthesisError> {
        self.gadget_fp_dom(Fr::zero(), inp)
    }

    pub fn gadget_fp_dom(&self, dom: Fr, inp: Vec<FpVar<Fr>>) -> Result<FpVar<Fr>, SynthesisError> {
        let w = self.width;
        let mut st: Vec<FpVar<Fr>> = vec![FpVar::constant(dom)];
        st.extend(inp);
        for r in 0..RF + self.rp {
            for j in 0..w {
                st[j] = &st[j] + FpVar::constant(self.ark[r][j]);
            }
            let sbox = |x: &FpVar<Fr>| -> Result<FpVar<Fr>, SynthesisError> {
                let x2 = x.square()?;
                let x4 = x2.square()?;
                Ok(&x4 * x)
            };
            if self.is_full(r) {
                for j in 0..w {
                    st[j] = sbox(&st[j])?;
                }
            } else {
                st[0] = sbox(&st[0])?;
            }
            let mut n = Vec::with_capacity(w);
            for i in 0..w {
                let mut acc = FpVar::constant(Fr::zero());
                for j in 0..w {
                    acc += &st[j] * self.mds[i][j];
                }
                n.push(acc);
            }
            st = n;
        }
        Ok(st[1].clone())
    }
}

/// Sparse linear combination with merged terms (keeps Poseidon's linear layers from blowing up).
#[derive(Clone, Default, Debug)]
pub struct Lc {
    pub terms: Vec<(Variable<Fr>, Fr)>,
    pub constant: Fr,
}

impl Lc {
    pub fn constant(c: Fr) -> Self {
        Lc { terms: vec![], constant: c }
    }
    pub fn var(v: Variable<Fr>) -> Self {
        Lc { terms: vec![(v, Fr::one())], constant: Fr::zero() }
    }
    pub fn add_const(&mut self, c: Fr) {
        self.constant += c;
    }
    pub fn add_term(&mut self, v: Variable<Fr>, c: Fr) {
        if let Some(t) = self.terms.iter_mut().find(|(w, _)| *w == v) {
            t.1 += c;
        } else {
            self.terms.push((v, c));
        }
    }
    pub fn add_scaled(&mut self, o: &Lc, k: Fr) {
        for (v, c) in &o.terms {
            self.add_term(*v, *c * k);
        }
        self.constant += o.constant * k;
    }
    pub fn to_lc(&self) -> LinearCombination<Fr> {
        let mut v: Vec<(Variable<Fr>, Fr)> = self.terms.iter().filter(|(_, c)| !c.is_zero()).cloned().collect();
        if !self.constant.is_zero() {
            v.push((Variable::One(), self.constant));
        }
        LinearCombination::from_iter(v)
    }
}
