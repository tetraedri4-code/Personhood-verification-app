//! Curve types, hashing and public generators (BLS12-381, RFC 9380 hash-to-curve).
use ark_bls12_381::{g1, Bls12_381, Fr as F, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::hashing::{
    curve_maps::wb::WBMap, map_to_curve_hasher::MapToCurveBasedHasher, HashToCurve,
};
use ark_ec::{pairing::Pairing, CurveGroup, Group};
use ark_ff::{field_hashers::DefaultFieldHasher, PrimeField};
use ark_serialize::CanonicalSerialize;
use sha2::{Digest, Sha256};

pub type Fr = F;
pub type G1 = G1Projective;
pub type G1A = G1Affine;
pub type G2 = G2Projective;
pub type G2A = G2Affine;
pub type E = Bls12_381;
pub type GT = <E as Pairing>::TargetField;

pub const G1_BYTES: usize = 48; // compressed
pub const G2_BYTES: usize = 96; // compressed
pub const FR_BYTES: usize = 32;

/// Hash to G1 with a distinct domain-separation tag (RFC 9380, BLS12381G1_XMD:SHA-256_SSWU_RO_).
pub fn hash_to_g1(dst: &[u8], msg: &[u8]) -> G1A {
    let h = MapToCurveBasedHasher::<G1, DefaultFieldHasher<Sha256, 128>, WBMap<g1::Config>>::new(dst)
        .expect("hasher");
    h.hash(msg).expect("hash to curve")
}

/// Hash to a scalar (expand to 48 bytes, reduce mod q), as in the BBS draft's hash_to_scalar.
pub fn hash_to_fr(dst: &[u8], msg: &[u8]) -> Fr {
    let mut out = Vec::with_capacity(64);
    for ctr in 0u8..2 {
        let mut h = Sha256::new();
        h.update((dst.len() as u32).to_be_bytes());
        h.update(dst);
        h.update([ctr]);
        h.update(msg);
        out.extend_from_slice(&h.finalize());
    }
    Fr::from_be_bytes_mod_order(&out[..48])
}

pub fn g1_bytes(p: &G1A) -> Vec<u8> {
    let mut v = Vec::with_capacity(48);
    p.serialize_compressed(&mut v).unwrap();
    v
}

/// Public generators of the scheme.
#[derive(Clone)]
pub struct Gens {
    pub p1: G1A,          // BBS P1
    pub q1: G1A,          // BBS Q1 (domain)
    pub h: Vec<G1A>,      // BBS message generators, one per hidden value (10)
    pub g2: G2A,          // G2 generator
    pub ped_b: G1A,       // Pedersen value base (Bulletproofs B, GK g)
    pub ped_h: G1A,       // Pedersen blinding base (Bulletproofs B_blinding, GK h)
    pub p_acc: G1A,       // accumulator base P
    pub wp1: G1A,         // witness BBS signature on the handle: P1
    pub wh: G1A,          // witness BBS signature on the handle: generator of r
}

/// Design v2 (§4.1, §4.3): m = (s, delta, r, tau, gamma, ell, c, gamma0, e), plus rho from the blind-issuance
/// commitment C = h_rho^rho h_s^s h_delta^delta, which the signature also covers: 10 hidden values.
pub const N_ATTR: usize = 10;
pub const A_RHO: usize = 0;
pub const A_S: usize = 1;
pub const A_DELTA: usize = 2;
pub const A_R: usize = 3;
pub const A_TAU: usize = 4;
pub const A_GAMMA: usize = 5;
pub const A_ELL: usize = 6;
pub const A_C: usize = 7;
pub const A_GAMMA0: usize = 8;
pub const A_E: usize = 9;

impl Gens {
    /// One shared copy (hashing to the curve is not free).
    pub fn cached() -> &'static Gens {
        static G: std::sync::OnceLock<Gens> = std::sync::OnceLock::new();
        G.get_or_init(Gens::new)
    }

    pub fn new() -> Self {
        let dst = b"EUPC-V1-GENERATORS";
        let h = (0..N_ATTR)
            .map(|i| hash_to_g1(dst, format!("H_{i}").as_bytes()))
            .collect();
        Gens {
            p1: hash_to_g1(dst, b"P1"),
            q1: hash_to_g1(dst, b"Q1"),
            h,
            g2: G2::generator().into_affine(),
            ped_b: hash_to_g1(dst, b"PEDERSEN_B"),
            ped_h: hash_to_g1(dst, b"PEDERSEN_H"),
            p_acc: hash_to_g1(dst, b"ACC_P"),
            wp1: hash_to_g1(dst, b"WITNESS_P1"),
            wh: hash_to_g1(dst, b"WITNESS_H"),
        }
    }
}
