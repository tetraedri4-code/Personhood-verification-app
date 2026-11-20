//! Encodings: hex of canonical compressed arkworks encodings (points are subgroup-checked on decode),
//! and the wire format of a presentation proof.
use crate::params::{Fr, G1A, E};
use crate::scheme::{CryptoError, Result};
use crate::statement::Proof;
use ark_bulletproofs::r1cs::R1CSProof;
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize, Compress, Validate};

pub fn ser<T: CanonicalSerialize>(x: &T) -> Vec<u8> {
    let mut b = vec![];
    x.serialize_compressed(&mut b).expect("serialize");
    b
}

pub fn de<T: CanonicalDeserialize>(b: &[u8]) -> Result<T> {
    let mut rd = b;
    let v = T::deserialize_with_mode(&mut rd, Compress::Yes, Validate::Yes).map_err(|e| CryptoError::Encoding(e.to_string()))?;
    if !rd.is_empty() {
        return Err(CryptoError::Encoding("trailing bytes".into()));
    }
    Ok(v)
}

pub fn to_hex<T: CanonicalSerialize>(x: &T) -> String {
    hex::encode(ser(x))
}

pub fn from_hex<T: CanonicalDeserialize>(s: &str) -> Result<T> {
    de(&hex::decode(s).map_err(|e| CryptoError::Encoding(e.to_string()))?)
}

/// Upper bound on any vector length in a proof, so a hostile length prefix cannot allocate much.
const MAX_ITEMS: u64 = 4096;

/// 2: commitment form (Schnorr commitments sent, challenge computed) and a BBS witness signature.
const VERSION: u8 = 2;

pub fn encode_proof(p: &Proof) -> Vec<u8> {
    assert!(p.gens.is_empty(), "accumulator generations are not part of this prototype's wire format");
    let mut b = vec![VERSION];
    for pt in [p.abar, p.bbar, p.d, p.wabar, p.wbbar, p.wd] {
        pt.serialize_compressed(&mut b).unwrap();
    }
    p.vcoms.serialize_compressed(&mut b).unwrap();
    p.r1cs.serialize_compressed(&mut b).unwrap();
    p.lego.serialize_compressed(&mut b).unwrap();
    p.clcoms.serialize_compressed(&mut b).unwrap();
    p.dcoms.serialize_compressed(&mut b).unwrap();
    p.cnew.serialize_compressed(&mut b).unwrap();
    p.outputs.serialize_compressed(&mut b).unwrap();
    p.ts.serialize_compressed(&mut b).unwrap();
    p.z.serialize_compressed(&mut b).unwrap();
    b
}

fn read_vec<T: CanonicalDeserialize>(rd: &mut &[u8]) -> Result<Vec<T>> {
    let n = u64::deserialize_compressed(&mut *rd).map_err(|e| CryptoError::Encoding(e.to_string()))?;
    if n > MAX_ITEMS {
        return Err(CryptoError::Encoding("vector too long".into()));
    }
    (0..n).map(|_| T::deserialize_compressed(&mut *rd).map_err(|e| CryptoError::Encoding(e.to_string()))).collect()
}

fn read<T: CanonicalDeserialize>(rd: &mut &[u8]) -> Result<T> {
    T::deserialize_compressed(&mut *rd).map_err(|e| CryptoError::Encoding(e.to_string()))
}

pub fn decode_proof(b: &[u8]) -> Result<Proof> {
    if b.first() != Some(&VERSION) {
        return Err(CryptoError::Encoding("unknown proof version".into()));
    }
    let mut rd = &b[1..];
    let abar: G1A = read(&mut rd)?;
    let bbar: G1A = read(&mut rd)?;
    let d: G1A = read(&mut rd)?;
    let wabar: G1A = read(&mut rd)?;
    let wbbar: G1A = read(&mut rd)?;
    let wd: G1A = read(&mut rd)?;
    let vcoms = read_vec::<G1A>(&mut rd)?;
    let r1cs: Option<R1CSProof<G1A>> = read(&mut rd)?;
    let lego: Option<legogroth16::Proof<E>> = read(&mut rd)?;
    let clcoms = read_vec::<G1A>(&mut rd)?;
    let dcoms = read_vec::<G1A>(&mut rd)?;
    let cnew: Option<G1A> = read(&mut rd)?;
    let outputs = read_vec::<G1A>(&mut rd)?;
    let ts = read_vec::<G1A>(&mut rd)?;
    let z = read_vec::<Fr>(&mut rd)?;
    if !rd.is_empty() {
        return Err(CryptoError::Encoding("trailing bytes".into()));
    }
    Ok(Proof { abar, bbar, d, wabar, wbbar, wd, ts, vcoms, r1cs, lego, clcoms, gens: vec![], dcoms, cnew, outputs, c: Fr::from(0u64), z })
}
