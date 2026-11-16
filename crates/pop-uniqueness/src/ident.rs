//! Every operator has a long-term identity key (a scalar sk with public key g2^sk). With it an
//! operator signs every message it sends in a round, receives sub-shares encrypted to it, and can
//! prove to third parties what a ciphertext addressed to it contained (for complaints).
//!
//! * Signature: BLS, sig = H(msg)^sk in G1, checked with e(sig, g2) = e(H(msg), pk).
//! * Encryption: ElGamal-style. The sender picks e, sends E = g2^e and value XOR KDF(pk^e). The pad is
//!   used once (fresh e per message). Integrity comes from the sender's signature over the message and
//!   from checking the decrypted value against the sender's public commitments.
//!   The sender also proves that it knows e, bound to the message's context. A receiver never raises
//!   its key on a point without that proof: otherwise a cheating dealer could resend the E of an
//!   honest dealer's ciphertext, provoke a complaint, and read the honest dealer's sub-share from the
//!   opening.
//! * Opening for a complaint: the receiver publishes pk^e = E^sk with a Chaum–Pedersen proof that it
//!   used its own key, so anyone can decrypt that one message and check it.
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group};
use ark_ff::Zero;
use ark_std::UniformRand;
use pop_crypto::codec::{from_hex, ser, to_hex};
use pop_crypto::params::{hash_to_fr, hash_to_g1, Fr, E, G1, G1A, G2, G2A};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

const DST_SIG: &[u8] = b"POP-UNIQUENESS-V2-SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_";

pub struct IdentityKey {
    sk: Fr,
    pub public: G2A,
}

fn point(s: &str) -> Result<G2A, String> {
    let p: G2A = from_hex(s).map_err(|e| e.to_string())?;
    if p.is_zero() {
        return Err("point at infinity".into());
    }
    Ok(p)
}

pub fn parse_public(s: &str) -> Result<G2A, String> {
    point(s)
}

impl IdentityKey {
    pub fn generate() -> Self {
        Self::from_secret(Fr::rand(&mut rand::thread_rng()))
    }

    fn from_secret(sk: Fr) -> Self {
        IdentityKey { sk, public: (G2::generator() * sk).into_affine() }
    }

    pub fn to_hex(&self) -> String {
        to_hex(&self.sk)
    }

    pub fn from_hex(s: &str) -> Result<Self, String> {
        let sk: Fr = from_hex(s).map_err(|e| e.to_string())?;
        if sk.is_zero() {
            return Err("zero identity key".into());
        }
        Ok(Self::from_secret(sk))
    }

    pub fn public_hex(&self) -> String {
        to_hex(&self.public)
    }

    pub fn sign(&self, msg: &[u8]) -> String {
        to_hex(&(G1::from(hash_to_g1(DST_SIG, msg)) * self.sk).into_affine())
    }

    /// The Diffie–Hellman point shared with the sender of `sealed`.
    fn shared(&self, sealed: &Sealed) -> Result<G2A, String> {
        Ok((point(&sealed.e)? * self.sk).into_affine())
    }

    pub fn open(&self, context: &[u8], sealed: &Sealed) -> Result<Fr, String> {
        if !sealed_ok(context, sealed) {
            return Err("the ciphertext is malformed or its sender did not prove it made it".into());
        }
        unpad(&self.shared(sealed)?, context, sealed)
    }

    /// Reveal the shared point of one ciphertext, with a proof that it was computed with this key.
    pub fn reveal(&self, context: &[u8], sealed: &Sealed) -> Result<Opening, String> {
        if !sealed_ok(context, sealed) {
            return Err("refusing to open a ciphertext whose sender did not prove it made it".into());
        }
        let e = point(&sealed.e)?;
        let shared = (e * self.sk).into_affine();
        let k = Fr::rand(&mut rand::thread_rng());
        let (a1, a2) = ((G2::generator() * k).into_affine(), (e * k).into_affine());
        let c = dleq_challenge(&self.public, &e, &shared, &a1, &a2, context);
        Ok(Opening { shared: to_hex(&shared), a1: to_hex(&a1), a2: to_hex(&a2), z: to_hex(&(k + c * self.sk)) })
    }
}

pub fn verify(public: &G2A, msg: &[u8], sig: &str) -> bool {
    let Ok(s) = from_hex::<G1A>(sig) else { return false };
    !s.is_zero() && E::pairing(s, G2A::generator()) == E::pairing(hash_to_g1(DST_SIG, msg), *public)
}

/// A scalar encrypted to one operator.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Sealed {
    pub e: String,
    pub ct: String,
    /// proof that the sender knows e, bound to the context
    #[serde(default)]
    pub pok: Option<Pok>,
}

fn seal_pok_context(context: &[u8]) -> Vec<u8> {
    [b"seal|".as_slice(), context].concat()
}

/// Is this a ciphertext a receiver may open: E is a valid point, the sender proved it knows e for
/// this very context, and the ciphertext has the right length. Anyone can check this, so a deal
/// that fails it convicts its (signing) dealer without any opening.
pub fn sealed_ok(context: &[u8], sealed: &Sealed) -> bool {
    let (Ok(e), Some(pok)) = (point(&sealed.e), &sealed.pok) else { return false };
    sealed.ct.len() == 64 && hex::decode(&sealed.ct).is_ok() && pok_verify(&e, &seal_pok_context(context), pok)
}

/// What a receiver publishes to let others decrypt one message addressed to it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Opening {
    pub shared: String,
    a1: String,
    a2: String,
    z: String,
}

fn pad(shared: &G2A, e: &G2A, context: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"pop-uniqueness-seal-v1");
    h.update(ser(e));
    h.update(ser(shared));
    h.update((context.len() as u64).to_be_bytes());
    h.update(context);
    h.finalize().into()
}

pub fn seal(to: &G2A, context: &[u8], value: &Fr) -> Sealed {
    let e = Fr::rand(&mut rand::thread_rng());
    let big_e = (G2::generator() * e).into_affine();
    let shared = (*to * e).into_affine();
    let p = pad(&shared, &big_e, context);
    let v = ser(value);
    let ct: Vec<u8> = v.iter().zip(p.iter()).map(|(a, b)| a ^ b).collect();
    Sealed { e: to_hex(&big_e), ct: hex::encode(ct), pok: Some(pok_prove(&e, &seal_pok_context(context))) }
}

fn unpad(shared: &G2A, context: &[u8], sealed: &Sealed) -> Result<Fr, String> {
    let ct = hex::decode(&sealed.ct).map_err(|e| e.to_string())?;
    if ct.len() != 32 {
        return Err("ciphertext must be 32 bytes".into());
    }
    let p = pad(shared, &point(&sealed.e)?, context);
    let v: Vec<u8> = ct.iter().zip(p.iter()).map(|(a, b)| a ^ b).collect();
    pop_crypto::codec::de::<Fr>(&v).map_err(|_| "decrypts to no valid scalar".to_string())
}

fn dleq_challenge(pk: &G2A, e: &G2A, shared: &G2A, a1: &G2A, a2: &G2A, context: &[u8]) -> Fr {
    let mut h = Sha256::new();
    for p in [pk, e, shared, a1, a2] {
        h.update(ser(p));
    }
    h.update(context);
    hash_to_fr(b"POP-UNIQUENESS-V2-DLEQ", &h.finalize())
}

/// Decrypt with a revealed shared point, after checking the receiver's proof.
/// `Err` = the opening is missing or invalid (the receiver's fault); `Ok(Err)` = the ciphertext is
/// malformed or holds no scalar (the sender's fault).
pub fn open_with(receiver: &G2A, context: &[u8], sealed: &Sealed, o: Option<&Opening>) -> Result<Result<Fr, String>, String> {
    if !sealed_ok(context, sealed) {
        return Ok(Err("the ciphertext is malformed or its sender did not prove it made it".into()));
    }
    let o = o.ok_or("a well-formed ciphertext needs an opening")?;
    let (e, shared, a1, a2) = (point(&sealed.e)?, point(&o.shared)?, point(&o.a1)?, point(&o.a2)?);
    let z: Fr = from_hex(&o.z).map_err(|e| e.to_string())?;
    let c = dleq_challenge(receiver, &e, &shared, &a1, &a2, context);
    if G2::generator() * z != G2::from(a1) + *receiver * c || e * z != G2::from(a2) + shared * c {
        return Err("the opening proof does not verify".into());
    }
    Ok(unpad(&shared, context, sealed))
}

/// Schnorr proof of knowledge of the discrete log of a G2 point (a dealer's constant-term commitment).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pok {
    a: String,
    z: String,
}

fn pok_challenge(point: &G2A, a: &G2A, context: &[u8]) -> Fr {
    let mut h = Sha256::new();
    h.update(ser(point));
    h.update(ser(a));
    h.update(context);
    hash_to_fr(b"POP-UNIQUENESS-V2-POK", &h.finalize())
}

pub fn pok_prove(secret: &Fr, context: &[u8]) -> Pok {
    let k = Fr::rand(&mut rand::thread_rng());
    let a = (G2::generator() * k).into_affine();
    let c = pok_challenge(&(G2::generator() * secret).into_affine(), &a, context);
    Pok { a: to_hex(&a), z: to_hex(&(k + c * secret)) }
}

pub fn pok_verify(public: &G2A, context: &[u8], p: &Pok) -> bool {
    let (Ok(a), Ok(z)) = (from_hex::<G2A>(&p.a), from_hex::<Fr>(&p.z)) else { return false };
    G2::generator() * z == G2::from(a) + *public * pok_challenge(public, &a, context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sign_seal_open() {
        let (a, b) = (IdentityKey::generate(), IdentityKey::generate());
        let sig = a.sign(b"hello");
        assert!(verify(&a.public, b"hello", &sig));
        assert!(!verify(&a.public, b"hellp", &sig));
        assert!(!verify(&b.public, b"hello", &sig));
        assert!(!verify(&a.public, b"hello", "00"));

        let v = Fr::rand(&mut rand::thread_rng());
        let s = seal(&b.public, b"ctx", &v);
        assert_eq!(b.open(b"ctx", &s).unwrap(), v);
        assert_ne!(b.open(b"other", &s).ok(), Some(v));
        assert_ne!(a.open(b"ctx", &s).ok(), Some(v));
        let s2 = seal(&b.public, b"ctx", &v);
        assert_ne!(s, s2, "fresh randomness per message");

        // a third party decrypts with the receiver's opening, and only with a correct one
        let o = b.reveal(b"ctx", &s).unwrap();
        assert_eq!(open_with(&b.public, b"ctx", &s, Some(&o)).unwrap().unwrap(), v);
        assert!(open_with(&a.public, b"ctx", &s, Some(&o)).is_err());
        assert!(open_with(&b.public, b"ctx", &s, None).is_err());
        let mut bad = o.clone();
        bad.shared = to_hex(&G2::generator().into_affine());
        assert!(open_with(&b.public, b"ctx", &s, Some(&bad)).is_err(), "a made-up shared point is refused");
        assert!(open_with(&b.public, b"ctx", &s2, Some(&o)).is_err(), "an opening fits one ciphertext");

        // A ciphertext is opened only if its sender proved it knows e for this context. Someone who
        // copies E from another message (to have the receiver reveal that message's pad) cannot.
        let mut copied = seal(&b.public, b"mine", &v);
        copied.e = s.e.clone();
        assert!(!sealed_ok(b"mine", &copied));
        assert!(b.open(b"mine", &copied).is_err() && b.reveal(b"mine", &copied).is_err());
        let mut replayed = s.clone();
        assert!(sealed_ok(b"ctx", &replayed) && !sealed_ok(b"other", &replayed));
        assert!(b.reveal(b"other", &replayed).is_err());
        replayed.pok = None;
        assert!(b.reveal(b"ctx", &replayed).is_err());
        // such a message convicts its sender without an opening
        assert!(matches!(open_with(&b.public, b"mine", &copied, None), Ok(Err(_))));

        let p = pok_prove(&v, b"c");
        let pv = (G2::generator() * v).into_affine();
        assert!(pok_verify(&pv, b"c", &p));
        assert!(!pok_verify(&pv, b"d", &p));
        assert!(!pok_verify(&a.public, b"c", &p));

        let k2 = IdentityKey::from_hex(&a.to_hex()).unwrap();
        assert_eq!(k2.public, a.public);
    }
}
