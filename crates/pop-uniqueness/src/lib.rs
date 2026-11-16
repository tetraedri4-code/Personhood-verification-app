//! # pop-uniqueness
//!
//! The threshold uniqueness service of the design (§4.2): the deduplication key K is never in one
//! place. n operators each hold a Shamir share; any t of them evaluate d for the issuer, fewer learn
//! nothing. The issuer blinds the identity, so the operators never see whom they are asked about.
//!
//! * [`shamir`]: sharing, Lagrange coefficients, Feldman commitments.
//! * [`operator`]: one operator's server. It holds a share per key and epoch, answers blinded
//!   evaluations, and takes part in rounds that create a key, refresh the shares or hand the key to a
//!   changed operator set.
//! * [`client`]: [`ThresholdUniqueness`], the issuer's side. It implements
//!   [`pop_protocol::uniqueness::UniquenessService`], so the issuer does not know which kind of
//!   service it talks to.
//! * [`admin`]: the coordinator's side of a round, used by `pop uniqueness ...`.
//!
//! ## The function
//!
//! d = SHA-256("pop-dedup-v2", Y, x, H1(x)^K) with x = country|identifier and Y = g2^K the public
//! group key (2HashDH; Jarecki, Kiayias, Krawczyk, Xu 2017). The issuer sends a = H1(x)^r for a random
//! r, operator i returns a^{k_i}, the issuer combines t answers with Lagrange coefficients, removes r
//! and checks the result against Y with a pairing: e(u, g2) = e(H1(x), Y). A wrong or missing share
//! therefore gives an error, never a wrong d.
//!
//! ## Why refresh and resharing do not change d
//!
//! Both give every operator a new share of the same K (see [`shamir`]); Y does not change and neither
//! does H1(x)^K. Only a new key (a new Y, a new version) changes d, and the issuer migrates records
//! across versions (`pop-issuer`).
pub mod admin;
pub mod client;
pub mod operator;
pub mod shamir;
pub mod wire;

pub use client::{OperatorEndpoint, ThresholdConfig, ThresholdUniqueness};
pub use operator::{router, Operator, OperatorConfig};

use sha2::{Digest, Sha256};

/// Version string of a group key, as stored in enrolment records.
pub fn key_version(group_key_hex: &str) -> String {
    let mut h = Sha256::new();
    h.update(b"pop-uniqueness-group-key-v1");
    h.update(group_key_hex.to_lowercase().as_bytes());
    format!("threshold:{}", hex::encode(&h.finalize()[..8]))
}

/// Plain HTTP is accepted only for loopback addresses (local demo and tests).
pub(crate) fn url_is_safe(u: &str) -> bool {
    match url::Url::parse(u) {
        Ok(p) if p.scheme() == "https" => true,
        Ok(p) if p.scheme() == "http" => matches!(p.host_str(), Some("127.0.0.1") | Some("localhost") | Some("[::1]")),
        _ => false,
    }
}
