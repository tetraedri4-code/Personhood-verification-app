//! JSON messages of the operator API. Points and scalars are hex of compressed arkworks encodings.
use crate::ident::{Opening, Pok, Sealed};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub index: u32,
    pub url: String,
    /// the operator's identity public key (hex, G2): it signs with it and sub-shares are encrypted to it
    pub identity: String,
}

/// `GET /v1/public`: nothing secret. Verification keys g2^{share} let anyone check an operator's answers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInfo {
    pub index: u32,
    /// identity public key; pin it out of band before approving a round that names this operator
    pub identity: String,
    pub keys: Vec<PublicKeyInfo>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicKeyInfo {
    /// group key Y = g2^K
    pub key: String,
    /// evaluations answered since this process started
    pub evaluations: u64,
    pub epochs: Vec<PublicEpoch>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PublicEpoch {
    pub epoch: u64,
    pub threshold: usize,
    /// operator index ↦ g2^{share}
    pub vks: BTreeMap<u32, String>,
}

/// `POST /v1/evaluate`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvalRequest {
    pub key: String,
    /// blinded point a = H1(x)^r in G1
    pub point: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EvalResponse {
    pub index: u32,
    /// one answer per share epoch this operator holds for the key (two while a round is being
    /// finalized). The client uses the newest epoch for which it has enough answers.
    pub partials: Vec<Partial>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Partial {
    pub epoch: u64,
    pub threshold: usize,
    /// a^{share}
    pub value: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RoundKind {
    /// create a new key: every receiver deals a random polynomial
    Dkg,
    /// give new shares of an existing key to `receivers`: every dealer deals a polynomial whose
    /// constant term is its current share. With receivers = the current set this is a refresh.
    Reshare,
}

/// What a round is about. Every participant's administrator approves the same spec at their own
/// operator; the round's id is the hash of the spec, and every message of the round is signed over
/// that id, so nobody takes part in a round other than the one they approved.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundSpec {
    /// random, so that two rounds with the same content differ
    pub nonce: String,
    pub kind: RoundKind,
    /// reshare: the group key
    pub key: Option<String>,
    /// reshare: the epoch the dealers' shares belong to, its threshold and verification keys
    pub from_epoch: Option<u64>,
    pub old_threshold: Option<usize>,
    #[serde(default)]
    pub old_vks: BTreeMap<u32, String>,
    /// number of the epoch the round creates; higher than any epoch a participant holds
    pub new_epoch: u64,
    pub dealers: Vec<u32>,
    pub receivers: Vec<u32>,
    /// every dealer and receiver, with address and identity key
    pub peers: Vec<Peer>,
    /// threshold of the new shares
    pub threshold: usize,
}

impl RoundSpec {
    pub fn id(&self) -> String {
        let mut h = Sha256::new();
        h.update(b"pop-uniqueness-round-v1");
        h.update(serde_json::to_vec(self).expect("spec serializes"));
        hex::encode(h.finalize())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundId {
    pub round_id: String,
}

/// A signed message between operators. `body` is the JSON text of a [`Body`]; the signature covers
/// the round id, the sender and exactly these bytes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope {
    pub round_id: String,
    pub from: u32,
    pub body: String,
    pub sig: String,
}

impl Envelope {
    pub fn signed_bytes(round_id: &str, from: u32, body: &str) -> Vec<u8> {
        format!("pop-uniqueness-msg-v1|{round_id}|{from}|{body}").into_bytes()
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Body {
    /// dealer → everyone, first: a hash that fixes the dealer's polynomial commitments before it
    /// has seen anyone else's
    Commit { hash: String },
    /// dealer → one receiver: the Feldman commitments, and the polynomial's value at the receiver's
    /// index, encrypted to the receiver. Key generation adds a proof that the dealer knows its secret.
    Deal { to: u32, commitments: Vec<String>, pok: Option<Pok>, sealed: Sealed },
    /// receiver → everyone: "all deals to me check out". `transcript` is a hash over every dealer's
    /// commit; `commits` are those signed commits, so that when two operators disagree, everyone
    /// can see whether a dealer signed two different ones or the sender made its hash up.
    Ready {
        transcript: String,
        #[serde(default)]
        commits: Vec<Envelope>,
    },
    /// receiver → everyone: "my new share is on disk"
    Committed { key: String, epoch: u64 },
    /// receiver → everyone: a deal that does not check out, opened so that anyone can verify
    /// (no opening when the deal's ciphertext is malformed: that is visible without one)
    Complaint { deal: Box<Envelope>, commit: Box<Envelope>, opening: Option<Opening> },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Failure {
    pub reason: String,
    /// the operator proven to have misbehaved, if the evidence names one
    pub blamed: Option<u32>,
}

/// `POST /v1/admin/round/advance`: where this operator stands in the round.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundStatus {
    pub round_id: String,
    pub phase: String,
    pub waiting_for: Vec<String>,
    pub done: bool,
    pub failed: Option<Failure>,
    /// group key and epoch, once this operator has stored its new share (None for a leaving dealer)
    pub result: Option<(String, u64)>,
}
