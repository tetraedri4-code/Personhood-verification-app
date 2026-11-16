//! JSON messages of the operator API. Points and scalars are hex of compressed arkworks encodings.
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub index: u32,
    pub url: String,
}

/// `GET /v1/public`: nothing secret. Verification keys g2^{share} let anyone check an operator's answers.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PublicInfo {
    pub index: u32,
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

/// `POST /v1/admin/round/start`: what a round is about. Every participant gets the same spec.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RoundSpec {
    pub round_id: String,
    pub kind: RoundKind,
    /// reshare: the group key
    pub key: Option<String>,
    /// reshare: the epoch the dealers' shares belong to, its threshold and verification keys
    pub from_epoch: Option<u64>,
    pub old_threshold: Option<usize>,
    #[serde(default)]
    pub old_vks: BTreeMap<u32, String>,
    pub dealers: Vec<u32>,
    pub receivers: Vec<Peer>,
    /// threshold of the new shares
    pub threshold: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundId {
    pub round_id: String,
}

/// `POST /v1/peer/deal`: dealer → receiver
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Deal {
    pub round_id: String,
    pub from: u32,
    /// Feldman commitments to the dealer's polynomial, g2^{c_0}, ..., g2^{c_{t-1}}
    pub commitments: Vec<String>,
    /// the polynomial at the receiver's index
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RoundStatus {
    pub received: Vec<u32>,
    pub missing: Vec<u32>,
    /// dealer ↦ hash of the commitments this operator saw from it. All receivers must agree.
    pub transcript: BTreeMap<u32, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitRequest {
    pub round_id: String,
    pub transcript: BTreeMap<u32, String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommitResponse {
    /// None for a dealer that receives no new share
    pub key: Option<String>,
    pub epoch: Option<u64>,
}

/// `POST /v1/admin/finalize`: erase every share of `key` older than `epoch`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct FinalizeRequest {
    pub key: String,
    pub epoch: u64,
    /// Must be true for an operator that holds no share of `epoch` (it left the set) and so erases its
    /// last share of the key. Guards against a wrong epoch number erasing the key everywhere.
    #[serde(default)]
    pub leaving: bool,
}

/// `POST /v1/admin/discard`: drop the newest epoch of `key`, to undo a round whose commit did not
/// reach every receiver. Only before `finalize`: once the older shares are erased, discarding the
/// newest ones loses the key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DiscardRequest {
    pub key: String,
    pub epoch: u64,
}
