//! One operator of the threshold uniqueness service.
//!
//! An operator holds, per group key Y, one share per epoch (normally one epoch; two between the commit
//! of a round and its finalization). It serves three kinds of callers, each with its own bearer token:
//!
//! * the issuer (`eval_token`): `POST /v1/evaluate`, a^{share} for a blinded point a;
//! * the operator's own administrator (`admin_token`): start, deal, check, commit or abort a round, and
//!   finalize it (erase the older shares);
//! * the other operators (`peer_token`): `POST /v1/peer/deal`, a sub-share in a round.
//!
//! `GET /v1/public` is open: verification keys are public by design.
//!
//! ## Rounds
//!
//! A round is all-or-nothing and has no complaint phase: if any check fails anywhere, the
//! administrators abort and nothing changes. Every dealer picks a polynomial h_i of degree t'-1, sends
//! h_i(j) to receiver j with Feldman commitments to the coefficients, and every receiver checks its
//! value against the commitments.
//!
//! * key generation: h_i(0) is random; the new share of j is Σ_i h_i(j) and Y = Π_i C_i0.
//! * reshare (and refresh, which is a reshare to the same set): h_i(0) is dealer i's current share, the
//!   commitment C_i0 must equal i's published verification key, and the new share of j is
//!   Σ_i λ_i h_i(j) with λ_i the Lagrange coefficient of i among the dealers. Y cannot change: the
//!   receivers check it.
//!
//! Before committing, the administrators compare what every receiver saw (the transcript). A dealer
//! that sent different commitments to different receivers, or anyone who dealt in a dealer's name, is
//! caught there.
use crate::shamir::{commit, commitment_at, distinct_nonzero, eval_poly, lagrange_at_zero};
use crate::wire::*;
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::Zero;
use ark_std::UniformRand;
use axum::{
    extract::State,
    http::{header, HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use pop_crypto::codec::{from_hex, to_hex};
use pop_crypto::params::{Fr, G1A, G2, G2A};
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

#[derive(Clone, Debug)]
pub struct OperatorConfig {
    /// this operator's index (its x coordinate in the sharing); fixed for its lifetime, at least 1
    pub index: u32,
    /// bearer token of the issuer
    pub eval_token: String,
    /// bearer token of this operator's administrator
    pub admin_token: String,
    /// bearer token the operators use among themselves
    pub peer_token: String,
    /// where the shares are kept; None = memory only (tests, demo)
    pub state_file: Option<PathBuf>,
    /// Upper bound on evaluations per minute. Identity codes are guessable, so whoever can evaluate
    /// without limit can test guesses against the enrolment table. Set it to a small multiple of the
    /// expected enrolment rate.
    pub max_evals_per_minute: u32,
    /// refuse rounds whose new threshold is lower than this
    pub min_threshold: usize,
}

impl OperatorConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.index >= 1, "operator index must be at least 1");
        for (name, t) in [("eval", &self.eval_token), ("admin", &self.admin_token), ("peer", &self.peer_token)] {
            anyhow::ensure!(t.len() >= 24, "{name} token must be at least 24 characters");
        }
        anyhow::ensure!(self.eval_token != self.admin_token && self.eval_token != self.peer_token && self.admin_token != self.peer_token, "the three tokens must differ");
        anyhow::ensure!(self.min_threshold >= 1, "min_threshold must be at least 1");
        Ok(())
    }
}

#[derive(Clone, Serialize, Deserialize)]
struct Epoch {
    epoch: u64,
    threshold: usize,
    share: String,
    vks: BTreeMap<u32, String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Persisted {
    /// group key (hex) ↦ epochs, oldest first
    keys: BTreeMap<String, Vec<Epoch>>,
}

struct ReceivedDeal {
    commitments: Vec<G2A>,
    value: Fr,
    hash: String,
}

struct Round {
    spec: RoundSpec,
    created: u64,
    /// my polynomial, if I am a dealer
    poly: Option<Vec<Fr>>,
    deals: BTreeMap<u32, ReceivedDeal>,
}

#[derive(Default)]
struct Inner {
    st: Persisted,
    rounds: HashMap<String, Round>,
    evals: BTreeMap<String, u64>,
    /// (minute, evaluations in it)
    window: (u64, u32),
}

pub struct Operator {
    cfg: OperatorConfig,
    inner: Mutex<Inner>,
    http: reqwest::Client,
}

const ROUND_TTL_SECS: u64 = 15 * 60;
const MAX_OPEN_ROUNDS: usize = 4;
const MAX_OPERATORS: usize = 64;

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

fn commitments_hash(c: &[G2A]) -> String {
    let mut h = Sha256::new();
    for p in c {
        h.update(pop_crypto::codec::ser(p));
    }
    hex::encode(h.finalize())
}

pub struct ApiErr(StatusCode, String);

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}

fn err(code: StatusCode, msg: impl Into<String>) -> ApiErr {
    ApiErr(code, msg.into())
}

fn bad(msg: impl Into<String>) -> ApiErr {
    err(StatusCode::BAD_REQUEST, msg)
}

fn point_g2(s: &str) -> Result<G2A, ApiErr> {
    let p: G2A = from_hex(s).map_err(|e| bad(format!("bad G2 point: {e}")))?;
    if p.is_zero() {
        return Err(bad("point at infinity"));
    }
    Ok(p)
}

impl Operator {
    pub fn new(cfg: OperatorConfig) -> anyhow::Result<Arc<Self>> {
        cfg.validate()?;
        let mut inner = Inner::default();
        if let Some(p) = &cfg.state_file {
            match std::fs::read(p) {
                Ok(b) => inner.st = serde_json::from_slice(&b).map_err(|e| anyhow::anyhow!("share file {} is damaged: {e}", p.display()))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => anyhow::bail!("cannot read share file {}: {e}", p.display()),
            }
        }
        let http = reqwest::Client::builder().timeout(std::time::Duration::from_secs(20)).redirect(reqwest::redirect::Policy::none()).build()?;
        Ok(Arc::new(Operator { cfg, inner: Mutex::new(inner), http }))
    }

    pub fn index(&self) -> u32 {
        self.cfg.index
    }

    /// Write the shares: temp file, owner-only permissions, then rename.
    fn persist(&self, st: &Persisted) -> Result<(), ApiErr> {
        let Some(p) = &self.cfg.state_file else { return Ok(()) };
        let io = |e: std::io::Error| err(StatusCode::INTERNAL_SERVER_ERROR, format!("cannot write share file: {e}"));
        if let Some(d) = p.parent() {
            std::fs::create_dir_all(d).map_err(io)?;
        }
        let tmp = p.with_extension("tmp");
        {
            let mut o = std::fs::OpenOptions::new();
            o.write(true).create(true).truncate(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                o.mode(0o600);
            }
            let mut f = o.open(&tmp).map_err(io)?;
            std::io::Write::write_all(&mut f, &serde_json::to_vec_pretty(st).unwrap()).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        std::fs::rename(&tmp, p).map_err(io)
    }

    fn auth(&self, headers: &HeaderMap, token: &str) -> Result<(), ApiErr> {
        let given = headers.get(header::AUTHORIZATION).and_then(|v| v.to_str().ok()).and_then(|v| v.strip_prefix("Bearer ")).unwrap_or_default();
        if ct_eq(given.as_bytes(), token.as_bytes()) {
            Ok(())
        } else {
            Err(err(StatusCode::UNAUTHORIZED, "missing or wrong bearer token"))
        }
    }

    pub fn public(&self) -> PublicInfo {
        let g = self.inner.lock().unwrap();
        PublicInfo {
            index: self.cfg.index,
            keys: g
                .st
                .keys
                .iter()
                .map(|(k, eps)| PublicKeyInfo {
                    key: k.clone(),
                    evaluations: g.evals.get(k).copied().unwrap_or(0),
                    epochs: eps.iter().map(|e| PublicEpoch { epoch: e.epoch, threshold: e.threshold, vks: e.vks.clone() }).collect(),
                })
                .collect(),
        }
    }

    fn evaluate(&self, req: &EvalRequest) -> Result<EvalResponse, ApiErr> {
        let a: G1A = from_hex(&req.point).map_err(|e| bad(format!("bad point: {e}")))?;
        if a.is_zero() {
            return Err(bad("point at infinity"));
        }
        let key = req.key.to_lowercase();
        let mut g = self.inner.lock().unwrap();
        let minute = now_secs() / 60;
        if g.window.0 != minute {
            g.window = (minute, 0);
        }
        if g.window.1 >= self.cfg.max_evals_per_minute {
            return Err(err(StatusCode::TOO_MANY_REQUESTS, "evaluation rate limit reached"));
        }
        g.window.1 += 1;
        let eps = g.st.keys.get(&key).ok_or_else(|| err(StatusCode::NOT_FOUND, "this operator holds no share of that key"))?;
        let mut partials = vec![];
        for e in eps {
            let share: Fr = from_hex(&e.share).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
            partials.push(Partial { epoch: e.epoch, threshold: e.threshold, value: to_hex(&(a * share).into_affine()) });
        }
        *g.evals.entry(key).or_default() += 1;
        Ok(EvalResponse { index: self.cfg.index, partials })
    }

    fn start_round(&self, spec: RoundSpec) -> Result<(), ApiErr> {
        let me = self.cfg.index;
        if !(16..=64).contains(&spec.round_id.len()) || !spec.round_id.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err(bad("round id must be 16 to 64 hex characters"));
        }
        let recv: Vec<u32> = spec.receivers.iter().map(|p| p.index).collect();
        if recv.is_empty() || recv.len() > MAX_OPERATORS || spec.dealers.is_empty() || spec.dealers.len() > MAX_OPERATORS {
            return Err(bad("a round needs between 1 and 64 dealers and receivers"));
        }
        if !distinct_nonzero(&recv) || !distinct_nonzero(&spec.dealers) {
            return Err(bad("operator indices must be distinct and at least 1"));
        }
        if spec.threshold < 1 || spec.threshold > recv.len() {
            return Err(bad("threshold must be between 1 and the number of receivers"));
        }
        if spec.threshold < self.cfg.min_threshold {
            return Err(err(StatusCode::FORBIDDEN, format!("this operator refuses thresholds below {}", self.cfg.min_threshold)));
        }
        let am_dealer = spec.dealers.contains(&me);
        let am_receiver = recv.contains(&me);
        if !am_dealer && !am_receiver {
            return Err(bad("this operator is not part of the round"));
        }
        if let Some(p) = spec.receivers.iter().find(|p| !crate::url_is_safe(&p.url)) {
            return Err(bad(format!("receiver {} must be reached over https", p.index)));
        }
        let mut g = self.inner.lock().unwrap();
        let now = now_secs();
        g.rounds.retain(|_, r| now.saturating_sub(r.created) <= ROUND_TTL_SECS);
        if g.rounds.contains_key(&spec.round_id) {
            return Err(err(StatusCode::CONFLICT, "round already started"));
        }
        if g.rounds.len() >= MAX_OPEN_ROUNDS {
            return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many open rounds; abort one first"));
        }
        let mut rng = rand::thread_rng();
        let constant = match spec.kind {
            RoundKind::Dkg => {
                let mut d = spec.dealers.clone();
                let mut r = recv.clone();
                d.sort_unstable();
                r.sort_unstable();
                if d != r || spec.key.is_some() {
                    return Err(bad("in key generation every receiver deals, and there is no key yet"));
                }
                Fr::rand(&mut rng)
            }
            RoundKind::Reshare => {
                let (Some(key), Some(from), Some(old_t)) = (spec.key.as_ref(), spec.from_epoch, spec.old_threshold) else {
                    return Err(bad("reshare needs key, from_epoch and old_threshold"));
                };
                if *key != key.to_lowercase() {
                    return Err(bad("key must be lower-case hex"));
                }
                let y = point_g2(key)?;
                if spec.dealers.len() < old_t {
                    return Err(bad(format!("{} dealers cannot reshare a key with threshold {old_t}", spec.dealers.len())));
                }
                // the dealers' verification keys must interpolate to Y; this is what lets a new
                // operator, which has no earlier state, trust the spec
                let mut acc = G2::zero();
                for i in &spec.dealers {
                    let vk = point_g2(spec.old_vks.get(i).ok_or_else(|| bad(format!("no verification key for dealer {i}")))?)?;
                    acc += vk * lagrange_at_zero(&spec.dealers, *i);
                }
                if acc.into_affine() != y {
                    return Err(bad("the dealers' verification keys do not combine to the group key"));
                }
                match g.st.keys.get(key) {
                    Some(eps) => {
                        if eps.iter().any(|e| e.epoch > from) {
                            return Err(err(StatusCode::CONFLICT, "this operator already holds a newer epoch of the key"));
                        }
                        let e = eps.iter().find(|e| e.epoch == from).ok_or_else(|| bad("this operator has no share of that epoch"))?;
                        if e.threshold != old_t || spec.dealers.iter().any(|i| e.vks.get(i) != spec.old_vks.get(i)) {
                            return Err(bad("the spec disagrees with this operator's record of the epoch"));
                        }
                        if am_dealer {
                            from_hex::<Fr>(&e.share).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                        } else {
                            Fr::zero()
                        }
                    }
                    None if am_dealer => return Err(bad("this operator holds no share of that key")),
                    None => Fr::zero(),
                }
            }
        };
        let mut round = Round { spec: spec.clone(), created: now, poly: None, deals: BTreeMap::new() };
        if am_dealer {
            let poly: Vec<Fr> = std::iter::once(constant).chain((1..spec.threshold).map(|_| Fr::rand(&mut rng))).collect();
            if am_receiver {
                // my own deal is in place before anyone can deal in my name
                let commitments = commit(&poly);
                round.deals.insert(me, ReceivedDeal { hash: commitments_hash(&commitments), value: eval_poly(&poly, me), commitments });
            }
            round.poly = Some(poly);
        }
        g.rounds.insert(spec.round_id.clone(), round);
        Ok(())
    }

    /// As a dealer: send every other receiver its sub-share.
    async fn deal(&self, round_id: &str) -> Result<(), ApiErr> {
        let me = self.cfg.index;
        let msgs: Vec<(Peer, Deal)> = {
            let g = self.inner.lock().unwrap();
            let r = g.rounds.get(round_id).ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown round"))?;
            let poly = r.poly.as_ref().ok_or_else(|| bad("this operator is not a dealer in the round"))?;
            let commitments: Vec<String> = commit(poly).iter().map(to_hex).collect();
            r.spec
                .receivers
                .iter()
                .filter(|p| p.index != me)
                .map(|p| (p.clone(), Deal { round_id: round_id.to_string(), from: me, commitments: commitments.clone(), value: to_hex(&eval_poly(poly, p.index)) }))
                .collect()
        };
        for (peer, deal) in msgs {
            let url = format!("{}/v1/peer/deal", peer.url.trim_end_matches('/'));
            let resp = self.http.post(&url).bearer_auth(&self.cfg.peer_token).json(&deal).send().await.map_err(|e| err(StatusCode::BAD_GATEWAY, format!("operator {} unreachable: {e}", peer.index)))?;
            if !resp.status().is_success() {
                let code = resp.status();
                let body = resp.text().await.unwrap_or_default();
                return Err(err(StatusCode::BAD_GATEWAY, format!("operator {} refused the deal ({code}): {}", peer.index, body.chars().take(200).collect::<String>())));
            }
        }
        Ok(())
    }

    fn receive_deal(&self, d: Deal) -> Result<(), ApiErr> {
        let me = self.cfg.index;
        let mut g = self.inner.lock().unwrap();
        let r = g.rounds.get_mut(&d.round_id).ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown round"))?;
        if !r.spec.receivers.iter().any(|p| p.index == me) {
            return Err(bad("this operator receives nothing in the round"));
        }
        if d.from == me || !r.spec.dealers.contains(&d.from) {
            return Err(bad("not a dealer of the round"));
        }
        if d.commitments.len() != r.spec.threshold {
            return Err(bad("wrong number of commitments"));
        }
        let commitments: Vec<G2A> = d.commitments.iter().map(|c| from_hex::<G2A>(c).map_err(|e| bad(e.to_string()))).collect::<Result<_, _>>()?;
        let value: Fr = from_hex(&d.value).map_err(|e| bad(e.to_string()))?;
        if G2::generator() * value != commitment_at(&commitments, me) {
            return Err(bad("the value does not match the commitments"));
        }
        if r.spec.kind == RoundKind::Reshare && r.spec.old_vks.get(&d.from).map(String::as_str) != Some(to_hex(&commitments[0]).as_str()) {
            return Err(bad("the dealer did not share its current share"));
        }
        let hash = commitments_hash(&commitments);
        match r.deals.get(&d.from) {
            Some(prev) if prev.hash == hash && prev.value == value => Ok(()),
            Some(_) => Err(err(StatusCode::CONFLICT, "a different deal from this dealer was already received")),
            None => {
                r.deals.insert(d.from, ReceivedDeal { commitments, value, hash });
                Ok(())
            }
        }
    }

    fn status(&self, round_id: &str) -> Result<RoundStatus, ApiErr> {
        let g = self.inner.lock().unwrap();
        let r = g.rounds.get(round_id).ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown round"))?;
        Ok(RoundStatus {
            received: r.deals.keys().copied().collect(),
            missing: r.spec.dealers.iter().copied().filter(|i| !r.deals.contains_key(i)).collect(),
            transcript: r.deals.iter().map(|(i, d)| (*i, d.hash.clone())).collect(),
        })
    }

    fn commit(&self, req: &CommitRequest) -> Result<CommitResponse, ApiErr> {
        let me = self.cfg.index;
        let mut g = self.inner.lock().unwrap();
        let r = g.rounds.get(&req.round_id).ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown round"))?;
        let spec = r.spec.clone();
        if !spec.receivers.iter().any(|p| p.index == me) {
            // a dealer that leaves keeps its old share until the round is finalized
            g.rounds.remove(&req.round_id);
            return Ok(CommitResponse { key: None, epoch: None });
        }
        if let Some(i) = spec.dealers.iter().find(|i| !r.deals.contains_key(i)) {
            return Err(err(StatusCode::CONFLICT, format!("no deal from operator {i} yet")));
        }
        let mine: BTreeMap<u32, String> = r.deals.iter().map(|(i, d)| (*i, d.hash.clone())).collect();
        if mine != req.transcript {
            return Err(err(StatusCode::CONFLICT, "this operator saw other commitments than the transcript says; abort the round"));
        }
        let weight = |i: u32| match spec.kind {
            RoundKind::Dkg => Fr::from(1u64),
            RoundKind::Reshare => lagrange_at_zero(&spec.dealers, i),
        };
        let share: Fr = r.deals.iter().map(|(i, d)| weight(*i) * d.value).sum();
        // the polynomial of the new sharing, in the exponent: F_k = Π_i C_ik^{w_i}
        let mut poly = vec![G2::zero(); spec.threshold];
        for (i, d) in &r.deals {
            let w = weight(*i);
            for (k, c) in d.commitments.iter().enumerate() {
                poly[k] += *c * w;
            }
        }
        let poly: Vec<G2A> = poly.into_iter().map(|p| p.into_affine()).collect();
        let key = to_hex(&poly[0]);
        if poly[0].is_zero() {
            return Err(err(StatusCode::CONFLICT, "the round produced an empty key; abort it"));
        }
        let epoch = match spec.kind {
            RoundKind::Dkg => {
                if g.st.keys.contains_key(&key) {
                    return Err(err(StatusCode::CONFLICT, "key already exists"));
                }
                1
            }
            RoundKind::Reshare => {
                if spec.key.as_deref() != Some(key.as_str()) {
                    return Err(err(StatusCode::CONFLICT, "the round would change the group key; abort it"));
                }
                spec.from_epoch.unwrap_or(0) + 1
            }
        };
        if g.st.keys.get(&key).is_some_and(|eps| eps.iter().any(|e| e.epoch >= epoch)) {
            return Err(err(StatusCode::CONFLICT, "this operator already holds that epoch"));
        }
        let vks: BTreeMap<u32, String> = spec.receivers.iter().map(|p| (p.index, to_hex(&commitment_at(&poly, p.index).into_affine()))).collect();
        if to_hex(&(G2::generator() * share).into_affine()) != vks[&me] {
            return Err(err(StatusCode::INTERNAL_SERVER_ERROR, "the new share does not match its verification key"));
        }
        g.st.keys.entry(key.clone()).or_default().push(Epoch { epoch, threshold: spec.threshold, share: to_hex(&share), vks });
        if let Err(e) = self.persist(&g.st) {
            // not on disk means not committed
            let eps = g.st.keys.get_mut(&key).unwrap();
            eps.pop();
            if eps.is_empty() {
                g.st.keys.remove(&key);
            }
            return Err(e);
        }
        g.rounds.remove(&req.round_id);
        tracing::info!("operator {me}: holds epoch {epoch} of key {}", crate::key_version(&key));
        Ok(CommitResponse { key: Some(key), epoch: Some(epoch) })
    }

    /// Erase every share of `key` older than `epoch`. This is what makes a refresh worth anything: a
    /// share stolen before the refresh is useless once the others have erased theirs.
    fn finalize(&self, req: &FinalizeRequest) -> Result<usize, ApiErr> {
        let key = req.key.to_lowercase();
        let mut g = self.inner.lock().unwrap();
        let eps = g.st.keys.get(&key).ok_or_else(|| err(StatusCode::NOT_FOUND, "this operator holds no share of that key"))?.clone();
        let kept: Vec<Epoch> = eps.iter().filter(|e| e.epoch >= req.epoch).cloned().collect();
        let erased = eps.len() - kept.len();
        if erased == 0 {
            return Ok(0);
        }
        if kept.is_empty() && !req.leaving {
            return Err(err(StatusCode::CONFLICT, format!("this operator holds no share of epoch {}; erasing its last share needs \"leaving\": true", req.epoch)));
        }
        if kept.is_empty() {
            g.st.keys.remove(&key);
        } else {
            g.st.keys.insert(key.clone(), kept);
        }
        if let Err(e) = self.persist(&g.st) {
            g.st.keys.insert(key, eps);
            return Err(e);
        }
        Ok(erased)
    }
}

impl Operator {
    /// Undo a commit: drop `epoch` if it is the newest one this operator holds.
    fn discard(&self, req: &DiscardRequest) -> Result<bool, ApiErr> {
        let key = req.key.to_lowercase();
        let mut g = self.inner.lock().unwrap();
        let Some(eps) = g.st.keys.get(&key).cloned() else { return Ok(false) };
        match eps.last() {
            Some(e) if e.epoch == req.epoch => {}
            Some(e) if e.epoch > req.epoch => return Err(err(StatusCode::CONFLICT, "a newer epoch exists; only the newest can be discarded")),
            _ => return Ok(false),
        }
        if eps.len() == 1 {
            g.st.keys.remove(&key);
        } else {
            g.st.keys.get_mut(&key).unwrap().pop();
        }
        if let Err(e) = self.persist(&g.st) {
            g.st.keys.insert(key, eps);
            return Err(e);
        }
        Ok(true)
    }
}

type St = Arc<Operator>;

#[derive(Clone, Copy)]
enum Door {
    Eval,
    Admin,
    Peer,
}

/// The token check runs before the body is read, so a caller without the right token learns nothing
/// about the request format and cannot make the operator parse anything.
async fn guard(State((s, door)): State<(St, Door)>, req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let token = match door {
        Door::Eval => &s.cfg.eval_token,
        Door::Admin => &s.cfg.admin_token,
        Door::Peer => &s.cfg.peer_token,
    };
    match s.auth(req.headers(), token) {
        Ok(()) => next.run(req).await,
        Err(e) => e.into_response(),
    }
}

pub fn router(op: Arc<Operator>) -> Router {
    let door = |d: Door| axum::middleware::from_fn_with_state((op.clone(), d), guard);
    let eval = Router::new().route("/v1/evaluate", post(h_evaluate)).layer(door(Door::Eval));
    let peer = Router::new().route("/v1/peer/deal", post(h_peer_deal)).layer(door(Door::Peer));
    let admin = Router::new()
        .route("/v1/admin/round/start", post(h_start))
        .route("/v1/admin/round/deal", post(h_deal))
        .route("/v1/admin/round/status", post(h_status))
        .route("/v1/admin/round/commit", post(h_commit))
        .route("/v1/admin/round/abort", post(h_abort))
        .route("/v1/admin/finalize", post(h_finalize))
        .route("/v1/admin/discard", post(h_discard))
        .layer(door(Door::Admin));
    Router::new()
        .route("/v1/public", get(h_public))
        .merge(eval)
        .merge(peer)
        .merge(admin)
        .layer(axum::extract::DefaultBodyLimit::max(64 * 1024))
        .with_state(op)
}

async fn h_public(State(s): State<St>) -> Json<PublicInfo> {
    Json(s.public())
}

async fn h_evaluate(State(s): State<St>, Json(req): Json<EvalRequest>) -> Result<Json<EvalResponse>, ApiErr> {
    Ok(Json(s.evaluate(&req)?))
}

async fn h_peer_deal(State(s): State<St>, Json(req): Json<Deal>) -> Result<Json<serde_json::Value>, ApiErr> {
    s.receive_deal(req)?;
    Ok(Json(json!({"ok": true})))
}

async fn h_start(State(s): State<St>, Json(req): Json<RoundSpec>) -> Result<Json<serde_json::Value>, ApiErr> {
    s.start_round(req)?;
    Ok(Json(json!({"ok": true})))
}

async fn h_deal(State(s): State<St>, Json(req): Json<RoundId>) -> Result<Json<serde_json::Value>, ApiErr> {
    s.deal(&req.round_id).await?;
    Ok(Json(json!({"ok": true})))
}

async fn h_status(State(s): State<St>, Json(req): Json<RoundId>) -> Result<Json<RoundStatus>, ApiErr> {
    Ok(Json(s.status(&req.round_id)?))
}

async fn h_commit(State(s): State<St>, Json(req): Json<CommitRequest>) -> Result<Json<CommitResponse>, ApiErr> {
    Ok(Json(s.commit(&req)?))
}

async fn h_abort(State(s): State<St>, Json(req): Json<RoundId>) -> Result<Json<serde_json::Value>, ApiErr> {
    let existed = s.inner.lock().unwrap().rounds.remove(&req.round_id).is_some();
    Ok(Json(json!({"aborted": existed})))
}

async fn h_finalize(State(s): State<St>, Json(req): Json<FinalizeRequest>) -> Result<Json<serde_json::Value>, ApiErr> {
    Ok(Json(json!({"erased": s.finalize(&req)?})))
}

async fn h_discard(State(s): State<St>, Json(req): Json<DiscardRequest>) -> Result<Json<serde_json::Value>, ApiErr> {
    Ok(Json(json!({"discarded": s.discard(&req)?})))
}
