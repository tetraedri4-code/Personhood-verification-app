//! One operator of the threshold uniqueness service.
//!
//! An operator holds its identity key and, per group key Y, one share per epoch (normally one epoch;
//! two while a round is between commit and the last operator's confirmation). It serves:
//!
//! * the issuer (`eval_token`): `POST /v1/evaluate`, a^{share} for a blinded point a;
//! * its own administrator (`admin_token`): approve a round, advance it, abort it;
//! * the other operators: `POST /v1/peer/msg`, signed messages of a round. There is no shared
//!   secret between operators: a message counts only if it is signed with the identity key the
//!   approved round spec names for its sender.
//!
//! `GET /v1/public` is open: identity key and verification keys are public by design.
//!
//! ## Rounds
//!
//! Each operator's administrator approves the same round spec at their own operator and then keeps
//! calling `advance`. Nobody holds anyone else's credentials; operators talk to each other directly.
//!
//! 1. **Commit.** Every dealer picks a polynomial h_i of degree t'-1 and sends everyone a hash of its
//!    Feldman commitments. Nobody reveals anything until it holds every dealer's hash, so no dealer
//!    can choose its contribution after seeing the others'.
//! 2. **Deal.** Every dealer sends each receiver j the commitments and h_i(j), encrypted to j.
//!    The receiver checks the hash, the value against the commitments, and
//!    * key generation: a proof that the dealer knows h_i(0);
//!    * reshare: that the commitment to h_i(0) is the dealer's published verification key.
//! 3. **Complaint.** A receiver that gets a bad deal publishes it, opened with a proof, so that
//!    every operator can check for itself who is at fault: the dealer (its signed deal is bad) or the
//!    receiver (it complained about a good deal). The round fails and names the culprit; the
//!    administrators run it again without that operator.
//! 4. **Ready.** A receiver whose deals all check out says so, with a hash over every dealer's
//!    commitments. Operators that saw different commitments notice here and the round fails.
//! 5. **Store.** When every receiver is ready with the same hash, each computes its new share
//!    (Σ_i h_i(j) in key generation, Σ_i λ_i h_i(j) in a reshare), checks that the group key did not
//!    change, writes the share to disk and says so.
//! 6. **Erase.** When every receiver has confirmed that its new share is on disk, each operator
//!    erases its older shares of the key. An operator that left erases its last one.
//!
//! A round that stalls after step 5 leaves the new epoch at some operators. Nothing was erased, the
//! old epoch still works everywhere, and the next successful round erases the leftover.
use crate::ident::{self, IdentityKey};
use crate::round::{self, check_deal, check_spec, commit_hash, commitments_hash, pok_context, seal_context, Checked};
use crate::shamir::{commit, commitment_at, eval_poly, lagrange_at_zero};
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
    /// where the identity key and the shares are kept; None = memory only (tests, demo)
    pub state_file: Option<PathBuf>,
    /// Upper bound on evaluations per minute. Identity codes are guessable, so whoever can evaluate
    /// without limit can test guesses against the enrolment table. Set it to a small multiple of the
    /// expected enrolment rate.
    pub max_evals_per_minute: u32,
    /// refuse rounds whose new threshold is lower than this
    pub min_threshold: usize,
    /// Tests only: make this operator misbehave. Not reachable from any configuration file.
    #[doc(hidden)]
    pub test_fault: Option<Fault>,
}

/// Misbehaviour an operator can be told to show in tests.
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// as a dealer, send this receiver a wrong value
    BadShareTo(u32),
    /// as a receiver, complain about this dealer's (good) deal
    FalseComplaintAgainst(u32),
}

impl OperatorConfig {
    pub fn validate(&self) -> anyhow::Result<()> {
        anyhow::ensure!(self.index >= 1, "operator index must be at least 1");
        for (name, t) in [("eval", &self.eval_token), ("admin", &self.admin_token)] {
            anyhow::ensure!(t.len() >= 24, "{name} token must be at least 24 characters");
        }
        anyhow::ensure!(self.eval_token != self.admin_token, "the two tokens must differ");
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
    /// identity keys of the epoch's operators, pinned for later rounds
    #[serde(default)]
    ids: BTreeMap<u32, String>,
}

#[derive(Default, Serialize, Deserialize)]
struct Persisted {
    /// identity secret key (hex)
    #[serde(default)]
    identity: String,
    /// group key (hex) ↦ epochs, oldest first
    keys: BTreeMap<String, Vec<Epoch>>,
}

struct GoodDeal {
    commitments: Vec<G2A>,
    value: Fr,
    hash: String,
}

struct Out {
    to: u32,
    env: Envelope,
    delivered: bool,
}

struct Round {
    spec: RoundSpec,
    checked: Checked,
    created: u64,
    /// my polynomial, if I am a dealer
    poly: Option<Vec<Fr>>,
    /// dealer ↦ (committed hash, the signed commit)
    commits: BTreeMap<u32, (String, Envelope)>,
    /// dealer ↦ its deal to me, checked
    deals: BTreeMap<u32, GoodDeal>,
    readys: BTreeMap<u32, String>,
    committed: BTreeMap<u32, (String, u64)>,
    outbox: Vec<Out>,
    /// my deals, made when I committed and held back until every dealer has committed
    pending_deals: Vec<(u32, Body)>,
    sent_commit: bool,
    sent_deals: bool,
    sent_ready: bool,
    stored: Option<(String, u64)>,
    done: bool,
    failed: Option<Failure>,
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
    identity: IdentityKey,
    inner: Mutex<Inner>,
    http: reqwest::Client,
}

const ROUND_TTL_SECS: u64 = 30 * 60;
const MAX_OPEN_ROUNDS: usize = 4;

fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
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

fn write_private(p: &std::path::Path, content: &[u8]) -> std::io::Result<()> {
    if let Some(d) = p.parent() {
        std::fs::create_dir_all(d)?;
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
        let mut f = o.open(&tmp)?;
        std::io::Write::write_all(&mut f, content)?;
        f.sync_all()?;
    }
    std::fs::rename(&tmp, p)
}

impl Operator {
    pub fn new(cfg: OperatorConfig) -> anyhow::Result<Arc<Self>> {
        cfg.validate()?;
        let mut st = Persisted::default();
        if let Some(p) = &cfg.state_file {
            match std::fs::read(p) {
                Ok(b) => st = serde_json::from_slice(&b).map_err(|e| anyhow::anyhow!("share file {} is damaged: {e}", p.display()))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => anyhow::bail!("cannot read share file {}: {e}", p.display()),
            }
        }
        let identity = if st.identity.is_empty() {
            // shares without the identity key they were dealt to: something was tampered with
            anyhow::ensure!(st.keys.is_empty(), "the share file holds shares but no identity key");
            let k = IdentityKey::generate();
            st.identity = k.to_hex();
            if let Some(p) = &cfg.state_file {
                write_private(p, &serde_json::to_vec_pretty(&st)?).map_err(|e| anyhow::anyhow!("cannot write share file {}: {e}", p.display()))?;
            }
            k
        } else {
            IdentityKey::from_hex(&st.identity).map_err(|e| anyhow::anyhow!("identity key in the share file: {e}"))?
        };
        let http = reqwest::Client::builder().timeout(std::time::Duration::from_secs(20)).redirect(reqwest::redirect::Policy::none()).build()?;
        Ok(Arc::new(Operator { cfg, identity, inner: Mutex::new(Inner { st, ..Default::default() }), http }))
    }

    pub fn index(&self) -> u32 {
        self.cfg.index
    }

    pub fn identity(&self) -> String {
        self.identity.public_hex()
    }

    fn persist(&self, st: &Persisted) -> Result<(), ApiErr> {
        let Some(p) = &self.cfg.state_file else { return Ok(()) };
        write_private(p, &serde_json::to_vec_pretty(st).unwrap()).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, format!("cannot write share file: {e}")))
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
            identity: self.identity.public_hex(),
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

    // ------------------------------------------------------------------ rounds

    fn envelope(&self, round_id: &str, body: &Body) -> Envelope {
        let body = serde_json::to_string(body).expect("body serializes");
        let sig = self.identity.sign(&Envelope::signed_bytes(round_id, self.cfg.index, &body));
        Envelope { round_id: round_id.to_string(), from: self.cfg.index, body, sig }
    }

    /// The administrator approves a round. Returns its id.
    fn start_round(&self, spec: RoundSpec) -> Result<String, ApiErr> {
        let me = self.cfg.index;
        let checked = check_spec(&spec).map_err(bad)?;
        if spec.threshold < self.cfg.min_threshold {
            return Err(err(StatusCode::FORBIDDEN, format!("this operator refuses thresholds below {}", self.cfg.min_threshold)));
        }
        let am_dealer = spec.dealers.contains(&me);
        if !am_dealer && !spec.receivers.contains(&me) {
            return Err(bad("this operator is not part of the round"));
        }
        if checked.peers[&me].1 != self.identity.public {
            return Err(bad("the spec names another identity key for this operator"));
        }
        let mut g = self.inner.lock().unwrap();
        let now = now_secs();
        g.rounds.retain(|_, r| now.saturating_sub(r.created) <= ROUND_TTL_SECS);
        if g.rounds.contains_key(&checked.id) {
            return Ok(checked.id); // approving twice is harmless
        }
        if g.rounds.len() >= MAX_OPEN_ROUNDS {
            return Err(err(StatusCode::TOO_MANY_REQUESTS, "too many open rounds; abort one first"));
        }
        let mut rng = rand::thread_rng();
        let constant = match spec.kind {
            RoundKind::Dkg => Fr::rand(&mut rng),
            RoundKind::Reshare => {
                let key = spec.key.as_ref().expect("checked");
                let from = spec.from_epoch.expect("checked");
                match g.st.keys.get(key) {
                    Some(eps) => {
                        if eps.iter().any(|e| e.epoch >= spec.new_epoch) {
                            return Err(err(StatusCode::CONFLICT, format!("this operator already holds epoch {} or later of the key", spec.new_epoch)));
                        }
                        match eps.iter().find(|e| e.epoch == from) {
                            Some(e) => {
                                if Some(e.threshold) != spec.old_threshold || spec.dealers.iter().any(|i| e.vks.get(i) != spec.old_vks.get(i)) {
                                    return Err(bad("the spec disagrees with this operator's record of the epoch"));
                                }
                                // operators this one already knows must appear under the identity key it knows
                                for p in &spec.peers {
                                    if e.ids.get(&p.index).is_some_and(|known| *known != p.identity) {
                                        return Err(bad(format!("the spec names another identity key for operator {} than the one pinned in epoch {from}", p.index)));
                                    }
                                }
                                from_hex::<Fr>(&e.share).map_err(|e| err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
                            }
                            None if am_dealer => return Err(bad("this operator has no share of that epoch")),
                            None => Fr::zero(),
                        }
                    }
                    None if am_dealer => return Err(bad("this operator holds no share of that key")),
                    None => Fr::zero(),
                }
            }
        };
        let poly = am_dealer.then(|| std::iter::once(constant).chain((1..spec.threshold).map(|_| Fr::rand(&mut rng))).collect::<Vec<Fr>>());
        let id = checked.id.clone();
        g.rounds.insert(
            id.clone(),
            Round {
                spec,
                checked,
                created: now,
                poly,
                commits: BTreeMap::new(),
                deals: BTreeMap::new(),
                readys: BTreeMap::new(),
                committed: BTreeMap::new(),
                outbox: vec![],
                pending_deals: vec![],
                sent_commit: false,
                sent_deals: false,
                sent_ready: false,
                stored: None,
                done: false,
                failed: None,
            },
        );
        Ok(id)
    }

    fn my_deal(&self, r: &Round) -> (Vec<String>, Option<ident::Pok>) {
        let poly = r.poly.as_ref().expect("dealer");
        let commitments: Vec<String> = commit(poly).iter().map(to_hex).collect();
        // deterministic per round: derived from the polynomial, so the hash committed to stays valid
        let pok = (r.spec.kind == RoundKind::Dkg).then(|| ident::pok_prove(&poly[0], &pok_context(&r.checked.id, self.cfg.index)));
        (commitments, pok)
    }

    /// Do every step that is possible now. Called under the lock; sends nothing itself.
    fn progress(&self, g: &mut Inner, id: &str) -> Result<(), ApiErr> {
        let me = self.cfg.index;
        let Inner { st, rounds, .. } = g;
        let r = rounds.get_mut(id).ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown round"))?;
        if r.failed.is_some() || r.done {
            return Ok(());
        }
        let everyone: Vec<u32> = r.checked.peers.keys().copied().collect();
        let am_dealer = r.poly.is_some();
        let am_receiver = r.spec.receivers.contains(&me);
        let queue = |r: &mut Round, body: &Body, to: &[u32]| {
            let env = self.envelope(id, body);
            for t in to.iter().filter(|t| **t != me) {
                r.outbox.push(Out { to: *t, env: env.clone(), delivered: false });
            }
            env
        };

        // 1. commit to my polynomial
        if am_dealer && !r.sent_commit {
            let (commitments, pok) = self.my_deal(r);
            // the proof of knowledge is randomized; fix it now so the committed hash matches the deal
            let hash = commit_hash(&commitments, &pok);
            let env = queue(r, &Body::Commit { hash: hash.clone() }, &everyone);
            r.commits.insert(me, (hash, env));
            r.sent_commit = true;
            // keep the exact deal that was committed to
            let poly = r.poly.clone().expect("dealer");
            let mut deals = vec![];
            for to in r.spec.receivers.clone() {
                let mut value = eval_poly(&poly, to);
                if self.cfg.test_fault == Some(Fault::BadShareTo(to)) {
                    value += Fr::from(1u64);
                }
                if to == me {
                    let c: Vec<G2A> = commit(&poly);
                    r.deals.insert(me, GoodDeal { hash: commitments_hash(&c), commitments: c, value });
                } else {
                    let sealed = ident::seal(&r.checked.peers[&to].1, &seal_context(id, me, to), &value);
                    deals.push((to, Body::Deal { to, commitments: commitments.clone(), pok: pok.clone(), sealed }));
                }
            }
            r.pending_deals = deals;
        }
        // 2. deal, once every dealer is bound to its commitment
        if am_dealer && !r.sent_deals && r.spec.dealers.iter().all(|d| r.commits.contains_key(d)) {
            for (to, body) in std::mem::take(&mut r.pending_deals) {
                queue(r, &body, &[to]);
            }
            r.sent_deals = true;
        }
        // 4. ready
        if am_receiver && !r.sent_ready && r.spec.dealers.iter().all(|d| r.deals.contains_key(d)) {
            let mut h = Sha256::new();
            h.update(id.as_bytes());
            for (d, deal) in &r.deals {
                h.update(d.to_be_bytes());
                h.update(deal.hash.as_bytes());
            }
            let transcript = hex::encode(h.finalize());
            if let Some((other, _)) = r.readys.iter().find(|(_, t)| **t != transcript) {
                r.failed = Some(Failure { reason: format!("operator {other} saw other commitments than this operator: a dealer sent different deals"), blamed: None });
                return Ok(());
            }
            queue(r, &Body::Ready { transcript: transcript.clone() }, &everyone);
            r.readys.insert(me, transcript);
            r.sent_ready = true;
        }
        // 5. store the new share
        if am_receiver && r.sent_ready && r.stored.is_none() && r.spec.receivers.iter().all(|x| r.readys.contains_key(x)) {
            let spec = r.spec.clone();
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
            let fail = |r: &mut Round, reason: &str| {
                r.failed = Some(Failure { reason: reason.into(), blamed: None });
                Ok(())
            };
            if poly[0].is_zero() {
                return fail(r, "the round produced an empty key");
            }
            if spec.kind == RoundKind::Reshare && spec.key.as_deref() != Some(key.as_str()) {
                return fail(r, "the round would change the group key");
            }
            if st.keys.get(&key).is_some_and(|eps| eps.iter().any(|e| e.epoch >= spec.new_epoch)) {
                return fail(r, "this operator already holds that epoch or a later one");
            }
            let vks: BTreeMap<u32, String> = spec.receivers.iter().map(|j| (*j, to_hex(&commitment_at(&poly, *j).into_affine()))).collect();
            if to_hex(&(G2::generator() * share).into_affine()) != vks[&me] {
                return fail(r, "the new share does not match its verification key");
            }
            let ids = spec.peers.iter().filter(|p| spec.receivers.contains(&p.index)).map(|p| (p.index, p.identity.clone())).collect();
            st.keys.entry(key.clone()).or_default().push(Epoch { epoch: spec.new_epoch, threshold: spec.threshold, share: to_hex(&share), vks, ids });
            if let Err(e) = self.persist(st) {
                // not on disk means not stored
                let eps = st.keys.get_mut(&key).unwrap();
                eps.pop();
                if eps.is_empty() {
                    st.keys.remove(&key);
                }
                return Err(e);
            }
            let epoch = spec.new_epoch;
            queue(r, &Body::Committed { key: key.clone(), epoch }, &everyone);
            r.committed.insert(me, (key.clone(), epoch));
            r.stored = Some((key.clone(), epoch));
            tracing::info!("operator {me}: holds epoch {epoch} of key {}", crate::key_version(&key));
        }
        // 6. erase the older shares, once every receiver has its new share on disk
        if !r.done && r.spec.receivers.iter().all(|x| r.committed.contains_key(x)) {
            let first = r.committed.values().next().cloned().expect("receivers");
            if r.committed.values().any(|c| *c != first) {
                r.failed = Some(Failure { reason: "operators stored different keys or epochs".into(), blamed: None });
                return Ok(());
            }
            let (key, epoch) = first;
            if let Some(eps) = st.keys.get(&key).cloned() {
                let kept: Vec<Epoch> = eps.iter().filter(|e| e.epoch >= epoch).cloned().collect();
                if kept.len() != eps.len() {
                    if kept.is_empty() {
                        st.keys.remove(&key);
                    } else {
                        st.keys.insert(key.clone(), kept);
                    }
                    if let Err(e) = self.persist(st) {
                        st.keys.insert(key, eps);
                        return Err(e);
                    }
                    tracing::info!("operator {me}: erased its shares older than epoch {epoch}");
                }
            }
            r.done = true;
        }
        Ok(())
    }

    fn status_of(&self, r: &Round) -> RoundStatus {
        let missing = |have: &dyn Fn(&u32) -> bool, who: &[u32]| who.iter().copied().filter(|x| !have(x)).collect::<Vec<u32>>();
        let mut waiting = vec![];
        let phase = if r.failed.is_some() {
            "failed"
        } else if r.done {
            "done"
        } else if !r.spec.dealers.iter().all(|d| r.commits.contains_key(d)) {
            waiting.push(format!("commitments from {:?}", missing(&|d| r.commits.contains_key(d), &r.spec.dealers)));
            "commit"
        } else if r.spec.receivers.contains(&self.cfg.index) && !r.sent_ready {
            waiting.push(format!("deals from {:?}", missing(&|d| r.deals.contains_key(d), &r.spec.dealers)));
            "deal"
        } else if r.spec.receivers.iter().any(|x| !r.readys.contains_key(x)) {
            waiting.push(format!("ready from {:?}", missing(&|x| r.readys.contains_key(x), &r.spec.receivers)));
            "ready"
        } else {
            waiting.push(format!("confirmation from {:?}", missing(&|x| r.committed.contains_key(x), &r.spec.receivers)));
            "store"
        };
        let undelivered: Vec<u32> = {
            let mut v: Vec<u32> = r.outbox.iter().filter(|o| !o.delivered).map(|o| o.to).collect();
            v.sort_unstable();
            v.dedup();
            v
        };
        if !undelivered.is_empty() {
            waiting.push(format!("operators {undelivered:?} to accept messages (have they approved the round?)"));
        }
        RoundStatus { round_id: r.checked.id.clone(), phase: phase.into(), waiting_for: waiting, done: r.done, failed: r.failed.clone(), result: r.stored.clone() }
    }

    /// Take the round as far as it goes now: act, then deliver what is waiting to be sent.
    async fn advance(&self, id: &str) -> Result<RoundStatus, ApiErr> {
        let to_send: Vec<(usize, String, Envelope)> = {
            let mut g = self.inner.lock().unwrap();
            self.progress(&mut g, id)?;
            let r = g.rounds.get(id).ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown round"))?;
            r.outbox.iter().enumerate().filter(|(_, o)| !o.delivered).map(|(i, o)| (i, r.checked.peers[&o.to].0.clone(), o.env.clone())).collect()
        };
        let mut delivered = vec![];
        let mut blocked: Vec<String> = vec![];
        for (i, url, env) in to_send {
            // keep the order per receiver: after one failure, send that receiver nothing more this time
            if blocked.contains(&url) {
                continue;
            }
            match self.http.post(format!("{url}/v1/peer/msg")).json(&env).send().await {
                Ok(resp) if resp.status().is_success() => delivered.push(i),
                _ => blocked.push(url),
            }
        }
        let mut g = self.inner.lock().unwrap();
        if let Some(r) = g.rounds.get_mut(id) {
            for i in delivered {
                r.outbox[i].delivered = true;
            }
        }
        self.progress(&mut g, id)?;
        let r = g.rounds.get(id).ok_or_else(|| err(StatusCode::NOT_FOUND, "unknown round"))?;
        Ok(self.status_of(r))
    }

    /// A signed message from another operator.
    fn receive(&self, env: Envelope) -> Result<(), ApiErr> {
        let me = self.cfg.index;
        let mut g = self.inner.lock().unwrap();
        let r = g.rounds.get_mut(&env.round_id).ok_or_else(|| err(StatusCode::NOT_FOUND, "this operator has not approved that round"))?;
        if env.from == me {
            return Err(bad("a message in this operator's own name"));
        }
        let body = round::open_envelope(&env, &r.spec, &r.checked).map_err(|e| err(StatusCode::UNAUTHORIZED, e))?;
        if r.failed.is_some() || r.done {
            return Ok(());
        }
        let from = env.from;
        let is_dealer = r.spec.dealers.contains(&from);
        let is_receiver = r.spec.receivers.contains(&from);
        match body {
            Body::Commit { hash } => {
                if !is_dealer {
                    return Err(bad("not a dealer"));
                }
                match r.commits.get(&from) {
                    Some((h, _)) if *h == hash => {}
                    Some(_) => r.failed = Some(Failure { reason: format!("operator {from} committed to two different polynomials"), blamed: Some(from) }),
                    None => {
                        r.commits.insert(from, (hash, env));
                    }
                }
            }
            Body::Deal { to, commitments, pok, sealed } => {
                if !is_dealer || to != me || !r.spec.receivers.contains(&me) {
                    return Err(bad("not a deal for this operator"));
                }
                if r.deals.contains_key(&from) {
                    return Ok(());
                }
                let Some((hash, commit_env)) = r.commits.get(&from).cloned() else {
                    return Err(err(StatusCode::CONFLICT, "no commitment from this dealer yet"));
                };
                // reveal nothing before every dealer is bound
                if !r.spec.dealers.iter().all(|d| r.commits.contains_key(d)) {
                    return Err(err(StatusCode::CONFLICT, "not every dealer has committed yet"));
                }
                let ctx = seal_context(&r.checked.id, from, me);
                let value = self.identity.open(&ctx, &sealed);
                let verdict = check_deal(&r.spec, &r.checked.id, from, me, &commitments, &pok, value, &hash);
                let verdict = if self.cfg.test_fault == Some(Fault::FalseComplaintAgainst(from)) { Err("test fault".to_string()) } else { verdict };
                match verdict {
                    Ok((c, v)) => {
                        r.deals.insert(from, GoodDeal { hash: commitments_hash(&c), commitments: c, value: v });
                    }
                    Err(why) => {
                        // publish the evidence; every operator judges it for itself
                        let opening = self.identity.reveal(&ctx, &sealed).map_err(bad)?;
                        let body = Body::Complaint { deal: Box::new(env), commit: Box::new(commit_env), opening };
                        let complaint = self.envelope(&r.checked.id, &body);
                        for t in r.checked.peers.keys().copied().filter(|t| *t != me).collect::<Vec<_>>() {
                            r.outbox.push(Out { to: t, env: complaint.clone(), delivered: false });
                        }
                        r.failed = Some(Failure { reason: format!("operator {from} sent this operator a bad deal: {why}"), blamed: Some(from) });
                    }
                }
            }
            Body::Ready { transcript } => {
                if !is_receiver {
                    return Err(bad("not a receiver"));
                }
                let mine = r.readys.get(&me).cloned();
                match r.readys.get(&from) {
                    Some(t) if *t == transcript => {}
                    Some(_) => r.failed = Some(Failure { reason: format!("operator {from} sent two different ready messages"), blamed: Some(from) }),
                    None => {
                        if mine.is_some_and(|m| m != transcript) {
                            r.failed = Some(Failure { reason: format!("operator {from} saw other commitments than this operator: a dealer sent different deals"), blamed: None });
                        } else {
                            r.readys.insert(from, transcript);
                        }
                    }
                }
            }
            Body::Committed { key, epoch } => {
                if !is_receiver {
                    return Err(bad("not a receiver"));
                }
                if epoch != r.spec.new_epoch || r.spec.key.as_ref().is_some_and(|k| *k != key) {
                    r.failed = Some(Failure { reason: format!("operator {from} stored another key or epoch"), blamed: Some(from) });
                } else {
                    r.committed.entry(from).or_insert((key, epoch));
                }
            }
            Body::Complaint { deal, commit, opening } => {
                r.failed = Some(match round::verify_complaint(&r.spec, &r.checked, from, &deal, &commit, &opening) {
                    Ok(dealer) => Failure { reason: format!("operator {dealer} sent operator {from} a bad deal (proven by {from}'s complaint)"), blamed: Some(dealer) },
                    Err(why) => Failure { reason: format!("operator {from} made a complaint that does not hold: {why}"), blamed: Some(from) },
                });
            }
        }
        Ok(())
    }
}

type St = Arc<Operator>;

#[derive(Clone, Copy)]
enum Door {
    Eval,
    Admin,
}

/// The token check runs before the body is read, so a caller without the right token learns nothing
/// about the request format and cannot make the operator parse anything.
async fn guard(State((s, door)): State<(St, Door)>, req: axum::extract::Request, next: axum::middleware::Next) -> Response {
    let token = match door {
        Door::Eval => &s.cfg.eval_token,
        Door::Admin => &s.cfg.admin_token,
    };
    match s.auth(req.headers(), token) {
        Ok(()) => next.run(req).await,
        Err(e) => e.into_response(),
    }
}

pub fn router(op: Arc<Operator>) -> Router {
    let door = |d: Door| axum::middleware::from_fn_with_state((op.clone(), d), guard);
    let eval = Router::new().route("/v1/evaluate", post(h_evaluate)).layer(door(Door::Eval));
    let admin = Router::new()
        .route("/v1/admin/round/start", post(h_start))
        .route("/v1/admin/round/advance", post(h_advance))
        .route("/v1/admin/round/abort", post(h_abort))
        .layer(door(Door::Admin));
    Router::new()
        .route("/v1/public", get(h_public))
        .route("/v1/peer/msg", post(h_peer))
        .merge(eval)
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

async fn h_peer(State(s): State<St>, Json(env): Json<Envelope>) -> Result<Json<serde_json::Value>, ApiErr> {
    s.receive(env)?;
    Ok(Json(json!({"ok": true})))
}

async fn h_start(State(s): State<St>, Json(req): Json<RoundSpec>) -> Result<Json<RoundId>, ApiErr> {
    Ok(Json(RoundId { round_id: s.start_round(req)? }))
}

async fn h_advance(State(s): State<St>, Json(req): Json<RoundId>) -> Result<Json<RoundStatus>, ApiErr> {
    Ok(Json(s.advance(&req.round_id).await?))
}

async fn h_abort(State(s): State<St>, Json(req): Json<RoundId>) -> Result<Json<serde_json::Value>, ApiErr> {
    let existed = s.inner.lock().unwrap().rounds.remove(&req.round_id).is_some();
    Ok(Json(json!({"aborted": existed})))
}
