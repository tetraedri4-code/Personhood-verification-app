//! The administrators' side of key generation, refresh and resharing.
//!
//! A round needs no coordinator. Somebody writes the round spec ([`spec_dkg`], [`spec_reshare`]) and
//! passes it around; each operator's administrator checks it, approves it at their own operator and
//! keeps it moving ([`join`]). Nobody needs anybody else's admin token, and no administrator ever
//! sees a share.
//!
//! [`dkg`] and [`reshare`] do the same for a whole cluster at once, for the demo, tests and
//! deployments where one party really does run every operator.
use crate::shamir::lagrange_at_zero;
use crate::wire::*;
use anyhow::{bail, ensure, Context};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use pop_crypto::codec::from_hex;
use pop_crypto::params::{G2, G2A};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;
use std::time::Duration;

/// An operator as its own administrator addresses it.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminEndpoint {
    pub index: u32,
    pub url: String,
    pub admin_token: String,
}

/// An operator as others know it. `identity` should be pinned out of band; if it is left out, the
/// key the operator publishes is taken on trust.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub index: u32,
    pub url: String,
    #[serde(default)]
    pub identity: Option<String>,
}

impl From<&AdminEndpoint> for Member {
    fn from(a: &AdminEndpoint) -> Self {
        Member { index: a.index, url: a.url.clone(), identity: None }
    }
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().timeout(Duration::from_secs(60)).redirect(reqwest::redirect::Policy::none()).build().expect("http client")
}

async fn call<T: DeserializeOwned>(c: &reqwest::Client, o: &AdminEndpoint, path: &str, body: &impl Serialize) -> anyhow::Result<T> {
    ensure!(crate::url_is_safe(&o.url), "operator {} must be reached over https (plain http only on loopback)", o.index);
    let resp = c.post(format!("{}{path}", o.url.trim_end_matches('/'))).bearer_auth(&o.admin_token).json(body).send().await.with_context(|| format!("operator {} unreachable", o.index))?;
    let status = resp.status();
    let text = resp.text().await.unwrap_or_default();
    ensure!(status.is_success(), "operator {} {path}: {status} {}", o.index, text.chars().take(300).collect::<String>());
    serde_json::from_str(&text).with_context(|| format!("operator {} {path}: unreadable answer", o.index))
}

pub async fn public(url: &str) -> anyhow::Result<PublicInfo> {
    ensure!(crate::url_is_safe(url), "operators must be reached over https (plain http only on loopback)");
    Ok(http().get(format!("{}/v1/public", url.trim_end_matches('/'))).send().await?.error_for_status()?.json().await?)
}

fn nonce() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

/// Fill in address and identity key of each member, checking a pinned key against the published one.
async fn peers(members: &[Member]) -> anyhow::Result<(Vec<Peer>, Vec<PublicInfo>)> {
    let mut out = vec![];
    let mut infos = vec![];
    for m in members {
        let info = public(&m.url).await.with_context(|| format!("operator {}", m.index))?;
        ensure!(info.index == m.index, "the server at {} is operator {}, not {}", m.url, info.index, m.index);
        if let Some(pinned) = &m.identity {
            ensure!(*pinned == info.identity, "operator {} publishes another identity key than the pinned one", m.index);
        }
        out.push(Peer { index: m.index, url: m.url.clone(), identity: info.identity.clone() });
        infos.push(info);
    }
    Ok((out, infos))
}

/// The spec of a key generation among `members`.
pub async fn spec_dkg(members: &[Member], threshold: usize) -> anyhow::Result<RoundSpec> {
    let (peers, _) = peers(members).await?;
    let idx: Vec<u32> = members.iter().map(|m| m.index).collect();
    Ok(RoundSpec { nonce: nonce(), kind: RoundKind::Dkg, key: None, from_epoch: None, old_threshold: None, old_vks: BTreeMap::new(), new_epoch: 1, dealers: idx.clone(), receivers: idx, peers, threshold })
}

fn epochs_of(info: &PublicInfo, key: &str) -> Vec<PublicEpoch> {
    info.keys.iter().find(|k| k.key == key).map(|k| k.epochs.clone()).unwrap_or_default()
}

/// The spec of a reshare of `key` from `dealers` (current holders, at least the threshold of them) to
/// `receivers` with `threshold`. The same set is a refresh.
pub async fn spec_reshare(key: &str, dealers: &[Member], receivers: &[Member], threshold: usize) -> anyhow::Result<RoundSpec> {
    let key = key.to_lowercase();
    let mut all: Vec<Member> = dealers.to_vec();
    for r in receivers {
        match all.iter().find(|m| m.index == r.index) {
            Some(m) => ensure!(m.url.trim_end_matches('/') == r.url.trim_end_matches('/'), "operator {} is listed with two addresses", r.index),
            None => all.push(r.clone()),
        }
    }
    let (peers, infos) = peers(&all).await?;
    // the newest epoch that every dealer holds
    let mut candidates: Vec<PublicEpoch> = epochs_of(&infos[0], &key);
    candidates.retain(|e| (0..dealers.len()).all(|i| epochs_of(&infos[i], &key).contains(e)));
    let cur = candidates.into_iter().max_by_key(|e| e.epoch).context("the dealers share no epoch of this key; name operators that hold the same epoch")?;
    ensure!(dealers.len() >= cur.threshold, "{} dealers given, the key needs {}", dealers.len(), cur.threshold);
    for d in dealers {
        ensure!(cur.vks.contains_key(&d.index), "operator {} holds no share of epoch {}", d.index, cur.epoch);
    }
    let left_out = holders_left_out(&cur, dealers, receivers);
    if !left_out.is_empty() {
        tracing::warn!(
            "operators {left_out:?} hold a share of epoch {} and take no part in this round: they will KEEP that share. \
             Name every reachable holder under the dealers (a dealer that is not a receiver erases its share at the end); \
             destroy the state file of a holder that is gone for good",
            cur.epoch
        );
    }
    // later than anything any participant holds, so a leftover of a stalled round is superseded
    let newest = infos.iter().flat_map(|i| epochs_of(i, &key)).map(|e| e.epoch).max().unwrap_or(cur.epoch);
    Ok(RoundSpec {
        nonce: nonce(),
        kind: RoundKind::Reshare,
        key: Some(key),
        from_epoch: Some(cur.epoch),
        old_threshold: Some(cur.threshold),
        old_vks: dealers.iter().map(|d| (d.index, cur.vks[&d.index].clone())).collect(),
        new_epoch: newest + 1,
        dealers: dealers.iter().map(|d| d.index).collect(),
        receivers: receivers.iter().map(|r| r.index).collect(),
        peers,
        threshold,
    })
}

/// Holders of `epoch` that a round among `dealers` and `receivers` leaves out. An operator erases its
/// old share only at the end of a round it takes part in, so these would keep theirs; if `threshold`
/// of them remain, the old sharing stays usable.
pub fn holders_left_out(epoch: &PublicEpoch, dealers: &[Member], receivers: &[Member]) -> Vec<u32> {
    epoch.vks.keys().copied().filter(|i| !dealers.iter().chain(receivers).any(|m| m.index == *i)).collect()
}

/// Approve `spec` at one's own operator. Read the spec first: this is the administrator's consent.
pub async fn approve(spec: &RoundSpec, me: &AdminEndpoint) -> anyhow::Result<String> {
    let id: RoundId = call(&http(), me, "/v1/admin/round/start", spec).await?;
    ensure!(id.round_id == spec.id(), "the operator computed another round id");
    Ok(id.round_id)
}

fn failure(index: u32, f: &Failure) -> anyhow::Error {
    match f.blamed {
        Some(b) => anyhow::anyhow!("round failed at operator {index}: {} [operator {b} is at fault; run the round again without it]", f.reason),
        None => anyhow::anyhow!("round failed at operator {index}: {}", f.reason),
    }
}

/// Approve the round at one's own operator and keep it moving until it is done, fails or times out.
/// Every administrator runs this for their own operator; the operators talk to each other.
pub async fn join(spec: &RoundSpec, me: &AdminEndpoint, timeout: Duration) -> anyhow::Result<RoundStatus> {
    drive(spec, std::slice::from_ref(me), timeout).await.map(|mut v| v.remove(0))
}

/// [`join`] for several operators at once.
pub async fn drive(spec: &RoundSpec, admins: &[AdminEndpoint], timeout: Duration) -> anyhow::Result<Vec<RoundStatus>> {
    let c = http();
    let id = RoundId { round_id: spec.id() };
    let abort = |why: anyhow::Error| async {
        for o in admins {
            let _ = call::<serde_json::Value>(&c, o, "/v1/admin/round/abort", &id).await;
        }
        Err(why)
    };
    for o in admins {
        if let Err(e) = approve(spec, o).await {
            return abort(e).await;
        }
    }
    let started = std::time::Instant::now();
    let mut pause = Duration::from_millis(20);
    loop {
        let mut all = vec![];
        for o in admins {
            match call::<RoundStatus>(&c, o, "/v1/admin/round/advance", &id).await {
                Ok(st) => all.push(st),
                Err(e) => return abort(e).await,
            }
        }
        // a failure with a named culprit is the better report: look at every operator before choosing
        let failed: Vec<(u32, Failure)> = admins.iter().zip(&all).filter_map(|(o, st)| st.failed.clone().map(|f| (o.index, f))).collect();
        if let Some((i, f)) = failed.iter().find(|(_, f)| f.blamed.is_some()).or(failed.first()) {
            // every operator has now seen the failure or will refuse to go on; stop the round here
            return abort(failure(*i, f)).await;
        }
        if all.iter().all(|st| st.done) {
            return Ok(all);
        }
        if started.elapsed() > timeout {
            let waits: Vec<String> = admins.iter().zip(&all).filter(|(_, st)| !st.done).map(|(o, st)| format!("operator {} ({}) waits for {}", o.index, st.phase, st.waiting_for.join(", "))).collect();
            // Not aborted: operators that have stored their new share keep it, and nothing was erased.
            bail!("the round did not finish in {} s: {}. Nothing was erased; run `status`, then start a new round", timeout.as_secs(), waits.join("; "));
        }
        tokio::time::sleep(pause).await;
        pause = (pause * 2).min(Duration::from_millis(500));
    }
}

const CLUSTER_TIMEOUT: Duration = Duration::from_secs(60);

/// Key generation among operators one party administers. Returns the group key (hex), to be pinned
/// in the issuer configuration.
pub async fn dkg(operators: &[AdminEndpoint], threshold: usize) -> anyhow::Result<String> {
    let members: Vec<Member> = operators.iter().map(Member::from).collect();
    let spec = spec_dkg(&members, threshold).await?;
    let st = drive(&spec, operators, CLUSTER_TIMEOUT).await?;
    let (key, _) = st.iter().find_map(|s| s.result.clone()).context("no operator stored a share")?;
    ensure!(st.iter().all(|s| s.result.as_ref().map(|r| &r.0) == Some(&key)), "operators disagree on the key");
    verify_epoch(&key, 1, operators).await?;
    Ok(key)
}

/// The newest epoch of `key` that every one of `holders` has, with its threshold and verification keys.
pub async fn current_epoch(key: &str, holders: &[AdminEndpoint]) -> anyhow::Result<PublicEpoch> {
    let key = key.to_lowercase();
    let mut common: Option<Vec<PublicEpoch>> = None;
    for o in holders {
        let info = public(&o.url).await.with_context(|| format!("operator {}", o.index))?;
        ensure!(info.index == o.index, "the server at {} is operator {}, not {}", o.url, info.index, o.index);
        let eps = epochs_of(&info, &key);
        ensure!(!eps.is_empty(), "operator {} holds no share of this key", o.index);
        common = Some(match common {
            None => eps,
            Some(c) => c.into_iter().filter(|e| eps.contains(e)).collect(),
        });
    }
    common.unwrap_or_default().into_iter().max_by_key(|e| e.epoch).context("the operators share no epoch of this key")
}

/// Check, from public data only, that `holders` all publish `epoch` of `key` with the same
/// verification keys and that those keys combine to the group key.
pub async fn verify_epoch(key: &str, epoch: u64, holders: &[AdminEndpoint]) -> anyhow::Result<PublicEpoch> {
    let e = current_epoch(key, holders).await?;
    ensure!(e.epoch == epoch, "operators are at epoch {}, expected {epoch}", e.epoch);
    let idx: Vec<u32> = e.vks.keys().copied().collect();
    ensure!(holders.iter().all(|h| idx.contains(&h.index)), "an operator is not in the epoch it reports");
    ensure!(idx.len() >= e.threshold && e.threshold >= 1, "fewer holders than the threshold");
    let y: G2A = from_hex(key).map_err(|e| anyhow::anyhow!("bad group key: {e}"))?;
    // every t-subset must give Y; checking the first t and the last t indices catches a bad key cheaply
    for subset in [&idx[..e.threshold], &idx[idx.len() - e.threshold..]] {
        let mut acc = G2::zero();
        for i in subset {
            acc += from_hex::<G2A>(&e.vks[i]).map_err(|e| anyhow::anyhow!("bad verification key: {e}"))? * lagrange_at_zero(subset, *i);
        }
        ensure!(acc.into_affine() == y, "the verification keys of epoch {epoch} do not combine to the group key");
    }
    Ok(e)
}

/// Reshare among operators one party administers: new shares of `key` for `receivers` with
/// `threshold`, dealt by `dealers`. The older shares are erased by the operators themselves once
/// every receiver has stored its new one. Returns the new epoch.
pub async fn reshare(key: &str, dealers: &[AdminEndpoint], receivers: &[AdminEndpoint], threshold: usize) -> anyhow::Result<u64> {
    let key = key.to_lowercase();
    let (d, r): (Vec<Member>, Vec<Member>) = (dealers.iter().map(Member::from).collect(), receivers.iter().map(Member::from).collect());
    let spec = spec_reshare(&key, &d, &r, threshold).await?;
    let mut all: Vec<AdminEndpoint> = dealers.to_vec();
    all.extend(receivers.iter().filter(|r| !dealers.iter().any(|d| d.index == r.index)).cloned());
    drive(&spec, &all, CLUSTER_TIMEOUT).await?;
    verify_epoch(&key, spec.new_epoch, receivers).await?;
    Ok(spec.new_epoch)
}
