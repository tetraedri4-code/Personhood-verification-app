//! The coordinator's side of key generation, refresh and resharing: it tells every operator's admin
//! endpoint what to do and compares what they report. It never sees a share.
//!
//! In this prototype one coordinator holds every operator's admin token. Operators that do not trust
//! each other run the same steps each against their own operator and compare transcripts out of band;
//! the operator API is built for that (every step is one authenticated call per operator).
use crate::shamir::lagrange_at_zero;
use crate::wire::*;
use anyhow::{bail, ensure, Context};
use ark_ec::CurveGroup;
use ark_ff::Zero;
use pop_crypto::codec::from_hex;
use pop_crypto::params::{G2, G2A};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AdminEndpoint {
    pub index: u32,
    pub url: String,
    pub admin_token: String,
}

impl AdminEndpoint {
    fn peer(&self) -> Peer {
        Peer { index: self.index, url: self.url.clone() }
    }
}

fn http() -> reqwest::Client {
    reqwest::Client::builder().timeout(std::time::Duration::from_secs(60)).redirect(reqwest::redirect::Policy::none()).build().expect("http client")
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

fn round_id() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

fn union<'a>(a: &'a [AdminEndpoint], b: &'a [AdminEndpoint]) -> Vec<&'a AdminEndpoint> {
    let mut v: Vec<&AdminEndpoint> = a.iter().collect();
    for o in b {
        if !v.iter().any(|x| x.index == o.index) {
            v.push(o);
        }
    }
    v
}

/// Run one round to the commit. On any failure the round is aborted everywhere and nothing changed.
async fn run_round(spec: RoundSpec, dealers: &[AdminEndpoint], receivers: &[AdminEndpoint]) -> anyhow::Result<(String, u64)> {
    let c = http();
    let all = union(dealers, receivers);
    let id = RoundId { round_id: spec.round_id.clone() };
    let attempt = async {
        for o in &all {
            let _: serde_json::Value = call(&c, o, "/v1/admin/round/start", &spec).await?;
        }
        for o in dealers {
            let _: serde_json::Value = call(&c, o, "/v1/admin/round/deal", &id).await?;
        }
        let mut transcript: Option<BTreeMap<u32, String>> = None;
        for o in receivers {
            let st: RoundStatus = call(&c, o, "/v1/admin/round/status", &id).await?;
            ensure!(st.missing.is_empty(), "operator {} has no deal from {:?}", o.index, st.missing);
            match &transcript {
                None => transcript = Some(st.transcript),
                Some(t) => ensure!(*t == st.transcript, "operator {} saw other commitments than the others: a dealer cheated or was impersonated", o.index),
            }
        }
        transcript.context("no receivers")
    };
    let transcript = match attempt.await {
        Ok(t) => t,
        Err(e) => {
            for o in &all {
                let _ = call::<serde_json::Value>(&c, o, "/v1/admin/round/abort", &id).await;
            }
            return Err(e.context("round aborted, nothing changed"));
        }
    };
    // From here on a failure leaves some operators with the new epoch and some without. The old epoch
    // stays valid everywhere until `finalize`, so evaluations keep working meanwhile.
    let req = CommitRequest { round_id: spec.round_id.clone(), transcript };
    let mut committed: Vec<(&AdminEndpoint, (String, u64))> = vec![];
    let mut failure: Option<anyhow::Error> = None;
    for o in receivers {
        match call::<CommitResponse>(&c, o, "/v1/admin/round/commit", &req).await {
            Ok(CommitResponse { key: Some(key), epoch: Some(epoch) }) => {
                if committed.first().is_some_and(|(_, x)| *x != (key.clone(), epoch)) {
                    failure = Some(anyhow::anyhow!("operators disagree on the key or epoch they committed"));
                }
                committed.push((o, (key, epoch)));
            }
            Ok(_) => failure = Some(anyhow::anyhow!("operator {} committed nothing", o.index)),
            Err(e) => failure = Some(e),
        }
        if failure.is_some() {
            break;
        }
    }
    if let Some(e) = failure {
        // Undo: the receivers that committed drop the new epoch. Nothing was erased yet (that is
        // `finalize`, which only runs after a complete round), so every old share is still there.
        let mut undone = true;
        for (o, (key, epoch)) in &committed {
            undone &= call::<serde_json::Value>(&c, o, "/v1/admin/discard", &DiscardRequest { key: key.clone(), epoch: *epoch }).await.is_ok();
        }
        for o in &all {
            let _ = call::<serde_json::Value>(&c, o, "/v1/admin/round/abort", &id).await;
        }
        return Err(e.context(if undone {
            "commit failed part-way; the new shares were discarded and nothing changed"
        } else {
            "commit failed part-way and could not be undone everywhere; the old shares still work. Check `pop uniqueness status` and discard the newest epoch at the operators that have it"
        }));
    }
    for o in dealers.iter().filter(|d| !receivers.iter().any(|r| r.index == d.index)) {
        let _: CommitResponse = call(&c, o, "/v1/admin/round/commit", &req).await?;
    }
    committed.into_iter().next().map(|(_, x)| x).context("no receivers")
}

/// Distributed key generation among `operators`. Returns the group key (hex), to be pinned in the
/// issuer configuration.
pub async fn dkg(operators: &[AdminEndpoint], threshold: usize) -> anyhow::Result<String> {
    let spec = RoundSpec {
        round_id: round_id(),
        kind: RoundKind::Dkg,
        key: None,
        from_epoch: None,
        old_threshold: None,
        old_vks: BTreeMap::new(),
        dealers: operators.iter().map(|o| o.index).collect(),
        receivers: operators.iter().map(|o| o.peer()).collect(),
        threshold,
    };
    let (key, _) = run_round(spec, operators, operators).await?;
    verify_epoch(&key, 1, operators).await?;
    Ok(key)
}

/// The newest epoch of `key` that every one of `holders` has, with its threshold and verification keys.
pub async fn current_epoch(key: &str, holders: &[AdminEndpoint]) -> anyhow::Result<PublicEpoch> {
    let key = key.to_lowercase();
    let mut common: Option<PublicEpoch> = None;
    for o in holders {
        let info = public(&o.url).await.with_context(|| format!("operator {}", o.index))?;
        ensure!(info.index == o.index, "the server at {} is operator {}, not {}", o.url, info.index, o.index);
        let k = info.keys.into_iter().find(|k| k.key == key).with_context(|| format!("operator {} holds no share of this key", o.index))?;
        let newest = k.epochs.into_iter().max_by_key(|e| e.epoch).context("no epoch")?;
        match &common {
            None => common = Some(newest),
            Some(c) => ensure!(*c == newest, "operators {} and others are at different epochs; finish or re-run the last round first", o.index),
        }
    }
    common.context("no holders given")
}

/// Check, from public data only, that `holders` all publish `epoch` of `key` with the same
/// verification keys and that those keys combine to the group key.
pub async fn verify_epoch(key: &str, epoch: u64, holders: &[AdminEndpoint]) -> anyhow::Result<PublicEpoch> {
    let e = current_epoch(key, holders).await?;
    ensure!(e.epoch == epoch, "operators are at epoch {}, expected {epoch}", e.epoch);
    let idx: Vec<u32> = e.vks.keys().copied().collect();
    ensure!(holders.iter().all(|h| idx.contains(&h.index)), "an operator is not in the epoch it reports");
    ensure!(idx.len() >= e.threshold && holders.len() >= e.threshold, "fewer holders than the threshold");
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

/// Give new shares of `key` to `receivers` with threshold `threshold`, dealt by `dealers` (at least the
/// current threshold of current holders). `receivers` may be the same set (a refresh), a superset, a
/// subset or other operators altogether. Old shares stay until [`finalize`]. Returns the new epoch.
pub async fn reshare(key: &str, dealers: &[AdminEndpoint], receivers: &[AdminEndpoint], threshold: usize) -> anyhow::Result<u64> {
    let key = key.to_lowercase();
    let cur = current_epoch(&key, dealers).await?;
    ensure!(dealers.len() >= cur.threshold, "{} dealers given, the key needs {}", dealers.len(), cur.threshold);
    for d in dealers {
        ensure!(cur.vks.contains_key(&d.index), "operator {} holds no share of the current epoch", d.index);
    }
    let spec = RoundSpec {
        round_id: round_id(),
        kind: RoundKind::Reshare,
        key: Some(key.clone()),
        from_epoch: Some(cur.epoch),
        old_threshold: Some(cur.threshold),
        old_vks: dealers.iter().map(|d| (d.index, cur.vks[&d.index].clone())).collect(),
        dealers: dealers.iter().map(|o| o.index).collect(),
        receivers: receivers.iter().map(|o| o.peer()).collect(),
        threshold,
    };
    let (got_key, epoch) = run_round(spec, dealers, receivers).await?;
    if got_key != key {
        bail!("the round returned another key");
    }
    verify_epoch(&key, epoch, receivers).await?;
    Ok(epoch)
}

/// Erase every share older than `epoch`, at the operators that hold `epoch` (`holders`) and at those
/// that left (`leavers`). Checks first, from public data, that the holders really have `epoch`:
/// erasing is the one step that cannot be undone.
pub async fn finalize(key: &str, epoch: u64, holders: &[AdminEndpoint], leavers: &[AdminEndpoint]) -> anyhow::Result<()> {
    let key = key.to_lowercase();
    let e = verify_epoch(&key, epoch, holders).await?;
    ensure!(holders.len() == e.vks.len(), "finalize needs every operator of the new epoch ({} of {} given), so that no share is lost", holders.len(), e.vks.len());
    let c = http();
    for (o, leaving) in holders.iter().map(|o| (o, false)).chain(leavers.iter().filter(|l| !holders.iter().any(|h| h.index == l.index)).map(|o| (o, true))) {
        let _: serde_json::Value = call(&c, o, "/v1/admin/finalize", &FinalizeRequest { key: key.clone(), epoch, leaving }).await?;
    }
    Ok(())
}
