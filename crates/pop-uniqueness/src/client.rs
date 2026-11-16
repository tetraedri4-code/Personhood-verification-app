//! The issuer's side: [`ThresholdUniqueness`] implements [`UniquenessService`] against t-of-n operators.
use crate::shamir::lagrange_at_zero;
use crate::wire::{EvalRequest, EvalResponse};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup};
use ark_ff::{Field, Zero};
use ark_std::UniformRand;
use async_trait::async_trait;
use pop_crypto::codec::{from_hex, ser, to_hex};
use pop_crypto::params::{hash_to_g1, Fr, E, G1, G1A, G2A};
use pop_protocol::uniqueness::{identity_input, DedupKey, UniquenessService};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const DST_H1: &[u8] = b"POP-UNIQUENESS-V2-H1_BLS12381G1_XMD:SHA-256_SSWU_RO_";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OperatorEndpoint {
    pub index: u32,
    pub url: String,
    /// this operator's evaluation token (give each operator its own)
    pub token: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ThresholdConfig {
    pub operators: Vec<OperatorEndpoint>,
    /// Group keys (hex of Y = g2^K), oldest first; the last one is used for new enrolments. These are
    /// pinned: an answer that does not verify against the pinned key is an error, so the operators
    /// cannot swap the key under the issuer.
    pub keys: Vec<String>,
}

pub struct ThresholdUniqueness {
    operators: Vec<OperatorEndpoint>,
    /// (version, hex, Y), newest first
    keys: Vec<(String, String, G2A)>,
    http: reqwest::Client,
}

/// Subsets tried when the first t answers do not combine to a valid result (a faulty operator).
const MAX_SUBSETS: usize = 64;
const MAX_EPOCHS_PER_ANSWER: usize = 4;

/// (thresholds the operators state, (operator, answer))
type EpochAnswers = (Vec<usize>, Vec<(u32, G1A)>);

impl ThresholdUniqueness {
    pub fn new(cfg: ThresholdConfig) -> anyhow::Result<Self> {
        anyhow::ensure!(!cfg.keys.is_empty(), "threshold uniqueness needs at least one group key");
        anyhow::ensure!(!cfg.operators.is_empty(), "threshold uniqueness needs operators");
        let idx: Vec<u32> = cfg.operators.iter().map(|o| o.index).collect();
        anyhow::ensure!(crate::shamir::distinct_nonzero(&idx), "operator indices must be distinct and at least 1");
        for o in &cfg.operators {
            anyhow::ensure!(crate::url_is_safe(&o.url), "operator {} must be reached over https (plain http only on loopback)", o.index);
        }
        let mut keys = vec![];
        for k in cfg.keys.iter().rev() {
            let k = k.to_lowercase();
            let y: G2A = from_hex(&k).map_err(|e| anyhow::anyhow!("bad group key: {e}"))?;
            anyhow::ensure!(!y.is_zero(), "group key is the point at infinity");
            let v = crate::key_version(&k);
            if !keys.iter().any(|(x, _, _): &(String, String, G2A)| *x == v) {
                keys.push((v, k, y));
            }
        }
        let http = reqwest::Client::builder().timeout(std::time::Duration::from_secs(10)).redirect(reqwest::redirect::Policy::none()).build()?;
        Ok(ThresholdUniqueness { operators: cfg.operators, keys, http })
    }

    async fn ask(&self, o: &OperatorEndpoint, req: &EvalRequest) -> anyhow::Result<EvalResponse> {
        let url = format!("{}/v1/evaluate", o.url.trim_end_matches('/'));
        let resp = self.http.post(url).bearer_auth(&o.token).json(req).send().await?;
        anyhow::ensure!(resp.status().is_success(), "status {}", resp.status());
        let r: EvalResponse = resp.json().await?;
        anyhow::ensure!(r.index == o.index, "answered as operator {}", r.index);
        Ok(r)
    }

    /// H1(x)^K for one key, or an error. Never a wrong value: the result is checked against Y.
    async fn evaluate(&self, key_hex: &str, y: &G2A, input: &[u8]) -> anyhow::Result<G1A> {
        let h = hash_to_g1(DST_H1, input);
        let r = loop {
            let r = Fr::rand(&mut rand::thread_rng());
            if !r.is_zero() {
                break r;
            }
        };
        let a = (G1::from(h) * r).into_affine();
        let req = EvalRequest { key: key_hex.to_string(), point: to_hex(&a) };
        // epoch ↦ (thresholds claimed, answers)
        let mut by_epoch: BTreeMap<u64, EpochAnswers> = BTreeMap::new();
        let mut failures = vec![];
        let answers = ask_all(self, &req).await;
        for (o, res) in answers {
            match res {
                Ok(resp) => {
                    // an operator holds at most a few epochs; more is not a real answer
                    for p in resp.partials.into_iter().take(MAX_EPOCHS_PER_ANSWER) {
                        let Ok(v) = from_hex::<G1A>(&p.value) else { continue };
                        let e = by_epoch.entry(p.epoch).or_insert((vec![], vec![]));
                        // one answer per operator and epoch: a repeated index would break interpolation
                        if e.1.iter().any(|(i, _)| *i == o) {
                            continue;
                        }
                        e.0.push(p.threshold);
                        e.1.push((o, v));
                    }
                }
                Err(e) => failures.push(format!("operator {o}: {e}")),
            }
        }
        let r_inv = r.inverse().expect("non-zero");
        let want = E::pairing(h, *y);
        for (epoch, (claimed, answers)) in by_epoch.iter().rev() {
            // the threshold most operators state; a wrong one only costs a failed check below
            let t = claimed.iter().copied().max_by_key(|t| (claimed.iter().filter(|x| *x == t).count(), std::cmp::Reverse(*t))).unwrap_or(0);
            if t == 0 || answers.len() < t {
                continue;
            }
            for subset in subsets(answers.len(), t).take(MAX_SUBSETS) {
                let idx: Vec<u32> = subset.iter().map(|i| answers[*i].0).collect();
                let b: G1 = subset.iter().map(|i| G1::from(answers[*i].1) * lagrange_at_zero(&idx, answers[*i].0)).sum();
                let u = (b * r_inv).into_affine();
                if E::pairing(u, G2A::generator()) == want {
                    return Ok(u);
                }
            }
            tracing::warn!("uniqueness: answers of epoch {epoch} do not combine to a valid result");
        }
        anyhow::bail!(
            "not enough valid answers from the uniqueness operators for key {} ({} of {} answered{}{})",
            crate::key_version(key_hex),
            self.operators.len() - failures.len(),
            self.operators.len(),
            if failures.is_empty() { "" } else { "; " },
            failures.join("; ")
        )
    }
}

async fn ask_all(s: &ThresholdUniqueness, req: &EvalRequest) -> Vec<(u32, anyhow::Result<EvalResponse>)> {
    let mut handles = vec![];
    for o in &s.operators {
        handles.push(async move { (o.index, s.ask(o, req).await) });
    }
    join_all(handles).await
}

/// Poll all futures concurrently (small n; avoids a dependency on `futures`).
async fn join_all<F: std::future::Future>(futs: Vec<F>) -> Vec<F::Output> {
    let mut futs: Vec<_> = futs.into_iter().map(|f| Box::pin(f)).collect();
    let mut out: Vec<Option<F::Output>> = futs.iter().map(|_| None).collect();
    std::future::poll_fn(|cx| {
        let mut pending = false;
        for (i, f) in futs.iter_mut().enumerate() {
            if out[i].is_none() {
                match f.as_mut().poll(cx) {
                    std::task::Poll::Ready(v) => out[i] = Some(v),
                    std::task::Poll::Pending => pending = true,
                }
            }
        }
        if pending {
            std::task::Poll::Pending
        } else {
            std::task::Poll::Ready(())
        }
    })
    .await;
    out.into_iter().map(|o| o.unwrap()).collect()
}

/// All t-element subsets of 0..n in lexicographic order.
fn subsets(n: usize, t: usize) -> impl Iterator<Item = Vec<usize>> {
    let mut cur: Option<Vec<usize>> = (t <= n && t > 0).then(|| (0..t).collect());
    std::iter::from_fn(move || {
        let out = cur.clone()?;
        let c = cur.as_mut().unwrap();
        let mut i = t;
        loop {
            if i == 0 {
                cur = None;
                break;
            }
            i -= 1;
            if c[i] < n - t + i {
                c[i] += 1;
                for j in i + 1..t {
                    c[j] = c[j - 1] + 1;
                }
                break;
            }
        }
        Some(out)
    })
}

#[async_trait]
impl UniquenessService for ThresholdUniqueness {
    async fn versions(&self) -> anyhow::Result<Vec<String>> {
        Ok(self.keys.iter().map(|(v, _, _)| v.clone()).collect())
    }

    async fn dedup_keys(&self, country: u32, subject: &str) -> anyhow::Result<Vec<DedupKey>> {
        let x = identity_input(country, subject);
        let mut out = vec![];
        for (version, key_hex, y) in &self.keys {
            let u = self.evaluate(key_hex, y, x.as_bytes()).await?;
            let mut h = Sha256::new();
            h.update(b"pop-dedup-v2");
            h.update(ser(y));
            h.update((x.len() as u64).to_be_bytes());
            h.update(x.as_bytes());
            h.update(ser(&u));
            out.push(DedupKey { version: version.clone(), d: hex::encode(h.finalize()) });
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn subsets() {
        let s: Vec<Vec<usize>> = super::subsets(4, 2).collect();
        assert_eq!(s.len(), 6);
        assert_eq!(s[0], vec![0, 1]);
        assert_eq!(s[5], vec![2, 3]);
        assert_eq!(super::subsets(3, 3).count(), 1);
        assert_eq!(super::subsets(2, 3).count(), 0);
    }
}
