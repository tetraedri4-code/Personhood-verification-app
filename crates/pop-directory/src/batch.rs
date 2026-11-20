//! Checking like proofs in batches (docs/crypto.md, "Checking many like proofs at once"). Likes that
//! arrive within a short wait are checked together; where a batch fails, it is halved until the false
//! proofs are found, so that a false proof cannot sink the true likes it arrived with. Each like's
//! answer waits at most the batch wait plus the check; the holder's schedule (likes go out at a random
//! moment of a half-hour window) absorbs that.
use pop_crypto::{root_from_hex, CryptoError, Day, IssuerPublicKey, LikeProof, Scheme, VerifyCtx, WitnessPublicKey};
use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::{mpsc, oneshot};

/// Ok(true): valid; Ok(false): not; Err: the check could not be made (keys missing).
pub type Verdict = Result<bool, String>;

struct Job {
    today: Day,
    root: String,
    cutoff: Day,
    ctx: String,
    post: String,
    proof: LikeProof,
    reply: oneshot::Sender<Verdict>,
}

pub struct Batcher {
    tx: mpsc::Sender<Job>,
}

/// Jobs waiting for the worker; beyond this, senders wait (back-pressure instead of unbounded memory).
const QUEUE: usize = 4096;

impl Batcher {
    /// Start the worker: it gathers up to `max` likes, or what arrived within `wait` of the first.
    pub fn start(scheme: Arc<Scheme>, issuer: IssuerPublicKey, witness: WitnessPublicKey, max: usize, wait: Duration) -> Self {
        let (tx, mut rx) = mpsc::channel::<Job>(QUEUE);
        let keys = Arc::new((issuer, witness));
        tokio::spawn(async move {
            while let Some(first) = rx.recv().await {
                let mut jobs = vec![first];
                let deadline = tokio::time::Instant::now() + wait;
                while jobs.len() < max {
                    match tokio::time::timeout_at(deadline, rx.recv()).await {
                        Ok(Some(j)) => jobs.push(j),
                        _ => break,
                    }
                }
                // a batch shares the day, the revocation root and the cutoff
                let mut groups: BTreeMap<(Day, String, Day), Vec<Job>> = BTreeMap::new();
                for j in jobs {
                    groups.entry((j.today, j.root.clone(), j.cutoff)).or_default().push(j);
                }
                for ((today, root, cutoff), group) in groups {
                    let (scheme, keys) = (scheme.clone(), keys.clone());
                    // checked on the blocking pool, so that the next batch gathers meanwhile
                    tokio::spawn(async move {
                        let (replies, items): (Vec<_>, Vec<_>) = group.into_iter().map(|j| (j.reply, (j.ctx, j.post, j.proof))).unzip();
                        let verdicts = tokio::task::spawn_blocking(move || check(&scheme, &keys.0, &keys.1, today, &root, cutoff, &items))
                            .await
                            .unwrap_or_else(|e| vec![Err(e.to_string()); replies.len()]);
                        for (r, v) in replies.into_iter().zip(verdicts) {
                            let _ = r.send(v);
                        }
                    });
                }
            }
        });
        Batcher { tx }
    }

    pub async fn check(&self, today: Day, root: &str, cutoff: Day, ctx: &str, post: &str, proof: &LikeProof) -> Verdict {
        let (reply, rx) = oneshot::channel();
        let job = Job { today, root: root.into(), cutoff, ctx: ctx.into(), post: post.into(), proof: proof.clone(), reply };
        self.tx.send(job).await.map_err(|_| "the like checker stopped".to_string())?;
        rx.await.map_err(|_| "the like checker stopped".to_string())?
    }
}

#[allow(clippy::too_many_arguments)]
fn check(scheme: &Scheme, issuer: &IssuerPublicKey, witness: &WitnessPublicKey, today: Day, root: &str, cutoff: Day, items: &[(String, String, LikeProof)]) -> Vec<Verdict> {
    let root = match root_from_hex(root) {
        Ok(r) => r,
        Err(_) => return vec![Ok(false); items.len()],
    };
    let vc = VerifyCtx { issuer, witness, today, revocation_root: root };
    let refs: Vec<(&str, &str, &LikeProof)> = items.iter().map(|(c, p, l)| (c.as_str(), p.as_str(), l)).collect();
    match scheme.sieve_likes(&mut rand::rngs::OsRng, &vc, cutoff, &refs) {
        Ok(flags) => flags.into_iter().map(Ok).collect(),
        Err(e @ CryptoError::MissingKeys(_)) => vec![Err(e.to_string()); items.len()],
        Err(_) => vec![Ok(false); items.len()],
    }
}
