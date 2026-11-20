//! Checking like proofs in batches (docs/crypto.md, "Checking many like proofs at once"). Likes that
//! arrive within a short wait are checked together; where a batch fails, it is halved until the false
//! proofs are found, so that a false proof cannot sink the true likes it arrived with. Each like's
//! answer waits at most the batch wait plus the check; the holder's schedule (likes go out at a random
//! moment of a half-hour window) absorbs that.
//!
//! The batch size adjusts to the recent share f of false proofs: about 0.3 / f, a power of two between
//! the configured smallest and largest (docs/crypto.md, "Batch size": a batch is cheapest per proof when
//! it holds about a third of a false proof on average). With no false proofs, the largest.
use pop_crypto::{root_from_hex, CryptoError, Day, IssuerPublicKey, LikeProof, Scheme, VerifyCtx, WitnessPublicKey};
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};
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
    share: Arc<Mutex<FalseShare>>,
    sizes: (usize, usize),
}

/// The share of false proofs among roughly the last [`FalseShare::WINDOW`] checked, as two counters that
/// decay by proof.
#[derive(Default)]
pub struct FalseShare {
    seen: f64,
    false_: f64,
}

impl FalseShare {
    pub const WINDOW: f64 = 4096.0;
    /// About this many false proofs per batch is cheapest.
    pub const TARGET: f64 = 0.3;

    pub fn record(&mut self, checked: usize, false_: usize) {
        let d = (1.0 - 1.0 / Self::WINDOW).powi(checked as i32);
        self.seen = self.seen * d + checked as f64;
        self.false_ = self.false_ * d + false_ as f64;
    }

    pub fn share(&self) -> f64 {
        if self.seen > 0.0 { self.false_ / self.seen } else { 0.0 }
    }

    /// The batch size for the current share: TARGET / share, as a power of two within [min, max].
    pub fn size(&self, min: usize, max: usize) -> usize {
        let f = self.share();
        let want = if f > 0.0 { Self::TARGET / f } else { f64::INFINITY };
        let mut b = min.max(1);
        while b * 2 <= max && (b * 2) as f64 <= want * std::f64::consts::SQRT_2 {
            b *= 2;
        }
        b.min(max)
    }
}

/// Jobs waiting for the worker; beyond this, senders wait (back-pressure instead of unbounded memory).
const QUEUE: usize = 4096;

impl Batcher {
    /// Start the worker: it gathers up to the current batch size (between `min` and `max`, see
    /// [`FalseShare::size`]) of likes, or what arrived within `wait` of the first.
    pub fn start(scheme: Arc<Scheme>, issuer: IssuerPublicKey, witness: WitnessPublicKey, min: usize, max: usize, wait: Duration) -> Self {
        let (tx, mut rx) = mpsc::channel::<Job>(QUEUE);
        let keys = Arc::new((issuer, witness));
        let share = Arc::new(Mutex::new(FalseShare::default()));
        let sh = share.clone();
        tokio::spawn(async move {
            let mut last = 0;
            while let Some(first) = rx.recv().await {
                let max = sh.lock().unwrap().size(min, max);
                if max != last {
                    tracing::info!("like batches of up to {max} (false share {:.4})", sh.lock().unwrap().share());
                    last = max;
                }
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
                    let (scheme, keys, sh) = (scheme.clone(), keys.clone(), sh.clone());
                    // checked on the blocking pool, so that the next batch gathers meanwhile
                    tokio::spawn(async move {
                        let (replies, items): (Vec<_>, Vec<_>) = group.into_iter().map(|j| (j.reply, (j.ctx, j.post, j.proof))).unzip();
                        let verdicts = tokio::task::spawn_blocking(move || check(&scheme, &keys.0, &keys.1, today, &root, cutoff, &items))
                            .await
                            .unwrap_or_else(|e| vec![Err(e.to_string()); replies.len()]);
                        let false_ = verdicts.iter().filter(|v| matches!(v, Ok(false))).count();
                        let checked = verdicts.iter().filter(|v| v.is_ok()).count();
                        sh.lock().unwrap().record(checked, false_);
                        for (r, v) in replies.into_iter().zip(verdicts) {
                            let _ = r.send(v);
                        }
                    });
                }
            }
        });
        Batcher { tx, share, sizes: (min, max) }
    }

    /// The batch size the next batch will have, and the recent share of false proofs.
    pub fn current(&self) -> (usize, f64) {
        let s = self.share.lock().unwrap();
        (s.size(self.sizes.0, self.sizes.1), s.share())
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

#[cfg(test)]
mod tests {
    use super::FalseShare;

    #[test]
    fn the_batch_size_follows_the_share_of_false_proofs() {
        let mut s = FalseShare::default();
        assert_eq!(s.size(16, 256), 256, "nothing seen: the largest");
        s.record(10_000, 0);
        assert_eq!(s.size(16, 256), 256);
        // a campaign: 1% false gives about 30 per batch at 0.3 per batch
        let mut s = FalseShare::default();
        s.record(10_000, 100);
        assert!((s.share() - 0.01).abs() < 1e-9);
        assert_eq!(s.size(16, 256), 32);
        // 0.1%: 300, so the largest
        let mut s = FalseShare::default();
        s.record(10_000, 10);
        assert_eq!(s.size(16, 256), 256);
        // a flood: the smallest
        let mut s = FalseShare::default();
        s.record(1_000, 500);
        assert_eq!(s.size(16, 256), 16);
        // the campaign ends: true proofs wash the share out within a few windows
        for _ in 0..40 {
            s.record(1_000, 0);
        }
        assert_eq!(s.size(16, 256), 256);
    }
}
