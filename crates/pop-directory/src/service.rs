use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use pop_crypto::{dates, fingerprint, root_from_hex, CryptoError, Day, IssuerPublicKey, Scheme, VerifyCtx, WitnessPublicKey};
use pop_protocol::api::*;
use pop_protocol::platform::{PlatformError, PlatformRegistry};
use pop_protocol::{binding_code, binding_context, context_id, withdraw_context, AccountRef};
use pop_storage::SharedStore;
use serde::Deserialize;
use serde_json::json;
use std::collections::BTreeMap;
use std::sync::{Arc, RwLock};
use tower_http::{compression::CompressionLayer, cors::CorsLayer};

pub type Clock = Arc<dyn Fn() -> Day + Send + Sync>;

pub struct DirectoryConfig {
    pub clock: Option<Clock>,
    /// lease of a badge, in days (design §4.5: nine months)
    pub lease_days: u32,
    /// how many posts with likes a count bucket should hold on average (docs/data-usage.md). Readers
    /// fetch the buckets of the posts they see; a bucket hides which of its posts they were looking at.
    /// Larger is more private and costs more data. While all posts of a platform fit in one bucket,
    /// readers download the whole table and sync only its changes instead.
    pub bucket_posts: u32,
    /// like proofs checked together at most (docs/crypto.md); 1: each by itself
    pub like_batch_max: usize,
    /// how long the first like of a batch waits for others, in milliseconds
    pub like_batch_wait_ms: u64,
}

impl Default for DirectoryConfig {
    fn default() -> Self {
        DirectoryConfig { clock: None, lease_days: 274, bucket_posts: 32, like_batch_max: 64, like_batch_wait_ms: 50 }
    }
}

/// Finest bucket split offered (about a million buckets).
pub const MAX_BUCKET_BITS: u32 = 20;
/// Buckets per request.
pub const MAX_BUCKETS_PER_REQUEST: usize = 64;

/// The first 32 bits of SHA-256(platform | post): the top `bits` of it are the post's bucket. Readers
/// compute the same (extension/src/background.js).
pub fn bucket_hash(platform: &str, post: &str) -> u32 {
    use sha2::{Digest, Sha256};
    let h = Sha256::digest(format!("{platform}|{post}").as_bytes());
    u32::from_be_bytes([h[0], h[1], h[2], h[3]])
}

/// Counts by platform, ordered by bucket hash, so that a bucket is a range. Rebuilt from the store at
/// start; a database would keep an index on (platform, hash) instead.
type BucketIndex = BTreeMap<String, BTreeMap<(u32, String), u64>>;

pub struct Directory {
    scheme: Arc<Scheme>,
    issuer_api: Arc<dyn IssuerApi>,
    issuer_pk: IssuerPublicKey,
    witness_pk: WitnessPublicKey,
    /// the issuer's current and previous revocation roots, and when they were fetched
    roots: RwLock<(String, Option<String>, std::time::Instant)>,
    /// the issuer's alarm cutoff and when it was last fetched
    alarm: RwLock<(Option<Day>, std::time::Instant)>,
    platforms: PlatformRegistry,
    store: SharedStore,
    cfg: DirectoryConfig,
    write: tokio::sync::Mutex<()>,
    buckets: RwLock<BucketIndex>,
    /// like proofs are checked in batches (started on the first like); None when like_batch_max is 1
    batcher: Option<crate::batch::Batcher>,
}

const T_BIND: &str = "bindings";
const T_NYM: &str = "nyms";
const T_LIKES: &str = "likes";
const T_COUNTS: &str = "like_counts";
const T_NONCES: &str = "nonces";
/// removed claims, kept for a while so that readers who sync with `since` learn of the removal
const T_GONE: &str = "gone";
const T_META: &str = "meta";
/// Removals older than this are forgotten; a reader who last synced before them gets the whole list.
const GONE_KEEP_DAYS: Day = 30;
const MAX_FIELD: usize = 256;

fn key(a: &str, b: &str) -> String {
    format!("{a}|{b}")
}

impl Directory {
    /// Fetch the issuer's public parameters (and LegoGroth16 verifying keys) and start.
    pub async fn connect(issuer_api: Arc<dyn IssuerApi>, platforms: PlatformRegistry, store: SharedStore, cfg: DirectoryConfig) -> anyhow::Result<Arc<Self>> {
        anyhow::ensure!((7..=3650).contains(&cfg.lease_days), "lease_days must be between 7 and 3650");
        anyhow::ensure!((1..=100_000).contains(&cfg.bucket_posts), "bucket_posts must be between 1 and 100000");
        anyhow::ensure!((1..=4096).contains(&cfg.like_batch_max), "like_batch_max must be between 1 and 4096");
        anyhow::ensure!(cfg.like_batch_wait_ms <= 10_000, "like_batch_wait_ms must be at most 10000");
        let mut buckets = BucketIndex::new();
        for (k, v) in store.list(T_COUNTS).await? {
            if let Some((platform, post)) = k.split_once('|') {
                let n = count_of(&v).0;
                if n > 0 {
                    buckets.entry(platform.to_string()).or_default().insert((bucket_hash(platform, post), post.to_string()), n);
                }
            }
        }
        let p = issuer_api.params().await?;
        let scheme = Arc::new(Scheme::new(p.config.clone()));
        for k in &p.statements {
            scheme.install_lego_keys(*k, &issuer_api.lego_keys(*k).await?)?;
        }
        let rv = issuer_api.revocations().await?;
        let issuer_pk = IssuerPublicKey::from_hex(&p.issuer_public_key)?;
        let witness_pk = WitnessPublicKey::from_hex(&p.witness_public_key)?;
        let batcher = (cfg.like_batch_max > 1).then(|| {
            crate::batch::Batcher::start(scheme.clone(), issuer_pk.clone(), witness_pk.clone(), cfg.like_batch_max, std::time::Duration::from_millis(cfg.like_batch_wait_ms))
        });
        Ok(Arc::new(Directory {
            scheme,
            issuer_pk,
            witness_pk,
            batcher,
            issuer_api,
            roots: RwLock::new((rv.root, rv.previous_root, std::time::Instant::now())),
            alarm: RwLock::new((p.alarm_cutoff, std::time::Instant::now())),
            platforms,
            store,
            cfg,
            write: tokio::sync::Mutex::new(()),
            buckets: RwLock::new(buckets),
        }))
    }

    pub fn today(&self) -> Day {
        self.cfg.clock.as_ref().map(|c| c()).unwrap_or_else(dates::today)
    }

    async fn meta(&self, name: &str) -> Result<u64, ApiErr> {
        Ok(self.store.get(T_META, name).await?.and_then(|v| v.as_u64()).unwrap_or(0))
    }

    /// A random name for this directory's store, made once. Change numbers count within it, so a
    /// reader whose numbers come from another store (a reset, a move) is sent the whole list.
    async fn instance(&self) -> Result<String, ApiErr> {
        if let Some(v) = self.store.get(T_META, "instance").await?.and_then(|v| v.as_str().map(String::from)) {
            return Ok(v);
        }
        let _g = self.write.lock().await;
        let id = hex::encode(rand::random::<[u8; 8]>());
        if self.store.insert_new(T_META, "instance", json!(id)).await? {
            return Ok(id);
        }
        Ok(self.store.get(T_META, "instance").await?.and_then(|v| v.as_str().map(String::from)).unwrap_or_default())
    }

    /// The current change number and the lowest one a reader can sync from. Taking the write lock
    /// for a moment means every change up to this number is fully stored before the list is read;
    /// changes made while it is read have higher numbers and are sent again next time.
    async fn sync_point(&self) -> Result<(u64, u64), ApiErr> {
        let _g = self.write.lock().await;
        Ok((self.meta("seq").await?, self.meta("gone_floor").await?))
    }

    /// The next change number. Call only while holding `write`.
    async fn next_seq(&self) -> Result<u64, ApiErr> {
        let n = self.meta("seq").await? + 1;
        self.store.put(T_META, "seq", json!(n)).await?;
        Ok(n)
    }

    /// Store a claim with a new change number. Call only while holding `write`.
    async fn put_claim(&self, key: &str, mut rec: BindingRecord) -> Result<(), ApiErr> {
        rec.seq = self.next_seq().await?;
        self.store.delete(T_GONE, key).await?;
        self.store.put(T_BIND, key, serde_json::to_value(rec)?).await?;
        Ok(())
    }

    /// Remove a claim and remember the removal. Call only while holding `write`.
    async fn remove_claim(&self, key: &str) -> Result<(), ApiErr> {
        let Some(v) = self.store.get(T_BIND, key).await? else { return Ok(()) };
        self.store.delete(T_BIND, key).await?;
        if let Ok(rec) = serde_json::from_value::<BindingRecord>(v) {
            let gone = GoneEntry { account_id: rec.entry.account_id, nym: rec.entry.nym };
            let seq = self.next_seq().await?;
            self.store.put(T_GONE, key, json!({"seq": seq, "on": self.today(), "entry": gone})).await?;
        }
        // forget old removals, and remember up to which change number the record is incomplete
        let today = self.today();
        let mut floor = self.meta("gone_floor").await?;
        for (k, v) in self.store.list(T_GONE).await? {
            let on = v.get("on").and_then(|x| x.as_u64()).unwrap_or(0) as Day;
            if on + GONE_KEEP_DAYS < today {
                floor = floor.max(v.get("seq").and_then(|x| x.as_u64()).unwrap_or(0));
                self.store.delete(T_GONE, &k).await?;
            }
        }
        self.store.put(T_META, "gone_floor", json!(floor)).await?;
        Ok(())
    }

    /// The revocation roots are fetched again when older than this. A root is never trusted for longer:
    /// a secret suspended a moment ago can prove against the root from before, which must stop working
    /// within minutes (the issuer offers the previous root for two minutes after a change).
    const ROOTS_TTL: std::time::Duration = std::time::Duration::from_secs(30);

    /// Accept a proof's revocation root if it is the issuer's current one, or the previous one shortly
    /// after a change.
    async fn check_root(&self, root: &str) -> Result<(), ApiErr> {
        let known = |r: &(String, Option<String>, std::time::Instant)| r.0 == root || r.1.as_deref() == Some(root);
        let stale = || err(StatusCode::CONFLICT, "stale revocation root; fetch the issuer's /v1/revocations and prove again");
        {
            let r = self.roots.read().unwrap();
            let age = r.2.elapsed();
            if age < Self::ROOTS_TTL && known(&r) {
                return Ok(());
            }
            // ask the issuer again, but not more than every few seconds whatever proofs arrive
            if age < std::time::Duration::from_secs(2) {
                return Err(stale());
            }
        }
        let rv = self.issuer_api.revocations().await.map_err(|e| err(StatusCode::BAD_GATEWAY, e.to_string()))?;
        let mut w = self.roots.write().unwrap();
        *w = (rv.root, rv.previous_root, std::time::Instant::now());
        if known(&w) {
            Ok(())
        } else {
            Err(stale())
        }
    }

    /// The issuer's alarm cutoff, fetched again when older than this.
    const ALARM_TTL: std::time::Duration = std::time::Duration::from_secs(300);

    async fn refresh_alarm(&self) -> Result<Option<Day>, ApiErr> {
        let p = self.issuer_api.params().await.map_err(|e| err(StatusCode::BAD_GATEWAY, e.to_string()))?;
        *self.alarm.write().unwrap() = (p.alarm_cutoff, std::time::Instant::now());
        Ok(p.alarm_cutoff)
    }

    /// The alarm cutoff as currently known, fetched again if old.
    async fn alarm(&self) -> Result<Option<Day>, ApiErr> {
        let (a, at) = *self.alarm.read().unwrap();
        if at.elapsed() < Self::ALARM_TTL {
            return Ok(a);
        }
        self.refresh_alarm().await
    }

    /// A proof names the alarm cutoff it was made under; it must be the issuer's current one. On a
    /// mismatch the issuer is asked again, so a change reaches this server at the first proof that
    /// knows of it.
    async fn check_alarm(&self, claimed: Option<Day>) -> Result<Option<Day>, ApiErr> {
        if self.alarm().await? == claimed {
            return Ok(claimed);
        }
        // ask the issuer again, but not more than every few seconds whatever proofs arrive
        let recent = self.alarm.read().unwrap().1.elapsed() < std::time::Duration::from_secs(5);
        if !recent && self.refresh_alarm().await? == claimed {
            return Ok(claimed);
        }
        Err(err(StatusCode::CONFLICT, "the alarm cutoff changed; fetch the issuer's /v1/params and prove again"))
    }

    /// Contexts are named by the operator: only platforms this directory was started with are accepted.
    /// Without this, an enrolled person could fill the store with bindings on made-up platforms.
    fn platform(&self, id: &str) -> Result<Arc<dyn pop_protocol::platform::Platform>, ApiErr> {
        self.platforms.get(id).ok_or_else(|| err(StatusCode::BAD_REQUEST, "unknown platform"))
    }

    /// A proof is accepted once. Binding records are public, so without this anyone could replay a
    /// published proof the same day, for example to bring back a badge its owner just withdrew.
    async fn use_nonce(&self, kind: &str, platform: &str, nonce: &str) -> Result<(), ApiErr> {
        if nonce.len() < 16 || nonce.len() > 64 {
            return Err(err(StatusCode::BAD_REQUEST, "bad nonce"));
        }
        let today = self.today();
        // proofs are valid for the day they name, plus or minus one: older nonces can go
        for (k, v) in self.store.list(T_NONCES).await? {
            if v.as_u64().map(|d| (d as Day) + 3 < today).unwrap_or(true) {
                self.store.delete(T_NONCES, &k).await?;
            }
        }
        if !self.store.insert_new(T_NONCES, &format!("{kind}|{platform}|{nonce}"), json!(today)).await? {
            return Err(err(StatusCode::CONFLICT, "this proof was already used"));
        }
        Ok(())
    }

    fn check_day(&self, d: Day) -> Result<(), ApiErr> {
        if d.abs_diff(self.today()) > 1 {
            return Err(err(StatusCode::BAD_REQUEST, "date out of window"));
        }
        Ok(())
    }

    fn vc(&self, today: Day, root: &str) -> Result<VerifyCtx<'_>, ApiErr> {
        Ok(VerifyCtx { issuer: &self.issuer_pk, witness: &self.witness_pk, today, revocation_root: root_from_hex(root)? })
    }

    /// Look for the code in the account's public texts, if the platform adapter can read them.
    async fn code_check(&self, entry: &mut BindingEntry) {
        let Some(p) = self.platforms.get(&entry.platform) else { return };
        let acct = AccountRef { platform: entry.platform.clone(), account_id: entry.account_id.clone(), handle: entry.handle.clone() };
        match p.public_texts(&acct).await {
            Ok(texts) => {
                if texts.iter().any(|t| t.to_lowercase().contains(&entry.code)) {
                    entry.code_seen_on = Some(self.today());
                } else {
                    entry.code_seen_on = None;
                }
            }
            Err(PlatformError::Unsupported(_)) => {}
            Err(e) => tracing::warn!("code check for {} failed: {e}", entry.account_id),
        }
    }

    async fn bind(&self, mut req: BindRequest) -> Result<BindingEntry, ApiErr> {
        self.check_day(req.today)?;
        if req.account_id.is_empty() || req.account_id.len() > MAX_FIELD || req.handle.is_empty() || req.handle.len() > MAX_FIELD {
            return Err(err(StatusCode::BAD_REQUEST, "bad account"));
        }
        let p = self.platform(&req.platform)?;
        self.check_root(&req.revocation_root).await?;
        let alarm = self.check_alarm(req.alarm_cutoff).await?;
        let ctx = context_id(&req.platform);
        let bind = binding_context(&req.platform, &req.account_id, &req.nonce);
        self.scheme
            .verify_binding(&self.vc(req.today, &req.revocation_root)?, dates::count_cutoff(req.today, alarm), &ctx, &bind, &req.proof)
            .map_err(|e| err(StatusCode::UNAUTHORIZED, e.to_string()))?;
        // where the platform can resolve handles, the handle must belong to the account id, and the
        // list shows the platform's spelling of it, not the submitter's
        match p.resolve_account(&req.handle).await {
            Ok(a) if a.account_id != req.account_id => return Err(err(StatusCode::BAD_REQUEST, "handle does not belong to this account")),
            Ok(a) => req.handle = a.handle,
            Err(PlatformError::Unsupported(_)) => {}
            Err(PlatformError::NotFound(_)) => return Err(err(StatusCode::BAD_REQUEST, "account not found on the platform")),
            Err(e) => return Err(err(StatusCode::BAD_GATEWAY, e.to_string())),
        }
        let today = self.today();
        let mut entry = BindingEntry {
            platform: req.platform.clone(),
            account_id: req.account_id.clone(),
            handle: req.handle.clone(),
            code: binding_code(&req.platform, &req.account_id, &req.proof.nym),
            slot: req.proof.slot,
            nym: fingerprint(&req.proof.nym),
            bound_on: today,
            lease_until: today + self.cfg.lease_days,
            counted: req.proof.probation_cleared,
            code_seen_on: None,
            proved_alarm: if req.proof.probation_cleared { alarm } else { None },
        };
        // A replayed proof is refused before the platform is asked anything. The platform is asked
        // outside the write lock, which readers of the list also take for a moment.
        {
            let _g = self.write.lock().await;
            self.use_nonce("bind", &req.platform, &req.nonce).await?;
        }
        self.code_check(&mut entry).await;
        let _g = self.write.lock().await;
        // A pseudonym is bound to one account at a time: re-binding moves it.
        // An account may have several claims, each from a different pseudonym: anyone enrolled can
        // submit a proof naming any account, so a new claim must never push out an existing one. Which
        // claim is real is decided by the code on the account, seen by this server or by a viewer.
        let fp = fingerprint(&req.proof.nym);
        let nk = key(&req.platform, &req.proof.nym);
        let bk = format!("{}|{}|{}", req.platform, req.account_id, fp);
        if let Some(prev) = self.store.get(T_NYM, &nk).await? {
            let prev = prev.as_str().unwrap_or_default().to_string();
            if prev != req.account_id {
                self.remove_claim(&format!("{}|{}|{}", req.platform, prev, fp)).await?;
            }
        }
        let rec = BindingRecord { entry: entry.clone(), request: req.clone(), seq: 0 };
        self.store.put(T_NYM, &nk, json!(req.account_id)).await?;
        self.put_claim(&bk, rec).await?;
        Ok(entry)
    }

    /// All claims on an account.
    async fn records(&self, platform: &str, account_id: &str) -> Result<Vec<BindingRecord>, ApiErr> {
        let prefix = format!("{platform}|{account_id}|");
        Ok(self
            .store
            .list(T_BIND)
            .await?
            .into_iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .filter_map(|(_, v)| serde_json::from_value::<BindingRecord>(v).ok())
            .filter(|r| r.entry.platform == platform && r.entry.account_id == account_id)
            .collect())
    }

    async fn withdraw(&self, req: WithdrawRequest) -> Result<(), ApiErr> {
        self.check_day(req.today)?;
        self.platform(&req.platform)?;
        self.check_root(&req.revocation_root).await?;
        if !self.records(&req.platform, &req.account_id).await?.iter().any(|r| r.request.proof.nym == req.proof.nym) {
            return Err(err(StatusCode::NOT_FOUND, "this pseudonym has no binding on this account"));
        }
        let alarm = self.check_alarm(req.alarm_cutoff).await?;
        let bind = withdraw_context(&req.platform, &req.account_id, &req.nonce);
        self.scheme
            .verify_binding(&self.vc(req.today, &req.revocation_root)?, dates::count_cutoff(req.today, alarm), &context_id(&req.platform), &bind, &req.proof)
            .map_err(|e| err(StatusCode::UNAUTHORIZED, e.to_string()))?;
        let _g = self.write.lock().await;
        self.use_nonce("withdraw", &req.platform, &req.nonce).await?;
        self.remove_claim(&format!("{}|{}|{}", req.platform, req.account_id, fingerprint(&req.proof.nym))).await?;
        self.store.delete(T_NYM, &key(&req.platform, &req.proof.nym)).await?;
        Ok(())
    }

    async fn like(&self, req: LikeRequest) -> Result<LikeResponse, ApiErr> {
        self.check_day(req.today)?;
        self.check_root(&req.revocation_root).await?;
        // only ids in the platform's canonical form: one post, one id, and no free-text keys in the store
        let p = self.platform(&req.platform)?;
        if req.post_id.is_empty() || req.post_id.len() > MAX_FIELD || p.canonical_post_id(&req.post_id).await.ok().as_deref() != Some(req.post_id.as_str()) {
            return Err(err(StatusCode::BAD_REQUEST, "post id is not in the platform's canonical form"));
        }
        let alarm = self.check_alarm(req.alarm_cutoff).await?;
        let cutoff = dates::count_cutoff(req.today, alarm);
        let ctx = context_id(&req.platform);
        match &self.batcher {
            Some(b) => match b.check(req.today, &req.revocation_root, cutoff, &ctx, &req.post_id, &req.proof).await {
                Ok(true) => {}
                Ok(false) => return Err(err(StatusCode::UNAUTHORIZED, CryptoError::InvalidProof.to_string())),
                Err(e) => return Err(err(StatusCode::UNAUTHORIZED, e)),
            },
            None => self
                .scheme
                .verify_like(&self.vc(req.today, &req.revocation_root)?, cutoff, &ctx, &req.post_id, &req.proof)
                .map_err(|e| err(StatusCode::UNAUTHORIZED, e.to_string()))?,
        }
        let _g = self.write.lock().await;
        let pk = key(&req.platform, &req.post_id);
        let new = self.store.insert_new(T_LIKES, &key(&pk, &req.proof.tag), json!({"on": req.today})).await?;
        let mut count = self.store.get(T_COUNTS, &pk).await?.map(|v| count_of(&v).0).unwrap_or(0);
        if new {
            count += 1;
            let seq = self.next_seq().await?;
            self.store.put(T_COUNTS, &pk, json!({"n": count, "seq": seq})).await?;
            let h = bucket_hash(&req.platform, &req.post_id);
            self.buckets.write().unwrap().entry(req.platform.clone()).or_default().insert((h, req.post_id.clone()), count);
        }
        Ok(LikeResponse { new, count })
    }
}

// ------------------------------------------------------------------ HTTP

pub struct ApiErr(StatusCode, String);

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}

impl<E: std::fmt::Display> From<E> for ApiErr {
    fn from(e: E) -> Self {
        ApiErr(StatusCode::BAD_REQUEST, e.to_string())
    }
}

fn err(code: StatusCode, msg: impl Into<String>) -> ApiErr {
    ApiErr(code, msg.into())
}

type St = Arc<Directory>;

/// The directory is read from browser extensions on any page, so its read endpoints allow any origin.
/// It sets no cookies and needs no credentials.
pub fn router(d: Arc<Directory>) -> Router {
    Router::new()
        .route("/v1/bindings", get(list).post(bind))
        .route("/v1/bindings/withdraw", post(withdraw))
        .route("/v1/bindings/recheck", post(recheck))
        .route("/v1/bindings/:platform/:account", get(record))
        .route("/v1/likes", post(like))
        .route("/v1/likes/counts", post(counts))
        .route("/v1/likes/table", get(table))
        .route("/v1/likes/buckets", get(bucket_bits).post(buckets))
        // the list and table are public and repetitive: gzip shrinks them several times over. Nothing
        // secret is in any answer here, so compression cannot leak one (as in the BREACH attack).
        .layer(CompressionLayer::new())
        .layer(CorsLayer::permissive())
        .with_state(d)
}

#[derive(Deserialize)]
struct ListQ {
    platform: String,
    #[serde(default)]
    since: u64,
    /// the `instance` of the answer the reader's `since` came from
    #[serde(default)]
    instance: Option<String>,
}

/// A stored count: a bare number from before change numbers, or `{"n", "seq"}`.
fn count_of(v: &serde_json::Value) -> (u64, u64) {
    match v.as_u64() {
        Some(n) => (n, 0),
        None => (v.get("n").and_then(|x| x.as_u64()).unwrap_or(0), v.get("seq").and_then(|x| x.as_u64()).unwrap_or(0)),
    }
}

/// The current list, or the changes since `since`. Readers sync instead of downloading the whole
/// list each time; the whole platform's changes are sent, so the directory still does not learn which
/// accounts anyone looks at.
async fn list(State(d): State<St>, Query(q): Query<ListQ>) -> Result<Json<BindingList>, ApiErr> {
    let today = d.today();
    let prefix = format!("{}|", q.platform);
    let instance = d.instance().await?;
    let (seq, floor) = d.sync_point().await?;
    let full = q.since == 0 || q.since < floor || q.since > seq || q.instance.as_deref() != Some(instance.as_str());
    let mut entries: Vec<BindingEntry> = d
        .store
        .list(T_BIND)
        .await?
        .into_iter()
        .filter(|(k, _)| k.starts_with(&prefix))
        .filter_map(|(_, v)| serde_json::from_value::<BindingRecord>(v).ok())
        .filter(|r| full || r.seq > q.since)
        .map(|r| r.entry)
        .filter(|e| e.lease_until >= today)
        .collect();
    let mut gone: Vec<GoneEntry> = if full {
        vec![]
    } else {
        d.store
            .list(T_GONE)
            .await?
            .into_iter()
            .filter(|(k, _)| k.starts_with(&prefix))
            .filter(|(_, v)| v.get("seq").and_then(|x| x.as_u64()).unwrap_or(0) > q.since)
            .filter_map(|(_, v)| serde_json::from_value(v.get("entry")?.clone()).ok())
            .collect()
    };
    entries.sort_by(|a, b| a.account_id.cmp(&b.account_id));
    gone.sort_by(|a, b| a.account_id.cmp(&b.account_id));
    let alarm_cutoff = d.alarm().await?;
    Ok(Json(BindingList { platform: q.platform, today, alarm_cutoff, instance, seq, full, entries, gone }))
}

async fn bind(State(d): State<St>, Json(req): Json<BindRequest>) -> Result<Json<BindingEntry>, ApiErr> {
    Ok(Json(d.bind(req).await?))
}

async fn withdraw(State(d): State<St>, Json(req): Json<WithdrawRequest>) -> Result<Json<serde_json::Value>, ApiErr> {
    d.withdraw(req).await?;
    Ok(Json(json!({"withdrawn": true})))
}

#[derive(Deserialize)]
struct RecheckReq {
    platform: String,
    account_id: String,
}

async fn recheck(State(d): State<St>, Json(r): Json<RecheckReq>) -> Result<Json<Vec<BindingEntry>>, ApiErr> {
    let mut out = vec![];
    for mut rec in d.records(&r.platform, &r.account_id).await? {
        d.code_check(&mut rec.entry).await;
        let _g = d.write.lock().await;
        let k = format!("{}|{}|{}", r.platform, r.account_id, fingerprint(&rec.request.proof.nym));
        // only a claim that still exists (it may have been withdrawn or renewed meanwhile: only the
        // check's result is taken over), and a new change number only when the result changed, so
        // that asking again does not make every reader download the claim again
        if let Some(mut cur) = d.store.get(T_BIND, &k).await?.and_then(|v| serde_json::from_value::<BindingRecord>(v).ok()) {
            let changed = cur.entry.code_seen_on != rec.entry.code_seen_on;
            cur.entry.code_seen_on = rec.entry.code_seen_on;
            let entry = cur.entry.clone();
            if changed {
                d.put_claim(&k, cur).await?;
            }
            out.push(entry);
        }
    }
    Ok(Json(out))
}

async fn record(State(d): State<St>, Path((platform, account)): Path<(String, String)>) -> Result<Json<Vec<BindingRecord>>, ApiErr> {
    Ok(Json(d.records(&platform, &account).await?))
}

async fn like(State(d): State<St>, Json(req): Json<LikeRequest>) -> Result<Json<LikeResponse>, ApiErr> {
    Ok(Json(d.like(req).await?))
}

async fn counts(State(d): State<St>, Json(req): Json<CountsRequest>) -> Result<Json<CountsResponse>, ApiErr> {
    if req.posts.len() > 500 {
        return Err(err(StatusCode::BAD_REQUEST, "at most 500 posts per request"));
    }
    let mut counts = BTreeMap::new();
    for p in req.posts {
        let c = d.store.get(T_COUNTS, &key(&req.platform, &p)).await?.map(|v| count_of(&v).0).unwrap_or(0);
        counts.insert(p, c);
    }
    Ok(Json(CountsResponse { counts }))
}

/// How finely the counts of a platform are split: buckets of about `bucket_posts` posts each.
fn bits_for(posts: usize, target: u32) -> u32 {
    let mut b = 0;
    while b < MAX_BUCKET_BITS && posts > (target as usize) << b {
        b += 1;
    }
    b
}

#[derive(Deserialize)]
struct BucketQ {
    platform: String,
}

/// `{"bits": b}`: readers fetch buckets at this split. 0 means one bucket: read the whole table
/// (`/v1/likes/table`) and sync its changes instead.
async fn bucket_bits(State(d): State<St>, Query(q): Query<BucketQ>) -> Json<serde_json::Value> {
    let n = d.buckets.read().unwrap().get(&q.platform).map_or(0, |m| m.len());
    Json(json!({"bits": bits_for(n, d.cfg.bucket_posts)}))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BucketsReq {
    platform: String,
    bits: u32,
    buckets: Vec<u32>,
}

/// The counts of every post in the asked buckets (the top `bits` bits of [`bucket_hash`]), by bucket;
/// an empty bucket is in the answer too. The answer also says the split currently recommended.
async fn buckets(State(d): State<St>, Json(req): Json<BucketsReq>) -> Result<Json<serde_json::Value>, ApiErr> {
    if req.bits > MAX_BUCKET_BITS {
        return Err(err(StatusCode::BAD_REQUEST, "bits too large"));
    }
    if req.buckets.is_empty() || req.buckets.len() > MAX_BUCKETS_PER_REQUEST {
        return Err(err(StatusCode::BAD_REQUEST, "between 1 and 64 buckets per request"));
    }
    if req.buckets.iter().any(|b| u64::from(*b) >> req.bits != 0) {
        return Err(err(StatusCode::BAD_REQUEST, "bucket out of range"));
    }
    // each bucket once: otherwise one request could ask for the whole table 64 times (security.md #43)
    if req.buckets.iter().collect::<std::collections::BTreeSet<_>>().len() != req.buckets.len() {
        return Err(err(StatusCode::BAD_REQUEST, "a bucket is asked for twice"));
    }
    let idx = d.buckets.read().unwrap();
    let all = idx.get(&req.platform);
    let mut out = serde_json::Map::new();
    for b in req.buckets {
        let shift = 32 - req.bits;
        let lo = if req.bits == 0 { 0 } else { u64::from(b) << shift };
        let hi = if req.bits == 0 { 1u64 << 32 } else { (u64::from(b) + 1) << shift };
        let mut m = serde_json::Map::new();
        if let Some(all) = all {
            for ((h, post), n) in all.range((lo as u32, String::new())..) {
                if u64::from(*h) >= hi {
                    break;
                }
                m.insert(post.clone(), json!(n));
            }
        }
        out.insert(b.to_string(), serde_json::Value::Object(m));
    }
    let n = all.map_or(0, |m| m.len());
    Ok(Json(json!({"platform": req.platform, "bits": bits_for(n, d.cfg.bucket_posts), "buckets": out})))
}

/// Every non-zero count of a platform, or those changed after `since`. Extensions keep the table and
/// sync it instead of asking about the posts on a page, so the directory does not learn what anyone
/// reads. At scale the table is also split into buckets (docs/real-servers.md).
async fn table(State(d): State<St>, Query(q): Query<ListQ>) -> Result<Json<CountTable>, ApiErr> {
    let prefix = format!("{}|", q.platform);
    let instance = d.instance().await?;
    let (seq, _) = d.sync_point().await?;
    let full = q.since == 0 || q.since > seq || q.instance.as_deref() != Some(instance.as_str());
    let counts = d
        .store
        .list(T_COUNTS)
        .await?
        .into_iter()
        .filter_map(|(k, v)| {
            let (n, s) = count_of(&v);
            (full || s > q.since).then(|| Some((k.strip_prefix(&prefix)?.to_string(), n)))?
        })
        .collect();
    Ok(Json(CountTable { platform: q.platform, instance, seq, full, counts }))
}

#[cfg(test)]
mod bucket_tests {
    use super::*;

    #[test]
    fn buckets_hold_about_the_set_number_of_posts() {
        assert_eq!(bits_for(0, 32), 0);
        assert_eq!(bits_for(32, 32), 0);
        assert_eq!(bits_for(33, 32), 1);
        assert_eq!(bits_for(32 * 1024, 32), 10);
        assert_eq!(bits_for(usize::MAX / 2, 32), MAX_BUCKET_BITS);
        for n in [100usize, 5_000, 1_000_000] {
            let b = bits_for(n, 32);
            assert!(n >> b <= 32 && (b == 0 || n >> (b - 1) > 32), "{n} posts: {b} bits");
        }
    }
}
