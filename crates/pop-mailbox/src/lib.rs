//! # pop-mailbox
//!
//! Holds encrypted likes from a paired computer until the holder app collects them
//! (`pop_protocol::mailbox`, docs/pairing.md). The server never sees the words or the keys: it keeps,
//! per mailbox, the end of the period with the tag that vouches for it, and padded ciphertexts with the
//! hash of their deletion codes.
//!
//! Rules it enforces:
//! * a mailbox is opened once, for at most [`MAX_PERIOD_MS`]; opening it again with the same end is a no-op
//! * deposits are refused after the end (or after an early close), and beyond [`MAX_ITEMS`]
//! * an item is deleted by whoever shows the code inside it, that is, whoever could decrypt it
//! * everything is deleted [`KEEP_AFTER_END_MS`] after the end
//!
//! The mailbox id is a bearer secret, so it travels only in POST bodies, never in a URL that a log could
//! keep, and is stored only as its SHA-256. State goes through `pop_storage::Store`, so the mailbox can
//! run inside the directory's process (as in the demo) or on its own.
use axum::{extract::State, http::StatusCode, response::IntoResponse, routing::post, Json, Router};
use pop_protocol::mailbox::*;
use pop_storage::SharedStore;
use serde::{Deserialize, Serialize};
use serde_json::json;
use sha2::Digest;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

const T_MAILBOX: &str = "mailbox";
/// The end may lie this much beyond [`MAX_PERIOD_MS`] from the server's now: the two clocks differ a little.
const CLOCK_SLACK_MS: u64 = 120_000;
const SWEEP_EVERY: std::time::Duration = std::time::Duration::from_secs(600);

#[derive(Clone, Debug)]
pub struct MailboxConfig {
    /// open mailboxes at most; beyond it new pairings are refused until old ones expire
    pub max_mailboxes: u64,
    /// items held at most over all mailboxes (each about 1 kB); beyond it deposits wait for collections
    pub max_items_total: u64,
}

impl Default for MailboxConfig {
    fn default() -> Self {
        MailboxConfig { max_mailboxes: 100_000, max_items_total: 200_000 }
    }
}

pub struct Mailboxes {
    store: SharedStore,
    cfg: MailboxConfig,
    /// read-modify-write of a mailbox record happens under this lock
    lock: tokio::sync::Mutex<()>,
    /// items held over all mailboxes; counted from the store at the first deposit
    items_total: std::sync::Mutex<Option<u64>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Record {
    end_ms: u64,
    tag: String,
    #[serde(default)]
    closed_ms: Option<u64>,
    next_seq: u64,
    items: Vec<Item>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct Item {
    seq: u64,
    received_ms: u64,
    item: String,
    dh: String,
}

impl Record {
    fn end(&self) -> u64 {
        self.closed_ms.map_or(self.end_ms, |c| c.min(self.end_ms))
    }
    fn expired(&self, now: u64) -> bool {
        now > self.end().saturating_add(KEEP_AFTER_END_MS)
    }
}

pub fn now_ms() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_millis() as u64).unwrap_or(0)
}

#[derive(Debug)]
pub struct MbError(pub StatusCode, pub String);

impl IntoResponse for MbError {
    fn into_response(self) -> axum::response::Response {
        (self.0, Json(json!({"error": self.1}))).into_response()
    }
}

impl From<pop_storage::StoreError> for MbError {
    fn from(e: pop_storage::StoreError) -> Self {
        MbError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string())
    }
}

fn bad(msg: &str) -> MbError {
    MbError(StatusCode::BAD_REQUEST, msg.into())
}

fn not_found() -> MbError {
    MbError(StatusCode::NOT_FOUND, "no such pairing (check the words)".into())
}

fn key(mailbox: &str) -> Result<String, MbError> {
    if !is_mailbox_id(mailbox) {
        return Err(bad("mailbox must be 32 bytes of lowercase hex"));
    }
    Ok(hex::encode(sha2::Sha256::digest(mailbox.as_bytes())))
}

fn is_hex(s: &str, len: usize) -> bool {
    s.len() == len && s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

const ITEM_HEX: usize = 2 * (12 + ITEM_PLAIN_BYTES + 16);

impl Mailboxes {
    pub fn new(store: SharedStore, cfg: MailboxConfig) -> Self {
        Mailboxes { store, cfg, lock: tokio::sync::Mutex::new(()), items_total: std::sync::Mutex::new(None) }
    }

    async fn get(&self, k: &str, now: u64) -> Result<Option<Record>, MbError> {
        let Some(v) = self.store.get(T_MAILBOX, k).await? else { return Ok(None) };
        let r: Record = serde_json::from_value(v).map_err(|e| MbError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        if r.expired(now) {
            self.store.delete(T_MAILBOX, k).await?;
            self.forget_items(r.items.len());
            return Ok(None);
        }
        Ok(Some(r))
    }

    fn forget_items(&self, n: usize) {
        if let Some(t) = self.items_total.lock().unwrap().as_mut() {
            *t = t.saturating_sub(n as u64);
        }
    }

    async fn total_items(&self) -> Result<u64, MbError> {
        if let Some(t) = *self.items_total.lock().unwrap() {
            return Ok(t);
        }
        let mut t = 0;
        for (_, v) in self.store.list(T_MAILBOX).await? {
            t += serde_json::from_value::<Record>(v).map(|r| r.items.len() as u64).unwrap_or(0);
        }
        *self.items_total.lock().unwrap() = Some(t);
        Ok(t)
    }

    async fn put(&self, k: &str, r: &Record) -> Result<(), MbError> {
        let v = serde_json::to_value(r).map_err(|e| MbError(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;
        Ok(self.store.put(T_MAILBOX, k, v).await?)
    }

    pub async fn open(&self, r: &OpenRequest, now: u64) -> Result<(), MbError> {
        let k = key(&r.mailbox)?;
        if !is_hex(&r.tag, 64) {
            return Err(bad("tag must be 32 bytes of lowercase hex"));
        }
        if r.end_ms <= now {
            return Err(bad("the end of the pairing has passed"));
        }
        if r.end_ms > now + MAX_PERIOD_MS + CLOCK_SLACK_MS {
            return Err(bad("a pairing lasts at most 30 days"));
        }
        let _g = self.lock.lock().await;
        if let Some(old) = self.get(&k, now).await? {
            // a repeated open (a retry) is fine; anything else would move the end
            return if old.end_ms == r.end_ms && old.tag == r.tag { Ok(()) } else { Err(MbError(StatusCode::CONFLICT, "this pairing is already open".into())) };
        }
        if self.store.count(T_MAILBOX).await? >= self.cfg.max_mailboxes {
            return Err(MbError(StatusCode::SERVICE_UNAVAILABLE, "too many pairings open; try later".into()));
        }
        self.put(&k, &Record { end_ms: r.end_ms, tag: r.tag.clone(), closed_ms: None, next_seq: 1, items: vec![] }).await
    }

    pub async fn deposit(&self, r: &DepositRequest, now: u64) -> Result<u64, MbError> {
        let k = key(&r.mailbox)?;
        if !is_hex(&r.item, ITEM_HEX) {
            return Err(bad("item has the wrong length"));
        }
        if !is_hex(&r.dh, 64) {
            return Err(bad("dh must be 32 bytes of lowercase hex"));
        }
        let _g = self.lock.lock().await;
        let mut rec = self.get(&k, now).await?.ok_or_else(not_found)?;
        if now > rec.end() || rec.closed_ms.is_some() {
            return Err(MbError(StatusCode::GONE, "this pairing has ended".into()));
        }
        if rec.items.len() >= MAX_ITEMS {
            return Err(MbError(StatusCode::TOO_MANY_REQUESTS, "the mailbox is full until the app collects it".into()));
        }
        if self.total_items().await? >= self.cfg.max_items_total {
            return Err(MbError(StatusCode::SERVICE_UNAVAILABLE, "the mailbox server is full; try later".into()));
        }
        let seq = rec.next_seq;
        rec.next_seq += 1;
        rec.items.push(Item { seq, received_ms: now, item: r.item.clone(), dh: r.dh.clone() });
        self.put(&k, &rec).await?;
        if let Some(t) = self.items_total.lock().unwrap().as_mut() {
            *t += 1;
        }
        Ok(seq)
    }

    pub async fn list(&self, r: &ListRequest, now: u64) -> Result<MailboxState, MbError> {
        let k = key(&r.mailbox)?;
        let rec = self.get(&k, now).await?.ok_or_else(not_found)?;
        Ok(MailboxState {
            end_ms: rec.end_ms,
            tag: rec.tag,
            closed_ms: rec.closed_ms,
            items: rec.items.into_iter().filter(|i| i.seq > r.after).map(|i| StoredItem { seq: i.seq, received_ms: i.received_ms, item: i.item }).collect(),
        })
    }

    pub async fn delete(&self, r: &DeleteRequest, now: u64) -> Result<u64, MbError> {
        let k = key(&r.mailbox)?;
        if r.codes.len() > MAX_ITEMS {
            return Err(bad("too many codes"));
        }
        let hashes: Vec<String> = r.codes.iter().filter_map(|c| deletion_hash(c)).collect();
        let _g = self.lock.lock().await;
        let mut rec = self.get(&k, now).await?.ok_or_else(not_found)?;
        let before = rec.items.len();
        rec.items.retain(|i| !hashes.contains(&i.dh));
        let n = (before - rec.items.len()) as u64;
        if n > 0 {
            self.put(&k, &rec).await?;
            self.forget_items(n as usize);
        }
        Ok(n)
    }

    pub async fn close(&self, r: &CloseRequest, now: u64) -> Result<(), MbError> {
        let k = key(&r.mailbox)?;
        let _g = self.lock.lock().await;
        let mut rec = self.get(&k, now).await?.ok_or_else(not_found)?;
        if now < rec.end() {
            rec.closed_ms = Some(now);
            self.put(&k, &rec).await?;
        }
        Ok(())
    }

    /// Delete every mailbox past its keeping time.
    pub async fn sweep(&self, now: u64) -> Result<usize, MbError> {
        let _g = self.lock.lock().await;
        let mut n = 0;
        for (k, v) in self.store.list(T_MAILBOX).await? {
            let rec = serde_json::from_value::<Record>(v).ok();
            if rec.as_ref().map_or(true, |r| r.expired(now)) {
                self.store.delete(T_MAILBOX, &k).await?;
                self.forget_items(rec.map_or(0, |r| r.items.len()));
                n += 1;
            }
        }
        Ok(n)
    }
}

type St = Arc<Mailboxes>;

/// Routes under `/v1/mailbox/`, all POST with JSON bodies. Starts a task that deletes expired mailboxes.
pub fn router(m: Arc<Mailboxes>) -> Router {
    let sweeper = m.clone();
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(SWEEP_EVERY).await;
            if let Err(e) = sweeper.sweep(now_ms()).await {
                tracing::warn!("mailbox sweep: {}", e.1);
            }
        }
    });
    Router::new()
        .route("/v1/mailbox/open", post(open))
        .route("/v1/mailbox/deposit", post(deposit))
        .route("/v1/mailbox/list", post(list))
        .route("/v1/mailbox/delete", post(delete))
        .route("/v1/mailbox/close", post(close))
        // called from the browser extension; no cookies or credentials are used
        .layer(CorsLayer::permissive())
        .with_state(m)
}

async fn open(State(m): State<St>, Json(r): Json<OpenRequest>) -> Result<Json<serde_json::Value>, MbError> {
    m.open(&r, now_ms()).await?;
    Ok(Json(json!({"end_ms": r.end_ms})))
}

async fn deposit(State(m): State<St>, Json(r): Json<DepositRequest>) -> Result<Json<serde_json::Value>, MbError> {
    Ok(Json(json!({"seq": m.deposit(&r, now_ms()).await?})))
}

async fn list(State(m): State<St>, Json(r): Json<ListRequest>) -> Result<Json<MailboxState>, MbError> {
    Ok(Json(m.list(&r, now_ms()).await?))
}

async fn delete(State(m): State<St>, Json(r): Json<DeleteRequest>) -> Result<Json<serde_json::Value>, MbError> {
    Ok(Json(json!({"deleted": m.delete(&r, now_ms()).await?})))
}

async fn close(State(m): State<St>, Json(r): Json<CloseRequest>) -> Result<Json<serde_json::Value>, MbError> {
    m.close(&r, now_ms()).await?;
    Ok(Json(json!({})))
}

#[cfg(test)]
mod tests {
    use super::*;
    use pop_storage::MemoryStore;

    const H: u64 = 3_600_000;

    fn setup() -> (Mailboxes, PairingKeys) {
        (Mailboxes::new(Arc::new(MemoryStore::new()), MailboxConfig { max_mailboxes: 2, max_items_total: (MAX_ITEMS + 1) as u64 }), PairingKeys::derive_canonical("able acid acorn actor adapt admit adult advice aerial", 10))
    }

    fn dep(k: &PairingKeys, post: &str) -> (DepositRequest, PairedLike) {
        let like = PairedLike::new("mockfeed", post, 1);
        let (item, dh) = k.seal(&like).unwrap();
        (DepositRequest { mailbox: k.mailbox.clone(), item, dh }, like)
    }

    #[tokio::test]
    async fn lifecycle() {
        let (m, k) = setup();
        let t0 = 1_700_000_000_000;
        let end = t0 + 2 * H;
        let open = OpenRequest { mailbox: k.mailbox.clone(), end_ms: end, tag: k.end_tag(end) };
        m.open(&open, t0).await.unwrap();
        m.open(&open, t0 + 1).await.unwrap();
        // the end cannot be moved
        let later = OpenRequest { end_ms: end + H, tag: k.end_tag(end + H), ..open.clone() };
        assert_eq!(m.open(&later, t0).await.unwrap_err().0, StatusCode::CONFLICT);

        let (d1, l1) = dep(&k, "p1");
        let (d2, _) = dep(&k, "p2");
        assert_eq!(m.deposit(&d1, t0 + 10).await.unwrap(), 1);
        assert_eq!(m.deposit(&d2, t0 + 20).await.unwrap(), 2);
        let st = m.list(&ListRequest { mailbox: k.mailbox.clone(), after: 0 }, t0 + 30).await.unwrap();
        assert!(k.check_end_tag(st.end_ms, &st.tag));
        assert_eq!(st.items.len(), 2);
        assert_eq!(k.open(&st.items[0].item).unwrap(), l1);
        assert_eq!(m.list(&ListRequest { mailbox: k.mailbox.clone(), after: 1 }, t0 + 30).await.unwrap().items.len(), 1);

        // a wrong code deletes nothing; the right one deletes its item only
        let wrong = DeleteRequest { mailbox: k.mailbox.clone(), codes: vec!["00".repeat(32), d1.dh.clone()] };
        assert_eq!(m.delete(&wrong, t0 + 40).await.unwrap(), 0);
        assert_eq!(m.delete(&DeleteRequest { mailbox: k.mailbox.clone(), codes: vec![l1.d.clone()] }, t0 + 40).await.unwrap(), 1);
        assert_eq!(m.list(&ListRequest { mailbox: k.mailbox.clone(), after: 0 }, t0 + 50).await.unwrap().items.len(), 1);

        // after the end: no deposits, items still collectable until the keeping time is over
        assert_eq!(m.deposit(&dep(&k, "p3").0, end + 1).await.unwrap_err().0, StatusCode::GONE);
        assert_eq!(m.list(&ListRequest { mailbox: k.mailbox.clone(), after: 0 }, end + 1).await.unwrap().items.len(), 1);
        assert_eq!(m.list(&ListRequest { mailbox: k.mailbox.clone(), after: 0 }, end + KEEP_AFTER_END_MS + 1).await.unwrap_err().0, StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn close_limits_and_sweep() {
        let (m, k) = setup();
        let t0 = 1_700_000_000_000;
        let end = t0 + 2 * H;
        assert_eq!(m.open(&OpenRequest { mailbox: k.mailbox.clone(), end_ms: t0 - 1, tag: k.end_tag(t0 - 1) }, t0).await.unwrap_err().0, StatusCode::BAD_REQUEST);
        let far = t0 + MAX_PERIOD_MS + CLOCK_SLACK_MS + 1;
        assert_eq!(m.open(&OpenRequest { mailbox: k.mailbox.clone(), end_ms: far, tag: k.end_tag(far) }, t0).await.unwrap_err().0, StatusCode::BAD_REQUEST);
        m.open(&OpenRequest { mailbox: k.mailbox.clone(), end_ms: end, tag: k.end_tag(end) }, t0).await.unwrap();

        // full
        for i in 0..MAX_ITEMS {
            m.deposit(&dep(&k, &format!("p{i}")).0, t0 + 1).await.unwrap();
        }
        assert_eq!(m.deposit(&dep(&k, "x").0, t0 + 1).await.unwrap_err().0, StatusCode::TOO_MANY_REQUESTS);

        // closed early: deposits refused at once, the vouched end is still shown
        m.close(&CloseRequest { mailbox: k.mailbox.clone() }, t0 + 100).await.unwrap();
        let st = m.list(&ListRequest { mailbox: k.mailbox.clone(), after: 0 }, t0 + 200).await.unwrap();
        assert_eq!((st.end_ms, st.closed_ms, st.end()), (end, Some(t0 + 100), t0 + 100));
        assert!(m.deposit(&dep(&k, "y").0, t0 + 200).await.is_err());

        // the cap on open mailboxes
        let k2 = PairingKeys::derive_canonical("zoo zone zinc zero zebra youth young yogurt yoga", 10);
        let k3 = PairingKeys::derive_canonical("zoo zone zinc zero zebra youth young yogurt yard", 10);
        m.open(&OpenRequest { mailbox: k2.mailbox.clone(), end_ms: end, tag: k2.end_tag(end) }, t0).await.unwrap();
        // the cap on items over all mailboxes: one more fits, then none
        m.deposit(&dep(&k2, "a").0, t0 + 300).await.unwrap();
        assert_eq!(m.deposit(&dep(&k2, "b").0, t0 + 300).await.unwrap_err().0, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(m.open(&OpenRequest { mailbox: k3.mailbox.clone(), end_ms: end, tag: k3.end_tag(end) }, t0).await.unwrap_err().0, StatusCode::SERVICE_UNAVAILABLE);

        // the sweep frees them after the keeping time
        assert_eq!(m.sweep(t0 + 100 + KEEP_AFTER_END_MS + 1).await.unwrap(), 1);
        assert_eq!(m.sweep(end + KEEP_AFTER_END_MS + 1).await.unwrap(), 1);
        m.open(&OpenRequest { mailbox: k3.mailbox.clone(), end_ms: end + KEEP_AFTER_END_MS + 3 * H, tag: k3.end_tag(end + KEEP_AFTER_END_MS + 3 * H) }, end + KEEP_AFTER_END_MS + 2).await.unwrap();

        // malformed input
        assert_eq!(m.list(&ListRequest { mailbox: "AB".into(), after: 0 }, t0).await.unwrap_err().0, StatusCode::BAD_REQUEST);
        let (mut d, _) = dep(&k3, "z");
        d.item.pop();
        assert_eq!(m.deposit(&d, t0).await.unwrap_err().0, StatusCode::BAD_REQUEST);
    }
}
