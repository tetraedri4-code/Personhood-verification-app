//! Measures what the holder app sends and receives, per operation, as JSON body bytes. Run with
//! `cargo test --release -p pop-cli --test data_usage -- --ignored --nocapture`.
//! docs/data-usage.md is written from this output.
use async_trait::async_trait;
use pop_cli::devnet::{self, DevnetOpts};
use pop_cli::wiring::{self, PlatformOpts};
use pop_crypto::{ProofSystem, SchemeConfig, StatementKind};
use pop_holder::{Holder, MemoryWallet};
use pop_protocol::api::*;
use pop_protocol::http::HttpClient;
use pop_protocol::platform::CodePlacement;
use serde::Serialize;
use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

#[derive(Default)]
struct Tally(Mutex<BTreeMap<&'static str, (u64, u64, u64)>>);

impl Tally {
    fn add(&self, name: &'static str, up: usize, down: usize) {
        let mut g = self.0.lock().unwrap();
        let e = g.entry(name).or_default();
        *e = (e.0 + 1, e.1 + up as u64, e.2 + down as u64);
    }
    fn take(&self) -> BTreeMap<&'static str, (u64, u64, u64)> {
        std::mem::take(&mut *self.0.lock().unwrap())
    }
}

fn len<T: Serialize + ?Sized>(v: &T) -> usize {
    serde_json::to_vec(v).map(|b| b.len()).unwrap_or(0)
}

struct Counting {
    inner: HttpClient,
    tally: Arc<Tally>,
}

macro_rules! counted {
    ($self:ident, $name:literal, $up:expr, $call:expr) => {{
        let r = $call.await;
        $self.tally.add($name, $up, r.as_ref().map(|v| len(v)).unwrap_or(0));
        r
    }};
}

#[async_trait]
impl IssuerApi for Counting {
    async fn params(&self) -> Result<Params, ApiError> {
        counted!(self, "issuer params", 0, IssuerApi::params(&self.inner))
    }
    async fn lego_keys(&self, kind: StatementKind) -> Result<Vec<u8>, ApiError> {
        let r = self.inner.lego_keys(kind).await;
        self.tally.add("proving keys (once, cached)", 0, r.as_ref().map(|b| b.len()).unwrap_or(0));
        r
    }
    async fn enrol_start(&self, purpose: Purpose) -> Result<EnrolStartResponse, ApiError> {
        counted!(self, "login start", len(&EnrolStartRequest { purpose }), self.inner.enrol_start(purpose))
    }
    async fn enrol_status(&self, session: &str) -> Result<EnrolStatus, ApiError> {
        counted!(self, "login status", session.len(), self.inner.enrol_status(session))
    }
    async fn enrol_finish(&self, req: &EnrolFinishRequest) -> Result<IssuanceResponse, ApiError> {
        counted!(self, "enrol finish", len(req), self.inner.enrol_finish(req))
    }
    async fn renew(&self, req: &RenewRequest) -> Result<RenewResponse, ApiError> {
        counted!(self, "renew", len(req), self.inner.renew(req))
    }
    async fn revocations(&self) -> Result<Revocations, ApiError> {
        counted!(self, "revocation list", 0, self.inner.revocations())
    }
    async fn revocations_since(&self, since: u64) -> Result<Revocations, ApiError> {
        counted!(self, "revocation list", 0, self.inner.revocations_since(since))
    }
    async fn revoke(&self, req: &RevokeRequest) -> Result<(), ApiError> {
        counted!(self, "revoke", len(req), self.inner.revoke(req))
    }
    async fn identity_recheck(&self, req: &RecheckRequest) -> Result<RecheckResponse, ApiError> {
        counted!(self, "re-check", len(req), self.inner.identity_recheck(req))
    }
    async fn replace(&self, req: &ReplaceRequest) -> Result<ReplaceResponse, ApiError> {
        counted!(self, "replace", len(req), self.inner.replace(req))
    }
    async fn replace_claim(&self, req: &ClaimRequest) -> Result<IssuanceResponse, ApiError> {
        counted!(self, "replace claim", len(req), self.inner.replace_claim(req))
    }
    async fn replace_pending(&self) -> Result<PendingReplacements, ApiError> {
        counted!(self, "pending replacements", 0, self.inner.replace_pending())
    }
    async fn backup_put(&self, req: &BackupPut) -> Result<Option<String>, ApiError> {
        counted!(self, "backup upload", len(req), self.inner.backup_put(req))
    }
    async fn backup_get(&self, id: &str) -> Result<BackupBlob, ApiError> {
        counted!(self, "backup download", id.len(), self.inner.backup_get(id))
    }
}

#[async_trait]
impl DirectoryApi for Counting {
    async fn bind(&self, req: &BindRequest) -> Result<BindingEntry, ApiError> {
        counted!(self, "bind", len(req), self.inner.bind(req))
    }
    async fn withdraw(&self, req: &WithdrawRequest) -> Result<(), ApiError> {
        counted!(self, "withdraw", len(req), self.inner.withdraw(req))
    }
    async fn recheck(&self, platform: &str, account_id: &str) -> Result<Vec<BindingEntry>, ApiError> {
        counted!(self, "code re-check", platform.len() + account_id.len(), DirectoryApi::recheck(&self.inner, platform, account_id))
    }
    async fn list(&self, platform: &str) -> Result<BindingList, ApiError> {
        counted!(self, "binding list", 0, self.inner.list(platform))
    }
    async fn like(&self, req: &LikeRequest) -> Result<LikeResponse, ApiError> {
        counted!(self, "like", len(req), self.inner.like(req))
    }
    async fn counts(&self, req: &CountsRequest) -> Result<CountsResponse, ApiError> {
        counted!(self, "counts", len(req), self.inner.counts(req))
    }
}

#[tokio::test]
#[ignore]
async fn data_usage() {
    for (name, ps) in [("LegoGroth16 (default)", ProofSystem::LegoGroth16), ("Bulletproofs", ProofSystem::Bulletproofs)] {
        // tree depth 8 (65,000 revocations) is the default of a real deployment
        let d = devnet::start(DevnetOpts { scheme: SchemeConfig { proof_system: ps, ..Default::default() }, data_dir: None, ports: [0; 4], rollout: true, uniqueness: devnet::UniquenessMode::Hmac, replace_wait_days: None })
            .await
            .unwrap();
        let tally = Arc::new(Tally::default());
        let p = wiring::platforms(&PlatformOpts { mockfeed_url: Some(d.feed_url.clone()), mockfeed_as: Some("alice".into()), ..Default::default() });
        let h = Holder::new(
            Arc::new(Counting { inner: HttpClient::new(&d.issuer_url), tally: tally.clone() }),
            Arc::new(Counting { inner: HttpClient::new(&d.directory_url), tally: tally.clone() }),
            p,
            Arc::new(MemoryWallet::default()),
        );
        println!("\n=== {name}, tree depth {} ===", SchemeConfig::default().tree_depth);
        let report = |op: &str| {
            let t = tally.take();
            let (mut up, mut down) = (0, 0);
            println!("{op}");
            for (k, (n, u, dn)) in &t {
                println!("    {k:<32} x{n:<2} up {u:>9} B   down {dn:>9} B");
                if !k.starts_with("proving keys") {
                    up += u;
                    down += dn;
                }
            }
            println!("    {:<32}     up {up:>9} B   down {down:>9} B   (without proving keys)", "TOTAL");
        };
        let url = h.enrol_start().await.unwrap();
        let code = devnet::mock_login(&url, "T-DATA-1").await.unwrap();
        h.enrol_finish(&code).await.unwrap();
        report("enrol");
        h.bind("mockfeed", "alice", 1, CodePlacement::Bio).await.unwrap();
        report("bind one account");
        h.like("mockfeed", "p1").await.unwrap();
        report("report one like");
        h.renew().await.unwrap();
        report("renew (quarterly)");
        h.backup_create().await.unwrap();
        report("create backup");
        let url = h.recheck_start().await.unwrap();
        let code = devnet::mock_login(&url, "T-DATA-1").await.unwrap();
        h.recheck_finish(&code).await.unwrap();
        report("identity re-check (every two years), incl. backup update");
        h.pending_replacement().await.unwrap();
        report("check for a waiting replacement (app start)");
        let url = h.replace_start().await.unwrap();
        let code = devnet::mock_login(&url, "T-DATA-1").await.unwrap();
        h.replace_finish(&code).await.unwrap();
        report("replace the secret, incl. backup update");

        // what the browser extension downloads: the first sync, then a sync after one more like
        let http = reqwest::Client::builder().no_gzip().build().unwrap();
        let get = |path: String, gzip: bool| {
            let mut r = http.get(format!("{}{path}", d.directory_url));
            if gzip {
                r = r.header("accept-encoding", "gzip");
            }
            async move { r.send().await.unwrap().bytes().await.unwrap() }
        };
        let list = get("/v1/bindings?platform=mockfeed&since=0".into(), false).await;
        let list_gz = get("/v1/bindings?platform=mockfeed&since=0".into(), true).await;
        let parsed = serde_json::from_slice::<BindingList>(&list).unwrap();
        let table = get("/v1/likes/table?platform=mockfeed&since=0".into(), false).await;
        let t: CountTable = serde_json::from_slice(&table).unwrap();
        println!("extension, first sync: binding list {} B ({} B gzip) for {} entries; likes table {} B for {} posts", list.len(), list_gz.len(), parsed.entries.len(), table.len(), t.counts.len());
        let empty = get(format!("/v1/bindings?platform=mockfeed&since={}&instance={}", parsed.seq, parsed.instance), false).await;
        let empty_t = get(format!("/v1/likes/table?platform=mockfeed&since={}&instance={}", t.seq, t.instance), false).await;
        println!("extension, sync with no changes: {} B + {} B", empty.len(), empty_t.len());
        // a larger list, to see per-entry sizes and what gzip does to them
        let mut big = parsed.clone();
        big.entries = (0..1000).map(|i| {
            let mut e = parsed.entries[0].clone();
            e.account_id = format!("did:plc:{:024x}", i * 7919);
            e.handle = format!("user{i}.example.social");
            e.nym = pop_crypto::fingerprint(&format!("n{i}"));
            e.code = format!("pop1-{:04x}-{:04x}-{:04x}", i, i * 3, i * 7);
            e
        }).collect();
        let raw = serde_json::to_vec(&big).unwrap();
        let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
        std::io::Write::write_all(&mut enc, &raw).unwrap();
        let gz = enc.finish().unwrap();
        println!("1,000 synthetic entries: {} B, {} B gzip", raw.len(), gz.len());
    }
}
