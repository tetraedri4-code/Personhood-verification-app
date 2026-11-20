//! HTTP clients for [`IssuerApi`] and [`DirectoryApi`]. How a request reaches the server is a
//! [`Transport`]: [`Direct`] sends it as it is; `pop_ohttp::Oblivious` sends it through an Oblivious HTTP
//! relay (RFC 9458), so that the server does not learn who sent it (design §4.7).
use crate::api::*;
use async_trait::async_trait;
use pop_crypto::StatementKind;
use serde::{de::DeserializeOwned, Serialize};
use std::sync::Arc;

/// A response as the transport received it.
pub struct RawResponse {
    pub status: u16,
    pub body: Vec<u8>,
    /// the server's `Date` header (through a relay: inside the encrypted answer)
    pub server_date: Option<String>,
    /// the relay's own `Date` header, when the request went through one
    pub relay_date: Option<String>,
}

/// Carries one request to a server. `base` is the server's address (scheme and host), `path` starts with
/// `/` and may hold a query; a body is always JSON.
#[async_trait]
pub trait Transport: Send + Sync {
    async fn send(&self, method: &str, base: &str, path: &str, json_body: Option<Vec<u8>>) -> Result<RawResponse, ApiError>;
}

/// Straight to the server: it sees this computer's address.
pub struct Direct(pub reqwest::Client);

#[async_trait]
impl Transport for Direct {
    async fn send(&self, method: &str, base: &str, path: &str, json_body: Option<Vec<u8>>) -> Result<RawResponse, ApiError> {
        let method = reqwest::Method::from_bytes(method.as_bytes()).map_err(|e| ApiError::Transport(e.to_string()))?;
        let mut rb = self.0.request(method, format!("{base}{path}"));
        if let Some(b) = json_body {
            rb = rb.header(reqwest::header::CONTENT_TYPE, "application/json").body(b);
        }
        let r = rb.send().await.map_err(|e| ApiError::Transport(e.to_string()))?;
        let status = r.status().as_u16();
        let server_date = r.headers().get(reqwest::header::DATE).and_then(|v| v.to_str().ok()).map(String::from);
        let body = r.bytes().await.map_err(|e| ApiError::Transport(e.to_string()))?.to_vec();
        Ok(RawResponse { status, body, server_date, relay_date: None })
    }
}

#[derive(Clone)]
pub struct HttpClient {
    base: String,
    transport: Arc<dyn Transport>,
    /// where the dates of answers go, and which server this is
    clock: Option<(Arc<crate::clock::Clock>, crate::clock::Source)>,
}

impl HttpClient {
    pub fn new(base: &str) -> Self {
        Self::with_client(base, reqwest::Client::new())
    }
    pub fn with_client(base: &str, client: reqwest::Client) -> Self {
        Self::with_transport(base, Arc::new(Direct(client)))
    }
    pub fn with_transport(base: &str, transport: Arc<dyn Transport>) -> Self {
        HttpClient { base: base.trim_end_matches('/').to_string(), transport, clock: None }
    }
    /// Report the dates of this server's answers (and of its relay's) to `clock`.
    pub fn with_clock(mut self, clock: Arc<crate::clock::Clock>, source: crate::clock::Source) -> Self {
        self.clock = Some((clock, source));
        self
    }
    pub fn base(&self) -> &str {
        &self.base
    }

    async fn send(&self, method: &str, path: &str, body: Option<Vec<u8>>) -> Result<Vec<u8>, ApiError> {
        let r = self.transport.send(method, &self.base, path, body).await?;
        if let Some((c, src)) = &self.clock {
            if let Some(d) = &r.server_date {
                c.observe_http_date(*src, d);
            }
            if let Some(d) = &r.relay_date {
                c.observe_http_date(crate::clock::Source::Relay, d);
            }
        }
        if (200..300).contains(&r.status) {
            return Ok(r.body);
        }
        let text = String::from_utf8_lossy(&r.body).into_owned();
        let message = serde_json::from_str::<ErrorBody>(&text).map(|e| e.error).unwrap_or(text);
        Err(ApiError::Server { status: r.status, message })
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let b = self.send("GET", path, None).await?;
        serde_json::from_slice(&b).map_err(|e| ApiError::Decode(e.to_string()))
    }

    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>, ApiError> {
        self.send("GET", path, None).await
    }

    pub async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T, ApiError> {
        let body = serde_json::to_vec(body).map_err(|e| ApiError::Decode(e.to_string()))?;
        let b = self.send("POST", path, Some(body)).await?;
        serde_json::from_slice(&b).map_err(|e| ApiError::Decode(e.to_string()))
    }
}

fn enc(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

#[async_trait]
impl IssuerApi for HttpClient {
    async fn params(&self) -> Result<Params, ApiError> {
        self.get("/v1/params").await
    }
    async fn lego_keys(&self, kind: StatementKind) -> Result<Vec<u8>, ApiError> {
        self.get_bytes(&format!("/v1/params/lego/{}", kind.name())).await
    }
    async fn enrol_start(&self, purpose: Purpose) -> Result<EnrolStartResponse, ApiError> {
        self.post("/v1/enrol/start", &EnrolStartRequest { purpose }).await
    }
    async fn enrol_status(&self, session: &str) -> Result<EnrolStatus, ApiError> {
        self.get(&format!("/v1/enrol/status?session={}", enc(session))).await
    }
    async fn enrol_finish(&self, req: &EnrolFinishRequest) -> Result<IssuanceResponse, ApiError> {
        self.post("/v1/enrol/finish", req).await
    }
    async fn renew(&self, req: &RenewRequest) -> Result<RenewResponse, ApiError> {
        self.post("/v1/renew", req).await
    }
    async fn revocations(&self) -> Result<Revocations, ApiError> {
        self.get("/v1/revocations").await
    }
    async fn revocations_since(&self, since: u64) -> Result<Revocations, ApiError> {
        self.get(&format!("/v1/revocations?since={since}")).await
    }
    async fn revoke(&self, req: &RevokeRequest) -> Result<(), ApiError> {
        let _: serde_json::Value = self.post("/v1/revoke", req).await?;
        Ok(())
    }
    async fn reports(&self) -> Result<Reports, ApiError> {
        self.get("/v1/reports").await
    }
    async fn identity_recheck(&self, req: &RecheckRequest) -> Result<RecheckResponse, ApiError> {
        self.post("/v1/recheck", req).await
    }
    async fn replace(&self, req: &ReplaceRequest) -> Result<ReplaceResponse, ApiError> {
        self.post("/v1/replace", req).await
    }
    async fn replace_claim(&self, req: &ClaimRequest) -> Result<IssuanceResponse, ApiError> {
        self.post("/v1/replace/claim", req).await
    }
    async fn replace_pending(&self) -> Result<PendingReplacements, ApiError> {
        self.get("/v1/replace/pending").await
    }
    async fn backup_put(&self, req: &BackupPut) -> Result<Option<String>, ApiError> {
        let v: serde_json::Value = self.post("/v1/backup", req).await?;
        Ok(v["ticket"].as_str().map(String::from))
    }
    async fn backup_get(&self, id: &str) -> Result<BackupBlob, ApiError> {
        self.get(&format!("/v1/backup/{}", enc(id))).await
    }
}

#[async_trait]
impl DirectoryApi for HttpClient {
    async fn bind(&self, req: &BindRequest) -> Result<BindingEntry, ApiError> {
        self.post("/v1/bindings", req).await
    }
    async fn withdraw(&self, req: &WithdrawRequest) -> Result<(), ApiError> {
        let _: serde_json::Value = self.post("/v1/bindings/withdraw", req).await?;
        Ok(())
    }
    async fn recheck(&self, platform: &str, account_id: &str) -> Result<Vec<BindingEntry>, ApiError> {
        self.post("/v1/bindings/recheck", &serde_json::json!({"platform": platform, "account_id": account_id})).await
    }
    async fn list(&self, platform: &str) -> Result<BindingList, ApiError> {
        self.get(&format!("/v1/bindings?platform={}", enc(platform))).await
    }
    async fn list_since(&self, platform: &str, since: u64, instance: &str) -> Result<BindingList, ApiError> {
        self.get(&format!("/v1/bindings?platform={}&since={since}&instance={}", enc(platform), enc(instance))).await
    }
    async fn like(&self, req: &LikeRequest) -> Result<LikeResponse, ApiError> {
        self.post("/v1/likes", req).await
    }
    async fn counts(&self, req: &CountsRequest) -> Result<CountsResponse, ApiError> {
        self.post("/v1/likes/counts", req).await
    }
}
