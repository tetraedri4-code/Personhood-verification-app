//! HTTP clients for [`IssuerApi`] and [`DirectoryApi`]. To route traffic through a relay (design §4.7),
//! give the clients a `reqwest::Client` configured with a proxy, or implement the traits differently.
use crate::api::*;
use async_trait::async_trait;
use pop_crypto::StatementKind;
use serde::{de::DeserializeOwned, Serialize};

#[derive(Clone)]
pub struct HttpClient {
    base: String,
    client: reqwest::Client,
}

impl HttpClient {
    pub fn new(base: &str) -> Self {
        Self::with_client(base, reqwest::Client::new())
    }
    pub fn with_client(base: &str, client: reqwest::Client) -> Self {
        HttpClient { base: base.trim_end_matches('/').to_string(), client }
    }
    pub fn base(&self) -> &str {
        &self.base
    }

    async fn check(resp: reqwest::Response) -> Result<reqwest::Response, ApiError> {
        let status = resp.status();
        if status.is_success() {
            return Ok(resp);
        }
        let text = resp.text().await.unwrap_or_default();
        let message = serde_json::from_str::<ErrorBody>(&text).map(|e| e.error).unwrap_or(text);
        Err(ApiError::Server { status: status.as_u16(), message })
    }

    pub async fn get<T: DeserializeOwned>(&self, path: &str) -> Result<T, ApiError> {
        let r = self.client.get(format!("{}{}", self.base, path)).send().await.map_err(|e| ApiError::Transport(e.to_string()))?;
        Self::check(r).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))
    }

    pub async fn get_bytes(&self, path: &str) -> Result<Vec<u8>, ApiError> {
        let r = self.client.get(format!("{}{}", self.base, path)).send().await.map_err(|e| ApiError::Transport(e.to_string()))?;
        Ok(Self::check(r).await?.bytes().await.map_err(|e| ApiError::Decode(e.to_string()))?.to_vec())
    }

    pub async fn post<B: Serialize + ?Sized, T: DeserializeOwned>(&self, path: &str, body: &B) -> Result<T, ApiError> {
        let r = self
            .client
            .post(format!("{}{}", self.base, path))
            .json(body)
            .send()
            .await
            .map_err(|e| ApiError::Transport(e.to_string()))?;
        Self::check(r).await?.json().await.map_err(|e| ApiError::Decode(e.to_string()))
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
