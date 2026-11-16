//! JSON messages of the issuer and directory APIs, and the client traits the holder app depends on.
//! A real deployment can put these services anywhere (one host, many hosts, behind relays); the holder
//! only needs something that implements [`IssuerApi`] and [`DirectoryApi`].
use async_trait::async_trait;
use pop_crypto::{BindingProof, BlindRequest, BlindSignature, Day, IssuedAttrs, LikeProof, RenewalProof, SchemeConfig, StatementKind};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

#[derive(Debug, thiserror::Error)]
pub enum ApiError {
    #[error("{status}: {message}")]
    Server { status: u16, message: String },
    #[error("transport: {0}")]
    Transport(String),
    #[error("bad response: {0}")]
    Decode(String),
}

/// Error body every server returns.
#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorBody {
    pub error: String,
}

// ------------------------------------------------------------------ issuer

/// `GET /v1/params`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Params {
    pub config: SchemeConfig,
    pub issuer_public_key: String,
    pub witness_public_key: String,
    /// statements whose LegoGroth16 keys are at `GET /v1/params/lego/{name}`
    pub statements: Vec<StatementKind>,
    /// the issuer's current day; components accept it only within one day of their own clock
    pub today: Day,
    /// published list of identity providers: code → name
    pub providers: BTreeMap<u32, String>,
}

/// `POST /v1/enrol/start`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrolStartResponse {
    pub session: String,
    /// open this in a browser; the identity provider redirects back to the issuer
    pub authorize_url: String,
}

/// `GET /v1/enrol/status?session=`
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "kebab-case")]
pub enum EnrolStatus {
    WaitingForLogin,
    Authenticated,
    AlreadyEnrolled,
    Failed,
    Done,
}

/// `POST /v1/enrol/finish`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EnrolFinishRequest {
    pub session: String,
    pub blind_request: BlindRequest,
    /// guardian key (Ed25519, hex): signs the holder's own revocation request (design §4.2)
    pub guardian_public_key: String,
    /// the code the issuer showed in the browser after the identity check. It ties the person who
    /// logged in to the device that finishes: someone who tricks a victim into logging in through a
    /// link does not see the victim's browser.
    pub confirm_code: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuanceResponse {
    pub signature: BlindSignature,
    pub attrs: IssuedAttrs,
    pub handle_signature: String,
}

/// `POST /v1/renew`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RenewRequest {
    pub nonce: String,
    pub today: Day,
    pub revocation_root: String,
    pub proof: RenewalProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RenewResponse {
    pub signature: BlindSignature,
    pub new_expiry: Day,
}

/// `GET /v1/revocations`: the full list, so a holder computes its path without revealing its handle.
/// At scale this becomes a bucketed lookup (design §4.6).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Revocations {
    pub epoch: u64,
    pub revoked: Vec<u64>,
    pub root: String,
    /// root of the previous epoch, still accepted by verifiers
    pub previous_root: Option<String>,
}

/// `POST /v1/revoke`: the holder's own request, signed with the guardian key.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RevokeRequest {
    pub handle: u64,
    pub guardian_public_key: String,
    /// Ed25519 signature over `revoke_message(handle)`
    pub signature: String,
}

pub fn revoke_message(handle: u64) -> Vec<u8> {
    format!("pop-revoke-v1|{handle}").into_bytes()
}

// ------------------------------------------------------------------ directory

/// `POST /v1/bindings`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BindRequest {
    pub platform: String,
    pub account_id: String,
    pub handle: String,
    pub nonce: String,
    pub today: Day,
    pub revocation_root: String,
    pub proof: BindingProof,
}

/// One claim in the public list (variant B of design §4.5: publicly checkable). An account can have
/// several claims from different pseudonyms; the real one is the one whose `code` is on the account.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BindingEntry {
    pub platform: String,
    pub account_id: String,
    pub handle: String,
    pub code: String,
    pub slot: u32,
    /// fingerprint of the pseudonym (the full value is in the proof)
    pub nym: String,
    pub bound_on: Day,
    pub lease_until: Day,
    /// probation passed: the secret is older than nine months, so likes and the badge "count"
    pub counted: bool,
    /// day a server-side check last saw the code in the account's public texts, if the platform allows it
    pub code_seen_on: Option<Day>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BindingList {
    pub platform: String,
    pub today: Day,
    pub entries: Vec<BindingEntry>,
}

/// Full record with its proof, for anyone who wants to re-verify. `GET /v1/bindings/{platform}/{account}`
/// returns every claim on the account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BindingRecord {
    pub entry: BindingEntry,
    pub request: BindRequest,
}

/// `POST /v1/bindings/withdraw`: switch the badge off. Needs a binding proof over `withdraw_context`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawRequest {
    pub platform: String,
    pub account_id: String,
    pub nonce: String,
    pub today: Day,
    pub revocation_root: String,
    pub proof: BindingProof,
}

/// `POST /v1/likes`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LikeRequest {
    pub platform: String,
    pub post_id: String,
    pub today: Day,
    pub revocation_root: String,
    pub proof: LikeProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LikeResponse {
    /// false if this person had already liked the post (the tag was known)
    pub new: bool,
    pub count: u64,
}

/// `POST /v1/likes/counts`: counts for many posts at once. The extension asks for every post on the
/// page in one request.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CountsRequest {
    pub platform: String,
    pub posts: Vec<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CountsResponse {
    pub counts: BTreeMap<String, u64>,
}

// ------------------------------------------------------------------ traits

#[async_trait]
pub trait IssuerApi: Send + Sync {
    async fn params(&self) -> Result<Params, ApiError>;
    async fn lego_keys(&self, kind: StatementKind) -> Result<Vec<u8>, ApiError>;
    async fn enrol_start(&self) -> Result<EnrolStartResponse, ApiError>;
    async fn enrol_status(&self, session: &str) -> Result<EnrolStatus, ApiError>;
    async fn enrol_finish(&self, req: &EnrolFinishRequest) -> Result<IssuanceResponse, ApiError>;
    async fn renew(&self, req: &RenewRequest) -> Result<RenewResponse, ApiError>;
    async fn revocations(&self) -> Result<Revocations, ApiError>;
    async fn revoke(&self, req: &RevokeRequest) -> Result<(), ApiError>;
}

#[async_trait]
pub trait DirectoryApi: Send + Sync {
    async fn bind(&self, req: &BindRequest) -> Result<BindingEntry, ApiError>;
    async fn withdraw(&self, req: &WithdrawRequest) -> Result<(), ApiError>;
    async fn recheck(&self, platform: &str, account_id: &str) -> Result<Vec<BindingEntry>, ApiError>;
    async fn list(&self, platform: &str) -> Result<BindingList, ApiError>;
    async fn like(&self, req: &LikeRequest) -> Result<LikeResponse, ApiError>;
    async fn counts(&self, req: &CountsRequest) -> Result<CountsResponse, ApiError>;
}
