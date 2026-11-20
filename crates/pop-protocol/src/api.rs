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
    /// Set while the alarm about stolen eID logins is on (`GET /v1/reports`): secrets that count from
    /// after this day are in probation until it is lifted. Proofs are checked against
    /// `dates::count_cutoff(today, alarm_cutoff)`.
    #[serde(default)]
    pub alarm_cutoff: Option<Day>,
    /// Size classes for messages through a relay (the issuer's `policy.pad_sizes`); the directory's
    /// gateway pads with them too. Empty: the defaults of the relay code.
    #[serde(default)]
    pub pad_sizes: Vec<u32>,
    /// Likes go out on a shared schedule of windows this long: a like clicked in one window is sent
    /// at a random moment of the next (`policy.like_window_secs`). 0: at once.
    #[serde(default)]
    pub like_window_secs: u32,
}

/// `GET /v1/reports`: how many people said "it wasn't me" per week, and the rule that turns them into
/// an alarm. Public, so anyone can check that the alarm follows the rule.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Reports {
    /// Mondays and counts, oldest first, the current week last
    pub weeks: Vec<(Day, u64)>,
    pub alarm_cutoff: Option<Day>,
    pub rule: String,
}

/// What an identity check is for. One login serves exactly one purpose.
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum Purpose {
    /// first enrolment of a person
    #[default]
    Enrol,
    /// the two-year identity re-check of an existing credential (same secret, same pseudonyms)
    Recheck,
    /// replace a lost or stolen secret by a new one (recovery level 2)
    Replace,
}

/// `POST /v1/enrol/start` (an empty body means `enrol`)
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EnrolStartRequest {
    #[serde(default)]
    pub purpose: Purpose,
}

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
    /// a re-check or replacement was asked for a person with no enrolment record
    NotEnrolled,
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
    /// one-time ticket that lets this holder create one encrypted backup (`PUT /v1/backup`)
    #[serde(default)]
    pub backup_ticket: Option<String>,
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

/// `POST /v1/recheck`: the two-year identity re-check. The session comes from `enrol/start` with
/// purpose `recheck`; the proof is a renewal proof that also shows the handle and the month of the
/// last check, bound to the session.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecheckRequest {
    pub session: String,
    pub confirm_code: String,
    pub today: Day,
    pub revocation_root: String,
    pub handle: u64,
    pub last_check: Day,
    pub proof: RenewalProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecheckResponse {
    pub signature: BlindSignature,
    pub new_expiry: Day,
    pub new_check: Day,
    /// see [`IssuanceResponse::backup_ticket`]
    #[serde(default)]
    pub backup_ticket: Option<String>,
    /// When the re-check lifted a suspension: the new handle (the old one stays revoked) and the
    /// witness's signature on it, hex.
    #[serde(default)]
    pub new_handle: Option<(u64, String)>,
}

/// `POST /v1/replace`: replace the secret after an identity check (session purpose `replace`).
/// With a signature of the enrolment's current guardian key the new credential is issued at once.
/// Without it the request waits (`replace_wait_days`) and the holder collects the credential later
/// with `POST /v1/replace/claim`. In that time the person refuses it by doing a re-check
/// (`POST /v1/recheck`) with the old app: that takes the eID and the old secret together, so neither
/// a thief of the phone nor a thief of the eID can refuse or force a replacement alone.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplaceRequest {
    pub session: String,
    pub confirm_code: String,
    /// commitment to the NEW secret, bound to the session
    pub blind_request: BlindRequest,
    /// the new guardian key
    pub guardian_public_key: String,
    /// Ed25519 signature of the OLD guardian key over `replace_message(session, commitment, new guardian key)`
    #[serde(default)]
    pub old_guardian_signature: Option<String>,
    /// "It wasn't me": the person did not enrol the existing secret. It is suspended at once and the
    /// report counted (`GET /v1/reports`). If nobody lifts the suspension during the wait, the new
    /// secret counts at once, at most once in two years per person. Only without `old_guardian_signature`.
    #[serde(default)]
    pub report_theft: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "kebab-case")]
pub enum ReplaceResponse {
    Issued { issuance: IssuanceResponse },
    /// the request is recorded; claim on or after `claim_after`, and no later than `claim_before`
    Pending {
        claim_token: String,
        claim_after: Day,
        claim_before: Day,
        /// the existing secret was suspended by this request's theft report
        #[serde(default)]
        suspended: bool,
    },
}

pub fn replace_message(session: &str, commitment: &str, new_guardian: &str) -> Vec<u8> {
    format!("pop-replace-v1|{session}|{commitment}|{new_guardian}").into_bytes()
}

/// `POST /v1/replace/claim`: collect the credential of a replacement that has waited long enough.
/// The blind request is bound to `claim_session(claim_token)`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClaimRequest {
    pub claim_token: String,
    pub blind_request: BlindRequest,
}

pub fn claim_session(claim_token: &str) -> Vec<u8> {
    format!("pop-replace-claim-v1|{claim_token}").into_bytes()
}

/// `GET /v1/replace/pending`: replacements that are waiting. A holder app looks for its own entry
/// (`pending_id(handle, nonce)`) and warns the person; nobody else can tell whose an entry is.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PendingReplacements {
    pub entries: Vec<PendingReplacement>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct PendingReplacement {
    pub id: String,
    pub nonce: String,
    pub requested_on: Day,
    pub claim_after: Day,
}

/// Id of a pending replacement in the public list: a hash of the handle and the entry's nonce. The
/// handle is known to the issuer and the holder only.
pub fn pending_id(handle: u64, nonce: &str) -> String {
    use sha2::{Digest, Sha256};
    hex::encode(&Sha256::digest(format!("pop-replace-pending-v1|{handle}|{nonce}").as_bytes())[..16])
}

/// `POST /v1/backup`: store an encrypted backup (recovery level 1). The server sees ciphertext only.
/// A new backup needs a `ticket` (handed out at enrolment, re-check and replacement); replacing or
/// deleting an existing one needs its `write_key`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupPut {
    pub id: String,
    pub write_key: String,
    #[serde(default)]
    pub ticket: Option<String>,
    /// base64; empty deletes the backup
    pub blob: String,
}

/// `GET /v1/backup/{id}`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BackupBlob {
    pub blob: String,
}

/// `GET /v1/revocations?since=N`: the revoked handles in the order they were revoked, from position
/// `from` on (`since` is clamped to the list's length). A holder keeps the list it has, asks only for
/// the rest, and checks the rebuilt tree against `root`; it never names its own handle. Asking with
/// `since=0` returns the whole list. At scale this becomes a bucketed lookup (design §4.6).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Revocations {
    pub epoch: u64,
    /// position in the full list of the first handle in `revoked`
    #[serde(default)]
    pub from: u64,
    /// length of the full list
    #[serde(default)]
    pub total: u64,
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
    /// the alarm cutoff the proof was made under (`Params::alarm_cutoff`)
    #[serde(default)]
    pub alarm_cutoff: Option<Day>,
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
    /// the alarm cutoff in force when the claim was proved, if any
    #[serde(default)]
    pub proved_alarm: Option<Day>,
}

impl BindingEntry {
    /// Whether the badge counts while `alarm` is the alarm cutoff. A claim proved as counted before
    /// the alarm still counts if it was made before the cutoff: its secret counted from no later than
    /// that day. One made after it must be proved again under the alarm.
    pub fn counts(&self, alarm: Option<Day>) -> bool {
        self.counted && alarm.map_or(true, |a| self.bound_on < a || self.proved_alarm == Some(a))
    }
}

/// `GET /v1/bindings?platform=P&since=N&instance=I`. With `since=0`, with an `instance` other than
/// the directory's, or when the directory no longer has the
/// changes since N, `full` is true and `entries` is the whole current list. Otherwise `entries` are the
/// claims added or changed after change number N, and `gone` the claims removed after it. Claims whose
/// lease has run out are not listed as gone: a reader drops them by `lease_until` and `today`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BindingList {
    pub platform: String,
    pub today: Day,
    /// the issuer's alarm cutoff as this directory last saw it; readers apply [`BindingEntry::counts`]
    #[serde(default)]
    pub alarm_cutoff: Option<Day>,
    /// names the directory's store; send it back with `since`
    #[serde(default)]
    pub instance: String,
    /// the directory's change number at the time of this answer: ask with `since` set to it next time
    #[serde(default)]
    pub seq: u64,
    #[serde(default = "yes")]
    pub full: bool,
    pub entries: Vec<BindingEntry>,
    #[serde(default)]
    pub gone: Vec<GoneEntry>,
}

fn yes() -> bool {
    true
}

/// A claim removed from the list (withdrawn, or its pseudonym moved to another account).
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct GoneEntry {
    pub account_id: String,
    /// fingerprint of the pseudonym, as in [`BindingEntry::nym`]
    pub nym: String,
}

/// `GET /v1/likes/table?platform=P&since=N&instance=I`: like counts changed after change number N, or every
/// non-zero count when `full` is true. Counts only grow, so there is nothing to remove.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CountTable {
    pub platform: String,
    pub instance: String,
    pub seq: u64,
    pub full: bool,
    pub counts: BTreeMap<String, u64>,
}

/// Full record with its proof, for anyone who wants to re-verify. `GET /v1/bindings/{platform}/{account}`
/// returns every claim on the account.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BindingRecord {
    pub entry: BindingEntry,
    pub request: BindRequest,
    /// the directory's change number when the claim was stored or last updated
    #[serde(default)]
    pub seq: u64,
}

/// `POST /v1/bindings/withdraw`: switch the badge off. Needs a binding proof over `withdraw_context`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct WithdrawRequest {
    pub platform: String,
    pub account_id: String,
    pub nonce: String,
    pub today: Day,
    /// the alarm cutoff the proof was made under (`Params::alarm_cutoff`)
    #[serde(default)]
    pub alarm_cutoff: Option<Day>,
    pub revocation_root: String,
    pub proof: BindingProof,
}

/// `POST /v1/likes`
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LikeRequest {
    pub platform: String,
    pub post_id: String,
    pub today: Day,
    /// the alarm cutoff the proof was made under (`Params::alarm_cutoff`)
    #[serde(default)]
    pub alarm_cutoff: Option<Day>,
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
    async fn enrol_start(&self, purpose: Purpose) -> Result<EnrolStartResponse, ApiError>;
    async fn enrol_status(&self, session: &str) -> Result<EnrolStatus, ApiError>;
    async fn enrol_finish(&self, req: &EnrolFinishRequest) -> Result<IssuanceResponse, ApiError>;
    async fn renew(&self, req: &RenewRequest) -> Result<RenewResponse, ApiError>;
    async fn revocations(&self) -> Result<Revocations, ApiError>;
    /// The revoked handles from position `since` on. The default asks for the whole list and cuts it.
    async fn revocations_since(&self, since: u64) -> Result<Revocations, ApiError> {
        let mut r = self.revocations().await?;
        let total = r.revoked.len() as u64;
        let from = since.min(total);
        r.revoked.drain(..from as usize);
        r.from = from;
        r.total = total;
        Ok(r)
    }
    async fn revoke(&self, req: &RevokeRequest) -> Result<(), ApiError>;
    async fn reports(&self) -> Result<Reports, ApiError>;
    async fn identity_recheck(&self, req: &RecheckRequest) -> Result<RecheckResponse, ApiError>;
    async fn replace(&self, req: &ReplaceRequest) -> Result<ReplaceResponse, ApiError>;
    async fn replace_claim(&self, req: &ClaimRequest) -> Result<IssuanceResponse, ApiError>;
    async fn replace_pending(&self) -> Result<PendingReplacements, ApiError>;
    /// Returns a new ticket when the call deleted a backup.
    async fn backup_put(&self, req: &BackupPut) -> Result<Option<String>, ApiError>;
    async fn backup_get(&self, id: &str) -> Result<BackupBlob, ApiError>;
}

#[async_trait]
pub trait DirectoryApi: Send + Sync {
    async fn bind(&self, req: &BindRequest) -> Result<BindingEntry, ApiError>;
    async fn withdraw(&self, req: &WithdrawRequest) -> Result<(), ApiError>;
    async fn recheck(&self, platform: &str, account_id: &str) -> Result<Vec<BindingEntry>, ApiError>;
    async fn list(&self, platform: &str) -> Result<BindingList, ApiError>;
    /// Changes to the list after change number `since` (see [`BindingList`]). The default returns the
    /// whole list.
    async fn list_since(&self, platform: &str, since: u64, instance: &str) -> Result<BindingList, ApiError> {
        let _ = (since, instance);
        self.list(platform).await
    }
    async fn like(&self, req: &LikeRequest) -> Result<LikeResponse, ApiError>;
    async fn counts(&self, req: &CountsRequest) -> Result<CountsResponse, ApiError>;
}
