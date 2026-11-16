//! # pop-idp
//!
//! How the issuer learns who is enrolling. The issuer depends only on the [`IdentityProvider`] trait.
//!
//! * [`oidc::OidcProvider`]: generic OpenID Connect authorization-code flow (discovery, token exchange,
//!   ID token checked against the provider's JWKS). The local mock IdP (`pop-mock-idp`) speaks the same
//!   protocol, so the demo runs the code path a real broker would use. docs/real-identity-provider.md
//!   shows the configuration for a Finnish bank-ID broker.
//! * [`StaticProvider`]: no network at all, for unit tests.
use async_trait::async_trait;
use serde::{Deserialize, Serialize};

pub mod oidc;

/// Level of assurance (eIDAS).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Loa {
    Low,
    Substantial,
    High,
}

/// What the issuer needs from an identity check. `subject` must be a lifelong identifier unique within
/// the scheme (in Finland: the personal identity code). The issuer uses it only as input to the keyed
/// deduplication hash and then drops it (design §4.2; Finnish Data Protection Act s. 29).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VerifiedIdentity {
    pub provider: String,
    pub country: u32,
    pub subject: String,
    pub loa: Loa,
}

#[derive(Debug, thiserror::Error)]
pub enum IdpError {
    #[error("identity provider configuration: {0}")]
    Config(String),
    #[error("identity provider request failed: {0}")]
    Http(String),
    #[error("identity token rejected: {0}")]
    Token(String),
    #[error("level of assurance too low: got {0:?}")]
    LoaTooLow(Loa),
}

#[async_trait]
pub trait IdentityProvider: Send + Sync {
    /// Short name shown in the published provider list, e.g. "mock-idp" or "ftn-broker".
    fn name(&self) -> &str;
    /// URL the person's browser opens to log in. `state` comes back on the redirect; `nonce` must come
    /// back inside the ID token.
    async fn authorization_url(&self, state: &str, nonce: &str) -> Result<String, IdpError>;
    /// Exchange the code from the redirect for a verified identity.
    async fn complete(&self, code: &str, nonce: &str) -> Result<VerifiedIdentity, IdpError>;
}

/// Accepts any code of the form "subject" and returns it as a verified identity. Tests only.
pub struct StaticProvider {
    pub country: u32,
}

#[async_trait]
impl IdentityProvider for StaticProvider {
    fn name(&self) -> &str {
        "static-test"
    }
    async fn authorization_url(&self, state: &str, _nonce: &str) -> Result<String, IdpError> {
        Ok(format!("static:{state}"))
    }
    async fn complete(&self, code: &str, _nonce: &str) -> Result<VerifiedIdentity, IdpError> {
        Ok(VerifiedIdentity { provider: "static-test".into(), country: self.country, subject: code.into(), loa: Loa::High })
    }
}
