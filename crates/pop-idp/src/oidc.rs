//! Generic OpenID Connect relying party (authorization-code flow with a client secret).
use crate::*;
use jsonwebtoken::{decode, decode_header, jwk::JwkSet, DecodingKey, Validation};
use std::collections::HashMap;

/// Configuration of one OIDC provider. Everything provider-specific lives here, so switching from the
/// mock to a real broker is a configuration change (see docs/real-identity-provider.md).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OidcConfig {
    /// name in the published provider list
    pub name: String,
    /// issuer URL; `{issuer}/.well-known/openid-configuration` must exist
    pub issuer: String,
    pub client_id: String,
    pub client_secret: String,
    /// the issuer service's callback, registered with the provider
    pub redirect_uri: String,
    /// space-separated scopes, e.g. "openid" or "openid ssn"
    pub scopes: String,
    /// ID-token claim that holds the lifelong identifier, e.g. "hetu", "ssn", "sub"
    pub subject_claim: String,
    /// ISO 3166 numeric country code of the identities this provider issues (246 = Finland)
    pub country: u32,
    /// map from the provider's `acr` values to levels of assurance; unknown values count as Low
    pub acr_map: HashMap<String, Loa>,
    /// optional `acr_values` to request
    pub acr_values: Option<String>,
    pub min_loa: Loa,
}

#[derive(Clone, Debug, Deserialize)]
struct Discovery {
    issuer: String,
    authorization_endpoint: String,
    token_endpoint: String,
    jwks_uri: String,
}

pub struct OidcProvider {
    cfg: OidcConfig,
    http: reqwest::Client,
    disc: tokio::sync::OnceCell<Discovery>,
}

impl OidcProvider {
    pub fn new(cfg: OidcConfig) -> Self {
        Self::with_client(cfg, reqwest::Client::new())
    }
    pub fn with_client(cfg: OidcConfig, http: reqwest::Client) -> Self {
        OidcProvider { cfg, http, disc: tokio::sync::OnceCell::new() }
    }

    async fn discovery(&self) -> Result<&Discovery, IdpError> {
        self.disc
            .get_or_try_init(|| async {
                let url = format!("{}/.well-known/openid-configuration", self.cfg.issuer.trim_end_matches('/'));
                let d: Discovery = self
                    .http
                    .get(&url)
                    .send()
                    .await
                    .map_err(|e| IdpError::Http(e.to_string()))?
                    .error_for_status()
                    .map_err(|e| IdpError::Http(e.to_string()))?
                    .json()
                    .await
                    .map_err(|e| IdpError::Http(e.to_string()))?;
                for u in [&d.authorization_endpoint, &d.token_endpoint, &d.jwks_uri, &self.cfg.issuer] {
                    require_secure(u)?;
                }
                if d.issuer.trim_end_matches('/') != self.cfg.issuer.trim_end_matches('/') {
                    return Err(IdpError::Config(format!("discovery issuer {} != configured {}", d.issuer, self.cfg.issuer)));
                }
                Ok(d)
            })
            .await
    }
}

#[derive(Deserialize)]
struct TokenResponse {
    id_token: String,
}

#[async_trait]
impl IdentityProvider for OidcProvider {
    fn name(&self) -> &str {
        &self.cfg.name
    }

    async fn authorization_url(&self, state: &str, nonce: &str) -> Result<String, IdpError> {
        let d = self.discovery().await?;
        let mut u = url::Url::parse(&d.authorization_endpoint).map_err(|e| IdpError::Config(e.to_string()))?;
        {
            let mut q = u.query_pairs_mut();
            q.append_pair("response_type", "code")
                .append_pair("client_id", &self.cfg.client_id)
                .append_pair("redirect_uri", &self.cfg.redirect_uri)
                .append_pair("scope", &self.cfg.scopes)
                .append_pair("state", state)
                .append_pair("nonce", nonce);
            if let Some(a) = &self.cfg.acr_values {
                q.append_pair("acr_values", a);
            }
        }
        Ok(u.to_string())
    }

    async fn complete(&self, code: &str, nonce: &str) -> Result<VerifiedIdentity, IdpError> {
        let d = self.discovery().await?;
        let tok: TokenResponse = self
            .http
            .post(&d.token_endpoint)
            .form(&[
                ("grant_type", "authorization_code"),
                ("code", code),
                ("redirect_uri", self.cfg.redirect_uri.as_str()),
                ("client_id", self.cfg.client_id.as_str()),
                ("client_secret", self.cfg.client_secret.as_str()),
            ])
            .send()
            .await
            .map_err(|e| IdpError::Http(e.to_string()))?
            .error_for_status()
            .map_err(|e| IdpError::Http(e.to_string()))?
            .json()
            .await
            .map_err(|e| IdpError::Http(e.to_string()))?;
        let jwks: JwkSet = self
            .http
            .get(&d.jwks_uri)
            .send()
            .await
            .map_err(|e| IdpError::Http(e.to_string()))?
            .json()
            .await
            .map_err(|e| IdpError::Http(e.to_string()))?;
        let header = decode_header(&tok.id_token).map_err(|e| IdpError::Token(e.to_string()))?;
        // only signatures with the provider's public key: a token "signed" with a shared secret or with
        // no signature must never pass
        use jsonwebtoken::Algorithm as A;
        if !matches!(header.alg, A::RS256 | A::RS384 | A::RS512 | A::PS256 | A::PS384 | A::PS512 | A::ES256 | A::ES384 | A::EdDSA) {
            return Err(IdpError::Token(format!("signature algorithm {:?} not accepted", header.alg)));
        }
        let jwk = match &header.kid {
            Some(kid) => jwks.find(kid),
            None => jwks.keys.first(),
        }
        .ok_or_else(|| IdpError::Token("no matching key in JWKS".into()))?;
        let key = DecodingKey::from_jwk(jwk).map_err(|e| IdpError::Token(e.to_string()))?;
        let mut v = Validation::new(header.alg);
        v.set_audience(&[&self.cfg.client_id]);
        v.set_issuer(&[&d.issuer]);
        v.set_required_spec_claims(&["exp", "iss", "aud", "sub"]);
        let claims = decode::<HashMap<String, serde_json::Value>>(&tok.id_token, &key, &v)
            .map_err(|e| IdpError::Token(e.to_string()))?
            .claims;
        if claims.get("nonce").and_then(|n| n.as_str()) != Some(nonce) {
            return Err(IdpError::Token("nonce mismatch".into()));
        }
        let subject = claims
            .get(&self.cfg.subject_claim)
            .and_then(|s| s.as_str())
            .ok_or_else(|| IdpError::Token(format!("claim {} missing", self.cfg.subject_claim)))?
            .to_string();
        let loa = claims
            .get("acr")
            .and_then(|a| a.as_str())
            .and_then(|a| self.cfg.acr_map.get(a).copied())
            .unwrap_or(Loa::Low);
        if loa < self.cfg.min_loa {
            return Err(IdpError::LoaTooLow(loa));
        }
        Ok(VerifiedIdentity { provider: self.cfg.name.clone(), country: self.cfg.country, subject, loa })
    }
}

/// Provider endpoints must be https. Plain http is accepted only on this machine (the mock).
fn require_secure(u: &str) -> Result<(), IdpError> {
    let p = url::Url::parse(u).map_err(|e| IdpError::Config(format!("{u}: {e}")))?;
    let loopback = matches!(p.host_str(), Some("127.0.0.1" | "localhost" | "[::1]"));
    if p.scheme() == "https" || (p.scheme() == "http" && loopback) {
        Ok(())
    } else {
        Err(IdpError::Config(format!("{u}: identity provider endpoints must use https")))
    }
}
