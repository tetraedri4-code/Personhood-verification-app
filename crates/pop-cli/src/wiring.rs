//! Builders that turn configuration into running parts.
use anyhow::Context;
use pop_crypto::{dates, ProofSystem, Scheme, SchemeConfig};
use pop_holder::{Holder, WalletStore};
use pop_idp::oidc::{OidcConfig, OidcProvider};
use pop_idp::Loa;
use pop_issuer::{HmacUniqueness, Issuer, IssuerConfig};
use pop_platform_bluesky::{Bluesky, BlueskyConfig};
use pop_platform_mockfeed::MockFeed;
use pop_protocol::http::HttpClient;
use pop_protocol::platform::PlatformRegistry;
use pop_storage::{JsonFileStore, MemoryStore, SharedStore};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;

/// Configuration file of `pop issuer` (JSON). See docs/real-identity-provider.md.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct IssuerFile {
    /// directory for keys and the JSON store; omit for in-memory
    pub data_dir: Option<PathBuf>,
    #[serde(default)]
    pub scheme: SchemeConfig,
    pub oidc: OidcConfig,
    /// code of this provider in the credential (attribute e); publish the list and never reuse a code
    #[serde(default = "one")]
    pub provider_code: u32,
    /// "YYYY-MM-DD" quarter start: secrets enrolled now count as certified then (rollout window)
    pub rollout_certified: Option<String>,
    /// hex, at least 32 bytes. Omit to generate one into `data_dir/uniqueness.key`.
    pub uniqueness_key: Option<String>,
}

fn one() -> u32 {
    1
}

pub fn store(dir: Option<&Path>, name: &str) -> anyhow::Result<SharedStore> {
    Ok(match dir {
        Some(d) => Arc::new(JsonFileStore::open(d.join(name))?),
        None => MemoryStore::shared(),
    })
}

fn parse_day(s: &str) -> anyhow::Result<u32> {
    let p: Vec<u32> = s.split('-').map(|x| x.parse()).collect::<Result<_, _>>().context("date must be YYYY-MM-DD")?;
    anyhow::ensure!(p.len() == 3, "date must be YYYY-MM-DD");
    Ok(dates::from_civil(p[0] as i32, p[1], p[2]))
}

fn uniqueness_key(f: &IssuerFile) -> anyhow::Result<Vec<u8>> {
    if let Some(k) = &f.uniqueness_key {
        return Ok(hex::decode(k)?);
    }
    let fresh = || rand::random::<[u8; 32]>().to_vec();
    match &f.data_dir {
        None => Ok(fresh()),
        Some(d) => {
            std::fs::create_dir_all(d)?;
            let p = d.join("uniqueness.key");
            if let Ok(b) = std::fs::read(&p) {
                return Ok(b);
            }
            let k = fresh();
            std::fs::write(&p, &k)?;
            Ok(k)
        }
    }
}

pub async fn build_issuer(f: &IssuerFile) -> anyhow::Result<Arc<Issuer>> {
    let scheme = Arc::new(Scheme::new(f.scheme.clone()));
    let min_loa = f.oidc.min_loa;
    let idp = Arc::new(OidcProvider::new(f.oidc.clone()));
    let uniq = Arc::new(HmacUniqueness::new(uniqueness_key(f)?));
    let cfg = IssuerConfig {
        keys_dir: f.data_dir.as_ref().map(|d| d.join("keys")),
        provider_code: f.provider_code,
        min_loa,
        rollout_certified: f.rollout_certified.as_deref().map(parse_day).transpose()?,
        clock: None,
    };
    Issuer::new(scheme, idp, uniq, store(f.data_dir.as_deref(), "issuer-db")?, cfg).await
}

/// Which platforms a process knows, from command-line options.
#[derive(Clone, Debug, Default)]
pub struct PlatformOpts {
    pub mockfeed_url: Option<String>,
    pub mockfeed_as: Option<String>,
    pub bluesky: bool,
    pub bluesky_identifier: Option<String>,
    pub bluesky_app_password: Option<String>,
    pub bluesky_pds: Option<String>,
    pub bluesky_appview: Option<String>,
}

/// To add a platform: build its adapter here. Nothing else in the repository changes.
pub fn platforms(o: &PlatformOpts) -> PlatformRegistry {
    let mut r = PlatformRegistry::new();
    if let Some(u) = &o.mockfeed_url {
        r = r.with(Arc::new(MockFeed::new(u, o.mockfeed_as.clone())));
    }
    if o.bluesky || o.bluesky_identifier.is_some() {
        let d = BlueskyConfig::default();
        r = r.with(Arc::new(Bluesky::new(BlueskyConfig {
            appview: o.bluesky_appview.clone().unwrap_or(d.appview),
            pds: o.bluesky_pds.clone().unwrap_or(d.pds),
            identifier: o.bluesky_identifier.clone(),
            app_password: o.bluesky_app_password.clone(),
        })));
    }
    r
}

pub fn build_holder(issuer_url: &str, directory_url: &str, platforms: PlatformRegistry, wallet: Arc<dyn WalletStore>) -> Holder {
    Holder::new(Arc::new(HttpClient::new(issuer_url)), Arc::new(HttpClient::new(directory_url)), platforms, wallet)
}

pub fn mock_oidc(idp_url: &str, issuer_url: &str) -> OidcConfig {
    OidcConfig {
        name: "mock-idp".into(),
        issuer: idp_url.into(),
        client_id: "pop-issuer".into(),
        client_secret: "mock-secret".into(),
        redirect_uri: format!("{issuer_url}/v1/enrol/callback"),
        scopes: "openid".into(),
        subject_claim: "hetu".into(),
        country: 246,
        acr_map: [("mock:loa:high".to_string(), Loa::High)].into_iter().collect(),
        acr_values: None,
        min_loa: Loa::Substantial,
    }
}

pub fn proof_system(s: &str) -> anyhow::Result<ProofSystem> {
    match s.to_lowercase().as_str() {
        "lego" | "legogroth16" => Ok(ProofSystem::LegoGroth16),
        "bp" | "bulletproofs" => Ok(ProofSystem::Bulletproofs),
        _ => anyhow::bail!("proof system must be legogroth16 or bulletproofs"),
    }
}
