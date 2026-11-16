//! Builders that turn configuration into running parts.
use anyhow::Context;
use pop_crypto::{dates, ProofSystem, Scheme, SchemeConfig};
use pop_holder::{Holder, WalletStore};
use pop_idp::oidc::{OidcConfig, OidcProvider};
use pop_idp::Loa;
use pop_issuer::{hmac_key_version, HmacUniqueness, Issuer, IssuerConfig, UniquenessService};
use pop_uniqueness::{ThresholdConfig, ThresholdUniqueness};
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
    /// Who computes the deduplication key. Omit for the single-operator keyed hash.
    #[serde(default)]
    pub uniqueness: UniquenessFile,
    /// Keyed hash only: a key given in the configuration (hex, at least 32 bytes) instead of in
    /// `data_dir/uniqueness-keys/`. It counts as the oldest key.
    #[serde(default)]
    pub uniqueness_key: Option<String>,
    /// Days a replacement of a lost secret waits when the old guardian key did not sign it; the old
    /// app can refuse it in that time. Default 90.
    #[serde(default)]
    pub replace_wait_days: Option<u32>,
}

/// The `uniqueness` section of the issuer configuration.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum UniquenessFile {
    /// One operator, HMAC-SHA256. Keys live in `data_dir/uniqueness-keys/NNNN.key`; the highest number
    /// is the current key. `pop uniqueness rotate-key` adds one.
    #[default]
    Hmac,
    /// t-of-n operators (`pop uniqueness operator`), see docs/real-servers.md.
    Threshold(ThresholdConfig),
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

const KEY_DIR: &str = "uniqueness-keys";

fn write_secret(p: &Path, content: &[u8]) -> anyhow::Result<()> {
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(p).with_context(|| format!("cannot create {}", p.display()))?;
    std::io::Write::write_all(&mut f, content)?;
    f.sync_all()?;
    Ok(())
}

/// The keyed-hash keys, oldest first: the key from the configuration, the single key file of the first
/// prototype (`uniqueness.key`), then `uniqueness-keys/NNNN.key` in order. Returns the keys and the
/// highest NNNN in use.
fn hmac_keys(f: &IssuerFile) -> anyhow::Result<(Vec<Vec<u8>>, u32)> {
    let mut keys = vec![];
    let mut last = 0;
    if let Some(k) = &f.uniqueness_key {
        keys.push(hex::decode(k.trim()).context("uniqueness_key must be hex")?);
    }
    if let Some(d) = &f.data_dir {
        match std::fs::read(d.join("uniqueness.key")) {
            Ok(b) => keys.push(b),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("cannot read uniqueness.key"),
        }
        let dir = d.join(KEY_DIR);
        let mut files: Vec<(u32, PathBuf)> = vec![];
        match std::fs::read_dir(&dir) {
            Ok(rd) => {
                for ent in rd {
                    let p = ent?.path();
                    if p.extension().and_then(|e| e.to_str()) != Some("key") {
                        continue;
                    }
                    let n: u32 = p.file_stem().and_then(|s| s.to_str()).and_then(|s| s.parse().ok()).with_context(|| format!("unexpected key file name {}", p.display()))?;
                    files.push((n, p));
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).context("cannot read the uniqueness key directory"),
        }
        files.sort();
        for (n, p) in files {
            // a key file that cannot be read is an error, not a missing key
            let text = std::fs::read_to_string(&p).with_context(|| format!("cannot read {}", p.display()))?;
            keys.push(hex::decode(text.trim()).with_context(|| format!("{} is not hex", p.display()))?);
            last = n;
        }
    }
    Ok((keys, last))
}

fn new_hmac_key(f: &IssuerFile, number: u32) -> anyhow::Result<Vec<u8>> {
    let k = rand::random::<[u8; 32]>().to_vec();
    if let Some(d) = &f.data_dir {
        let dir = d.join(KEY_DIR);
        std::fs::create_dir_all(&dir)?;
        write_secret(&dir.join(format!("{number:04}.key")), hex::encode(&k).as_bytes())?;
    }
    Ok(k)
}

/// Add a new keyed-hash key; it becomes the current one at the next start of the issuer. The older
/// keys must stay in place: records under them are still matched, and moved to the new key when their
/// owner next logs in. Returns (new version, all versions newest first).
pub fn rotate_hmac_key(f: &IssuerFile) -> anyhow::Result<(String, Vec<String>)> {
    anyhow::ensure!(matches!(f.uniqueness, UniquenessFile::Hmac), "this issuer uses the threshold service: make a new key with `pop uniqueness dkg` and append it to `uniqueness.keys`");
    anyhow::ensure!(f.data_dir.is_some(), "rotation needs a data_dir to keep the keys in");
    let (keys, last) = hmac_keys(f)?;
    anyhow::ensure!(!keys.is_empty(), "there is no key yet; the issuer makes the first one when it starts");
    let k = new_hmac_key(f, last + 1)?;
    let mut versions: Vec<String> = keys.iter().map(|k| hmac_key_version(k)).collect();
    versions.push(hmac_key_version(&k));
    versions.reverse();
    Ok((versions[0].clone(), versions))
}

/// Enrolment records per key version, straight from the store (no keys needed).
pub async fn records_per_version(f: &IssuerFile) -> anyhow::Result<std::collections::BTreeMap<String, u64>> {
    let mut m = std::collections::BTreeMap::new();
    for (_, v) in store(f.data_dir.as_deref(), "issuer-db")?.list("enrolments").await? {
        *m.entry(v["key_version"].as_str().unwrap_or("(none)").to_string()).or_default() += 1;
    }
    Ok(m)
}

async fn build_uniqueness(f: &IssuerFile, db: &SharedStore) -> anyhow::Result<Arc<dyn UniquenessService>> {
    match &f.uniqueness {
        UniquenessFile::Threshold(c) => Ok(Arc::new(ThresholdUniqueness::new(c.clone())?)),
        UniquenessFile::Hmac => {
            let (mut keys, last) = hmac_keys(f)?;
            if keys.is_empty() {
                // Fail closed: a first start has no records. Records without any key mean the key was
                // lost; making a fresh one would let everybody enrol again.
                let n = db.count("enrolments").await?;
                anyhow::ensure!(
                    n == 0,
                    "refusing to start: {n} enrolment record(s) exist but no uniqueness key was found in the data directory. \
                     Restore the key (docs/real-servers.md, \"Uniqueness keys\")."
                );
                keys.push(new_hmac_key(f, last + 1)?);
            }
            Ok(Arc::new(HmacUniqueness::new(keys)?))
        }
    }
}

pub async fn build_issuer(f: &IssuerFile) -> anyhow::Result<Arc<Issuer>> {
    let scheme = Arc::new(Scheme::new(f.scheme.clone()));
    let min_loa = f.oidc.min_loa;
    let idp = Arc::new(OidcProvider::new(f.oidc.clone()));
    let db = store(f.data_dir.as_deref(), "issuer-db")?;
    let uniq = build_uniqueness(f, &db).await?;
    let cfg = IssuerConfig {
        keys_dir: f.data_dir.as_ref().map(|d| d.join("keys")),
        provider_code: f.provider_code,
        min_loa,
        rollout_certified: f.rollout_certified.as_deref().map(parse_day).transpose()?,
        clock: None,
        replace_wait_days: f.replace_wait_days.unwrap_or(90),
    };
    Issuer::new(scheme, idp, uniq, db, cfg).await
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
