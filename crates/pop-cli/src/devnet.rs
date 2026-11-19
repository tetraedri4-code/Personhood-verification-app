//! Everything on one machine: mock identity provider, issuer, directory and mock feed, each on its own
//! port and each talking to the others only over HTTP, as they would when deployed apart.
use crate::wiring::{self, IssuerFile, PlatformOpts, UniquenessFile};
use pop_uniqueness::admin::{self, AdminEndpoint};
use pop_uniqueness::{Operator, OperatorConfig, OperatorEndpoint, ThresholdConfig};
use serde::{Deserialize, Serialize};
use pop_crypto::SchemeConfig;
use pop_directory::{Directory, DirectoryConfig};
use pop_mock_idp::{MockClient, MockIdpConfig};
use pop_protocol::http::HttpClient;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;

#[derive(Clone, Debug)]
pub struct DevnetOpts {
    pub scheme: SchemeConfig,
    pub data_dir: Option<PathBuf>,
    /// ports for feed, idp, issuer, directory; 0 = any free port
    pub ports: [u16; 4],
    pub uniqueness: UniquenessMode,
    /// days a replacement without the old guardian key waits (None = the issuer's default, 90)
    pub replace_wait_days: Option<u32>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UniquenessMode {
    /// single-operator keyed hash
    Hmac,
    /// `operators` operators with the given threshold, plus one standby operator that holds no share
    /// until a reshare brings it in. Each is its own server on its own port.
    Threshold { operators: u32, threshold: usize },
}

impl Default for DevnetOpts {
    fn default() -> Self {
        DevnetOpts { scheme: SchemeConfig::default(), data_dir: None, ports: [4000, 4001, 4002, 4003], uniqueness: UniquenessMode::Hmac, replace_wait_days: None }
    }
}

#[derive(Clone, Debug)]
pub struct Devnet {
    pub feed_url: String,
    pub idp_url: String,
    pub issuer_url: String,
    pub directory_url: String,
    /// the threshold uniqueness operators, if any
    pub uniqueness: Option<UniquenessCluster>,
}

/// What the devnet knows about its uniqueness operators: enough to run rounds against them.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UniquenessCluster {
    /// group key Y (hex)
    pub key: String,
    pub threshold: usize,
    /// operators that hold a share after key generation
    pub members: Vec<AdminEndpoint>,
    /// an operator that runs but holds no share yet
    pub standby: AdminEndpoint,
    eval_tokens: Vec<String>,
    #[serde(skip)]
    file: Option<std::path::PathBuf>,
}

fn token() -> String {
    hex::encode(rand::random::<[u8; 24]>())
}

/// Start the operators and, on the first run, generate the key. With a data directory the tokens, the
/// group key and every operator's shares survive a restart.
async fn start_uniqueness(n: u32, threshold: usize, data_dir: Option<&std::path::Path>) -> anyhow::Result<(UniquenessCluster, ThresholdConfig)> {
    let file = data_dir.map(|d| d.join("uniqueness-devnet.json"));
    let saved: Option<UniquenessCluster> = match &file {
        Some(f) if f.exists() => Some(serde_json::from_slice(&std::fs::read(f)?)?),
        _ => None,
    };
    let total = n + 1;
    let mut admins = vec![];
    let mut endpoints = vec![];
    let mut eval_tokens = vec![];
    for index in 1..=total {
        let old_admin = saved.as_ref().and_then(|s| s.members.iter().chain([&s.standby]).find(|m| m.index == index)).map(|m| m.admin_token.clone());
        let old_eval = saved.as_ref().and_then(|s| s.eval_tokens.get(index as usize - 1).cloned());
        let (admin_token, eval_token) = (old_admin.unwrap_or_else(token), old_eval.unwrap_or_else(token));
        let op = Operator::new(OperatorConfig {
            index,
            eval_token: eval_token.clone(),
            admin_token: admin_token.clone(),
            state_file: data_dir.map(|d| d.join(format!("uniqueness-operator-{index}.json"))),
            max_evals_per_minute: 6000,
            min_threshold: threshold.min(2),
            test_fault: None,
        })?;
        let (l, url) = listen(0).await?;
        serve(l, pop_uniqueness::router(op));
        admins.push(AdminEndpoint { index, url: url.clone(), admin_token });
        endpoints.push(OperatorEndpoint { index, url, token: eval_token.clone() });
        eval_tokens.push(eval_token);
    }
    let by_index = |i: u32| admins.iter().find(|a| a.index == i).cloned();
    let (key, members, standby) = match &saved {
        // everyone keeps index, tokens and shares; only the ports are new
        Some(s) => (
            s.key.clone(),
            s.members.iter().filter_map(|m| by_index(m.index)).collect::<Vec<_>>(),
            by_index(s.standby.index).ok_or_else(|| anyhow::anyhow!("saved devnet has another number of operators"))?,
        ),
        None => {
            let members = admins[..n as usize].to_vec();
            (admin::dkg(&members, threshold).await?, members, admins[n as usize].clone())
        }
    };
    let cluster = UniquenessCluster { key: key.clone(), threshold, members, standby, eval_tokens, file };
    cluster.save()?;
    Ok((cluster, ThresholdConfig { operators: endpoints, keys: vec![key] }))
}

impl UniquenessCluster {
    fn save(&self) -> anyhow::Result<()> {
        let Some(f) = &self.file else { return Ok(()) };
        if let Some(d) = f.parent() {
            std::fs::create_dir_all(d)?;
        }
        std::fs::write(f, serde_json::to_vec_pretty(self)?)?;
        Ok(())
    }

    /// Refresh: every member gets a new share of the same key and erases the old one by itself.
    pub async fn refresh(&self) -> anyhow::Result<u64> {
        admin::reshare(&self.key, &self.members, &self.members, self.threshold).await
    }

    /// Replace the last member by the standby operator: the remaining members and the newcomer get
    /// new shares, the member that left erases its share.
    pub async fn replace_last_member(&mut self) -> anyhow::Result<(u32, u32, u64)> {
        let leaver = self.members.last().cloned().expect("members");
        let mut new_set: Vec<AdminEndpoint> = self.members[..self.members.len() - 1].to_vec();
        new_set.push(self.standby.clone());
        let epoch = admin::reshare(&self.key, &self.members, &new_set, self.threshold).await?;
        let joined = self.standby.index;
        self.standby = leaver.clone();
        self.members = new_set;
        self.save()?;
        Ok((leaver.index, joined, epoch))
    }
}

async fn listen(port: u16) -> anyhow::Result<(TcpListener, String)> {
    let l = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], port))).await?;
    let url = format!("http://127.0.0.1:{}", l.local_addr()?.port());
    Ok((l, url))
}

fn serve(l: TcpListener, app: axum::Router) {
    tokio::spawn(async move {
        if let Err(e) = axum::serve(l, app).await {
            tracing::error!("server stopped: {e}");
        }
    });
}

pub async fn start(o: DevnetOpts) -> anyhow::Result<Devnet> {
    let (l_feed, feed_url) = listen(o.ports[0]).await?;
    let (l_idp, idp_url) = listen(o.ports[1]).await?;
    let (l_iss, issuer_url) = listen(o.ports[2]).await?;
    let (l_dir, directory_url) = listen(o.ports[3]).await?;

    serve(l_feed, pop_mockfeed::router());

    let oidc = wiring::mock_oidc(&idp_url, &issuer_url);
    serve(
        l_idp,
        pop_mock_idp::router(MockIdpConfig {
            issuer: idp_url.clone(),
            clients: vec![MockClient { client_id: oidc.client_id.clone(), client_secret: oidc.client_secret.clone(), redirect_uri: oidc.redirect_uri.clone() }],
        }),
    );

    let (uniqueness, uniq_file) = match o.uniqueness {
        UniquenessMode::Hmac => (None, UniquenessFile::Hmac),
        UniquenessMode::Threshold { operators, threshold } => {
            let (c, cfg) = start_uniqueness(operators, threshold, o.data_dir.as_deref()).await?;
            (Some(c), UniquenessFile::Threshold(cfg))
        }
    };
    let issuer = wiring::build_issuer(&IssuerFile {
        data_dir: o.data_dir.clone(),
        scheme: o.scheme.clone(),
        oidc,
        provider_code: 1,
        uniqueness: uniq_file,
        uniqueness_key: None,
        policy: pop_issuer::Policy { replace_wait_days: o.replace_wait_days.unwrap_or(pop_issuer::Policy::default().replace_wait_days), ..Default::default() },
    })
    .await?;
    serve(l_iss, pop_issuer::router(issuer));

    let platforms = wiring::platforms(&PlatformOpts { mockfeed_url: Some(feed_url.clone()), ..Default::default() });
    let dir = Directory::connect(
        Arc::new(HttpClient::new(&issuer_url)),
        platforms,
        wiring::store(o.data_dir.as_deref(), "directory-db")?,
        DirectoryConfig::default(),
    )
    .await?;
    serve(l_dir, pop_directory::router(dir));

    Ok(Devnet { feed_url, idp_url, issuer_url, directory_url, uniqueness })
}

/// Complete the mock identity check without a browser: the mock IdP logs `subject` in at once when
/// asked with `login_hint` and `auto=1`, and redirects to the issuer's callback. Returns the confirmation code
/// from the issuer's page (empty if the issuer showed none, e.g. for a person already enrolled).
pub async fn mock_login(authorize_url: &str, subject: &str) -> anyhow::Result<String> {
    let mut u = reqwest::Url::parse(authorize_url)?;
    u.query_pairs_mut().append_pair("login_hint", subject).append_pair("auto", "1");
    let html = reqwest::Client::new().get(u).send().await?.error_for_status()?.text().await?;
    // the issuer's page shows the confirmation code a person would type into the app
    Ok(html.split("id=\"confirm-code\"").nth(1).and_then(|r| r.split('>').nth(1)).and_then(|r| r.split('<').next()).unwrap_or_default().to_string())
}
