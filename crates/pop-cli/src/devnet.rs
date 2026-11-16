//! Everything on one machine: mock identity provider, issuer, directory and mock feed, each on its own
//! port and each talking to the others only over HTTP, as they would when deployed apart.
use crate::wiring::{self, IssuerFile, PlatformOpts};
use pop_crypto::{dates, SchemeConfig};
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
    /// enrolments count at once (rollout window) instead of after nine months of probation
    pub rollout: bool,
}

impl Default for DevnetOpts {
    fn default() -> Self {
        DevnetOpts { scheme: SchemeConfig::default(), data_dir: None, ports: [4000, 4001, 4002, 4003], rollout: true }
    }
}

#[derive(Clone, Debug)]
pub struct Devnet {
    pub feed_url: String,
    pub idp_url: String,
    pub issuer_url: String,
    pub directory_url: String,
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

    // a quarter start more than nine months back, so demo badges are "counted" at once
    let rollout = o.rollout.then(|| dates::fmt_day(dates::quarter_start(dates::quarter_of(dates::today()).saturating_sub(4))));
    let issuer = wiring::build_issuer(&IssuerFile {
        data_dir: o.data_dir.clone(),
        scheme: o.scheme.clone(),
        oidc,
        provider_code: 1,
        rollout_certified: rollout,
        uniqueness_key: None,
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

    Ok(Devnet { feed_url, idp_url, issuer_url, directory_url })
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
