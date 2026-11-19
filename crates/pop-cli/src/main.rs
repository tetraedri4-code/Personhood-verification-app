use anyhow::Context;
use clap::{Args, Parser, Subcommand};
use pop_cli::devnet::{self, DevnetOpts};
use pop_cli::wiring::{self, IssuerFile, PlatformOpts};
use pop_crypto::{dates, SchemeConfig};
use pop_directory::{Directory, DirectoryConfig};
use pop_holder::{local_api, FileWallet, Holder};
use pop_mock_idp::{MockClient, MockIdpConfig};
use pop_protocol::http::HttpClient;
use pop_protocol::platform::CodePlacement;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;

#[derive(Parser)]
#[command(name = "pop", about = "Voluntary personhood app: services, holder app and local demo", version)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run mock feed, mock identity provider, issuer and directory on this machine
    Devnet(DevnetArgs),
    /// Start a devnet and walk through the whole flow, then keep serving
    Demo(DevnetArgs),
    /// Run the issuer service from a configuration file
    Issuer {
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "127.0.0.1:4002")]
        listen: SocketAddr,
    },
    /// Run the directory service
    Directory {
        #[arg(long, default_value = "127.0.0.1:4003")]
        listen: SocketAddr,
        #[arg(long)]
        issuer_url: String,
        /// directory for the JSON store; omit for in-memory
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[command(flatten)]
        platforms: PlatformArgs,
        /// lease of a badge, in days (default nine months)
        #[arg(long, default_value_t = 274, value_parser = clap::value_parser!(u32).range(7..=3650))]
        lease_days: u32,
    },
    /// Run an Oblivious HTTP relay (RFC 9458) in front of the issuer's and directory's gateways, so
    /// that they do not see the holder's address (docs/relay.md). Someone other than their operator
    /// should run it.
    Relay {
        #[arg(long, default_value = "127.0.0.1:4004")]
        listen: SocketAddr,
        /// a server to relay to, as name=address (repeat): `--gateway directory=https://dir.example`
        #[arg(long = "gateway", required = true)]
        gateways: Vec<String>,
    },
    /// Run the mock identity provider alone
    MockIdp {
        #[arg(long, default_value = "127.0.0.1:4001")]
        listen: SocketAddr,
        /// public URL of this server
        #[arg(long, default_value = "http://127.0.0.1:4001")]
        public_url: String,
        #[arg(long, default_value = "pop-issuer")]
        client_id: String,
        #[arg(long, default_value = "mock-secret")]
        client_secret: String,
        #[arg(long, default_value = "http://127.0.0.1:4002/v1/enrol/callback")]
        redirect_uri: String,
    },
    /// Run the mock feed alone
    Mockfeed {
        #[arg(long, default_value = "127.0.0.1:4000")]
        listen: SocketAddr,
    },
    /// The holder app (the person's device)
    Holder(HolderArgs),
    /// Uniqueness keys: run a threshold operator, generate, refresh or hand over the shared key, rotate keys
    Uniqueness {
        #[command(subcommand)]
        cmd: UniqCmd,
    },
}

#[derive(Subcommand)]
enum UniqCmd {
    /// Run one operator of the threshold service
    Operator {
        /// JSON: index, eval_token, admin_token, state_file, max_evals_per_minute, min_threshold
        #[arg(long)]
        config: PathBuf,
        #[arg(long, default_value = "127.0.0.1:4100")]
        listen: SocketAddr,
    },
    /// Generate a new shared key among operators you administer yourself. Prints the group key to pin in the issuer configuration
    Dkg {
        /// JSON list of {index, url, admin_token}
        #[arg(long)]
        cluster: PathBuf,
        #[arg(long)]
        threshold: usize,
    },
    /// Give every operator you administer a new share of the same key; the old shares are erased
    Refresh {
        #[arg(long)]
        cluster: PathBuf,
        #[arg(long)]
        key: String,
    },
    /// Hand the key to a changed operator set you administer (add, remove or replace operators, or change the threshold)
    Reshare {
        #[arg(long)]
        key: String,
        /// cluster file of current holders that deal (at least the current threshold of them)
        #[arg(long)]
        from: PathBuf,
        /// cluster file of the new operator set
        #[arg(long)]
        to: PathBuf,
        #[arg(long)]
        threshold: usize,
    },
    /// Operators with different administrators: write a round, pass the file around, and each administrator joins it
    Round {
        #[command(subcommand)]
        cmd: RoundCmd,
    },
    /// Show what each operator of a cluster file publishes: keys, epochs, thresholds, evaluation counts
    Status {
        #[arg(long)]
        cluster: PathBuf,
    },
    /// Single-operator keyed hash: add a new key next to the old ones (takes effect at the next issuer start)
    RotateKey {
        /// the issuer configuration file
        #[arg(long)]
        config: PathBuf,
    },
    /// Count the issuer's enrolment records per key version (an old key with no records left can be retired)
    Records {
        #[arg(long)]
        config: PathBuf,
    },
}

#[derive(Subcommand)]
enum RoundCmd {
    /// Write the spec of a key generation. `members` is a JSON list of {index, url, identity}; leave
    /// `identity` out only if you accept the key each operator publishes
    NewDkg {
        #[arg(long)]
        members: PathBuf,
        #[arg(long)]
        threshold: usize,
        #[arg(long)]
        out: PathBuf,
    },
    /// Write the spec of a refresh (same members in --from and --to) or a change of operators or threshold
    NewReshare {
        #[arg(long)]
        key: String,
        /// members file of current holders that deal
        #[arg(long)]
        from: PathBuf,
        /// members file of the new operator set
        #[arg(long)]
        to: PathBuf,
        #[arg(long)]
        threshold: usize,
        #[arg(long)]
        out: PathBuf,
    },
    /// Print what a spec says, for the administrator to check before joining
    Show {
        #[arg(long)]
        spec: PathBuf,
    },
    /// Approve the round at your own operator and keep it moving until it is done
    Join {
        #[arg(long)]
        spec: PathBuf,
        /// JSON {index, url, admin_token} of your own operator
        #[arg(long)]
        operator: PathBuf,
        /// give up after this many seconds (the others may not have joined yet)
        #[arg(long, default_value_t = 600)]
        timeout: u64,
    },
}

#[derive(serde::Deserialize)]
struct OperatorFile {
    index: u32,
    eval_token: String,
    admin_token: String,
    state_file: PathBuf,
    #[serde(default = "default_rate")]
    max_evals_per_minute: u32,
    #[serde(default = "default_min_threshold")]
    min_threshold: usize,
}

fn default_rate() -> u32 {
    120
}

fn default_min_threshold() -> usize {
    2
}

fn read_json<T: serde::de::DeserializeOwned>(p: &PathBuf) -> anyhow::Result<T> {
    serde_json::from_slice(&std::fs::read(p).with_context(|| format!("cannot read {}", p.display()))?).with_context(|| format!("cannot parse {}", p.display()))
}

async fn uniqueness_cmd(cmd: UniqCmd) -> anyhow::Result<()> {
    use pop_uniqueness::admin::{self, AdminEndpoint};
    let cluster = |p: &PathBuf| read_json::<Vec<AdminEndpoint>>(p);
    match cmd {
        UniqCmd::Operator { config, listen } => {
            let f: OperatorFile = read_json(&config)?;
            let index = f.index;
            let op = pop_uniqueness::Operator::new(pop_uniqueness::OperatorConfig {
                index,
                eval_token: f.eval_token,
                admin_token: f.admin_token,
                state_file: Some(f.state_file),
                max_evals_per_minute: f.max_evals_per_minute,
                min_threshold: f.min_threshold,
                test_fault: None,
            })?;
            println!("Uniqueness operator {index} listening on http://{listen}");
            println!("Identity key (give it to the other administrators): {}", op.identity());
            serve(listen, pop_uniqueness::router(op)).await?;
        }
        UniqCmd::Dkg { cluster: c, threshold } => {
            let ops = cluster(&c)?;
            let key = admin::dkg(&ops, threshold).await?;
            println!("New key shared {threshold}-of-{}.", ops.len());
            println!("Group key (append to `uniqueness.keys` in the issuer configuration):\n{key}");
            println!("Version: {}", pop_uniqueness::key_version(&key));
        }
        UniqCmd::Refresh { cluster: c, key } => {
            let ops = cluster(&c)?;
            let cur = admin::current_epoch(&key, &ops).await?;
            let epoch = admin::reshare(&key, &ops, &ops, cur.threshold).await?;
            println!("Shares refreshed: epoch {epoch}, old shares erased. The key and every deduplication key are unchanged.");
        }
        UniqCmd::Reshare { key, from, to, threshold } => {
            let (dealers, receivers) = (cluster(&from)?, cluster(&to)?);
            let epoch = admin::reshare(&key, &dealers, &receivers, threshold).await?;
            println!("New shares dealt: epoch {epoch}, {threshold}-of-{}. Every operator of the round erased its older shares.", receivers.len());
            println!("An operator that held a share but took no part still has it: check with `pop uniqueness status`.");
        }
        UniqCmd::Round { cmd } => {
            use pop_uniqueness::admin::Member;
            use pop_uniqueness::wire::RoundSpec;
            let members = |p: &PathBuf| read_json::<Vec<Member>>(p);
            let write = |spec: &RoundSpec, out: &PathBuf| -> anyhow::Result<()> {
                std::fs::write(out, serde_json::to_vec_pretty(spec)?)?;
                println!("Round {} written to {}. Send the file to every administrator; each checks it (`round show`) and runs `round join`.", spec.id(), out.display());
                Ok(())
            };
            match cmd {
                RoundCmd::NewDkg { members: m, threshold, out } => write(&admin::spec_dkg(&members(&m)?, threshold).await?, &out)?,
                RoundCmd::NewReshare { key, from, to, threshold, out } => write(&admin::spec_reshare(&key, &members(&from)?, &members(&to)?, threshold).await?, &out)?,
                RoundCmd::Show { spec } => {
                    let s: RoundSpec = read_json(&spec)?;
                    pop_uniqueness::round::check_spec(&s).map_err(|e| anyhow::anyhow!("this spec is not valid: {e}"))?;
                    println!("Round {}", s.id());
                    match &s.key {
                        None => println!("  generates a NEW key, shared {}-of-{}", s.threshold, s.receivers.len()),
                        Some(k) => println!("  gives new shares of key {} ({}-of-{}), dealt from epoch {} by operators {:?}, as epoch {}", pop_uniqueness::key_version(k), s.threshold, s.receivers.len(), s.from_epoch.unwrap_or(0), s.dealers, s.new_epoch),
                    }
                    println!("  operators that will hold a share afterwards: {:?}", s.receivers);
                    let leaving: Vec<u32> = s.dealers.iter().copied().filter(|d| !s.receivers.contains(d)).collect();
                    if !leaving.is_empty() {
                        println!("  operators that leave and erase their share: {leaving:?}");
                    }
                    println!("  identity keys (compare each with what its administrator gave you):");
                    for p in &s.peers {
                        println!("    operator {} at {}: {}", p.index, p.url, p.identity);
                    }
                }
                RoundCmd::Join { spec, operator, timeout } => {
                    let s: RoundSpec = read_json(&spec)?;
                    let me: AdminEndpoint = read_json(&operator)?;
                    println!("Joining round {} as operator {} ...", s.id(), me.index);
                    let st = admin::join(&s, &me, std::time::Duration::from_secs(timeout)).await?;
                    match st.result {
                        Some((key, epoch)) => println!("Done. This operator holds epoch {epoch} of key {} and erased its older shares.\nGroup key: {key}", pop_uniqueness::key_version(&key)),
                        None => println!("Done. This operator left the set and erased its share."),
                    }
                }
            }
        }
        UniqCmd::Status { cluster: c } => {
            for o in cluster(&c)? {
                match admin::public(&o.url).await {
                    Ok(info) => {
                        println!("operator {} at {}", info.index, o.url);
                        for k in info.keys {
                            let eps: Vec<String> = k.epochs.iter().map(|e| format!("epoch {} ({}-of-{}, operators {:?})", e.epoch, e.threshold, e.vks.len(), e.vks.keys().collect::<Vec<_>>())).collect();
                            println!("  {}  {}  evaluations since start: {}", pop_uniqueness::key_version(&k.key), eps.join(", "), k.evaluations);
                        }
                    }
                    Err(e) => println!("operator {} at {}: unreachable ({e})", o.index, o.url),
                }
            }
        }
        UniqCmd::RotateKey { config } => {
            let f: IssuerFile = read_json(&config)?;
            let (new, all) = wiring::rotate_hmac_key(&f)?;
            println!("New key {new} written. Restart the issuer to use it.");
            println!("Keys now (newest first): {}", all.join(", "));
            println!("Keep the older key files: records under them are matched and moved to the new key when their owner next logs in.");
        }
        UniqCmd::Records { config } => {
            let f: IssuerFile = read_json(&config)?;
            for (v, n) in wiring::records_per_version(&f).await? {
                println!("{v}: {n} record(s)");
            }
        }
    }
    Ok(())
}

#[derive(Args, Clone)]
struct DevnetArgs {
    /// legogroth16 (default) or bulletproofs
    #[arg(long, default_value = "legogroth16")]
    proof_system: String,
    /// depth of the 4-ary revocation tree (capacity 4^depth - 1 revoked handles)
    #[arg(long, default_value_t = 8)]
    tree_depth: usize,
    /// keep keys and data here between runs; omit for in-memory
    #[arg(long)]
    data_dir: Option<PathBuf>,
    /// who holds the deduplication key: `threshold` (2-of-3 operators, each its own server, plus a
    /// standby) or `hmac` (one keyed hash inside the issuer)
    #[arg(long, default_value = "threshold")]
    uniqueness: String,
}

#[derive(Args, Clone, Default)]
struct PlatformArgs {
    /// enable the mock feed adapter at this URL
    #[arg(long)]
    mockfeed_url: Option<String>,
    /// mock feed handle the holder acts as (the mock has no passwords)
    #[arg(long)]
    mockfeed_as: Option<String>,
    /// enable the Bluesky adapter (read-only unless an identifier and app password are given)
    #[arg(long)]
    bluesky: bool,
    #[arg(long, env = "POP_BLUESKY_IDENTIFIER")]
    bluesky_identifier: Option<String>,
    /// app password, from Bluesky Settings > Privacy and security > App passwords. Prefer the env var.
    #[arg(long, env = "POP_BLUESKY_APP_PASSWORD", hide_env_values = true)]
    bluesky_app_password: Option<String>,
    #[arg(long)]
    bluesky_pds: Option<String>,
    #[arg(long)]
    bluesky_appview: Option<String>,
}

impl From<PlatformArgs> for PlatformOpts {
    fn from(a: PlatformArgs) -> Self {
        PlatformOpts {
            mockfeed_url: a.mockfeed_url,
            mockfeed_as: a.mockfeed_as,
            bluesky: a.bluesky,
            bluesky_identifier: a.bluesky_identifier,
            bluesky_app_password: a.bluesky_app_password,
            bluesky_pds: a.bluesky_pds,
            bluesky_appview: a.bluesky_appview,
        }
    }
}

#[derive(Args)]
struct HolderArgs {
    /// wallet directory (holds the secret)
    #[arg(long, default_value = "./wallet")]
    wallet: PathBuf,
    #[arg(long, default_value = "http://127.0.0.1:4002")]
    issuer_url: String,
    #[arg(long, default_value = "http://127.0.0.1:4003")]
    directory_url: String,
    /// send requests to the issuer through this Oblivious HTTP relay (with `pop relay`: its address
    /// followed by `/issuer`), so that the issuer does not see this computer's address
    #[arg(long, env = "POP_ISSUER_RELAY")]
    issuer_relay: Option<String>,
    /// the same for the directory (with `pop relay`: its address followed by `/directory`)
    #[arg(long, env = "POP_DIRECTORY_RELAY")]
    directory_relay: Option<String>,
    #[command(flatten)]
    platforms: PlatformArgs,
    #[command(subcommand)]
    cmd: HolderCmd,
}

#[derive(Subcommand)]
enum HolderCmd {
    /// Enrol: identity check in the browser, then blind issuance
    Enrol {
        /// with the mock identity provider only: log this test identity code in without a browser
        #[arg(long)]
        mock_login: Option<String>,
    },
    /// Bind an account: prove, register, and show the code in the bio (or a post)
    Bind {
        platform: String,
        handle: String,
        #[arg(long, default_value_t = 1)]
        slot: u32,
        /// put the code in a new post instead of the bio
        #[arg(long)]
        post: bool,
    },
    /// Switch the badge off for an account
    Unbind { platform: String, handle: String },
    /// Report a like with a one-per-person tag
    Like { platform: String, post: String },
    /// Renew the credential blindly
    Renew,
    /// Revoke your own credential with the guardian key
    Revoke,
    /// The two-year identity re-check: log in again, keep the same secret and badges
    Recheck {
        #[arg(long)]
        mock_login: Option<String>,
    },
    /// Make an encrypted backup and print its paper code (again: new code, old backup deleted)
    Backup,
    /// Restore a backup onto a device without a credential
    Restore {
        /// the paper code; dashes, spaces and case do not matter. Leave it out to be asked for it:
        /// a code on the command line ends up in the shell history
        code: Option<String>,
    },
    /// Replace a lost or stolen secret after an identity check. At once if this wallet still has the
    /// old guardian key; otherwise it waits and the old app can refuse it
    Replace {
        #[arg(long)]
        mock_login: Option<String>,
        /// "It wasn't me": your enrolment was refused because someone else enrolled with your
        /// identity. Their secret is suspended at once and the report counted. Secure your eID first.
        #[arg(long)]
        not_me: bool,
    },
    /// Collect the new credential of a replacement whose wait is over
    Claim,
    /// Refuse a replacement of this wallet's secret that someone else asked for. This is an identity
    /// re-check: your eID together with this wallet's secret outranks the eID alone
    Veto {
        #[arg(long)]
        mock_login: Option<String>,
    },
    Status,
    /// Serve the local API for the browser extension
    Serve {
        #[arg(long, default_value = "127.0.0.1:4010")]
        listen: SocketAddr,
        /// pairing token; default: stored in the wallet directory
        #[arg(long)]
        token: Option<String>,
    },
}

fn devnet_opts(a: &DevnetArgs) -> anyhow::Result<DevnetOpts> {
    Ok(DevnetOpts {
        scheme: SchemeConfig { proof_system: wiring::proof_system(&a.proof_system)?, tree_depth: a.tree_depth, ..Default::default() },
        data_dir: a.data_dir.clone(),
        uniqueness: match a.uniqueness.as_str() {
            "threshold" => devnet::UniquenessMode::Threshold { operators: 3, threshold: 2 },
            "hmac" => devnet::UniquenessMode::Hmac,
            _ => anyhow::bail!("--uniqueness must be threshold or hmac"),
        },
        ..Default::default()
    })
}

async fn serve(listen: SocketAddr, app: axum::Router) -> anyhow::Result<()> {
    let l = tokio::net::TcpListener::bind(listen).await.with_context(|| format!("cannot listen on {listen}"))?;
    axum::serve(l, app).await?;
    Ok(())
}

fn print_devnet(d: &devnet::Devnet) {
    println!("Mock feed          {}", d.feed_url);
    println!("Mock ID provider   {}", d.idp_url);
    println!("Issuer             {}", d.issuer_url);
    println!("Directory          {}", d.directory_url);
    println!("Relay (OHTTP)      {}/issuer, {}/directory", d.relay_url, d.relay_url);
    if let Some(c) = &d.uniqueness {
        for m in &c.members {
            println!("Uniqueness op {}    {}  (holds a share, {}-of-{})", m.index, m.url, c.threshold, c.members.len());
        }
        println!("Uniqueness op {}    {}  (standby, no share)", c.standby.index, c.standby.url);
    }
}

fn holder_for(wallet: PathBuf, d: &devnet::Devnet, as_handle: &str) -> anyhow::Result<Holder> {
    let p = wiring::platforms(&PlatformOpts { mockfeed_url: Some(d.feed_url.clone()), mockfeed_as: Some(as_handle.into()), ..Default::default() });
    // the demo's holders go through the devnet's relay
    wiring::build_holder_via(&d.issuer_url, &d.directory_url, &d.relays(), p, Arc::new(FileWallet::open(wallet)?))
}

async fn demo(a: DevnetArgs) -> anyhow::Result<()> {
    println!("Starting the local services (the first start runs the proof-system setup, about a minute)...");
    let mut d = devnet::start(devnet_opts(&a)?).await?;
    print_devnet(&d);
    let tmp = a.data_dir.clone().unwrap_or_else(|| std::env::temp_dir().join(format!("pop-demo-{}", std::process::id())));
    let step = |n: u32, s: &str| println!("\n[{n}] {s}");

    step(1, "Alice enrols with the mock bank ID. Her secret is drawn on her device and signed blindly.");
    let alice = Arc::new(holder_for(tmp.join("wallet-alice"), &d, "alice")?);
    let _ = std::fs::remove_file(tmp.join("wallet-alice/wallet.json"));
    let url = alice.enrol_start().await?;
    let code = devnet::mock_login(&url, "010190-900A").await?;
    println!("    the issuer's page shows confirmation code {code}; Alice types it into her app");
    alice.enrol_finish(&code).await?;
    println!("    enrolled; credential valid until {}", alice.status()?.expiry.unwrap());

    step(2, "A second device tries to enrol the same identity code. The issuer refuses.");
    let dup = holder_for(tmp.join("wallet-dup"), &d, "bob")?;
    let _ = std::fs::remove_file(tmp.join("wallet-dup/wallet.json"));
    let url = dup.enrol_start().await?;
    let code = devnet::mock_login(&url, "010190-900A").await?;
    match dup.enrol_finish(&code).await {
        Err(e) => println!("    refused: {e}"),
        Ok(()) => anyhow::bail!("duplicate enrolment was accepted"),
    }

    step(3, "Alice binds @alice on the mock feed. The proof is bound to the account; the code goes into her bio.");
    let t = std::time::Instant::now();
    let out = alice.bind("mockfeed", "alice", 1, CodePlacement::Bio).await?;
    println!("    code {} (proof made and verified in {:.1} s)", out.entry.code, t.elapsed().as_secs_f64());
    println!("    directory saw the code in the bio: {}", out.entry.code_seen_on.is_some());

    step(4, "Bob enrols and binds @bob. Carol enrols but binds nothing.");
    let bob = Arc::new(holder_for(tmp.join("wallet-bob"), &d, "bob")?);
    let carol = Arc::new(holder_for(tmp.join("wallet-carol"), &d, "carol")?);
    for (h, id, w) in [(&bob, "020285-901B", "wallet-bob"), (&carol, "030375-902C", "wallet-carol")] {
        let _ = std::fs::remove_file(tmp.join(w).join("wallet.json"));
        let url = h.enrol_start().await?;
        let code = devnet::mock_login(&url, id).await?;
        h.enrol_finish(&code).await?;
    }
    bob.bind("mockfeed", "bob", 1, CodePlacement::Bio).await?;

    step(5, "The like farm put 40 likes on post p2. Verified people like: Alice p3 (twice), Bob p3, Carol p3 and p2.");
    let r = alice.like("mockfeed", "p3").await?;
    println!("    Alice likes p3: new person = {}, verified count = {}", r.new, r.count);
    let r = alice.like("mockfeed", "p3").await?;
    println!("    Alice likes p3 again: new person = {}, verified count = {}", r.new, r.count);
    bob.like("mockfeed", "p3").await?;
    carol.like("mockfeed", "p3").await?;
    carol.like("mockfeed", "p2").await?;
    let c = pop_protocol::api::DirectoryApi::counts(
        &HttpClient::new(&d.directory_url),
        &pop_protocol::api::CountsRequest { platform: "mockfeed".into(), posts: vec!["p2".into(), "p3".into()] },
    )
    .await?;
    println!("    p2: 40 platform likes, {} from verified people", c.counts["p2"]);
    println!("    p3:  6 platform likes, {} from verified people", c.counts["p3"]);

    step(6, "@dailytruth copies Alice's code into its own bio. The code commits to Alice's account, so no badge appears.");
    let http = reqwest::Client::new();
    let tok: serde_json::Value = http.post(format!("{}/api/login", d.feed_url)).json(&serde_json::json!({"handle": "dailytruth"})).send().await?.json().await?;
    http.put(format!("{}/api/me/bio", d.feed_url))
        .bearer_auth(tok["token"].as_str().unwrap_or_default())
        .json(&serde_json::json!({"bio": format!("The news THEY won't tell you!! {}", out.entry.code)}))
        .send()
        .await?
        .error_for_status()?;
    let list = pop_protocol::api::DirectoryApi::list(&HttpClient::new(&d.directory_url), "mockfeed").await?;
    println!("    verified accounts in the directory: {}", list.entries.iter().map(|e| format!("@{}", e.handle)).collect::<Vec<_>>().join(", "));

    step(7, "Alice renews her credential blindly. Her pseudonym and badge stay.");
    let exp = alice.renew().await?;
    println!("    new expiry {}", dates::fmt_day(exp));

    if let Some(c) = d.uniqueness.as_mut() {
        step(8, "The uniqueness operators refresh their shares, then one operator is replaced. The key is never put together.");
        let epoch = c.refresh().await?;
        println!("    refreshed: every operator holds a new share (epoch {epoch}) and erased the old one");
        let (left, joined, epoch) = c.replace_last_member().await?;
        println!("    operator {left} left and erased its share; operator {joined} joined (epoch {epoch})");
        let url = dup.enrol_start().await?;
        let code = devnet::mock_login(&url, "010190-900A").await?;
        anyhow::ensure!(code.is_empty() && dup.enrol_finish(&code).await.is_err(), "Alice's identity was not recognised after the operator change");
        println!("    Alice's identity code is still recognised: a second enrolment is refused as before");
    }

    step(9, "Bob does the two-year identity re-check: he logs in again, his secret and badge stay.");
    let url = bob.recheck_start().await?;
    let code = devnet::mock_login(&url, "020285-901B").await?;
    let next = bob.recheck_finish(&code).await?;
    println!("    re-checked; the next one is due by {}", dates::fmt_day(next));

    step(10, "Bob makes an encrypted backup, loses his phone, and restores on a new one with the paper code.");
    let paper = bob.backup_create().await?;
    println!("    paper code: {paper}  (the server stores ciphertext it cannot read)");
    let bob2 = Arc::new(holder_for(tmp.join("wallet-bob-new"), &d, "bob")?);
    let _ = std::fs::remove_file(tmp.join("wallet-bob-new/wallet.json"));
    bob2.restore(&paper).await?;
    let again = bob2.bind("mockfeed", "bob", 1, CodePlacement::Bio).await?;
    println!("    restored: same secret, same code on @bob ({})", again.entry.code);

    step(11, "Carol lost her phone and has no backup. With only her eID the replacement waits; a re-check with the old app would cancel it.");
    let carol2 = Arc::new(holder_for(tmp.join("wallet-carol-new"), &d, "carol")?);
    let _ = std::fs::remove_file(tmp.join("wallet-carol-new/wallet.json"));
    let url = carol2.replace_start().await?;
    let code = devnet::mock_login(&url, "030375-902C").await?;
    if let pop_holder::ReplaceOutcome::Waiting { claim_after, .. } = carol2.replace_finish(&code, false).await? {
        println!("    request recorded; the new secret can be collected from {claim_after}");
    }
    if let Some(p) = carol.pending_replacement().await? {
        println!("    Carol's old app sees the request (made on {}); whoever has it AND her eID could refuse", dates::fmt_day(p.requested_on));
    }
    println!("    had she kept her guardian key (it is in the backup), the new secret would come at once, with nine months of probation");

    step(12, "Someone enrols with Dave's eID before he does. Dave's enrolment is refused; he secures his eID and reports \"it wasn't me\".");
    let thief = Arc::new(holder_for(tmp.join("wallet-thief"), &d, "dave")?);
    let url = thief.enrol_start().await?;
    thief.enrol_finish(&devnet::mock_login(&url, "040490-903D").await?).await?;
    let dave = Arc::new(holder_for(tmp.join("wallet-dave"), &d, "dave")?);
    let url = dave.enrol_start().await?;
    let code = devnet::mock_login(&url, "040490-903D").await?;
    anyhow::ensure!(code.is_empty() && dave.enrol_finish(&code).await.is_err(), "Dave's second enrolment was not refused");
    println!("    Dave's enrolment is refused: his identity is already enrolled. The app points him to the instructions: {}", reset_eid_help());
    let url = dave.replace_start().await?;
    let code = devnet::mock_login(&url, "040490-903D").await?;
    match dave.replace_finish(&code, true).await? {
        pop_holder::ReplaceOutcome::Issued { counted_from } => println!("    reported; Dave has a new secret at once, which counts from {counted_from} (a week's probation)"),
        pop_holder::ReplaceOutcome::Waiting { claim_after, .. } => println!("    reported; Dave's new secret can be collected from {claim_after}"),
    }
    println!("    the thief's wallet now sees itself suspended: {}", thief.suspended().await?);
    let r = pop_protocol::api::IssuerApi::reports(&HttpClient::new(&d.issuer_url)).await?;
    println!("    public weekly count of such reports this week: {} (alarm cutoff: {:?})", r.weeks.last().map(|w| w.1).unwrap_or(0), r.alarm_cutoff.map(dates::fmt_day));
    println!("    for 90 days, the thief's app AND Dave's eID together could block Dave's new secret; Dave secured his eID, so they cannot");
    println!("    (a quick replacement like this one is possible once in two years; later reports wait 90 days and then nine months)");

    let token = std::env::var("POP_PAIRING_TOKEN").ok().filter(|t| t.len() >= 16).unwrap_or_else(local_api::new_token);
    let l = tokio::net::TcpListener::bind("127.0.0.1:4010").await?;
    println!("\nServices keep running. To see badges and counts in a browser:");
    println!("  1. Load the folder `extension/` as an unpacked extension (chrome://extensions, developer mode).");
    println!("  2. In its options set the pairing token: {token}");
    println!("  3. Open {}  (you are Alice's holder app on http://127.0.0.1:4010)", d.feed_url);
    println!("Press Ctrl-C to stop.");
    axum::serve(l, local_api::router(alice, token)).await?;
    Ok(())
}

/// The identity check: with the mock provider it can run without a browser; otherwise the person
/// opens the address and types the code the issuer's page shows.
/// Where to read how to secure an eID: the copy built into the app, or the repository's.
fn reset_eid_help() -> String {
    format!("{} (or http://127.0.0.1:4010{} while `pop holder serve` runs)", pop_holder::holder::RESET_EID_HELP, pop_holder::holder::RESET_EID_PATH)
}

async fn login(url: &str, mock_login: Option<String>) -> anyhow::Result<String> {
    Ok(match mock_login {
        Some(id) => devnet::mock_login(url, &id).await?,
        None => {
            println!("Open this address in your own browser and log in:\n\n  {url}\n\nThen type the 6-digit code from that page here and press Enter.");
            let mut s = String::new();
            std::io::stdin().read_line(&mut s)?;
            s
        }
    })
}

async fn holder_cmd(a: HolderArgs) -> anyhow::Result<()> {
    let wallet_dir = a.wallet.clone();
    let relays = wiring::Relays { issuer: a.issuer_relay.clone(), directory: a.directory_relay.clone() };
    let h = Arc::new(wiring::build_holder_via(&a.issuer_url, &a.directory_url, &relays, wiring::platforms(&a.platforms.into()), Arc::new(FileWallet::open(&a.wallet)?))?);
    match a.cmd {
        HolderCmd::Enrol { mock_login } => {
            let code = login(&h.enrol_start().await?, mock_login).await?;
            if let Err(e) = h.enrol_finish(&code).await {
                if matches!(e, pop_holder::HolderError::EnrolNotReady(pop_protocol::api::EnrolStatus::AlreadyEnrolled)) {
                    println!("This identity is already enrolled, so a second enrolment is refused.\n");
                    println!("If you enrolled it yourself on a phone you no longer have, run `pop holder restore` (with your backup code)");
                    println!("or `pop holder replace`. The new secret counts after about nine months.\n");
                    println!("If you did NOT enrol it, someone has used your eID. First secure your eID: close it with its provider,");
                    println!("report the crime to the police and get new eID means. How, with phone numbers: {}", reset_eid_help());
                    println!("Then run `pop holder replace --not-me` with the new eID means. The other secret is suspended at once.");
                }
                return Err(e.into());
            }
            println!("Enrolled. {}", serde_json::to_string_pretty(&h.status()?)?);
        }
        HolderCmd::Bind { platform, handle, slot, post } => {
            let out = h.bind(&platform, &handle, slot, if post { CodePlacement::Post } else { CodePlacement::Bio }).await?;
            println!("Bound {} on {platform}. Code: {}", out.entry.handle, out.entry.code);
            if let Some(n) = out.publish_note {
                println!("{n}");
            }
            println!("Lease until {}. Counted: {}.", dates::fmt_day(out.entry.lease_until), out.entry.counted);
        }
        HolderCmd::Unbind { platform, handle } => {
            h.unbind(&platform, &handle).await?;
            println!("Badge withdrawn.");
        }
        HolderCmd::Like { platform, post } => {
            let r = h.like(&platform, &post).await?;
            println!("Reported. New person: {}. Verified likes on this post: {}.", r.new, r.count);
        }
        HolderCmd::Renew => println!("Renewed until {}.", dates::fmt_day(h.renew().await?)),
        HolderCmd::Revoke => {
            h.revoke().await?;
            println!("Credential revoked.");
        }
        HolderCmd::Recheck { mock_login } => {
            let code = login(&h.recheck_start().await?, mock_login).await?;
            let next = h.recheck_finish(&code).await?;
            println!("Identity re-checked. Same secret, same badges. Next re-check by {}.", dates::fmt_day(next));
        }
        HolderCmd::Backup => {
            let code = h.backup_create().await?;
            println!("Backup stored, encrypted. Write this code on paper and keep it away from this device:\n\n  {code}\n");
            println!("It is shown this once and is not kept here. Whoever has it can restore your secret; without it nobody can read the backup.");
        }
        HolderCmd::Restore { code } => {
            let code = match code {
                Some(c) => c,
                None => {
                    println!("Type the backup code from your paper and press Enter.");
                    let mut s = String::new();
                    std::io::stdin().read_line(&mut s)?;
                    s
                }
            };
            h.restore(&code).await?;
            println!("Restored. {}", serde_json::to_string_pretty(&h.status()?)?);
            println!("If the credential has expired, run `pop holder renew`.");
        }
        HolderCmd::Replace { mock_login, not_me } => {
            if not_me {
                println!("Before you go on: if you have not secured your eID yet, do it first, or whoever used it can undo this.");
                println!("How: {}\n", reset_eid_help());
            }
            let code = login(&h.replace_start().await?, mock_login).await?;
            match h.replace_finish(&code, not_me).await? {
                pop_holder::ReplaceOutcome::Issued { counted_from } if not_me => {
                    println!("Reported. The secret enrolled with your identity is revoked from now on, and you have a new one.");
                    println!("Bind your accounts again now; they and your likes count from {counted_from}.");
                    println!("For 90 days, someone who has the old app AND can log in with your eID can still block this and take the");
                    println!("identity back. If that happens, your eID is still not safe: tell the police and your eID provider. {}", reset_eid_help());
                }
                pop_holder::ReplaceOutcome::Issued { counted_from } => {
                    println!("Secret replaced. The old secret is revoked; its badges run out with their leases.");
                    println!("The new secret is in probation: bind your accounts again now, they and your likes count from {counted_from}.");
                }
                pop_holder::ReplaceOutcome::Waiting { claim_after, claim_before, suspended } => {
                    if suspended {
                        println!("Reported. The secret enrolled with your identity is suspended from now on: it can no longer bind accounts or like.");
                        println!("It can be lifted only by someone who has that app AND can log in with your eID. If that happens, your eID is");
                        println!("still not safe: tell the police and your eID provider. {}", reset_eid_help());
                    }
                    println!("Request recorded. This wallet does not have the old guardian key, so the replacement waits.");
                    println!("Until then it can be refused from the app with the old secret, which takes your eID as well. Run `pop holder claim` between {claim_after} and {claim_before}.");
                }
            }
        }
        HolderCmd::Claim => println!("Secret replaced. Bind your accounts again; they and your likes count from {}.", h.replace_claim().await?),
        HolderCmd::Veto { mock_login } => {
            let pending = h.pending_replacement().await?.is_some();
            let suspended = h.suspended().await?;
            anyhow::ensure!(pending || suspended, "nobody is waiting to replace this wallet's secret, and it is not suspended");
            let code = login(&h.recheck_start().await?, mock_login).await?;
            h.recheck_finish(&code).await?;
            if suspended {
                println!("Suspension lifted: same secret, same badges. If someone had replaced it with a theft report, their new secret is revoked.");
            }
            if pending {
                println!("Replacement refused.");
            }
            println!("If you did not ask for this, someone else can log in with your eID. Secure it now: {}", reset_eid_help());
        }
        HolderCmd::Status => {
            let suspended = h.suspended().await.unwrap_or(false);
            println!("{}", serde_json::to_string_pretty(&h.status()?)?);
            if suspended {
                println!(
                    "\nWARNING: someone logged in with your eID and reported that they did not enrol this secret, so it is suspended.\n\
                     If that was not you, run `pop holder veto` (it asks you to log in), then secure your eID: {}",
                    reset_eid_help()
                );
            }
            if let Ok(Some(p)) = h.pending_replacement().await {
                println!(
                    "\nWARNING: on {} someone logged in with your eID and asked to REPLACE this wallet's secret. It takes effect from {}.\nIf that was not you, run `pop holder veto` now (it asks you to log in), then secure your eID: {}",
                    dates::fmt_day(p.requested_on),
                    dates::fmt_day(p.claim_after),
                    reset_eid_help()
                );
            }
        }
        HolderCmd::Serve { listen, token } => {
            anyhow::ensure!(listen.ip().is_loopback(), "the local API must listen on a loopback address");
            let tf = wallet_dir.join("pairing-token");
            let token = match token {
                Some(t) => t,
                None => match std::fs::read_to_string(&tf) {
                    Ok(t) => t.trim().to_string(),
                    Err(_) => {
                        let t = local_api::new_token();
                        std::fs::write(&tf, &t)?;
                        t
                    }
                },
            };
            if let Ok(Some(p)) = h.pending_replacement().await {
                println!(
                    "WARNING: on {} someone logged in with your eID and asked to REPLACE this wallet's secret (from {}). If that was not you, run `pop holder veto`, then secure your eID: http://{listen}{}",
                    dates::fmt_day(p.requested_on),
                    dates::fmt_day(p.claim_after),
                    pop_holder::holder::RESET_EID_PATH
                );
            }
            if h.suspended().await.unwrap_or(false) {
                println!(
                    "WARNING: this wallet's secret is suspended by a theft report made with your eID. If that was not you, run `pop holder veto`, then secure your eID: http://{listen}{}",
                    pop_holder::holder::RESET_EID_PATH
                );
            }
            println!("Holder app listening on http://{listen}\nPairing token for the extension: {token}");
            serve(listen, local_api::router(h, token)).await?;
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // The arkworks gadget crates open a tracing span per gadget whose fields print the whole constraint
    // system; with a subscriber listening that makes proving thousands of times slower. Always off.
    let mut filter = tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    for d in ["r1cs=off", "ark_r1cs_std=off", "ark_relations=off", "ark_crypto_primitives=off", "legogroth16=off"] {
        filter = filter.add_directive(d.parse().expect("directive"));
    }
    tracing_subscriber::fmt().with_env_filter(filter).init();
    match Cli::parse().cmd {
        Cmd::Devnet(a) => {
            println!("Starting (the first start runs the proof-system setup, about a minute)...");
            let d = devnet::start(devnet_opts(&a)?).await?;
            print_devnet(&d);
            println!("Press Ctrl-C to stop.");
            tokio::signal::ctrl_c().await?;
        }
        Cmd::Demo(a) => demo(a).await?,
        Cmd::Issuer { config, listen } => {
            let f: IssuerFile = serde_json::from_slice(&std::fs::read(&config).with_context(|| format!("cannot read {}", config.display()))?)?;
            let issuer = wiring::build_issuer(&f).await?;
            println!("Issuer listening on http://{listen}");
            serve(listen, wiring::with_gateway(pop_issuer::router(issuer))?).await?;
        }
        Cmd::Directory { listen, issuer_url, data_dir, platforms, lease_days } => {
            let d = Directory::connect(
                Arc::new(HttpClient::new(&issuer_url)),
                wiring::platforms(&platforms.into()),
                wiring::store(data_dir.as_deref(), "directory-db")?,
                DirectoryConfig { lease_days, ..Default::default() },
            )
            .await?;
            println!("Directory listening on http://{listen}");
            serve(listen, wiring::with_gateway(pop_directory::router(d))?).await?;
        }
        Cmd::Relay { listen, gateways } => {
            let mut m = std::collections::BTreeMap::new();
            for g in gateways {
                let (name, url) = g.split_once('=').context("--gateway takes name=address")?;
                m.insert(name.to_string(), url.to_string());
            }
            println!("Relay listening on http://{listen} for {}", m.keys().cloned().collect::<Vec<_>>().join(", "));
            serve(listen, pop_ohttp::relay::router(m)?).await?;
        }
        Cmd::MockIdp { listen, public_url, client_id, client_secret, redirect_uri } => {
            println!("Mock identity provider listening on http://{listen}");
            serve(listen, pop_mock_idp::router(MockIdpConfig { issuer: public_url, clients: vec![MockClient { client_id, client_secret, redirect_uri }] })).await?;
        }
        Cmd::Mockfeed { listen } => {
            println!("Mock feed listening on http://{listen}");
            serve(listen, pop_mockfeed::router()).await?;
        }
        Cmd::Holder(a) => holder_cmd(a).await?,
        Cmd::Uniqueness { cmd } => uniqueness_cmd(cmd).await?,
    }
    Ok(())
}
