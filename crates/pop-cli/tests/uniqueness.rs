//! The uniqueness key in the running system: fail closed on a lost key, versions and migration, and
//! the threshold service behind the issuer. Each test starts its own services (Bulletproofs, so there
//! is no setup to wait for; enrolment needs no proof anyway).
use pop_cli::devnet::{self, Devnet, DevnetOpts, UniquenessMode};
use pop_cli::wiring::{self, IssuerFile, PlatformOpts, UniquenessFile};
use pop_crypto::{ProofSystem, SchemeConfig};
use pop_holder::{Holder, MemoryWallet};
use std::path::{Path, PathBuf};
use std::sync::Arc;

fn scheme() -> SchemeConfig {
    SchemeConfig { proof_system: ProofSystem::Bulletproofs, tree_depth: 4, slots: 3, bp_gens_log2: 13 }
}

fn opts(dir: &Path, uniqueness: UniquenessMode) -> DevnetOpts {
    DevnetOpts { scheme: scheme(), data_dir: Some(dir.to_path_buf()), ports: [0; 5], uniqueness, replace_wait_days: None, bucket_posts: None, like_window_secs: None }
}

fn tmp(name: &str) -> PathBuf {
    let p = std::env::temp_dir().join(format!("pop-uniq-e2e-{}-{name}", std::process::id()));
    let _ = std::fs::remove_dir_all(&p);
    std::fs::create_dir_all(&p).unwrap();
    p
}

fn holder(d: &Devnet) -> Holder {
    let p = wiring::platforms(&PlatformOpts { mockfeed_url: Some(d.feed_url.clone()), mockfeed_as: Some("alice".into()), ..Default::default() });
    wiring::build_holder(&d.issuer_url, &d.directory_url, p, Arc::new(MemoryWallet::default()))
}

/// Try to enrol `id`; true if a credential was issued.
async fn enrol(d: &Devnet, id: &str) -> bool {
    let h = holder(d);
    let url = h.enrol_start().await.unwrap();
    let code = devnet::mock_login(&url, id).await.unwrap();
    h.enrol_finish(&code).await.is_ok()
}

/// The issuer configuration the devnet uses for `dir`, as far as the key commands need it.
fn issuer_file(dir: &Path) -> IssuerFile {
    IssuerFile {
        data_dir: Some(dir.to_path_buf()),
        scheme: scheme(),
        oidc: wiring::mock_oidc("http://127.0.0.1:1", "http://127.0.0.1:2"),
        provider_code: 1,
        uniqueness: UniquenessFile::Hmac,
        uniqueness_key: None,
        policy: Default::default(),
    }
}

#[tokio::test]
async fn rotation_migrates_records_and_still_refuses_a_second_enrolment() {
    let dir = tmp("rotate");
    let d = devnet::start(opts(&dir, UniquenessMode::Hmac)).await.unwrap();
    assert!(enrol(&d, "ROT-ALICE").await);
    assert!(enrol(&d, "ROT-BOB").await);
    assert!(!enrol(&d, "ROT-ALICE").await);
    let f = issuer_file(&dir);
    let before = wiring::records_per_version(&f).await.unwrap();
    assert_eq!(before.len(), 1);
    let (v1, n) = before.iter().next().map(|(k, n)| (k.clone(), *n)).unwrap();
    assert_eq!(n, 2);
    assert!(v1.starts_with("hmac:"));

    // rotate, then restart (a second set of services on the same data directory)
    let (v2, all) = wiring::rotate_hmac_key(&f).unwrap();
    assert_eq!(all, vec![v2.clone(), v1.clone()]);
    let d = devnet::start(opts(&dir, UniquenessMode::Hmac)).await.unwrap();

    // Alice is found under the old key, refused, and her record moves to the new key
    assert!(!enrol(&d, "ROT-ALICE").await);
    let m = wiring::records_per_version(&f).await.unwrap();
    assert_eq!((m.get(&v1).copied(), m.get(&v2).copied()), (Some(1), Some(1)));
    // refused again, now by the migrated record; nothing is duplicated
    assert!(!enrol(&d, "rot-alice ").await);
    assert_eq!(wiring::records_per_version(&f).await.unwrap(), m);
    // a new person enrols under the new key
    assert!(enrol(&d, "ROT-CAROL").await);
    assert_eq!(wiring::records_per_version(&f).await.unwrap().get(&v2).copied(), Some(2));
    // Bob never logged in again: his record waits under the old key and still blocks him
    assert!(!enrol(&d, "ROT-BOB").await);
    assert_eq!(wiring::records_per_version(&f).await.unwrap().get(&v1).copied(), None);

    // rotating twice more keeps everyone recognised
    wiring::rotate_hmac_key(&f).unwrap();
    wiring::rotate_hmac_key(&f).unwrap();
    let d = devnet::start(opts(&dir, UniquenessMode::Hmac)).await.unwrap();
    for id in ["ROT-ALICE", "ROT-BOB", "ROT-CAROL"] {
        assert!(!enrol(&d, id).await, "{id}");
    }
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn issuer_refuses_to_start_without_the_key_of_its_records() {
    let dir = tmp("failclosed");
    let d = devnet::start(opts(&dir, UniquenessMode::Hmac)).await.unwrap();
    assert!(enrol(&d, "FC-ALICE").await);
    let key_file = dir.join("uniqueness-keys/0001.key");
    let key = std::fs::read(&key_file).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(std::fs::metadata(&key_file).unwrap().permissions().mode() & 0o777, 0o600);
    }

    // key lost: no start, and no fresh key is written in its place
    std::fs::remove_file(&key_file).unwrap();
    let e = devnet::start(opts(&dir, UniquenessMode::Hmac)).await.unwrap_err().to_string();
    assert!(e.contains("refusing to start"), "{e}");
    assert!(!key_file.exists());
    assert!(wiring::rotate_hmac_key(&issuer_file(&dir)).is_err(), "rotation is not a way around a lost key");

    // another key in its place: no start either
    std::fs::write(&key_file, hex::encode([7u8; 32])).unwrap();
    let e = format!("{:#}", devnet::start(opts(&dir, UniquenessMode::Hmac)).await.unwrap_err());
    assert!(e.contains("refusing to start") && e.contains("1 record(s) under hmac:"), "{e}");

    // an unreadable key file is an error, not "no key"
    std::fs::write(&key_file, "not hex").unwrap();
    assert!(devnet::start(opts(&dir, UniquenessMode::Hmac)).await.is_err());

    // an older key removed while records still sit under it: no start
    std::fs::write(&key_file, &key).unwrap();
    wiring::rotate_hmac_key(&issuer_file(&dir)).unwrap();
    std::fs::remove_file(&key_file).unwrap();
    let e = format!("{:#}", devnet::start(opts(&dir, UniquenessMode::Hmac)).await.unwrap_err());
    assert!(e.contains("refusing to start"), "{e}");

    // switching the service kind under existing records: no start
    let e = format!("{:#}", devnet::start(opts(&dir, UniquenessMode::Threshold { operators: 3, threshold: 2 })).await.unwrap_err());
    assert!(e.contains("refusing to start"), "{e}");

    // key restored: starts, and Alice is still enrolled
    std::fs::write(&key_file, &key).unwrap();
    let d = devnet::start(opts(&dir, UniquenessMode::Hmac)).await.unwrap();
    assert!(!enrol(&d, "FC-ALICE").await);
    let _ = std::fs::remove_dir_all(dir);
}

#[tokio::test]
async fn threshold_service_behind_the_issuer() {
    let dir = tmp("threshold");
    let mode = UniquenessMode::Threshold { operators: 3, threshold: 2 };
    let mut d = devnet::start(opts(&dir, mode)).await.unwrap();
    assert!(enrol(&d, "TH-ALICE").await);
    assert!(!enrol(&d, "TH-ALICE").await);
    let f = issuer_file(&dir);
    let m = wiring::records_per_version(&f).await.unwrap();
    assert!(m.keys().all(|v| v.starts_with("threshold:")), "{m:?}");

    let c = d.uniqueness.as_mut().unwrap();
    assert_eq!(c.refresh().await.unwrap(), 2);
    assert!(!enrol(&d, "TH-ALICE").await, "recognised after a refresh");
    let c = d.uniqueness.as_mut().unwrap();
    let (left, joined, epoch) = c.replace_last_member().await.unwrap();
    assert_eq!((left, joined, epoch), (3, 4, 3));
    assert!(!enrol(&d, "TH-ALICE").await, "recognised after an operator was replaced");
    assert!(enrol(&d, "TH-BOB").await);

    // restart everything from disk: same key, same shares, same answers
    let d = devnet::start(opts(&dir, mode)).await.unwrap();
    let c = d.uniqueness.as_ref().unwrap();
    assert_eq!(c.members.iter().map(|m| m.index).collect::<Vec<_>>(), vec![1, 2, 4]);
    assert!(!enrol(&d, "TH-ALICE").await);
    assert!(!enrol(&d, "TH-BOB").await);
    assert!(enrol(&d, "TH-CAROL").await);

    // the share files of two operators lost: the issuer answers "try later", it does not enrol anyone twice
    std::fs::remove_file(dir.join("uniqueness-operator-1.json")).unwrap();
    std::fs::remove_file(dir.join("uniqueness-operator-2.json")).unwrap();
    let d = devnet::start(opts(&dir, mode)).await.unwrap();
    let h = holder(&d);
    let url = h.enrol_start().await.unwrap();
    let r = reqwest::Client::new().get({
        let mut u = reqwest::Url::parse(&url).unwrap();
        u.query_pairs_mut().append_pair("login_hint", "TH-ALICE").append_pair("auto", "1");
        u
    }).send().await.unwrap();
    assert_eq!(r.status().as_u16(), 503);
    let _ = std::fs::remove_dir_all(dir);
}
