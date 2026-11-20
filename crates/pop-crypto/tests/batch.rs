//! Checking many like proofs at once: correctness on both proof systems, and (ignored) a measurement of
//! the time per proof against checking them one by one.
//!
//! cargo test --release -p pop-crypto --test batch -- --ignored --nocapture --test-threads 1
use pop_crypto::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;
use std::time::Instant;

struct World {
    scheme: Scheme,
    ik: IssuerKey,
    wk: WitnessKey,
}

fn world(ps: ProofSystem, depth: usize, rng: &mut ChaCha20Rng) -> World {
    let scheme = Scheme::new(SchemeConfig { proof_system: ps, tree_depth: depth, ..Default::default() });
    if ps == ProofSystem::LegoGroth16 {
        let pk = scheme.lego_setup(rng, StatementKind::Like);
        scheme.install_lego_keys(StatementKind::Like, &pk).unwrap();
    }
    World { scheme, ik: IssuerKey::generate(rng), wk: WitnessKey::generate(rng) }
}

fn enrol(w: &World, rng: &mut ChaCha20Rng, today: Day, handle: u64) -> Credential {
    enrol_with(w, &w.ik, rng, today, handle)
}

/// Enrolled by `ik`, which may be another issuer than the one the proofs are checked against: then the
/// proof passes every per-proof check and fails only the combined BBS check.
fn enrol_with(w: &World, ik: &IssuerKey, rng: &mut ChaCha20Rng, today: Day, handle: u64) -> Credential {
    let q = dates::quarter_of(today);
    let a = IssuedAttrs {
        handle,
        expiry: dates::quarter_end(q),
        certified: dates::week_start(today.saturating_sub(300)),
        last_check: dates::month_start(today),
        country: 246,
        first_quarter: q.saturating_sub(4),
        provider: 1,
    };
    let (secrets, req) = BlindRequest::new(rng, &w.scheme, b"s");
    let sig = w.scheme.issue_blind(rng, ik, &req, &a, b"s").unwrap();
    let hs = w.wk.sign_handle(rng, handle);
    w.scheme.finish_issuance(&ik.public, &w.wk.public, &secrets, &sig, &a, &hs).unwrap()
}

const TODAY: Day = 318;
const CTX: &str = "pop:ctx:mockfeed";

/// `n` like proofs by `people` people on different posts, made on all cores.
fn likes(w: &World, rng: &mut ChaCha20Rng, people: usize, n: usize, tree: &revtree::RevocationTree) -> Vec<(String, LikeProof)> {
    let creds: Vec<Credential> = (0..people).map(|i| enrol(w, rng, TODAY, (i as u64 + 1) << 30)).collect();
    let threads = std::thread::available_parallelism().map(|x| x.get()).unwrap_or(1);
    let seeds: Vec<u64> = (0..threads as u64).map(|t| 1000 + t).collect();
    std::thread::scope(|s| {
        let hs: Vec<_> = seeds
            .iter()
            .enumerate()
            .map(|(t, seed)| {
                let creds = &creds;
                s.spawn(move || {
                    let mut rng = ChaCha20Rng::seed_from_u64(*seed);
                    (0..n)
                        .filter(|i| i % threads == t)
                        .map(|i| {
                            let post = format!("post-{i}");
                            let lp = w.scheme.prove_like(&mut rng, &creds[i % creds.len()], tree, &w.ik.public, &w.wk.public, CTX, &post, TODAY, TODAY).unwrap();
                            (post, lp)
                        })
                        .collect::<Vec<_>>()
                })
            })
            .collect();
        hs.into_iter().flat_map(|h| h.join().unwrap()).collect()
    })
}

/// A like proof by a credential of another issuer: false, but only the combined check sees it.
fn forged(w: &World, rng: &mut ChaCha20Rng, tree: &revtree::RevocationTree, post: &str) -> LikeProof {
    let other = IssuerKey::generate(rng);
    let c = enrol_with(w, &other, rng, TODAY, 1 << 45);
    w.scheme.prove_like(rng, &c, tree, &other.public, &w.wk.public, CTX, post, TODAY, TODAY).unwrap()
}

fn check(ps: ProofSystem) {
    let mut rng = ChaCha20Rng::seed_from_u64(5);
    let w = world(ps, 4, &mut rng);
    let tree = w.scheme.revocation_tree(&[5, 1 << 50]).unwrap();
    let vc = VerifyCtx { issuer: &w.ik.public, witness: &w.wk.public, today: TODAY, revocation_root: tree.root() };
    let ls = likes(&w, &mut rng, 2, 4, &tree);
    let items: Vec<(&str, &str, &LikeProof)> = ls.iter().map(|(p, l)| (CTX, p.as_str(), l)).collect();
    w.scheme.verify_likes(&mut rng, &vc, TODAY, &items).unwrap();
    w.scheme.verify_likes(&mut rng, &vc, TODAY, &items[..1]).unwrap();
    // one proof claimed for another post
    let mut bad = items.clone();
    bad[2].1 = "post-0";
    assert!(w.scheme.verify_likes(&mut rng, &vc, TODAY, &bad).is_err());
    // one proof's tag swapped for another's
    let mut swapped = ls[3].1.clone();
    swapped.tag = ls[1].1.tag.clone();
    let mut bad = items.clone();
    bad[3].2 = &swapped;
    assert!(w.scheme.verify_likes(&mut rng, &vc, TODAY, &bad).is_err());
    // two proofs whose SNARK parts are swapped: each part is valid, but not for its own proof
    let mut a: serde_json::Value = serde_json::to_value(&ls[0].1).unwrap();
    let b: serde_json::Value = serde_json::to_value(&ls[1].1).unwrap();
    a["proof"] = b["proof"].clone();
    let mixed: LikeProof = serde_json::from_value(a).unwrap();
    let mut bad = items.clone();
    bad[0].2 = &mixed;
    assert!(w.scheme.verify_likes(&mut rng, &vc, TODAY, &bad).is_err());
    // the sieve finds exactly the false ones, wherever they are in the batch
    let garbage = LikeProof { tag: ls[2].1.tag.clone(), proof: "00".into() };
    let f = forged(&w, &mut rng, &tree, "post-9");
    assert!(w.scheme.verify_like(&vc, TODAY, CTX, "post-9", &f).is_err());
    assert!(w.scheme.verify_likes(&mut rng, &vc, TODAY, &[items[0], (CTX, "post-9", &f)]).is_err());
    let mut mixed_batch = items.clone();
    mixed_batch[0].2 = &mixed;
    mixed_batch[3].2 = &garbage;
    mixed_batch.push(items[1]);
    mixed_batch.push((CTX, "post-9", &f));
    mixed_batch.push(items[2]);
    let flags = w.scheme.sieve_likes(&mut rng, &vc, TODAY, &mixed_batch).unwrap();
    assert_eq!(flags, vec![false, true, true, false, true, false, true]);
    assert_eq!(w.scheme.sieve_likes(&mut rng, &vc, TODAY, &items).unwrap(), vec![true; 4]);
    // mostly false: the budget switches to one-by-one checks, and the answer is the same
    let f2 = forged(&w, &mut rng, &tree, "post-8");
    let many: Vec<(&str, &str, &LikeProof)> = vec![(CTX, "post-9", &f), (CTX, "post-8", &f2), (CTX, "post-9", &f), items[0], (CTX, "post-8", &f2), (CTX, "post-9", &f), (CTX, "post-8", &f2), items[3]];
    assert_eq!(w.scheme.sieve_likes(&mut rng, &vc, TODAY, &many).unwrap(), vec![false, false, false, true, false, false, false, true]);
    assert_eq!(w.scheme.sieve_likes(&mut rng, &vc, TODAY, &[]).unwrap(), Vec::<bool>::new());
    // against another revocation root
    let other = w.scheme.revocation_tree(&[7]).unwrap();
    let vc2 = VerifyCtx { revocation_root: other.root(), ..vc };
    assert!(w.scheme.verify_likes(&mut rng, &vc2, TODAY, &items).is_err());
}

#[test]
fn batch_check_accepts_good_likes_and_refuses_any_bad_one_lego() {
    check(ProofSystem::LegoGroth16);
}

#[test]
fn batch_check_accepts_good_likes_and_refuses_any_bad_one_bulletproofs() {
    check(ProofSystem::Bulletproofs);
}

fn measure(ps: ProofSystem, n: usize, sizes: &[usize]) {
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let w = world(ps, 8, &mut rng);
    let tree = w.scheme.revocation_tree(&[5, 1 << 50]).unwrap();
    let vc = VerifyCtx { issuer: &w.ik.public, witness: &w.wk.public, today: TODAY, revocation_root: tree.root() };
    let t = Instant::now();
    let ls = likes(&w, &mut rng, 8, n, &tree);
    eprintln!("{ps:?}: made {n} like proofs in {:.1} s on all cores", t.elapsed().as_secs_f64());
    let items: Vec<(&str, &str, &LikeProof)> = ls.iter().map(|(p, l)| (CTX, p.as_str(), l)).collect();
    // one by one
    let t = Instant::now();
    for (c, p, l) in &items {
        w.scheme.verify_like(&vc, TODAY, c, p, l).unwrap();
    }
    let one = t.elapsed().as_secs_f64() * 1000.0 / n as f64;
    eprintln!("{ps:?}: one by one {one:.2} ms per proof");
    for &b in sizes {
        let t = Instant::now();
        let mut done = 0;
        while done + b <= n {
            w.scheme.verify_likes(&mut rng, &vc, TODAY, &items[done..done + b]).unwrap();
            done += b;
        }
        let per = t.elapsed().as_secs_f64() * 1000.0 / done as f64;
        eprintln!("{ps:?}: batches of {b:>3}: {per:.2} ms per proof ({:.1}x)", one / per);
    }
    // one batch with false proofs in it that only the combined check catches (another issuer's
    // credential)
    let b = sizes[sizes.len() - 1].min(n);
    let posts: Vec<String> = (0..4).map(|k| format!("forged-{k}")).collect();
    let forgeries: Vec<LikeProof> = posts.iter().map(|p| forged(&w, &mut rng, &tree, p)).collect();
    for m in [1usize, 4] {
        let mut bad = items[..b].to_vec();
        for k in 0..m {
            let at = (k * b) / m + 1;
            bad[at] = (CTX, posts[k].as_str(), &forgeries[k]);
        }
        let t = Instant::now();
        let flags = w.scheme.sieve_likes(&mut rng, &vc, TODAY, &bad).unwrap();
        let per = t.elapsed().as_secs_f64() * 1000.0 / b as f64;
        assert_eq!(flags.iter().filter(|f| !**f).count(), m);
        eprintln!("{ps:?}: sieve, batch of {b} with {m} false: {per:.2} ms per proof ({:.1}x)", one / per);
    }
}

#[test]
#[ignore]
fn measure_batch_lego() {
    measure(ProofSystem::LegoGroth16, 512, &[1, 4, 16, 64, 256, 512]);
}

#[test]
#[ignore]
fn measure_batch_bulletproofs() {
    measure(ProofSystem::Bulletproofs, 128, &[1, 4, 16, 64, 128]);
}

/// Per-proof cost of the directory's check (sieve) by batch size, with 0, 1 or 2 false proofs in every
/// batch (well formed: another issuer's credential, so only the combined check sees them).
fn measure_sizes(ps: ProofSystem, n: usize, sizes: &[usize]) {
    let mut rng = ChaCha20Rng::seed_from_u64(11);
    let w = world(ps, 8, &mut rng);
    let tree = w.scheme.revocation_tree(&[5, 1 << 50]).unwrap();
    let vc = VerifyCtx { issuer: &w.ik.public, witness: &w.wk.public, today: TODAY, revocation_root: tree.root() };
    let ls = likes(&w, &mut rng, 8, n, &tree);
    let items: Vec<(&str, &str, &LikeProof)> = ls.iter().map(|(p, l)| (CTX, p.as_str(), l)).collect();
    let fposts: Vec<String> = (0..2).map(|k| format!("forged-{k}")).collect();
    let forg: Vec<LikeProof> = fposts.iter().map(|p| forged(&w, &mut rng, &tree, p)).collect();
    let t = Instant::now();
    for (c, p, l) in &items {
        w.scheme.verify_like(&vc, TODAY, c, p, l).unwrap();
    }
    eprintln!("{ps:?}: one by one {:.2} ms per proof", t.elapsed().as_secs_f64() * 1000.0 / n as f64);
    for &b in sizes {
        let mut line = format!("{ps:?}: batch {b:>3}:");
        for m in 0..=2usize {
            let mut total = 0.0;
            let mut done = 0;
            while done + b <= n {
                let mut batch = items[done..done + b].to_vec();
                for k in 0..m {
                    batch[(k * b) / 2 + b / 4] = (CTX, fposts[k].as_str(), &forg[k]);
                }
                let t = Instant::now();
                let flags = w.scheme.sieve_likes(&mut rng, &vc, TODAY, &batch).unwrap();
                total += t.elapsed().as_secs_f64();
                assert_eq!(flags.iter().filter(|f| !**f).count(), m);
                done += b;
            }
            line += &format!("  {m} false: {:.2} ms", total * 1000.0 / done as f64);
        }
        eprintln!("{line}");
    }
}

#[test]
#[ignore]
fn measure_batch_sizes_lego() {
    measure_sizes(ProofSystem::LegoGroth16, 512, &[16, 32, 64, 128, 256]);
}

#[test]
#[ignore]
fn measure_batch_sizes_bulletproofs() {
    measure_sizes(ProofSystem::Bulletproofs, 256, &[16, 32, 64, 128, 256]);
}
