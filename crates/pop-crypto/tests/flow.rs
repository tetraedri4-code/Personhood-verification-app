//! End-to-end crypto flow on both proof systems: blind issuance, binding, likes, renewal, revocation.
use pop_crypto::*;
use rand::SeedableRng;
use rand_chacha::ChaCha20Rng;

struct World {
    scheme: Scheme,
    ik: IssuerKey,
    wk: WitnessKey,
}

fn world(ps: ProofSystem, rng: &mut ChaCha20Rng) -> World {
    let scheme = Scheme::new(SchemeConfig { proof_system: ps, tree_depth: 4, slots: 3, bp_gens_log2: 13 });
    if ps == ProofSystem::LegoGroth16 {
        // setup on one Scheme, install the published bytes on the same one (as a holder would)
        for k in StatementKind::ALL {
            let pk = scheme.lego_setup(rng, k);
            scheme.install_lego_keys(k, &pk).unwrap();
        }
    }
    World { scheme, ik: IssuerKey::generate(rng), wk: WitnessKey::generate(rng) }
}

fn attrs(today: Day, handle: u64) -> IssuedAttrs {
    let q = dates::quarter_of(today);
    IssuedAttrs {
        handle,
        expiry: dates::quarter_end(q),
        certified: dates::quarter_start(q.saturating_sub(4)),
        last_check: dates::month_start(today),
        country: 246,
        first_quarter: q.saturating_sub(4),
        provider: 1,
    }
}

fn enrol(w: &World, rng: &mut ChaCha20Rng, today: Day, handle: u64) -> Credential {
    let session = b"session-1";
    let (secrets, req) = BlindRequest::new(rng, &w.scheme, session);
    let a = attrs(today, handle);
    // replay into another session fails
    assert!(w.scheme.issue_blind(rng, &w.ik, &req, &a, b"other").is_err());
    let sig = w.scheme.issue_blind(rng, &w.ik, &req, &a, session).unwrap();
    let hs = w.wk.sign_handle(rng, handle);
    w.scheme.finish_issuance(&w.ik.public, &w.wk.public, &secrets, &sig, &a, &hs).unwrap()
}

fn run(ps: ProofSystem) {
    let mut rng = ChaCha20Rng::seed_from_u64(7);
    let w = world(ps, &mut rng);
    let today = 318;
    let alice = enrol(&w, &mut rng, today, 1 << 40);
    let bob = enrol(&w, &mut rng, today, 1 << 41);
    let tree = w.scheme.revocation_tree(&[5, 1 << 50]).unwrap();
    let vc = VerifyCtx { issuer: &w.ik.public, witness: &w.wk.public, today, revocation_root: tree.root() };
    let ctx = "pop:ctx:mockfeed";
    let bind = b"mockfeed|user:alice|nonce1";

    // binding
    let bp = w.scheme.prove_binding(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, 1, today, true, bind).unwrap();
    w.scheme.verify_binding(&vc, ctx, bind, &bp).unwrap();
    // the same proof cannot be claimed for another account
    assert!(w.scheme.verify_binding(&vc, ctx, b"mockfeed|user:mallory|nonce1", &bp).is_err());
    // nor in another context
    assert!(w.scheme.verify_binding(&vc, "pop:ctx:other", bind, &bp).is_err());
    // the pseudonym is stable per (context, slot) and differs across slots
    let bp2 = w.scheme.prove_binding(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, 1, today, false, b"x").unwrap();
    assert_eq!(bp.nym, bp2.nym);
    assert_eq!(bp.tags, bp2.tags);
    let bp3 = w.scheme.prove_binding(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, 2, today, false, b"x").unwrap();
    assert_ne!(bp.nym, bp3.nym);
    assert!(w.scheme.prove_binding(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, 4, today, false, b"x").is_err());
    // tampered: swapped nym
    let mut bad = bp.clone();
    bad.nym = bp3.nym.clone();
    assert!(w.scheme.verify_binding(&vc, ctx, bind, &bad).is_err());

    // likes: one tag per person per post
    let l1 = w.scheme.prove_like(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, "post-1", today).unwrap();
    let l2 = w.scheme.prove_like(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, "post-1", today).unwrap();
    let l3 = w.scheme.prove_like(&mut rng, &bob, &tree, &w.ik.public, &w.wk.public, ctx, "post-1", today).unwrap();
    let l4 = w.scheme.prove_like(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, "post-2", today).unwrap();
    for (l, p) in [(&l1, "post-1"), (&l2, "post-1"), (&l3, "post-1"), (&l4, "post-2")] {
        w.scheme.verify_like(&vc, ctx, p, l).unwrap();
    }
    assert!(w.scheme.verify_like(&vc, ctx, "post-2", &l1).is_err());
    assert_eq!(l1.tag, l2.tag);
    assert_ne!(l1.tag, l3.tag);
    assert_ne!(l1.tag, l4.tag);
    assert_eq!(w.scheme.like_tag(&alice, ctx, "post-1"), l1.tag);

    // renewal
    let session = b"renew-1";
    let (rp, rho) = w.scheme.prove_renewal(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, today, session).unwrap();
    let new_exp = dates::quarter_end(dates::quarter_of(today) + 1);
    assert!(w.scheme.reissue(&mut rng, &w.ik, &vc, b"other", &rp, new_exp).is_err());
    let sig = w.scheme.reissue(&mut rng, &w.ik, &vc, session, &rp, new_exp).unwrap();
    let alice2 = w.scheme.finish_renewal(&w.ik.public, &alice, rho, &sig, new_exp).unwrap();
    assert_eq!(alice2.expiry(), new_exp);
    let bp4 = w.scheme.prove_binding(&mut rng, &alice2, &tree, &w.ik.public, &w.wk.public, ctx, 1, today, false, b"y").unwrap();
    assert_eq!(bp4.nym, bp.nym, "renewal keeps pseudonyms");

    // revocation: once alice's handle is in the tree she can no longer prove
    let tree2 = w.scheme.revocation_tree(&[5, 1 << 40]).unwrap();
    assert!(matches!(
        w.scheme.prove_like(&mut rng, &alice, &tree2, &w.ik.public, &w.wk.public, ctx, "p", today),
        Err(CryptoError::Revoked)
    ));
    // a proof against an old root is rejected by a verifier that uses the new root
    let vc2 = VerifyCtx { revocation_root: tree2.root(), ..vc.clone() };
    assert!(w.scheme.verify_like(&vc2, ctx, "post-1", &l1).is_err());
    // expired credential cannot bind
    let late = dates::quarter_end(dates::quarter_of(today)) + 1;
    assert!(w.scheme.prove_binding(&mut rng, &bob, &tree, &w.ik.public, &w.wk.public, ctx, 1, late, false, b"z").is_err());
    eprintln!("{ps:?}: binding proof {} bytes, like proof {} bytes", bp.proof.len() / 2, l1.proof.len() / 2);
}

#[test]
fn flow_legogroth16() {
    run(ProofSystem::LegoGroth16);
}

#[test]
fn flow_bulletproofs() {
    run(ProofSystem::Bulletproofs);
}

#[test]
fn credential_json_roundtrip() {
    let mut rng = ChaCha20Rng::seed_from_u64(9);
    let w = world(ProofSystem::Bulletproofs, &mut rng);
    let c = enrol(&w, &mut rng, 318, 12345);
    let c2 = Credential::from_json(&c.to_json()).unwrap();
    assert_eq!(c2.to_json(), c.to_json());
}

#[test]
fn off_grid_rejected() {
    let mut a = attrs(318, 99);
    a.expiry += 1;
    assert!(a.check_grid().is_err());
}
