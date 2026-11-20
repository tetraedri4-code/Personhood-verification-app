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
        certified: dates::week_start(today.saturating_sub(300)),
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
    let bp = w.scheme.prove_binding(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, 1, today, today, true, bind).unwrap();
    w.scheme.verify_binding(&vc, today, ctx, bind, &bp).unwrap();
    // the same proof cannot be claimed for another account
    assert!(w.scheme.verify_binding(&vc, today, ctx, b"mockfeed|user:mallory|nonce1", &bp).is_err());
    // nor in another context
    assert!(w.scheme.verify_binding(&vc, today, "pop:ctx:other", bind, &bp).is_err());
    // the pseudonym is stable per (context, slot) and differs across slots
    let bp2 = w.scheme.prove_binding(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, 1, today, today, false, b"x").unwrap();
    assert_eq!(bp.nym, bp2.nym);
    assert_eq!(bp.tags, bp2.tags);
    let bp3 = w.scheme.prove_binding(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, 2, today, today, false, b"x").unwrap();
    assert_ne!(bp.nym, bp3.nym);
    assert!(w.scheme.prove_binding(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, 4, today, today, false, b"x").is_err());
    // tampered: swapped nym
    let mut bad = bp.clone();
    bad.nym = bp3.nym.clone();
    assert!(w.scheme.verify_binding(&vc, today, ctx, bind, &bad).is_err());

    // likes: one tag per person per post
    let l1 = w.scheme.prove_like(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, "post-1", today, today).unwrap();
    let l2 = w.scheme.prove_like(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, "post-1", today, today).unwrap();
    let l3 = w.scheme.prove_like(&mut rng, &bob, &tree, &w.ik.public, &w.wk.public, ctx, "post-1", today, today).unwrap();
    let l4 = w.scheme.prove_like(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, "post-2", today, today).unwrap();
    for (l, p) in [(&l1, "post-1"), (&l2, "post-1"), (&l3, "post-1"), (&l4, "post-2")] {
        w.scheme.verify_like(&vc, today, ctx, p, l).unwrap();
    }
    assert!(w.scheme.verify_like(&vc, today, ctx, "post-2", &l1).is_err());
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
    let bp4 = w.scheme.prove_binding(&mut rng, &alice2, &tree, &w.ik.public, &w.wk.public, ctx, 1, today, today, false, b"y").unwrap();
    assert_eq!(bp4.nym, bp.nym, "renewal keeps pseudonyms");

    // re-check: the issuer learns the handle and the old month, and moves the month forward
    {
        let later = today + 600; // 20 months on, inside the 24-month window
        let mut old = alice2.clone();
        // keep the credential alive up to `later` by blind renewals, as a real holder would
        let exp = dates::quarter_end(dates::quarter_of(later));
        let (rp, rho) = w.scheme.prove_renewal(&mut rng, &old, &tree, &w.ik.public, &w.wk.public, today, b"r2").unwrap();
        let sig = w.scheme.reissue(&mut rng, &w.ik, &vc, b"r2", &rp, exp).unwrap();
        old = w.scheme.finish_renewal(&w.ik.public, &old, rho, &sig, exp).unwrap();
        let vcl = VerifyCtx { today: later, ..vc.clone() };
        let (rp, rho) = w.scheme.prove_recheck(&mut rng, &old, &tree, &w.ik.public, &w.wk.public, later, b"rc").unwrap();
        let (h, oc) = (old.attrs.handle, old.attrs.last_check);
        let (ne, nc) = (dates::quarter_end(dates::quarter_of(later) + 1), dates::month_start(later));
        // wrong handle (another person's login), wrong month, wrong session, or a plain renewal proof: refused
        assert!(w.scheme.reissue_recheck(&mut rng, &w.ik, &vcl, b"rc", &rp, 1 << 41, oc, ne, nc, None).is_err());
        assert!(w.scheme.reissue_recheck(&mut rng, &w.ik, &vcl, b"rc", &rp, h, oc + 31, ne, nc, None).is_err());
        assert!(w.scheme.reissue_recheck(&mut rng, &w.ik, &vcl, b"other", &rp, h, oc, ne, nc, None).is_err());
        assert!(w.scheme.reissue(&mut rng, &w.ik, &vcl, b"rc", &rp, ne).is_err(), "a re-check proof is not a renewal proof");
        let (plain, _) = w.scheme.prove_renewal(&mut rng, &old, &tree, &w.ik.public, &w.wk.public, later, b"rc").unwrap();
        assert!(w.scheme.reissue_recheck(&mut rng, &w.ik, &vcl, b"rc", &plain, h, oc, ne, nc, None).is_err());
        let sig = w.scheme.reissue_recheck(&mut rng, &w.ik, &vcl, b"rc", &rp, h, oc, ne, nc, None).unwrap();
        let fresh = w.scheme.finish_recheck(&w.ik.public, &w.wk.public, &old, rho, &sig, ne, nc, None).unwrap();
        assert_eq!(fresh.attrs.last_check, nc);
        // same secret, same pseudonym; and it now renews at a date where the old one could not
        let far = later + 400;
        let vcf = VerifyCtx { today: far, ..vc.clone() };
        let _ = vcf;
        assert!(w.scheme.prove_renewal(&mut rng, &old, &tree, &w.ik.public, &w.wk.public, far, b"x").is_err(), "re-check overdue");
        assert!(w.scheme.prove_renewal(&mut rng, &fresh, &tree, &w.ik.public, &w.wk.public, later + 300, b"x").is_ok());
        let bp5 = w.scheme.prove_binding(&mut rng, &fresh, &tree, &w.ik.public, &w.wk.public, ctx, 1, later, later, false, b"y").unwrap();
        assert_eq!(bp5.nym, bp.nym, "a re-check keeps pseudonyms");

        // lifting a suspension: the old handle is revoked; the re-check proves against the list as it
        // was before the handle went on it, and the issuer swaps in a new handle
        let before = w.scheme.revocation_tree(&[5]).unwrap();
        let after = w.scheme.revocation_tree(&[5, h]).unwrap();
        assert!(matches!(w.scheme.prove_recheck(&mut rng, &fresh, &after, &w.ik.public, &w.wk.public, later, b"lift"), Err(CryptoError::Revoked)));
        let (rp, rho) = w.scheme.prove_recheck(&mut rng, &fresh, &before, &w.ik.public, &w.wk.public, later, b"lift").unwrap();
        let vcb = VerifyCtx { today: later, revocation_root: before.root(), ..vc.clone() };
        let nh = (1u64 << 42) + 9;
        assert!(w.scheme.reissue_recheck(&mut rng, &w.ik, &vcb, b"lift", &rp, h, nc, ne, nc, Some(h)).is_err(), "same handle");
        let sig = w.scheme.reissue_recheck(&mut rng, &w.ik, &vcb, b"lift", &rp, h, nc, ne, nc, Some(nh)).unwrap();
        let hs = w.wk.sign_handle(&mut rng, nh);
        let wrong = w.wk.sign_handle(&mut rng, nh + 1);
        assert!(w.scheme.finish_recheck(&w.ik.public, &w.wk.public, &fresh, rho, &sig, ne, nc, Some((nh, &wrong))).is_err());
        assert!(w.scheme.finish_recheck(&w.ik.public, &w.wk.public, &fresh, rho, &sig, ne, nc, None).is_err(), "signature is over the new handle");
        let lifted = w.scheme.finish_recheck(&w.ik.public, &w.wk.public, &fresh, rho, &sig, ne, nc, Some((nh, &hs))).unwrap();
        assert_eq!(lifted.attrs.handle, nh);
        let bp6 = w.scheme.prove_binding(&mut rng, &lifted, &after, &w.ik.public, &w.wk.public, ctx, 1, later, later, false, b"y").unwrap();
        assert_eq!(bp6.nym, bp.nym, "lifting keeps the secret and the pseudonyms");
        let vca = VerifyCtx { today: later, revocation_root: after.root(), ..vc.clone() };
        w.scheme.verify_binding(&vca, later, ctx, b"y", &bp6).unwrap();
    }

    // the public cutoff: a secret counting from after it can neither like nor claim a counted badge
    {
        let fresh_attrs = IssuedAttrs { certified: dates::week_start(today), ..attrs(today, 1 << 43) };
        let session = b"session-2";
        let (secrets, req) = BlindRequest::new(&mut rng, &w.scheme, session);
        let sig = w.scheme.issue_blind(&mut rng, &w.ik, &req, &fresh_attrs, session).unwrap();
        let hs = w.wk.sign_handle(&mut rng, 1 << 43);
        let carol = w.scheme.finish_issuance(&w.ik.public, &w.wk.public, &secrets, &sig, &fresh_attrs, &hs).unwrap();
        // no alarm: counts at once
        let l = w.scheme.prove_like(&mut rng, &carol, &tree, &w.ik.public, &w.wk.public, ctx, "fresh", today, today).unwrap();
        w.scheme.verify_like(&vc, today, ctx, "fresh", &l).unwrap();
        // alarm reaching back before her enrolment week
        let cut = dates::count_cutoff(today, Some(dates::week_start(today) - 7));
        assert!(w.scheme.prove_like(&mut rng, &carol, &tree, &w.ik.public, &w.wk.public, ctx, "fresh", today, cut).is_err());
        assert!(w.scheme.prove_binding(&mut rng, &carol, &tree, &w.ik.public, &w.wk.public, ctx, 1, today, cut, true, b"c").is_err());
        assert!(w.scheme.prove_binding(&mut rng, &carol, &tree, &w.ik.public, &w.wk.public, ctx, 1, today, cut, false, b"c").is_ok());
        // a proof made without the alarm does not verify under it, and the other way round
        assert!(w.scheme.verify_like(&vc, cut, ctx, "fresh", &l).is_err());
        let old_like = w.scheme.prove_like(&mut rng, &alice, &tree, &w.ik.public, &w.wk.public, ctx, "fresh", today, cut).unwrap();
        w.scheme.verify_like(&vc, cut, ctx, "fresh", &old_like).unwrap();
    }

    let tree2 = w.scheme.revocation_tree(&[5, 1 << 40]).unwrap();
    assert!(matches!(
        w.scheme.prove_like(&mut rng, &alice, &tree2, &w.ik.public, &w.wk.public, ctx, "p", today, today),
        Err(CryptoError::Revoked)
    ));
    // a proof against an old root is rejected by a verifier that uses the new root
    let vc2 = VerifyCtx { revocation_root: tree2.root(), ..vc.clone() };
    assert!(w.scheme.verify_like(&vc2, today, ctx, "post-1", &l1).is_err());
    // expired credential cannot bind
    let late = dates::quarter_end(dates::quarter_of(today)) + 1;
    assert!(w.scheme.prove_binding(&mut rng, &bob, &tree, &w.ik.public, &w.wk.public, ctx, 1, late, late, false, b"z").is_err());
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
