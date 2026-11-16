//! The checks of a round that do not depend on one operator's state: is a spec well-formed, is a
//! deal good, is a complaint justified. Receivers, complaint verifiers and tests share them.
use crate::ident::{self, Opening, Pok, Sealed};
use crate::shamir::{commitment_at, distinct_nonzero, lagrange_at_zero};
use crate::wire::*;
use ark_ec::{AffineRepr, CurveGroup, Group};
use ark_ff::Zero;
use pop_crypto::codec::{from_hex, ser, to_hex};
use pop_crypto::params::{Fr, G2, G2A};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

pub const MAX_OPERATORS: usize = 64;

/// The parsed, validated form of a spec.
pub struct Checked {
    pub id: String,
    /// index ↦ (url, identity key)
    pub peers: BTreeMap<u32, (String, G2A)>,
    pub group_key: Option<G2A>,
}

/// Everything about a spec that any participant can check without its own records.
pub fn check_spec(spec: &RoundSpec) -> Result<Checked, String> {
    if !(16..=64).contains(&spec.nonce.len()) || !spec.nonce.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err("nonce must be 16 to 64 hex characters".into());
    }
    let (d, r) = (&spec.dealers, &spec.receivers);
    if d.is_empty() || r.is_empty() || d.len() > MAX_OPERATORS || r.len() > MAX_OPERATORS {
        return Err("a round needs between 1 and 64 dealers and receivers".into());
    }
    if !distinct_nonzero(d) || !distinct_nonzero(r) {
        return Err("operator indices must be distinct and at least 1".into());
    }
    if spec.threshold < 1 || spec.threshold > r.len() {
        return Err("threshold must be between 1 and the number of receivers".into());
    }
    let mut peers = BTreeMap::new();
    for p in &spec.peers {
        if !crate::url_is_safe(&p.url) {
            return Err(format!("operator {} must be reached over https", p.index));
        }
        let key = ident::parse_public(&p.identity).map_err(|e| format!("identity key of operator {}: {e}", p.index))?;
        if to_hex(&key) != p.identity {
            return Err(format!("identity key of operator {} is not in canonical form", p.index));
        }
        if peers.insert(p.index, (p.url.trim_end_matches('/').to_string(), key)).is_some() {
            return Err(format!("operator {} is listed twice", p.index));
        }
    }
    let mut ids: Vec<Vec<u8>> = peers.values().map(|(_, k)| ser(k)).collect();
    ids.sort();
    ids.dedup();
    if ids.len() != peers.len() {
        return Err("two operators have the same identity key".into());
    }
    if d.iter().chain(r.iter()).any(|i| !peers.contains_key(i)) || peers.keys().any(|i| !d.contains(i) && !r.contains(i)) {
        return Err("`peers` must list exactly the dealers and receivers".into());
    }
    let group_key = match spec.kind {
        RoundKind::Dkg => {
            let (mut a, mut b) = (d.clone(), r.clone());
            a.sort_unstable();
            b.sort_unstable();
            if a != b || spec.key.is_some() || spec.from_epoch.is_some() || spec.new_epoch != 1 {
                return Err("in key generation every receiver deals, there is no key yet, and the epoch is 1".into());
            }
            None
        }
        RoundKind::Reshare => {
            let (Some(key), Some(from), Some(old_t)) = (spec.key.as_ref(), spec.from_epoch, spec.old_threshold) else {
                return Err("reshare needs key, from_epoch and old_threshold".into());
            };
            if *key != key.to_lowercase() {
                return Err("key must be lower-case hex".into());
            }
            let y = ident::parse_public(key).map_err(|e| format!("group key: {e}"))?;
            if spec.new_epoch <= from {
                return Err("the new epoch must be later than the one it is dealt from".into());
            }
            if d.len() < old_t {
                return Err(format!("{} dealers cannot reshare a key with threshold {old_t}", d.len()));
            }
            // The dealers' verification keys must interpolate to Y. This is what lets a new operator,
            // which has no earlier state, trust the spec: nobody can deal for another key.
            let mut acc = G2::zero();
            for i in d {
                let text = spec.old_vks.get(i).ok_or(format!("no verification key for dealer {i}"))?;
                let vk = ident::parse_public(text)?;
                // deals are compared with this text; another spelling of the same point would make
                // an honest dealer's deal look wrong
                if to_hex(&vk) != *text {
                    return Err(format!("verification key of dealer {i} is not in canonical form"));
                }
                acc += vk * lagrange_at_zero(d, *i);
            }
            if acc.into_affine() != y {
                return Err("the dealers' verification keys do not combine to the group key".into());
            }
            Some(y)
        }
    };
    Ok(Checked { id: spec.id(), peers, group_key })
}

pub fn seal_context(round_id: &str, from: u32, to: u32) -> Vec<u8> {
    format!("{round_id}|deal|{from}|{to}").into_bytes()
}

pub fn pok_context(round_id: &str, from: u32) -> Vec<u8> {
    format!("{round_id}|pok|{from}").into_bytes()
}

/// The hash a dealer commits to before dealing.
pub fn commit_hash(commitments: &[String], pok: &Option<Pok>) -> String {
    let mut h = Sha256::new();
    h.update(b"pop-uniqueness-commit-v1");
    h.update(serde_json::to_vec(&(commitments, pok)).expect("serializes"));
    hex::encode(h.finalize())
}

/// What a receiver that accepted every deal has seen: each dealer's committed hash. Two receivers
/// with the same transcript hold the same commitments from every dealer.
pub fn transcript<'a>(round_id: &str, commits: impl Iterator<Item = (u32, &'a str)>) -> String {
    let mut h = Sha256::new();
    h.update(b"pop-uniqueness-ready-v2");
    h.update(round_id.as_bytes());
    for (dealer, hash) in commits {
        h.update(dealer.to_be_bytes());
        h.update((hash.len() as u64).to_be_bytes());
        h.update(hash.as_bytes());
    }
    hex::encode(h.finalize())
}

/// Is this deal from `from` to `to` good? `value` is the decrypted value, or why it could not be
/// decrypted. Returns the parsed commitments and the value.
#[allow(clippy::too_many_arguments)]
pub fn check_deal(
    spec: &RoundSpec,
    round_id: &str,
    from: u32,
    to: u32,
    commitments: &[String],
    pok: &Option<Pok>,
    value: Result<Fr, String>,
    committed_hash: &str,
) -> Result<(Vec<G2A>, Fr), String> {
    if commit_hash(commitments, pok) != committed_hash {
        return Err("the deal is not what the dealer committed to".into());
    }
    if commitments.len() != spec.threshold {
        return Err("wrong number of commitments".into());
    }
    let c: Vec<G2A> = commitments.iter().map(|x| from_hex::<G2A>(x).map_err(|e| e.to_string())).collect::<Result<_, _>>()?;
    match spec.kind {
        RoundKind::Reshare => {
            if spec.old_vks.get(&from).map(String::as_str) != Some(to_hex(&c[0]).as_str()) {
                return Err("the dealer did not share its current share".into());
            }
        }
        RoundKind::Dkg => {
            if c[0].is_zero() {
                return Err("empty contribution".into());
            }
            match pok {
                Some(p) if ident::pok_verify(&c[0], &pok_context(round_id, from), p) => {}
                _ => return Err("no proof that the dealer knows its contribution".into()),
            }
        }
    }
    let v = value?;
    if G2::generator() * v != commitment_at(&c, to) {
        return Err("the value does not match the commitments".into());
    }
    Ok((c, v))
}

fn body_of(env: &Envelope, spec: &RoundSpec, checked: &Checked) -> Result<Body, String> {
    if env.round_id != checked.id {
        return Err("message of another round".into());
    }
    let (_, key) = checked.peers.get(&env.from).ok_or("sender is not part of the round")?;
    if !ident::verify(key, &Envelope::signed_bytes(&env.round_id, env.from, &env.body), &env.sig) {
        return Err("bad signature".into());
    }
    let _ = spec;
    serde_json::from_str(&env.body).map_err(|e| format!("unreadable message: {e}"))
}

/// Verify an envelope's signature against the spec and parse its body.
pub fn open_envelope(env: &Envelope, spec: &RoundSpec, checked: &Checked) -> Result<Body, String> {
    body_of(env, spec, checked)
}

/// Is `complainer`'s complaint justified? `Ok(dealer)` = the dealer is proven to have sent a bad
/// deal; `Err` = the complaint does not hold (and the complainer signed it).
pub fn verify_complaint(spec: &RoundSpec, checked: &Checked, complainer: u32, deal: &Envelope, commit: &Envelope, opening: Option<&Opening>) -> Result<u32, String> {
    let dealer = deal.from;
    if commit.from != dealer || !spec.dealers.contains(&dealer) || !spec.receivers.contains(&complainer) {
        return Err("the evidence is not a dealer's commit and deal".into());
    }
    let Body::Commit { hash } = body_of(commit, spec, checked)? else { return Err("not a commit".into()) };
    let Body::Deal { to, commitments, pok, sealed } = body_of(deal, spec, checked)? else { return Err("not a deal".into()) };
    if to != complainer {
        return Err("the deal was addressed to someone else".into());
    }
    let value = opened(checked, &checked.id, dealer, complainer, &sealed, opening)?;
    match check_deal(spec, &checked.id, dealer, complainer, &commitments, &pok, value, &hash) {
        Err(_) => Ok(dealer),
        Ok(_) => Err("the deal is good".into()),
    }
}

fn opened(checked: &Checked, round_id: &str, dealer: u32, complainer: u32, sealed: &Sealed, opening: Option<&Opening>) -> Result<Result<Fr, String>, String> {
    let (_, key) = checked.peers.get(&complainer).ok_or("complainer is not part of the round")?;
    ident::open_with(key, &seal_context(round_id, dealer, complainer), sealed, opening)
}
