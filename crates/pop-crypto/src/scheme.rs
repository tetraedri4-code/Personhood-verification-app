//! High-level API of the cryptographic core. Everything else in the repository talks to the crypto only
//! through this module; the benchmark engine (`statement`, `tree`, `poseidon`, ...) stays underneath.
//!
//! Flows (design v2 references in brackets):
//! * blind issuance [§4.3]: `BlindRequest::new` (holder) → `Scheme::issue_blind` (issuer)
//!   → `Scheme::finish_issuance` (holder). The issuer never sees s, rho or delta.
//! * witness signature on the handle r [§4.2 "Issued handles"]: `WitnessKey::sign_handle`.
//! * account binding with pseudonym and quarterly badge tags [§4.4, §4.5]: `Scheme::prove_binding`
//!   / `Scheme::verify_binding`.
//! * one-per-person like tag [voluntary-app report §3 row 9]: `Scheme::prove_like` / `verify_like`.
//! * blind credential renewal [§4.6]: `Scheme::prove_renewal` → `Scheme::reissue` → `Scheme::finish_renewal`.
//!
//! The proof system is pluggable: `ProofSystem::LegoGroth16` (default, small and fast, per-statement
//! trusted setup) or `ProofSystem::Bulletproofs` (no trusted setup, slower and larger).
use crate::codec::{self, from_hex, to_hex};
use crate::dates::{self, Day};
use crate::params::*;
use crate::poseidon::Poseidon;
use crate::revtree::RevocationTree;
use crate::statement::{self, Cfg, HashUse, Holder, LegoKeys, Public, Range};
use crate::tree::TreeShape;
use ark_bulletproofs::{BulletproofGens, PedersenGens};
use ark_ec::{pairing::Pairing, AffineRepr, CurveGroup, Group, VariableBaseMSM};
use ark_ff::{Field, PrimeField, UniformRand, Zero};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock};

pub use crate::statement::Backend as ProofSystem;

#[derive(Debug, thiserror::Error)]
pub enum CryptoError {
    #[error("invalid encoding: {0}")]
    Encoding(String),
    #[error("proof did not verify")]
    InvalidProof,
    #[error("credential signature does not verify")]
    BadSignature,
    #[error("attribute off the published grid: {0}")]
    OffGrid(String),
    #[error("credential handle is revoked")]
    Revoked,
    #[error("statement cannot be proved: {0}")]
    Unprovable(String),
    #[error("missing proving keys for statement {0}; download them from the issuer")]
    MissingKeys(String),
}

pub type Result<T> = std::result::Result<T, CryptoError>;

/// Public parameters every party must agree on. Published by the issuer at `/v1/params`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct SchemeConfig {
    pub proof_system: ProofSystem,
    /// Revocation tree: 4-ary, this depth. Capacity = 4^depth - 1 revoked handles.
    pub tree_depth: usize,
    /// k: pseudonym slots per platform context and person (design §4.4).
    pub slots: u32,
    /// Bulletproofs generator capacity, log2. Ignored for LegoGroth16.
    pub bp_gens_log2: usize,
}

impl Default for SchemeConfig {
    fn default() -> Self {
        SchemeConfig { proof_system: ProofSystem::LegoGroth16, tree_depth: 8, slots: 3, bp_gens_log2: 14 }
    }
}

/// The statements this prototype proves. Each has a fixed shape, hence one LegoGroth16 key pair.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum StatementKind {
    Binding,
    BindingProbation,
    Like,
    Renewal,
}

impl StatementKind {
    pub const ALL: [StatementKind; 4] = [Self::Binding, Self::BindingProbation, Self::Like, Self::Renewal];
    pub fn name(&self) -> &'static str {
        match self {
            Self::Binding => "binding",
            Self::BindingProbation => "binding-probation",
            Self::Like => "like",
            Self::Renewal => "renewal",
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------------------------

/// Issuer signing key (design: threshold-shared, one per quarter; here one party, one key).
pub struct IssuerKey {
    x: Fr,
    pub public: IssuerPublicKey,
}

#[derive(Clone, Debug, PartialEq)]
pub struct IssuerPublicKey {
    pub w: G2A,
}

impl IssuerKey {
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        let x = Fr::rand(rng);
        IssuerKey { x, public: IssuerPublicKey { w: (G2::generator() * x).into_affine() } }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        codec::ser(&self.x)
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let x: Fr = codec::de(b)?;
        Ok(IssuerKey { x, public: IssuerPublicKey { w: (G2::generator() * x).into_affine() } })
    }
}

/// Key of the log witnesses, who sign every issued handle r once (Pointcheval–Sanders).
pub struct WitnessKey {
    x: Fr,
    y: Fr,
    pub public: WitnessPublicKey,
}

#[derive(Clone, Debug, PartialEq)]
pub struct WitnessPublicKey {
    pub xt: G2A,
    pub yt: G2A,
}

#[derive(Clone, Debug, PartialEq)]
pub struct HandleSignature(pub G1A, pub G1A);

impl WitnessKey {
    pub fn generate<R: RngCore>(rng: &mut R) -> Self {
        Self::from_scalars(Fr::rand(rng), Fr::rand(rng))
    }
    fn from_scalars(x: Fr, y: Fr) -> Self {
        let g2 = G2::generator();
        WitnessKey { x, y, public: WitnessPublicKey { xt: (g2 * x).into_affine(), yt: (g2 * y).into_affine() } }
    }
    pub fn to_bytes(&self) -> Vec<u8> {
        codec::ser(&(self.x, self.y))
    }
    pub fn from_bytes(b: &[u8]) -> Result<Self> {
        let (x, y): (Fr, Fr) = codec::de(b)?;
        Ok(Self::from_scalars(x, y))
    }
    pub fn sign_handle<R: RngCore>(&self, rng: &mut R, r: u64) -> HandleSignature {
        let h = (G1::generator() * Fr::rand(rng)).into_affine();
        HandleSignature(h, (h * (self.x + self.y * Fr::from(r))).into_affine())
    }
}

impl WitnessPublicKey {
    pub fn verify_handle(&self, r: u64, sig: &HandleSignature) -> bool {
        if sig.0.is_zero() {
            return false;
        }
        let rhs = (self.xt.into_group() + self.yt * Fr::from(r)).into_affine();
        E::multi_pairing([sig.1, (-sig.0.into_group()).into_affine()], [G2::generator().into_affine(), rhs]).is_zero()
    }
}

// ---------------------------------------------------------------------------------------------
// Attributes and credential
// ---------------------------------------------------------------------------------------------

/// Attributes the issuer knows and sets (design §4.1). All lie on published grids.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct IssuedAttrs {
    /// revocation handle r, random in [1, 2^63)
    pub handle: u64,
    /// tau: expiry, the last day of a calendar quarter
    pub expiry: Day,
    /// gamma: first day of the quarter in which s was certified (probation)
    pub certified: Day,
    /// ell: first day of the month of the last eID check
    pub last_check: Day,
    /// c: ISO 3166 numeric code of the identity source's country (246 = Finland)
    pub country: u32,
    /// gamma0: quarter index of first enrolment
    pub first_quarter: u32,
    /// e: identity provider code from the published list
    pub provider: u32,
}

impl IssuedAttrs {
    /// The component refuses credentials whose issuer-known values are off the grid, so the issuer
    /// cannot tag one person with an unusual value (design §4.1).
    pub fn check_grid(&self) -> Result<()> {
        let q = dates::quarter_of(self.expiry);
        if self.expiry != dates::quarter_end(q) {
            return Err(CryptoError::OffGrid("expiry is not the last day of a quarter".into()));
        }
        if self.certified != dates::quarter_start(dates::quarter_of(self.certified)) {
            return Err(CryptoError::OffGrid("certification date is not a quarter start".into()));
        }
        if self.last_check != dates::month_start(self.last_check) {
            return Err(CryptoError::OffGrid("re-check date is not a month start".into()));
        }
        if self.handle == 0 || self.handle >= 1 << 63 {
            return Err(CryptoError::OffGrid("handle out of range".into()));
        }
        if self.provider > 64 || self.country > 999 || self.first_quarter > 4000 {
            return Err(CryptoError::OffGrid("small attribute out of range".into()));
        }
        Ok(())
    }
}

/// Values the holder draws and the issuer never sees.
#[derive(Clone)]
pub struct HolderSecrets {
    pub rho: Fr,
    pub s: Fr,
    /// delta: re-check grace, 1 to 4 months
    pub delta: u64,
}

/// A credential held by the component. Serialized only into the holder's own encrypted store.
#[derive(Clone)]
pub struct Credential {
    pub inner: statement::Credential,
    pub attrs: IssuedAttrs,
    pub handle_sig: HandleSignature,
}

impl Credential {
    pub fn handle(&self) -> u64 {
        self.attrs.handle
    }
    pub fn expiry(&self) -> Day {
        self.attrs.expiry
    }
    pub fn secret(&self) -> Fr {
        self.inner.m[A_S]
    }
}

/// Holder → issuer: commitment C = h_rho^rho h_s^s h_delta^delta and a Schnorr proof of its opening.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindRequest {
    pub commitment: String,
    pub challenge: String,
    pub responses: Vec<String>,
}

/// Issuer → holder.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BlindSignature {
    pub a: String,
    pub e: String,
}

// ---------------------------------------------------------------------------------------------
// Proof messages
// ---------------------------------------------------------------------------------------------

/// What a holder publishes to bind an account: the pseudonym, the four quarterly badge tags and the proof.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct BindingProof {
    pub slot: u32,
    pub nym: String,
    /// badge tags T_E for the four quarters the lease touches, in order
    pub tags: Vec<String>,
    pub quarters: Vec<u32>,
    pub probation_cleared: bool,
    pub proof: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
pub struct LikeProof {
    pub tag: String,
    pub proof: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RenewalProof {
    pub proof: String,
}

/// Everything a verifier checks a proof against, apart from the proof itself.
#[derive(Clone, Debug)]
pub struct VerifyCtx<'a> {
    pub issuer: &'a IssuerPublicKey,
    pub witness: &'a WitnessPublicKey,
    pub today: Day,
    /// revocation root the holder proved against; the verifier must check it is current or previous
    pub revocation_root: Fr,
}

// ---------------------------------------------------------------------------------------------
// Scheme
// ---------------------------------------------------------------------------------------------

pub struct Scheme {
    pub config: SchemeConfig,
    pub g: Gens,
    pub pos3: Poseidon,
    pub pos5: Poseidon,
    bp: OnceLock<BulletproofGens<G1A>>,
    lego: Mutex<HashMap<StatementKind, Arc<LegoKeys>>>,
}

fn dom(tag: &str) -> Fr {
    hash_to_fr(b"EUPC-HP-DOM", tag.as_bytes())
}

/// Scalar form of a platform context id P (a public string such as "pop:ctx:bluesky").
pub fn context_scalar(ctx: &str) -> Fr {
    hash_to_fr(b"POP-V1-CTX", ctx.as_bytes())
}

/// Scalar form of a post id, for like tags.
pub fn post_scalar(post: &str) -> Fr {
    hash_to_fr(b"POP-V1-POST", post.as_bytes())
}

fn output_base(label: &str, ctx: &str, slot: u32, extra: &str) -> G1A {
    hash_to_g1(b"POP-V1-HG", format!("{label}|{ctx}|{slot}|{extra}").as_bytes())
}

impl Scheme {
    pub fn new(config: SchemeConfig) -> Self {
        Scheme {
            config,
            g: Gens::new(),
            pos3: Poseidon::new(3),
            pos5: Poseidon::new(5),
            bp: OnceLock::new(),
            lego: Mutex::new(HashMap::new()),
        }
    }

    pub fn tree_shape(&self) -> TreeShape {
        TreeShape { arity: 4, depth: self.config.tree_depth }
    }

    pub fn revocation_tree(&self, revoked: &[u64]) -> Result<RevocationTree> {
        RevocationTree::build(revoked, self.tree_shape(), &self.pos3, &self.pos5).map_err(CryptoError::Unprovable)
    }

    fn bp_gens(&self) -> &BulletproofGens<G1A> {
        self.bp.get_or_init(|| {
            let n = if self.config.proof_system == ProofSystem::Bulletproofs { 1 << self.config.bp_gens_log2 } else { 1 };
            BulletproofGens::new(n, 1)
        })
    }

    // ------------------------------- LegoGroth16 keys -------------------------------

    /// Run the per-statement setup. In this prototype the issuer runs it alone and publishes the keys,
    /// so a dishonest issuer could forge proofs. A real deployment replaces this by a multi-party
    /// ceremony (see docs/crypto.md).
    pub fn lego_setup<R: RngCore>(&self, rng: &mut R, kind: StatementKind) -> Vec<u8> {
        let cfg = self.cfg_for(&self.dummy_stmt(kind));
        let keys = statement::lego_setup(rng, &cfg, cfg_pos(self, &cfg), &self.pos3, &self.pos5, 0);
        let mut b = vec![];
        keys.pk.serialize_compressed(&mut b).expect("serialize pk");
        self.lego.lock().unwrap().insert(kind, Arc::new(keys));
        b
    }

    /// Install proving keys downloaded from the issuer.
    pub fn install_lego_keys(&self, kind: StatementKind, pk_bytes: &[u8]) -> Result<()> {
        let pk = legogroth16::ProvingKey::<E>::deserialize_compressed(pk_bytes)
            .map_err(|e| CryptoError::Encoding(format!("lego pk: {e}")))?;
        let pvk = legogroth16::prepare_verifying_key(&pk.vk);
        self.lego.lock().unwrap().insert(kind, Arc::new(LegoKeys { pk, pvk }));
        Ok(())
    }

    pub fn has_keys(&self, kind: StatementKind) -> bool {
        self.config.proof_system != ProofSystem::LegoGroth16 || self.lego.lock().unwrap().contains_key(&kind)
    }

    // ------------------------------- issuance -------------------------------

    /// Issuer: check the holder's proof of opening and sign blindly.
    pub fn issue_blind<R: RngCore>(
        &self,
        rng: &mut R,
        key: &IssuerKey,
        req: &BlindRequest,
        attrs: &IssuedAttrs,
        session: &[u8],
    ) -> Result<BlindSignature> {
        attrs.check_grid()?;
        let c: G1A = from_hex(&req.commitment)?;
        if !self.check_opening(c, req, session)? {
            return Err(CryptoError::InvalidProof);
        }
        let m = issuer_attr_scalars(attrs);
        let mut b: G1 = self.g.p1 + self.g.q1 * statement::domain() + c;
        for j in 3..N_ATTR {
            b += self.g.h[j] * m[j];
        }
        let e = Fr::rand(rng);
        let a = (b * (key.x + e).inverse().unwrap()).into_affine();
        Ok(BlindSignature { a: to_hex(&a), e: to_hex(&e) })
    }

    fn check_opening(&self, c: G1A, req: &BlindRequest, session: &[u8]) -> Result<bool> {
        if req.responses.len() != 3 || c.is_zero() {
            return Ok(false);
        }
        let ch: Fr = from_hex(&req.challenge)?;
        let z: Vec<Fr> = req.responses.iter().map(|s| from_hex(s)).collect::<Result<_>>()?;
        let bases = [self.g.h[A_RHO], self.g.h[A_S], self.g.h[A_DELTA]];
        let t = G1::msm(&bases, &z).unwrap() - c * ch;
        Ok(opening_challenge(&c, &t.into_affine(), session) == ch)
    }

    /// Holder: check the blind signature and assemble the credential.
    pub fn finish_issuance(
        &self,
        issuer: &IssuerPublicKey,
        witness: &WitnessPublicKey,
        secrets: &HolderSecrets,
        sig: &BlindSignature,
        attrs: &IssuedAttrs,
        handle_sig: &HandleSignature,
    ) -> Result<Credential> {
        attrs.check_grid()?;
        let mut m = issuer_attr_scalars(attrs);
        m[A_RHO] = secrets.rho;
        m[A_S] = secrets.s;
        m[A_DELTA] = Fr::from(secrets.delta);
        let a: G1A = from_hex(&sig.a)?;
        let e: Fr = from_hex(&sig.e)?;
        if !statement::bbs_verify(&self.g, &issuer.w, &a, e, &statement::bbs_b(&self.g, &m)) {
            return Err(CryptoError::BadSignature);
        }
        if !witness.verify_handle(attrs.handle, handle_sig) {
            return Err(CryptoError::BadSignature);
        }
        let mv = attr_small_values(attrs, secrets.delta);
        Ok(Credential { inner: statement::Credential { a, e, m, mv }, attrs: attrs.clone(), handle_sig: handle_sig.clone() })
    }

    // ------------------------------- statements -------------------------------

    fn dummy_stmt(&self, kind: StatementKind) -> Stmt {
        let today = 400;
        match kind {
            StatementKind::Binding | StatementKind::BindingProbation => Stmt::Binding {
                ctx: "setup".into(),
                slot: 1,
                quarters: dates::lease_quarters(today),
                today,
                probation: kind == StatementKind::BindingProbation,
                root: Fr::zero(),
                bind: vec![],
            },
            StatementKind::Like => Stmt::Like { ctx: "setup".into(), post: "setup".into(), today, root: Fr::zero(), bind: vec![] },
            StatementKind::Renewal => Stmt::Renewal { today, root: Fr::zero(), bind: vec![], shown: None },
        }
    }

    fn cfg_for(&self, st: &Stmt) -> Cfg {
        let kind = st.kind();
        let (hashes, ranges, today, root, bind) = match st {
            Stmt::Binding { ctx, slot, quarters, today, probation, root, bind } => {
                let p = context_scalar(ctx);
                let mut h = vec![HashUse {
                    label: "nym",
                    tag: dom("nym"),
                    ctx: p,
                    slot: Fr::from(*slot as u64),
                    extra: Fr::from(0u64),
                    bases: vec![output_base("nym", ctx, *slot, "j=0")],
                    hidden: vec![false],
                }];
                for q in quarters {
                    h.push(HashUse {
                        label: "pub",
                        tag: dom("pub"),
                        ctx: p,
                        slot: Fr::from(*slot as u64),
                        extra: Fr::from(*q as u64),
                        bases: vec![output_base("pub", ctx, *slot, &format!("E={q}"))],
                        hidden: vec![false],
                    });
                }
                let mut r = vec![Range { label: "tau >= today", terms: vec![(A_TAU, 1)], constant: -(*today as i64) }];
                if *probation {
                    r.push(Range {
                        label: "gamma <= today - 9 months",
                        terms: vec![(A_GAMMA, -1)],
                        constant: *today as i64 - dates::PROBATION_DAYS as i64,
                    });
                }
                (h, r, *today, *root, bind.clone())
            }
            Stmt::Like { ctx, post, today, root, bind } => {
                let h = vec![HashUse {
                    label: "like",
                    tag: dom("like"),
                    ctx: context_scalar(ctx),
                    slot: Fr::from(0u64),
                    extra: post_scalar(post),
                    bases: vec![output_base("like", ctx, 0, post)],
                    hidden: vec![false],
                }];
                let r = vec![Range { label: "tau >= today", terms: vec![(A_TAU, 1)], constant: -(*today as i64) }];
                (h, r, *today, *root, bind.clone())
            }
            Stmt::Renewal { today, root, bind, .. } => {
                let t = *today as i64;
                let r = vec![
                    Range { label: "tau >= today - 12 months", terms: vec![(A_TAU, 1)], constant: dates::RENEW_GRACE_DAYS as i64 - t },
                    Range {
                        label: "ell + 24 months + delta >= today",
                        terms: vec![(A_ELL, 1), (A_DELTA, 30)],
                        constant: dates::RECHECK_DAYS as i64 - t,
                    },
                    Range { label: "delta <= 4 months", terms: vec![(A_DELTA, -1)], constant: 4 },
                ];
                (vec![], r, *today, *root, bind.clone())
            }
        };
        // Bind every public value of the statement into the Fiat–Shamir context as well.
        let mut context = Vec::new();
        context.extend_from_slice(b"POP-V1|");
        context.extend_from_slice(kind.name().as_bytes());
        context.extend_from_slice(&today.to_be_bytes());
        context.extend_from_slice(&codec::ser(&root));
        for h in &hashes {
            context.extend_from_slice(&codec::ser(&(h.tag, h.ctx, h.slot, h.extra)));
        }
        context.extend_from_slice(&(bind.len() as u64).to_be_bytes());
        context.extend_from_slice(&bind);
        let mut reveal = vec![];
        if let Stmt::Renewal { shown: Some((handle, last_check)), .. } = st {
            context.extend_from_slice(b"|RECHECK");
            context.extend_from_slice(&handle.to_be_bytes());
            context.extend_from_slice(&last_check.to_be_bytes());
            reveal = vec![(A_R, Fr::from(*handle)), (A_ELL, Fr::from(*last_check as u64))];
        }
        Cfg {
            name: kind.name().into(),
            context,
            hashes,
            n_gens: 0,
            tree: Some(self.tree_shape()),
            roots: vec![root],
            ranges,
            d_entries: vec![],
            reissue: kind == StatementKind::Renewal,
            reveal,
            backend: self.config.proof_system,
            width: 5,
            compact: false,
            lego: self.lego.lock().unwrap().get(&kind).cloned(),
        }
    }

    fn public<'a>(&'a self, issuer: &IssuerPublicKey, witness: &WitnessPublicKey) -> Public<'a> {
        Public {
            g: &self.g,
            w_iss: issuer.w,
            ps_xt: witness.xt,
            ps_yt: witness.yt,
            acc_q: G2::generator().into_affine(),
            gens: &[],
            pc: PedersenGens { B: self.g.ped_b, B_blinding: self.g.ped_h },
            bp: self.bp_gens(),
            pos5: &self.pos5,
            pos3: &self.pos3,
        }
    }

    fn prove_stmt<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        st: &Stmt,
        cred: &Credential,
        tree: &RevocationTree,
        issuer: &IssuerPublicKey,
        witness: &WitnessPublicKey,
    ) -> Result<statement::Proof> {
        self.prove_stmt_with(rng, st, cred, tree, issuer, witness, None)
    }

    #[allow(clippy::too_many_arguments)]
    fn prove_stmt_with<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        st: &Stmt,
        cred: &Credential,
        tree: &RevocationTree,
        issuer: &IssuerPublicKey,
        witness: &WitnessPublicKey,
        rho_new: Option<Fr>,
    ) -> Result<statement::Proof> {
        let cfg = self.cfg_for(st);
        if self.config.proof_system == ProofSystem::LegoGroth16 && cfg.lego.is_none() {
            return Err(CryptoError::MissingKeys(st.kind().name().into()));
        }
        let path = tree.path(cred.handle()).ok_or(CryptoError::Revoked)?;
        if path.root != st.root() {
            return Err(CryptoError::Unprovable("revocation root mismatch".into()));
        }
        for rg in &cfg.ranges {
            let mut v = rg.constant;
            for (a, c) in &rg.terms {
                v += *c * cred.inner.mv[*a] as i64;
            }
            if !(0..1 << statement::RANGE_BITS).contains(&v) {
                return Err(CryptoError::Unprovable(format!("condition fails: {}", rg.label)));
            }
        }
        let holder = Holder {
            cred: cred.inner.clone(),
            r_u64: cred.handle(),
            ps: (cred.handle_sig.0, cred.handle_sig.1),
            wits: vec![],
            paths: vec![path],
            rho_new,
        };
        let p = self.public(issuer, witness);
        let pr = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| statement::prove(rng, &p, &cfg, &holder)))
            .map_err(|_| CryptoError::Unprovable("prover failed".into()))?;
        Ok(pr)
    }

    fn verify_stmt(&self, st: &Stmt, vc: &VerifyCtx, proof_hex: &str) -> Result<statement::Proof> {
        let cfg = self.cfg_for(st);
        if self.config.proof_system == ProofSystem::LegoGroth16 && cfg.lego.is_none() {
            return Err(CryptoError::MissingKeys(st.kind().name().into()));
        }
        let bytes = hex::decode(proof_hex).map_err(|e| CryptoError::Encoding(e.to_string()))?;
        let pr = codec::decode_proof(&bytes)?;
        let expect_outputs = cfg.hashes.iter().map(|h| h.bases.len()).sum::<usize>();
        if pr.outputs.len() != expect_outputs || pr.cnew.is_some() != cfg.reissue || !pr.gens.is_empty() {
            return Err(CryptoError::InvalidProof);
        }
        let p = self.public(vc.issuer, vc.witness);
        let ok = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| statement::verify(&p, &cfg, &pr))).unwrap_or(false);
        if ok {
            Ok(pr)
        } else {
            Err(CryptoError::InvalidProof)
        }
    }

    // ------------------------------- binding -------------------------------

    /// Prove that the holder owns slot `slot` of context `ctx`, with the pseudonym and badge tags for the
    /// lease starting `today`. `bind` is the account the proof is for (platform + stable account id) plus
    /// a fresh nonce; it enters the challenge, so the proof cannot be shown as another account's badge.
    #[allow(clippy::too_many_arguments)]
    pub fn prove_binding<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        cred: &Credential,
        tree: &RevocationTree,
        issuer: &IssuerPublicKey,
        witness: &WitnessPublicKey,
        ctx: &str,
        slot: u32,
        today: Day,
        probation: bool,
        bind: &[u8],
    ) -> Result<BindingProof> {
        if slot == 0 || slot > self.config.slots {
            return Err(CryptoError::Unprovable(format!("slot must be 1..={}", self.config.slots)));
        }
        let quarters = dates::lease_quarters(today);
        let st = Stmt::Binding { ctx: ctx.into(), slot, quarters, today, probation, root: tree.root(), bind: bind.to_vec() };
        let pr = self.prove_stmt(rng, &st, cred, tree, issuer, witness)?;
        Ok(BindingProof {
            slot,
            nym: to_hex(&pr.outputs[0]),
            tags: pr.outputs[1..].iter().map(to_hex).collect(),
            quarters: quarters.to_vec(),
            probation_cleared: probation,
            proof: hex::encode(codec::encode_proof(&pr)),
        })
    }

    pub fn verify_binding(&self, vc: &VerifyCtx, ctx: &str, bind: &[u8], bp: &BindingProof) -> Result<()> {
        if bp.slot == 0 || bp.slot > self.config.slots {
            return Err(CryptoError::InvalidProof);
        }
        let quarters = dates::lease_quarters(vc.today);
        if bp.quarters != quarters || bp.tags.len() != 4 {
            return Err(CryptoError::InvalidProof);
        }
        let st = Stmt::Binding {
            ctx: ctx.into(),
            slot: bp.slot,
            quarters,
            today: vc.today,
            probation: bp.probation_cleared,
            root: vc.revocation_root,
            bind: bind.to_vec(),
        };
        let pr = self.verify_stmt(&st, vc, &bp.proof)?;
        let outs: Vec<String> = pr.outputs.iter().map(to_hex).collect();
        if outs[0] != bp.nym || outs[1..] != bp.tags[..] {
            return Err(CryptoError::InvalidProof);
        }
        Ok(())
    }

    // ------------------------------- likes -------------------------------

    #[allow(clippy::too_many_arguments)]
    pub fn prove_like<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        cred: &Credential,
        tree: &RevocationTree,
        issuer: &IssuerPublicKey,
        witness: &WitnessPublicKey,
        ctx: &str,
        post: &str,
        today: Day,
    ) -> Result<LikeProof> {
        let st = Stmt::Like { ctx: ctx.into(), post: post.into(), today, root: tree.root(), bind: vec![] };
        let pr = self.prove_stmt(rng, &st, cred, tree, issuer, witness)?;
        Ok(LikeProof { tag: to_hex(&pr.outputs[0]), proof: hex::encode(codec::encode_proof(&pr)) })
    }

    pub fn verify_like(&self, vc: &VerifyCtx, ctx: &str, post: &str, lp: &LikeProof) -> Result<()> {
        let st = Stmt::Like { ctx: ctx.into(), post: post.into(), today: vc.today, root: vc.revocation_root, bind: vec![] };
        let pr = self.verify_stmt(&st, vc, &lp.proof)?;
        if to_hex(&pr.outputs[0]) != lp.tag {
            return Err(CryptoError::InvalidProof);
        }
        Ok(())
    }

    /// The like tag a holder would produce for a post, without a proof (used to undo a like locally).
    pub fn like_tag(&self, cred: &Credential, ctx: &str, post: &str) -> String {
        let hu = HashUse {
            label: "like",
            tag: dom("like"),
            ctx: context_scalar(ctx),
            slot: Fr::from(0u64),
            extra: post_scalar(post),
            bases: vec![],
            hidden: vec![],
        };
        let x = statement::hash_value(&self.pos5, &hu, 5, cred.secret());
        to_hex(&(output_base("like", ctx, 0, post) * x).into_affine())
    }

    // ------------------------------- renewal -------------------------------

    /// Holder: prove the credential may renew; returns the proof and the new blinding rho'.
    pub fn prove_renewal<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        cred: &Credential,
        tree: &RevocationTree,
        issuer: &IssuerPublicKey,
        witness: &WitnessPublicKey,
        today: Day,
        session: &[u8],
    ) -> Result<(RenewalProof, Fr)> {
        let st = Stmt::Renewal { today, root: tree.root(), bind: session.to_vec(), shown: None };
        let rho_new = Fr::rand(rng);
        let pr = self.prove_stmt_with(rng, &st, cred, tree, issuer, witness, Some(rho_new))?;
        Ok((RenewalProof { proof: hex::encode(codec::encode_proof(&pr)) }, rho_new))
    }

    /// Issuer: verify a renewal proof and sign the same hidden attributes with a new expiry.
    pub fn reissue<R: RngCore>(
        &self,
        rng: &mut R,
        key: &IssuerKey,
        vc: &VerifyCtx,
        session: &[u8],
        rp: &RenewalProof,
        new_expiry: Day,
    ) -> Result<BlindSignature> {
        if new_expiry != dates::quarter_end(dates::quarter_of(new_expiry)) {
            return Err(CryptoError::OffGrid("new expiry".into()));
        }
        let st = Stmt::Renewal { today: vc.today, root: vc.revocation_root, bind: session.to_vec(), shown: None };
        let pr = self.verify_stmt(&st, vc, &rp.proof)?;
        let cnew = pr.cnew.ok_or(CryptoError::InvalidProof)?;
        let b = self.g.p1 + self.g.q1 * statement::domain() + cnew + self.g.h[A_TAU] * Fr::from(new_expiry as u64);
        let e = Fr::rand(rng);
        let a = (b * (key.x + e).inverse().unwrap()).into_affine();
        Ok(BlindSignature { a: to_hex(&a), e: to_hex(&e) })
    }

    /// Holder: install the renewed signature.
    pub fn finish_renewal(
        &self,
        issuer: &IssuerPublicKey,
        old: &Credential,
        rho_new: Fr,
        sig: &BlindSignature,
        new_expiry: Day,
    ) -> Result<Credential> {
        let mut attrs = old.attrs.clone();
        attrs.expiry = new_expiry;
        attrs.check_grid()?;
        let mut m = old.inner.m;
        m[A_RHO] = rho_new;
        m[A_TAU] = Fr::from(new_expiry as u64);
        let a: G1A = from_hex(&sig.a)?;
        let e: Fr = from_hex(&sig.e)?;
        if !statement::bbs_verify(&self.g, &issuer.w, &a, e, &statement::bbs_b(&self.g, &m)) {
            return Err(CryptoError::BadSignature);
        }
        let mut mv = old.inner.mv;
        mv[A_TAU] = new_expiry as u64;
        Ok(Credential { inner: statement::Credential { a, e, m, mv }, attrs, handle_sig: old.handle_sig.clone() })
    }
}

// ------------------------------- re-check -------------------------------
//
// The two-year identity re-check (design §4.6). The holder logs in with the eID and shows a renewal
// proof that also reveals the credential's handle and the month of its last check. The issuer, who
// knows from the login which enrolment record this is, checks that the handle is that record's, and
// signs the same hidden attributes with a new expiry and a new last-check month. The secret, and with
// it every pseudonym, stays; the issuer learns nothing it did not know from the login.
impl Scheme {
    /// Holder: like [`Scheme::prove_renewal`], with the handle and last-check month shown.
    pub fn prove_recheck<R: RngCore + CryptoRng>(
        &self,
        rng: &mut R,
        cred: &Credential,
        tree: &RevocationTree,
        issuer: &IssuerPublicKey,
        witness: &WitnessPublicKey,
        today: Day,
        session: &[u8],
    ) -> Result<(RenewalProof, Fr)> {
        let st = Stmt::Renewal { today, root: tree.root(), bind: session.to_vec(), shown: Some((cred.attrs.handle, cred.attrs.last_check)) };
        let rho_new = Fr::rand(rng);
        let pr = self.prove_stmt_with(rng, &st, cred, tree, issuer, witness, Some(rho_new))?;
        Ok((RenewalProof { proof: hex::encode(codec::encode_proof(&pr)) }, rho_new))
    }

    /// Issuer: verify a re-check proof for the credential with `handle` whose last check was in the
    /// month starting `old_check`, and sign with `new_expiry` and `new_check`.
    #[allow(clippy::too_many_arguments)]
    pub fn reissue_recheck<R: RngCore>(
        &self,
        rng: &mut R,
        key: &IssuerKey,
        vc: &VerifyCtx,
        session: &[u8],
        rp: &RenewalProof,
        handle: u64,
        old_check: Day,
        new_expiry: Day,
        new_check: Day,
    ) -> Result<BlindSignature> {
        if new_expiry != dates::quarter_end(dates::quarter_of(new_expiry)) || new_check != dates::month_start(new_check) || new_check < old_check {
            return Err(CryptoError::OffGrid("new expiry or re-check month".into()));
        }
        let st = Stmt::Renewal { today: vc.today, root: vc.revocation_root, bind: session.to_vec(), shown: Some((handle, old_check)) };
        let pr = self.verify_stmt(&st, vc, &rp.proof)?;
        let cnew = pr.cnew.ok_or(CryptoError::InvalidProof)?;
        // cnew commits to every attribute but the expiry, the old month included; swap the month
        let b = self.g.p1 + self.g.q1 * statement::domain() + cnew + self.g.h[A_TAU] * Fr::from(new_expiry as u64)
            + self.g.h[A_ELL] * (Fr::from(new_check as u64) - Fr::from(old_check as u64));
        let e = Fr::rand(rng);
        let a = (b * (key.x + e).inverse().unwrap()).into_affine();
        Ok(BlindSignature { a: to_hex(&a), e: to_hex(&e) })
    }

    /// Holder: install the re-checked signature.
    pub fn finish_recheck(&self, issuer: &IssuerPublicKey, old: &Credential, rho_new: Fr, sig: &BlindSignature, new_expiry: Day, new_check: Day) -> Result<Credential> {
        let mut attrs = old.attrs.clone();
        attrs.expiry = new_expiry;
        attrs.last_check = new_check;
        attrs.check_grid()?;
        if new_check < old.attrs.last_check {
            return Err(CryptoError::OffGrid("re-check month went backwards".into()));
        }
        let mut m = old.inner.m;
        m[A_RHO] = rho_new;
        m[A_TAU] = Fr::from(new_expiry as u64);
        m[A_ELL] = Fr::from(new_check as u64);
        let a: G1A = from_hex(&sig.a)?;
        let e: Fr = from_hex(&sig.e)?;
        if !statement::bbs_verify(&self.g, &issuer.w, &a, e, &statement::bbs_b(&self.g, &m)) {
            return Err(CryptoError::BadSignature);
        }
        let mut mv = old.inner.mv;
        mv[A_TAU] = new_expiry as u64;
        mv[A_ELL] = new_check as u64;
        Ok(Credential { inner: statement::Credential { a, e, m, mv }, attrs, handle_sig: old.handle_sig.clone() })
    }
}

fn cfg_pos<'a>(s: &'a Scheme, cfg: &Cfg) -> &'a Poseidon {
    if cfg.width == 3 {
        &s.pos3
    } else {
        &s.pos5
    }
}

enum Stmt {
    Binding { ctx: String, slot: u32, quarters: [u32; 4], today: Day, probation: bool, root: Fr, bind: Vec<u8> },
    Like { ctx: String, post: String, today: Day, root: Fr, bind: Vec<u8> },
    /// `shown`: a re-check shows the handle and the month of the last identity check to the issuer
    Renewal { today: Day, root: Fr, bind: Vec<u8>, shown: Option<(u64, Day)> },
}

impl Stmt {
    fn kind(&self) -> StatementKind {
        match self {
            Stmt::Binding { probation: false, .. } => StatementKind::Binding,
            Stmt::Binding { probation: true, .. } => StatementKind::BindingProbation,
            Stmt::Like { .. } => StatementKind::Like,
            Stmt::Renewal { .. } => StatementKind::Renewal,
        }
    }
    fn root(&self) -> Fr {
        match self {
            Stmt::Binding { root, .. } | Stmt::Like { root, .. } | Stmt::Renewal { root, .. } => *root,
        }
    }
}

fn issuer_attr_scalars(a: &IssuedAttrs) -> [Fr; N_ATTR] {
    let mut m = [Fr::zero(); N_ATTR];
    m[A_R] = Fr::from(a.handle);
    m[A_TAU] = Fr::from(a.expiry as u64);
    m[A_GAMMA] = Fr::from(a.certified as u64);
    m[A_ELL] = Fr::from(a.last_check as u64);
    m[A_C] = Fr::from(a.country as u64);
    m[A_GAMMA0] = Fr::from(a.first_quarter as u64);
    m[A_E] = Fr::from(a.provider as u64);
    m
}

fn attr_small_values(a: &IssuedAttrs, delta: u64) -> [u64; N_ATTR] {
    let mut mv = [0u64; N_ATTR];
    mv[A_DELTA] = delta;
    mv[A_R] = a.handle;
    mv[A_TAU] = a.expiry as u64;
    mv[A_GAMMA] = a.certified as u64;
    mv[A_ELL] = a.last_check as u64;
    mv[A_C] = a.country as u64;
    mv[A_GAMMA0] = a.first_quarter as u64;
    mv[A_E] = a.provider as u64;
    mv
}

fn opening_challenge(c: &G1A, t: &G1A, session: &[u8]) -> Fr {
    let mut h = Sha256::new();
    h.update(b"POP-V1-BLIND-OPENING");
    h.update(codec::ser(c));
    h.update(codec::ser(t));
    h.update((session.len() as u64).to_be_bytes());
    h.update(session);
    hash_to_fr(b"POP-V1-CHALLENGE", &h.finalize())
}

impl BlindRequest {
    /// Holder: draw s, rho and delta on the device and commit to them. `session` is the issuer's
    /// enrolment session id, which stops the request from being replayed into another session.
    pub fn new<R: RngCore>(rng: &mut R, scheme: &Scheme, session: &[u8]) -> (HolderSecrets, BlindRequest) {
        let secrets = HolderSecrets { rho: Fr::rand(rng), s: Fr::rand(rng), delta: 1 + rng.next_u64() % 4 };
        let req = Self::for_secrets(rng, scheme, &secrets, session);
        (secrets, req)
    }

    /// Commit to existing secrets (recovery re-issues on the same s).
    pub fn for_secrets<R: RngCore>(rng: &mut R, scheme: &Scheme, secrets: &HolderSecrets, session: &[u8]) -> BlindRequest {
        let w = [secrets.rho, secrets.s, Fr::from(secrets.delta)];
        let bases = [scheme.g.h[A_RHO], scheme.g.h[A_S], scheme.g.h[A_DELTA]];
        let c = G1::msm(&bases, &w).unwrap().into_affine();
        let k: Vec<Fr> = (0..3).map(|_| Fr::rand(rng)).collect();
        let t = G1::msm(&bases, &k).unwrap().into_affine();
        let ch = opening_challenge(&c, &t, session);
        let z: Vec<Fr> = (0..3).map(|i| k[i] + ch * w[i]).collect();
        BlindRequest { commitment: to_hex(&c), challenge: to_hex(&ch), responses: z.iter().map(to_hex).collect() }
    }
}

// ---------------------------------------------------------------------------------------------
// Serialization of keys and credentials (hex of canonical compressed encodings)
// ---------------------------------------------------------------------------------------------

#[derive(Serialize, Deserialize)]
pub struct IssuerPublicKeyHex {
    pub w: String,
}

impl IssuerPublicKey {
    pub fn to_hex(&self) -> String {
        to_hex(&self.w)
    }
    pub fn from_hex(s: &str) -> Result<Self> {
        Ok(IssuerPublicKey { w: from_hex(s)? })
    }
}

impl WitnessPublicKey {
    pub fn to_hex(&self) -> String {
        to_hex(&(self.xt, self.yt))
    }
    pub fn from_hex(s: &str) -> Result<Self> {
        let (xt, yt) = from_hex(s)?;
        Ok(WitnessPublicKey { xt, yt })
    }
}

impl HandleSignature {
    pub fn to_hex(&self) -> String {
        to_hex(&(self.0, self.1))
    }
    pub fn from_hex(s: &str) -> Result<Self> {
        let (a, b) = from_hex(s)?;
        Ok(HandleSignature(a, b))
    }
}

/// Root of a revocation tree as hex.
pub fn root_to_hex(r: &Fr) -> String {
    to_hex(r)
}
pub fn root_from_hex(s: &str) -> Result<Fr> {
    from_hex(s)
}

#[derive(Serialize, Deserialize)]
struct CredentialFile {
    a: String,
    e: String,
    m: Vec<String>,
    delta: u64,
    attrs: IssuedAttrs,
    handle_sig: String,
}

impl Credential {
    pub fn to_json(&self) -> serde_json::Value {
        serde_json::to_value(CredentialFile {
            a: to_hex(&self.inner.a),
            e: to_hex(&self.inner.e),
            m: self.inner.m.iter().map(to_hex).collect(),
            delta: self.inner.mv[A_DELTA],
            attrs: self.attrs.clone(),
            handle_sig: self.handle_sig.to_hex(),
        })
        .unwrap()
    }
    pub fn from_json(v: &serde_json::Value) -> Result<Self> {
        let f: CredentialFile = serde_json::from_value(v.clone()).map_err(|e| CryptoError::Encoding(e.to_string()))?;
        if f.m.len() != N_ATTR {
            return Err(CryptoError::Encoding("attribute count".into()));
        }
        let mut m = [Fr::zero(); N_ATTR];
        for (i, s) in f.m.iter().enumerate() {
            m[i] = from_hex(s)?;
        }
        Ok(Credential {
            inner: statement::Credential { a: from_hex(&f.a)?, e: from_hex(&f.e)?, m, mv: attr_small_values(&f.attrs, f.delta) },
            attrs: f.attrs,
            handle_sig: HandleSignature::from_hex(&f.handle_sig)?,
        })
    }
}

/// Stable short fingerprint of a field element or point (for display and ids).
pub fn fingerprint(hex_str: &str) -> String {
    let d = Sha256::digest(hex_str.as_bytes());
    hex::encode(&d[..8])
}

/// Exposed for tests and tools.
pub fn fr_to_u64_lossy(x: &Fr) -> u64 {
    x.into_bigint().0[0]
}
