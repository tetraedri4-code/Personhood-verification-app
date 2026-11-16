//! # pop-issuer
//!
//! The operator's issuing service (design v2 §4.2, §4.3, §4.6, adapted by the voluntary-app report §3):
//!
//! 1. `POST /v1/enrol/start` opens a session and returns the identity provider's login URL.
//! 2. The provider redirects the person's browser to `GET /v1/enrol/callback`. The issuer exchanges the
//!    code, computes the deduplication key d from the identity code and drops the identity code.
//! 3. `POST /v1/enrol/finish`: the holder sends a commitment to its secret; the issuer signs blindly if
//!    d is new, and the witness signs the new handle.
//! 4. `POST /v1/renew`: blind renewal against a proof; `POST /v1/revoke`: the holder's own revocation,
//!    signed with the guardian key; `GET /v1/revocations`: the revoked handles and the tree root.
//!
//! The issuer depends on three interfaces only: [`pop_idp::IdentityProvider`], [`UniquenessService`] and
//! [`pop_storage::Store`]. Swap any of them without touching this crate.
//!
//! Enrolment records are keyed by d and carry the version of the uniqueness key d was made under. The
//! issuer refuses to start if it holds records under a key the uniqueness service no longer has, and
//! moves a record to the newest key when its owner logs in (docs/uniqueness.md).
pub mod service;
pub mod uniqueness;

pub use service::{router, Issuer, IssuerConfig};
pub use uniqueness::{hmac_key_version, DedupKey, HmacUniqueness, UniquenessService};
