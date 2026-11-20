//! # pop-directory
//!
//! The public side of the voluntary app (voluntary-app report §3 rows 6, 7 and 9):
//!
//! * `POST /v1/bindings`: a holder submits a binding proof for an account. The directory verifies it
//!   against the issuer's public keys and revocation root, enforces one account per pseudonym, and
//!   returns the code the holder shows in the bio.
//! * `GET /v1/bindings?platform=`: the public list of verified accounts. Extensions download it whole
//!   and check locally, so the operator never learns which profiles anyone looks at.
//! * `POST /v1/likes`: one-per-person like tags with proofs, checked in batches ([`batch`]); `POST /v1/likes/counts`: counts.
//! * `GET /v1/likes/table`: every count (synced by changes); `GET`/`POST /v1/likes/buckets`: the counts
//!   of the buckets a reader asks for, each holding about `bucket_posts` posts.
//!
//! It talks to the issuer only through [`pop_protocol::api::IssuerApi`] and to platforms only through
//! [`pop_protocol::platform::Platform`] (optional, for server-side code checks where a platform offers a
//! public interface). Storage goes through [`pop_storage::Store`].
pub mod batch;
pub mod service;
pub use service::{bucket_hash, router, Directory, DirectoryConfig};
