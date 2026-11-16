//! # pop-protocol
//!
//! The contract between the independent parts of the system:
//!
//! * [`api`]: JSON messages of the issuer and directory HTTP APIs, and the client traits
//!   [`api::IssuerApi`] and [`api::DirectoryApi`] the holder app uses. [`http`] implements them over HTTP.
//! * [`platform`]: the [`platform::Platform`] trait every social platform adapter implements.
//! * [`ids`]: context ids, account references, binding codes.
//!
//! This crate depends only on `pop-crypto`. Servers, identity providers and platform adapters depend on
//! it, never on each other.
pub mod api;
pub mod http;
pub mod ids;
pub mod platform;

pub use ids::*;
