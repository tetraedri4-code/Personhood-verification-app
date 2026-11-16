//! # pop-crypto
//!
//! Cryptographic core of the voluntary personhood app. It has no I/O and knows nothing about identity
//! providers, servers or platforms. Use the [`scheme`] module; the other modules are the proof engine
//! taken from the design-v2 benchmark (`benchmark/pop-bench`), kept close to the original so that the
//! measured numbers still describe it.
//!
//! Research-grade: not audited, not constant-time.
#![allow(clippy::needless_range_loop, clippy::type_complexity, dead_code)]

pub mod acc;
pub mod codec;
pub mod dates;
pub mod gk;
pub mod params;
pub mod poseidon;
pub mod revtree;
pub mod scheme;
pub mod sigma;
pub mod statement;
pub mod tree;

pub use dates::Day;
pub use scheme::*;
