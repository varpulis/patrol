//! patrol — temporal grep library crate.
//!
//! The binary in `src/main.rs` is a thin wrapper over this library. Integration
//! tests under `tests/` consume the library directly.

pub mod engine;
pub mod event;
pub mod format;
pub mod nfa;
pub mod pattern;
pub mod timestamp;
