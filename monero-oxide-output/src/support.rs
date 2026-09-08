//! Internal support module for extracted FFI submodules.
//!
//! This crate historically had a large `src/lib.rs` containing:
//! - `extern "C"` functions (FFI surface)
//! - helper utilities (logging, env parsing, rpc helpers)
//! - shared types (wallet state, outputs, etc.)
//!
//! As we incrementally refactor into smaller modules (starting with send, then preview_fee, then sweep, then refresh),
//! we need a stable, small set of `pub(crate)` re-exports so submodules
//! don't have to import dozens of items from the crate root.
//!
//! This module should contain *no business logic*. Keep it to re-exports
//! and small type aliases.

pub(crate) mod bulk_bin;
pub(crate) mod bulk_models;
pub(crate) mod key_image;
pub(crate) mod reexports;
pub(crate) mod rpc;
pub(crate) mod response_limits;

pub(crate) use bulk_bin::*;
// NOTE: do not glob-reexport `bulk_models::*` from the support facade.
// Keep callers explicit (`crate::support::bulk_models::...`) to avoid growing this facade and to
// reduce unused re-export warnings during refactors.
pub(crate) use reexports::*;
pub(crate) use rpc::*;
