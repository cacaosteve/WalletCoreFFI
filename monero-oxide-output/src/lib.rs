use bytes::Buf;
use std::{
    cell::RefCell,
    collections::{hash_map::Entry, HashMap, HashSet},
    convert::TryInto,
    ffi::{CStr, CString},
    os::raw::{c_char, c_int},
    slice,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

// Bulk EPEE models (request/response structs + builders) extracted to `support::bulk_models`.
// Import into the crate root so existing `BlockingRpcTransport` methods can keep using the short names
// without further churn in this file.
use crate::support::bulk_models::{
    GetBlocksBinRequest, GetBlocksBinResponse, GetBlocksByHeightBinRequest,
    GetBlocksByHeightBinResponse, GetBlocksFastBinRequest, GetBlocksFastBinResponse,
};

// Bulk EPEE request/response models are now in `src/support/bulk_models.rs` and are referenced
// by fully-qualified paths at call sites where needed (to avoid keeping large model lists in the root).

// Re-import bulk-bin helpers into the crate root so existing `lib.rs` call sites continue to work
// while we incrementally extract bulk binary decoding into `src/support/bulk_bin.rs`.
use crate::support::bulk_bin_debug_enabled;
use crate::support::response_limits::{read_response, MAX_BINARY_RESPONSE_BYTES, MAX_JSON_RESPONSE_BYTES};

// (moved into the main std::sync import above)

/// Sensitive developer logs require a deliberately opted-in build AND runtime opt-in.
/// Normal mobile/desktop release artifacts never enable the feature.
#[cfg(not(feature = "diagnostic-logging"))]
pub(crate) fn diagnostics_enabled() -> bool {
    false
}

#[cfg(feature = "diagnostic-logging")]
pub(crate) fn diagnostics_enabled() -> bool {
    static ENABLED: once_cell::sync::Lazy<bool> = once_cell::sync::Lazy::new(|| {
        std::env::var("WALLETCORE_DIAGNOSTICS").as_deref() == Ok("1")
    });
    *ENABLED
}

#[test]
#[cfg(not(feature = "diagnostic-logging"))]
fn distributed_build_disables_sensitive_diagnostics() {
    assert!(!diagnostics_enabled());
}

macro_rules! walletcore_diagnostic {
    ($($arg:tt)*) => {{
        if crate::diagnostics_enabled() { std::eprintln!($($arg)*); }
    }};
}

pub mod api;
mod ffi;
mod support;

// Re-export new public ABI symbols implemented in FFI submodules.
// Keeping these at crate root ensures they are visible to consumers linking against
// the cdylib/staticlib, even as we continue extracting FFI into `src/ffi/*`.
pub use crate::ffi::mnemonic::wallet_generate_mnemonic_english;

// Bulk binary (EPEE / portable_storage) decoding helpers extracted from this file.
// Kept reachable via `crate::support::*` for FFI submodules.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BulkFetchMode {
    /// Fetch blocks one-by-one using JSON RPC (baseline behavior).
    PerBlock,
    /// Wallet2-style bulk sync using monerod binary endpoint `getblocks.bin` (blocks + output_indices).
    Wallet2FastBlocks,
    /// Range-based bulk fetch using monerod binary endpoint `get_blocks.bin` (blocks + tx blobs).
    RangeBlocks,
}

const WALLETCORE_LOG_VERSION: &str = "walletcore-log-v6";

/// Persisted cache schema / compatibility version.
///
/// Bump this when the persisted cache format or the semantics of persisted fields change
/// in a way that makes old caches unsafe to import (e.g. key image derivation changes,
/// or identity-binding fields becoming required).
const WALLETCORE_CACHE_VERSION: u32 = 3;

fn walletcore_disable_decoys() -> bool {
    matches!(
        std::env::var("WALLETCORE_DISABLE_DECOYS").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

fn walletcore_decoy_probe_enabled() -> bool {
    matches!(
        std::env::var("WALLETCORE_DECOY_PROBE").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

/// Decoy selection mode for send/preview.
///
/// Current modes:
/// - (unset): default (existing monero_interface transport; currently failing on some nodes)
/// - "bin16": use binary RPC-backed decoy provider (ring size forced to 16; work-in-progress)
fn walletcore_decoy_mode() -> Option<String> {
    std::env::var("WALLETCORE_DECOY_MODE")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn walletcore_decoy_mode_bin16() -> bool {
    matches!(walletcore_decoy_mode().as_deref(), Some("bin16"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InputSelectMode {
    /// Default behavior (current): smallest-first.
    SmallestFirst,
    /// Debug/reliability mode: pick largest outputs first to minimize input count and fee.
    LargestFirst,
}

/// Input selection override.
///
/// Values:
/// - (unset): `smallest_first` (current behavior)
/// - `largest_first`: prefer largest outputs first (useful for debugging / reducing input count)
fn walletcore_input_select_mode() -> InputSelectMode {
    match std::env::var("WALLETCORE_INPUT_SELECT")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("largest_first") | Some("largest") => InputSelectMode::LargestFirst,
        Some("smallest_first") | Some("smallest") | None | Some("") => {
            InputSelectMode::SmallestFirst
        }
        Some(_) => InputSelectMode::SmallestFirst,
    }
}
/// Fee priority override (used when fetching fee rate from daemon).
///
/// Values:
/// - (unset): default (Normal)
/// - "low" | "unimportant" => `FeePriority::Unimportant` (maps to daemon fee tier `fee`/`fees[0]`)
/// - "normal"             => `FeePriority::Normal`      (maps to daemon `fees[1]`)
/// - "high" | "elevated"  => `FeePriority::Elevated`    (maps to daemon `fees[2]`)
/// - "very_high" | "priority" => `FeePriority::Priority` (maps to daemon `fees[3]`)
fn walletcore_fee_priority() -> FeePriority {
    match std::env::var("WALLETCORE_FEE_PRIORITY")
        .ok()
        .map(|s| s.trim().to_ascii_lowercase())
        .as_deref()
    {
        Some("low") | Some("unimportant") => FeePriority::Unimportant,
        Some("high") | Some("elevated") => FeePriority::Elevated,
        Some("very_high") | Some("veryhigh") | Some("very-high") | Some("priority") => {
            FeePriority::Priority
        }
        Some("normal") | None | Some("") => FeePriority::Normal,
        Some(_) => FeePriority::Normal,
    }
}

/// Binary RPC-backed decoy provider placeholder.
///
/// NOTE: The `monero-daemon-rpc` crate already provides a `MoneroDaemon<T>` implementation which
/// supports binary RPC (bin_rpc) for decoy selection via `ProvidesDecoys`/`ProvidesUnvalidatedDecoys`.
/// We don't need to implement decoy selection ourselves; we just need to pass the correct provider
/// into `OutputWithDecoys::new(...)` when `WALLETCORE_DECOY_MODE=bin16` is enabled.
///
/// This struct remains as a lightweight holder for configuration/logging and to avoid churn while
/// migrating call sites. It is not used for decoy selection.
struct BinDecoyProvider {
    base_url: String,
}

/// Construct a daemon interface which supports binary RPC (bin_rpc) decoy selection.
///
/// NOTE: `monero-simple-request-rpc`'s `SimpleRequestTransport::new(url)` returns a fully constructed
/// `MoneroDaemon<SimpleRequestTransport>`, not the transport itself. That `MoneroDaemon` is the type
/// which implements `ProvidesUnvalidatedDecoys` (thus `ProvidesDecoys`) via bin RPC:
/// - get_output_distribution.bin
/// - get_outs.bin
async fn make_bin_decoy_daemon(
    base_url: &str,
) -> Result<
    monero_daemon_rpc::MoneroDaemon<monero_simple_request_rpc::SimpleRequestTransport>,
    monero_interface::InterfaceError,
> {
    monero_simple_request_rpc::SimpleRequestTransport::new(base_url.to_string()).await
}

/// Query `get_output_histogram` (JSON-RPC) and return `total_instances` for `amount=0` (RingCT).
///
/// This is used as a fallback input to decoy selection when `get_output_distribution(.bin)` is
/// unavailable/broken on a daemon. We only need the total count of RingCT outputs.
///
/// Expected response shape:
/// `{ "histogram": [ { "amount": 0, "total_instances": N, ... } ], ... }`
async fn ringct_total_instances_via_histogram(
    daemon: &monero_daemon_rpc::MoneroDaemon<monero_simple_request_rpc::SimpleRequestTransport>,
) -> Result<u64, monero_interface::InterfaceError> {
    #[derive(serde::Deserialize)]
    struct HistogramEntry {
        amount: u64,
        total_instances: u64,
    }

    #[derive(serde::Deserialize)]
    struct HistogramResponse {
        histogram: Vec<HistogramEntry>,
    }

    // Use the public untyped JSON-RPC call, then deserialize just what we need.
    let raw = daemon
        .json_rpc_call(
            "get_output_histogram",
            Some(r#"{ "amounts": [0] }"#.to_string()),
            8 * 1024,
        )
        .await?;

    let res: HistogramResponse = serde_json::from_str(&raw).map_err(|_| {
        monero_interface::InterfaceError::InvalidInterface(
            "get_output_histogram response wasn't the expected json".to_string(),
        )
    })?;

    let entry = res
        .histogram
        .into_iter()
        .find(|e| e.amount == 0)
        .ok_or_else(|| {
            monero_interface::InterfaceError::InvalidInterface(
                "get_output_histogram returned no entry for amount=0".to_string(),
            )
        })?;

    if entry.total_instances == 0 {
        return Err(monero_interface::InterfaceError::InvalidInterface(
            "get_output_histogram returned total_instances=0 for amount=0".to_string(),
        ));
    }

    Ok(entry.total_instances)
}

/// Broadcast a signed transaction using monerod's non-JSON-RPC endpoint:
/// `POST /send_raw_transaction` with body `{ "tx_as_hex": "...", "do_not_relay": false }`.
///
/// Your daemon returns `Method not found` for JSON-RPC `send_raw_transaction`, so we must use this route.
///
/// Returns `Ok(())` if status is OK, else `Err(InterfaceError::InterfaceError(...))` with details.
async fn broadcast_send_raw_transaction(
    base_url: &str,
    tx_bytes: &[u8],
) -> Result<(), monero_interface::InterfaceError> {
    #[derive(serde::Deserialize)]
    struct SendRawTxResponse {
        status: Option<String>,
        reason: Option<String>,
        fee_too_low: Option<bool>,
        too_big: Option<bool>,
        invalid_input: Option<bool>,
        invalid_output: Option<bool>,
        overspend: Option<bool>,
        not_relayed: Option<bool>,
        sanity_check_failed: Option<bool>,
        double_spend: Option<bool>,
    }

    let tx_as_hex = hex_lowercase(tx_bytes);
    let body = serde_json::json!({
        "tx_as_hex": tx_as_hex,
        "do_not_relay": false
    })
    .to_string()
    .into_bytes();

    // Use the existing SimpleRequest transport (handles auth if present and ensures response is read).
    let daemon = make_bin_decoy_daemon(base_url).await?;
    let raw = daemon
        .rpc_call(
            "send_raw_transaction",
            Some(String::from_utf8_lossy(&body).to_string()),
            64 * 1024,
        )
        .await
        .map_err(|err| {
            let s = err.to_string();
            walletcore_diagnostic!("🧭 send_raw_transaction rpc error: {s}");
            if is_http_client_failed_error(&s) {
                monero_interface::InterfaceError::InterfaceError(format!(
                    "send_raw_transaction status=Failed {s}"
                ))
            } else {
                err
            }
        })?;

    let res: SendRawTxResponse = serde_json::from_str(&raw).map_err(|_| {
        monero_interface::InterfaceError::InvalidInterface(
            "send_raw_transaction response wasn't the expected json".to_string(),
        )
    })?;

    let status = res.status.clone().unwrap_or_else(|| "UNKNOWN".to_string());
    walletcore_diagnostic!(
        "🧭 send_raw_transaction daemon status={} reason={}",
        status,
        res.reason.clone().unwrap_or_else(|| "(none)".to_string())
    );
    if status.eq_ignore_ascii_case("OK") {
        return Ok(());
    }

    // Under probe mode, include the raw daemon response JSON to make it possible to diagnose
    // cases where `reason` is missing/empty or the daemon returns non-standard fields.
    if matches!(
        std::env::var("WALLETCORE_DECOY_PROBE").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    ) {
        return Err(monero_interface::InterfaceError::InterfaceError(format!(
            "send_raw_transaction raw_response={} parsed_status={} parsed_reason={} fee_too_low={:?} too_big={:?} invalid_input={:?} invalid_output={:?} overspend={:?} not_relayed={:?} sanity_check_failed={:?} double_spend={:?}",
            raw,
            status,
            res.reason.clone().unwrap_or_else(|| "(none)".to_string()),
            res.fee_too_low,
            res.too_big,
            res.invalid_input,
            res.invalid_output,
            res.overspend,
            res.not_relayed,
            res.sanity_check_failed,
            res.double_spend
        )));
    }

    Err(monero_interface::InterfaceError::InterfaceError(format!(
        "send_raw_transaction status={} reason={} fee_too_low={:?} too_big={:?} invalid_input={:?} invalid_output={:?} overspend={:?} not_relayed={:?} sanity_check_failed={:?} double_spend={:?}",
        status,
        res.reason.unwrap_or_else(|| "(none)".to_string()),
        res.fee_too_low,
        res.too_big,
        res.invalid_input,
        res.invalid_output,
        res.overspend,
        res.not_relayed,
        res.sanity_check_failed,
        res.double_spend
    )))
}

fn parse_hex_32(s: &str) -> Option<[u8; 32]> {
    fn hex_val(b: u8) -> Option<u8> {
        match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        }
    }

    let s = s.trim();
    if s.len() != 64 {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0usize;
    while i < 32 {
        let hi = hex_val(bytes[i * 2])?;
        let lo = hex_val(bytes[i * 2 + 1])?;
        out[i] = (hi << 4) | lo;
        i += 1;
    }
    Some(out)
}

pub(crate) fn walletcore_debug_target_txid() -> Option<[u8; 32]> {
    std::env::var("WALLETCORE_DEBUG_TXID")
        .ok()
        .and_then(|s| parse_hex_32(&s))
}

pub(crate) fn walletcore_debug_target_height() -> Option<u64> {
    std::env::var("WALLETCORE_DEBUG_HEIGHT")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
}

pub(crate) fn walletcore_debug_target_window() -> u64 {
    std::env::var("WALLETCORE_DEBUG_HEIGHT_WINDOW")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(0)
}

pub(crate) fn build_stamp() -> &'static str {
    // Prefer a compile-time stamp if provided by the build system.
    //
    // Fallback: "unknown" (still useful to prove whether you're running a build that includes this log).
    option_env!("WALLETCORE_BUILD_STAMP").unwrap_or("unknown")
}

// `block_ids` encoding for wallet2-fast is fixed by the Monero daemon RPC schema:
//
//   KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids)
//
// i.e. a single packed blob of 32-byte hashes.
//
// We intentionally do not support alternative encodings here. If a daemon returns an unexpected
// response variant, we handle that via strategy fallback (e.g., range bulk) rather than trying
// non-spec request encodings.

pub(crate) fn bulk_mode_str(mode: BulkFetchMode) -> &'static str {
    match mode {
        BulkFetchMode::Wallet2FastBlocks => "wallet2(getblocks.bin)",
        BulkFetchMode::RangeBlocks => "range(get_blocks.bin)",
        BulkFetchMode::PerBlock => "per_block",
    }
}

// bulk-bin decoding helpers moved to `support::bulk_bin` (see `src/support/bulk_bin.rs`)

// bulk-bin decoding helpers moved to `support::bulk_bin` (see `src/support/bulk_bin.rs`)

// bulk-bin decoding helpers moved to `support::bulk_bin` (see `src/support/bulk_bin.rs`)

// bulk-bin decoding helpers moved to `support::bulk_bin` (see `src/support/bulk_bin.rs`)

// bulk-bin decoding helpers moved to `support::bulk_bin` (see `src/support/bulk_bin.rs`)

// bulk-bin decoding helpers moved to `support::bulk_bin` (see `src/support/bulk_bin.rs`)

// bulk-bin decoding helpers moved to `support::bulk_bin` (see `src/support/bulk_bin.rs`)

#[inline]
pub(crate) fn bulk_fetch_mode_from_env() -> BulkFetchMode {
    // Bulk mode selection:
    //
    // - WALLETCORE_BULK_MODE=range    => RangeBlocks (default)
    // - WALLETCORE_BULK_MODE=wallet2  => Wallet2FastBlocks
    // - WALLETCORE_BULK_MODE=off      => PerBlock
    //
    // Back-compat:
    // - WALLETCORE_BULK_FETCH=0 disables bulk (PerBlock)
    // - WALLETCORE_BULK_FETCH=1 enables bulk and uses WALLETCORE_BULK_MODE (or default)
    let bulk_enabled = std::env::var("WALLETCORE_BULK_FETCH")
        .ok()
        .map(|v| v != "0")
        .unwrap_or(true);

    if !bulk_enabled {
        return BulkFetchMode::PerBlock;
    }

    let mode = std::env::var("WALLETCORE_BULK_MODE")
        .ok()
        .unwrap_or_else(|| "range".to_string())
        .to_ascii_lowercase();

    match mode.as_str() {
        "wallet2" => BulkFetchMode::Wallet2FastBlocks,
        "range" => BulkFetchMode::RangeBlocks,
        "off" | "0" | "false" => BulkFetchMode::PerBlock,
        _ => BulkFetchMode::Wallet2FastBlocks,
    }
}

#[inline]
pub(crate) const fn default_range_block_batch() -> usize {
    if cfg!(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos"
    )) {
        75
    } else {
        500
    }
}

#[inline]
pub(crate) fn bulk_fetch_batch_from_env() -> usize {
    // Larger desktop responses substantially reduce RPC round trips. Mobile keeps the
    // established smaller memory envelope unless a consumer explicitly overrides it.
    let v = std::env::var("WALLETCORE_BULK_FETCH_BATCH")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or_else(default_range_block_batch);
    v.clamp(10, 2000)
}

#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
use std::sync::{
    atomic::AtomicU64,
    mpsc::{self, TryRecvError},
};

use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use futures::executor::block_on;
use monero_address::{
    AddressType as MoneroAddressType, MoneroAddress, Network as MoneroNetwork, SubaddressIndex,
};
use monero_ed25519::{Point as EdPoint, Scalar as EdScalar};
use monero_seed::{Language as MoneroSeedLanguage, Seed as MoneroSeed};
use monero_wallet::{
    transaction::{Input as MoneroInput, Pruned, Timelock, Transaction},
    ViewPair,
};

pub(crate) fn fingerprint32(label: &str, bytes: &[u8]) -> String {
    use sha3::{Digest, Keccak256};
    let mut h = Keccak256::new();
    h.update(label.as_bytes());
    h.update(bytes);
    let out = h.finalize();

    // Avoid adding a new `hex` dependency; render first 16 bytes as hex manually.
    let mut s = String::with_capacity(32);
    for b in out[..16].iter() {
        use core::fmt::Write as _;
        write!(&mut s, "{:02x}", b).ok();
    }
    s
}

// New monero-oxide split: use monero-interface traits + error types.
use monero_interface::{FeePriority, InterfaceError, ProvidesOutputs};

// Spend detection (key image computation) will use curve25519-dalek scalar math directly.
// No monero-wallet ed25519 aliases are needed here.

// Spend detection: compute key images for owned outputs so we can later detect on-chain spends.
// (imports live above; do not duplicate)

// TEMPORARY migration alias: keep the existing walletcore code compiling while we
// port from the old monero_wallet::rpc::{Rpc, RpcError} API to monero-interface.
// This is intentionally internal-only and should be removed once the migration is complete.
pub(crate) type RpcError = InterfaceError;

use serde::{Deserialize, Serialize};
// Keccak256 is used via EdScalar::hash(), no direct import needed
use once_cell::sync::Lazy;

use ureq::serde_json;
use zeroize::Zeroizing;

// --- Per-wallet debug log file (NexaWal WalletCaches) ---
//
// NexaWal stores cache blobs at:
//   Application Support/WalletCaches/{mainnet|stagenet}/{walletId}.cache
//
// We write a sibling log file:
//   Application Support/WalletCaches/{mainnet|stagenet}/{walletId}.walletcore.log
//
// This is intentionally best-effort (never fails refresh) and is meant for automated log capture.
fn nexawal_cache_log_path(wallet_id: &str, network: MoneroNetwork) -> Option<std::path::PathBuf> {
    // Map network to NexaWal directory naming.
    let net_dir = match network {
        MoneroNetwork::Mainnet => "mainnet",
        // NexaWal uses "stagenet" for non-mainnet in WalletManager.swift
        MoneroNetwork::Stagenet => "stagenet",
        // If the app ever uses other networks, fall back to stagenet naming.
        _ => "stagenet",
    };

    let base = dirs::data_dir()?;
    Some(
        base.join("WalletCaches")
            .join(net_dir)
            .join(format!("{wallet_id}.walletcore.log")),
    )
}

fn append_walletcore_log_line(wallet_id: &str, network: MoneroNetwork, line: &str) {
    use std::io::Write;
    if !diagnostics_enabled() { return; }

    let Some(path) = nexawal_cache_log_path(wallet_id, network) else {
        return;
    };

    // Ensure parent directory exists (matches NexaWal behavior).
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        // Include timestamp for easier correlation.
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0);
        let _ = writeln!(f, "{ts} {line}");
    }
}

/// Append opt-in binary-RPC timing data for local scan diagnostics.
///
/// The benchmark sets `WALLETCORE_RPC_TELEMETRY_PATH` to a run-specific JSONL file. Keeping
/// this disabled by default avoids adding I/O to ordinary wallet refreshes while allowing the
/// desktop benchmark to measure the actual request/response sizes and transport latency.
pub(crate) fn append_walletcore_rpc_telemetry(
    event: &str,
    route: &str,
    request_bytes: usize,
    response_bytes: Option<usize>,
    elapsed_ms: u128,
    status: Option<u16>,
    error: Option<&str>,
) {
    use std::io::Write;

    let Ok(raw_path) = std::env::var("WALLETCORE_RPC_TELEMETRY_PATH") else {
        return;
    };
    let raw_path = raw_path.trim();
    if raw_path.is_empty() {
        return;
    }

    let path = std::path::Path::new(raw_path);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let line = serde_json::json!({
        "timestamp_ms": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default(),
        "event": event,
        "route": route,
        "request_bytes": request_bytes,
        "response_bytes": response_bytes,
        "elapsed_ms": elapsed_ms,
        "status": status,
        "error": error,
    });

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{line}");
    }
}

/// Append opt-in range-response decoding telemetry to the benchmark JSONL stream.
///
/// This deliberately shares `WALLETCORE_RPC_TELEMETRY_PATH` with the transport events so one
/// benchmark artifact can distinguish daemon/network time from the CPU work required to turn a
/// decoded portable-storage response into ordered `ScannableBlock`s.
pub(crate) fn append_walletcore_range_decode_telemetry(
    mode: &str,
    threads: usize,
    blocks: usize,
    transactions: usize,
    decode_ms: u128,
    finalize_ms: u128,
) {
    use std::io::Write;

    let Ok(raw_path) = std::env::var("WALLETCORE_RPC_TELEMETRY_PATH") else {
        return;
    };
    let raw_path = raw_path.trim();
    if raw_path.is_empty() {
        return;
    }

    let path = std::path::Path::new(raw_path);
    if let Some(parent) = path.parent() {
        let _ = std::fs::create_dir_all(parent);
    }

    let line = serde_json::json!({
        "timestamp_ms": std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| duration.as_millis())
            .unwrap_or_default(),
        "event": "range_decode",
        "mode": mode,
        "threads": threads,
        "blocks": blocks,
        "transactions": transactions,
        "decode_ms": decode_ms,
        "finalize_ms": finalize_ms,
    });

    if let Ok(mut file) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(path)
    {
        let _ = writeln!(file, "{line}");
    }
}

/// Module-friendly logging helper.
///
/// Prefer calling this from submodules instead of relying on `macro_rules!`
/// visibility rules.
pub(crate) fn walletcore_log_line(wallet_id: &str, network: MoneroNetwork, line: &str) {
    walletcore_diagnostic!("{}", line);
    append_walletcore_log_line(wallet_id, network, line);
}

macro_rules! walletcore_log {
    ($wallet_id:expr, $network:expr, $($arg:tt)*) => {{
        let s = format!($($arg)*);
        walletcore_log_line($wallet_id, $network, &s);
    }};
}

/// Returns a monotonic timestamp suitable for latency measurements (not wall clock).
#[inline]
fn now_mono_ms() -> u128 {
    // Best-effort; monotonic by definition.
    std::time::Instant::now().elapsed().as_millis()
}

// NOTE (telemetry plan):
// I attempted to instrument monero-daemon-rpc directly to log whether scannable block fetch is
// using BIN RPC (`get_blocks.bin`) vs JSON fallback, request sizing, and response sizes.
// That code lives in your fork (https://github.com/cacaosteve/monero-oxide) under:
//
//   monero-oxide/interface/daemon/src/bin_rpc/blocks_bin.rs
//
// We cannot edit external clones from here. The correct workflow is:
//
// 1) Commit telemetry changes in the `cacaosteve/monero-oxide` repo (monero-daemon-rpc crate).
// 2) Update `monero-oxide-output/Cargo.toml` to pin `rev = "<new fork commit sha>"`.
// 3) Rebuild XCFramework, run NexaWal, and read per-wallet `.walletcore.log` to confirm:
//    - BIN vs JSON path
//    - per-request blocks, bytes, and latency
//    - decode vs fetch breakdown
//
// This will let us directly compare our request pattern against wallet2/Feather and close the
// current gap (fetch is ~2–3 blocks/sec at batch=25; Feather is ~27 blocks/sec on your link).

// Global tokio runtime singleton for upstream async daemon RPC.
// We use a single runtime per process to avoid expensive runtime creation per FFI call.
static TOKIO_RUNTIME: Lazy<tokio::runtime::Runtime> = Lazy::new(|| {
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("walletcore: failed to build tokio runtime")
});

pub(crate) static PANIC_HOOK_INSTALLED: Lazy<()> = Lazy::new(|| {
    std::panic::set_hook(Box::new(|info| {
        // Best-effort: print panic info to stdout so it shows up in Xcode / sim logs.
        // Avoid allocations as much as possible.
        let thread = std::thread::current();
        let thread_name = thread.name().unwrap_or("<unnamed>");
        walletcore_diagnostic!("🧨 walletcore panic: thread={}", thread_name);

        if let Some(loc) = info.location() {
            walletcore_diagnostic!(
                "🧨 walletcore panic location: {}:{}",
                loc.file(),
                loc.line()
            );
        }

        if let Some(msg) = info.payload().downcast_ref::<&str>() {
            walletcore_diagnostic!("🧨 walletcore panic message: {}", msg);
        } else if let Some(msg) = info.payload().downcast_ref::<String>() {
            walletcore_diagnostic!("🧨 walletcore panic message: {}", msg);
        } else {
            walletcore_diagnostic!("🧨 walletcore panic message: <non-string payload>");
        }

        // If backtraces are enabled, this may print a useful stack trace.
        // (On Apple platforms, make sure RUST_BACKTRACE=1 is set in the host env for the build/run.)
        walletcore_diagnostic!(
            "🧨 walletcore backtrace:\n{:?}",
            std::backtrace::Backtrace::force_capture()
        );
    }));
});

#[inline]
fn fee_rate_max_per_weight_cap() -> u64 {
    // Conservative safety cap to prevent a malicious/buggy node from returning an absurd fee.
    // Can be overridden via WALLETCORE_MAX_FEE_PER_WEIGHT.
    //
    // Note: this is a *per-weight* fee, not a total fee.
    std::env::var("WALLETCORE_MAX_FEE_PER_WEIGHT")
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(10_000_000) // default cap
}

use cuprate_epee_encoding::{from_bytes, to_bytes};

#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
use zmq;

const DEFAULT_LOCK_WINDOW: u64 = 10;
const COINBASE_LOCK_WINDOW: u64 = 60;

// Bounded number of recent block hashes to keep in the wallet cache (wallet2-style chain history).
// 4096 hashes = 4096 * 32 bytes ~= 128 KiB raw, small enough for iOS while still providing
// a good short-chain-history window.
const RECENT_BLOCK_HASHES_MAX: usize = 4096;

static LAST_ERROR_MESSAGE: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

// Keep the error produced by the current native call on its originating thread as well as in the
// legacy process-global slot. Async refresh workers must be able to capture their own terminal
// error even while a UI polling thread calls another FFI function (which traditionally clears the
// global slot at entry).
thread_local! {
    static THREAD_LAST_ERROR_MESSAGE: RefCell<Option<String>> = const { RefCell::new(None) };
}

// Bulk-bin decoding debug flags were previously maintained here, but the decoding logic has been
// extracted into `support::bulk_bin` / `support::bulk_models`. Any debug gating/state should live
// alongside that code.

/// Per-wallet cancellation flags for `wallet_refresh` / `wallet_refresh_async`.
/// This is best-effort: the refresh loop checks it frequently and aborts promptly.
///
/// Keyed by `wallet_id` string.
static REFRESH_CANCEL_FLAGS: Lazy<Mutex<HashMap<String, Arc<AtomicBool>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

/// Global throttling for `get_o_indexes.bin` calls to avoid overwhelming monerod and triggering
/// `Connection reset by peer` under high scan concurrency.
///
/// Configure in Xcode Scheme env vars:
/// - WALLETCORE_OINDEXES_CONCURRENCY=4   (default: 4, clamped 1..32)
/// - WALLETCORE_OINDEXES_RETRIES=3       (default: 3, clamped 0..10)
static OINDEXES_LIMIT: Lazy<Mutex<Option<std::sync::Arc<std::sync::Condvar>>>> =
    Lazy::new(|| Mutex::new(None));
static OINDEXES_IN_FLIGHT: Lazy<Mutex<usize>> = Lazy::new(|| Mutex::new(0));

#[inline]
fn oindexes_concurrency_from_env() -> usize {
    let v = std::env::var("WALLETCORE_OINDEXES_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(4);
    v.clamp(1, 32)
}

#[inline]
fn oindexes_retries_from_env() -> usize {
    let v = std::env::var("WALLETCORE_OINDEXES_RETRIES")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(3);
    v.clamp(0, 10)
}

#[inline]
fn oindexes_backoff_ms(attempt: usize) -> u64 {
    // 100ms, 250ms, 500ms, 1000ms...
    match attempt {
        0 => 100,
        1 => 250,
        2 => 500,
        _ => 1000,
    }
}

fn acquire_oindexes_slot() {
    // Lazily create a shared Condvar for wakeups.
    let cv = {
        let mut opt = OINDEXES_LIMIT.lock().expect("OINDEXES_LIMIT lock poisoned");
        opt.get_or_insert_with(|| std::sync::Arc::new(std::sync::Condvar::new()))
            .clone()
    };

    let limit = oindexes_concurrency_from_env();
    let mut in_flight = OINDEXES_IN_FLIGHT
        .lock()
        .expect("OINDEXES_IN_FLIGHT lock poisoned");
    while *in_flight >= limit {
        in_flight = cv
            .wait(in_flight)
            .expect("OINDEXES_IN_FLIGHT condvar wait failed");
    }
    *in_flight += 1;
}

fn release_oindexes_slot() {
    let cv_opt = OINDEXES_LIMIT.lock().expect("OINDEXES_LIMIT lock poisoned");
    if let Some(cv) = cv_opt.as_ref() {
        let mut in_flight = OINDEXES_IN_FLIGHT
            .lock()
            .expect("OINDEXES_IN_FLIGHT lock poisoned");
        if *in_flight > 0 {
            *in_flight -= 1;
        }
        cv.notify_one();
    }
}

fn is_transient_oindexes_error(err: &InterfaceError) -> bool {
    let s = err.to_string().to_lowercase();
    s.contains("connection reset")
        || s.contains("reset by peer")
        || s.contains("broken pipe")
        || s.contains("timed out")
        || s.contains("network error")
}

fn get_o_indexes_limited<I: ProvidesOutputs>(
    iface: &I,
    tx_hash: [u8; 32],
) -> Result<Vec<u64>, InterfaceError> {
    // Throttle + retry transient transport errors.
    let retries = oindexes_retries_from_env();
    for attempt in 0..=retries {
        acquire_oindexes_slot();
        // monero-interface: output indexes are provided via `ProvidesOutputs`.
        let res = block_on(iface.output_indexes(tx_hash));
        release_oindexes_slot();

        match res {
            Ok(v) => return Ok(v),
            Err(e) => {
                if attempt < retries && is_transient_oindexes_error(&e) {
                    std::thread::sleep(std::time::Duration::from_millis(oindexes_backoff_ms(
                        attempt,
                    )));
                    continue;
                }
                return Err(e);
            }
        }
    }
    // Unreachable, but Rust wants a return.
    Err(InterfaceError::InternalError(
        "get_o_indexes_limited: exhausted retries".to_string(),
    ))
}

#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
static ZMQ_RUNTIME: Lazy<Mutex<Option<ZmqRuntime>>> = Lazy::new(|| Mutex::new(None));

#[inline]
fn refresh_cancel_flag_for_wallet(wallet_id: &str) -> Arc<AtomicBool> {
    let mut map = REFRESH_CANCEL_FLAGS
        .lock()
        .expect("refresh cancel flags lock poisoned");
    match map.entry(wallet_id.to_string()) {
        Entry::Occupied(e) => e.get().clone(),
        Entry::Vacant(v) => {
            let flag = Arc::new(AtomicBool::new(false));
            v.insert(flag.clone());
            flag
        }
    }
}

#[inline]
pub(crate) fn refresh_cancelled_for_wallet(wallet_id: &str) -> bool {
    refresh_cancel_flag_for_wallet(wallet_id).load(Ordering::Relaxed)
}

#[inline]
pub(crate) fn set_refresh_cancel_for_wallet(wallet_id: &str, cancelled: bool) {
    refresh_cancel_flag_for_wallet(wallet_id).store(cancelled, Ordering::Relaxed);
}

fn set_last_error<S: Into<String>>(message: S) {
    let message = message.into();
    THREAD_LAST_ERROR_MESSAGE.with(|slot| {
        *slot.borrow_mut() = Some(message.clone());
    });
    if let Ok(mut slot) = LAST_ERROR_MESSAGE.lock() {
        *slot = Some(message);
    }
}

fn clear_last_error() {
    THREAD_LAST_ERROR_MESSAGE.with(|slot| {
        *slot.borrow_mut() = None;
    });
    if let Ok(mut slot) = LAST_ERROR_MESSAGE.lock() {
        *slot = None;
    }
}

fn walletcore_sweep_bisect_enabled() -> bool {
    matches!(
        std::env::var("WALLETCORE_SWEEP_BISECT").ok().as_deref(),
        Some("1") | Some("true") | Some("TRUE") | Some("yes") | Some("YES")
    )
}

pub(crate) fn is_invalid_input_send_raw_tx_error(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    // We currently bubble errors up in a few different string shapes (depending on which layer created them).
    // Make this matcher resilient so bisect triggers reliably.
    //
    // Examples we may see:
    // - `... send_raw_transaction status=Failed ... invalid_input=Some(true) ...`
    // - `... raw_response={...,"invalid_input":true,...} ...`
    m.contains("invalid_input=some(true)") || m.contains(r#""invalid_input":true"#)
}

pub(crate) fn is_double_spend_send_raw_tx_error(msg: &str) -> bool {
    let m = msg.to_ascii_lowercase();
    // Examples we may see:
    // - `... send_raw_transaction status=Failed ... double_spend=Some(true) ...`
    // - `... raw_response={...,"double_spend":true,...} ...`
    m.contains("double_spend=some(true)") || m.contains(r#""double_spend":true"#)
}

pub(crate) fn is_failed_send_raw_tx_error(_msg: &str) -> bool {
    // Intentionally disabled: we no longer bisect/quarantine on generic
    // `send_raw_transaction status=Failed` because it causes false positives.
    // Only quarantine on `invalid_input=Some(true)` (or explicit spent preflight).
    false
}

pub(crate) fn parse_http_status_code(msg: &str) -> Option<u16> {
    let m = msg;
    for needle in ["HTTP ", "http ", "status code "] {
        if let Some(idx) = m.find(needle) {
            let rest = &m[idx + needle.len()..];
            let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(code) = digits.parse::<u16>() {
                return Some(code);
            }
        }
    }
    None
}

/// Cuprate/monerod HTTP 4xx (except 408/429) is a hard failure, not a transient fetch stall.
pub(crate) fn is_http_client_failed_error(msg: &str) -> bool {
    match parse_http_status_code(msg) {
        Some(code) if (400..500).contains(&code) && code != 408 && code != 429 => true,
        _ => false,
    }
}

fn is_non_retryable_http_client_status(code: u16) -> bool {
    (400..500).contains(&code) && code != 408 && code != 429
}

fn map_ureq_error(route: &str, err: ureq::Error) -> RpcError {
    match err {
        ureq::Error::Status(code, resp) => {
            let text = resp.status_text().to_string();
            let body_preview = resp
                .into_string()
                .ok()
                .map(|s| s.chars().take(200).collect::<String>())
                .unwrap_or_default();
            walletcore_diagnostic!(
                "🧭 rpc HTTP status={} {} route={} body_preview={}",
                code, text, route, body_preview
            );
            let msg = format!("HTTP {code} {text} route={route} body={body_preview}");
            if is_non_retryable_http_client_status(code) {
                RpcError::InvalidInterface(format!("status=Failed {msg}"))
            } else {
                RpcError::InterfaceError(msg)
            }
        }
        ureq::Error::Transport(transport) => {
            walletcore_diagnostic!("🧭 rpc transport error route={} err={}", route, transport);
            RpcError::InterfaceError(format!("route={route} {transport}"))
        }
    }
}

pub(crate) fn walletcore_send_bisect_on_failed_enabled() -> bool {
    // Deprecated/ignored: bisecting on generic failed broadcasts is unsafe and can quarantine
    // valid inputs. Keep the env var for backward compatibility but disable behavior.
    false
}

/// Env toggle: enable bisect debugging on *normal sends* when daemon broadcast reports invalid_input=true.
pub(crate) fn walletcore_send_bisect_enabled() -> bool {
    std::env::var("WALLETCORE_SEND_BISECT")
        .ok()
        .map(|v| v != "0")
        .unwrap_or(false)
}

fn walletcore_debug_spend_detect_enabled() -> bool {
    std::env::var("WALLETCORE_DEBUG_SPEND_DETECT")
        .ok()
        .map(|v| v != "0")
        .unwrap_or(false)
}

// Env-gated diagnostics: dump selected tracked outputs (txid:vout + key metadata) for preview/send flows.
fn walletcore_debug_input_dump_enabled() -> bool {
    std::env::var("WALLETCORE_DEBUG_INPUT_DUMP")
        .ok()
        .map(|v| v != "0")
        .unwrap_or(false)
}

fn walletcore_debug_dump_tracked_outputs(
    wallet_id: &str,
    network: MoneroNetwork,
    label: &str,
    outputs: &[TrackedOutput],
    daemon_height: u64,
    top_block_timestamp: u64,
) {
    if !walletcore_debug_input_dump_enabled() {
        return;
    }

    walletcore_log!(
        wallet_id,
        network,
        "🧾 {} wallet_id={} selected_count={} daemon_height={} top_ts={}",
        label,
        wallet_id,
        outputs.len(),
        daemon_height,
        top_block_timestamp
    );

    for o in outputs {
        walletcore_log!(
            wallet_id,
            network,
            "🧾 {} wallet_id={} out={} key_image={} spent={} unlocked={} timelock_kind={} timelock_value={} subaddr={}:{} coinbase={} amount_piconero={}",
            label,
            wallet_id,
            format!("{}:{}", hex_lowercase(&o.tx_hash), o.index_in_tx),
            hex_lowercase(&o.key_image),
            o.spent,
            o.is_unlocked(daemon_height, top_block_timestamp),
            match o.additional_timelock {
                Timelock::None => "none",
                Timelock::Block(_) => "block",
                Timelock::Time(_) => "time",
            },
            match o.additional_timelock {
                Timelock::None => "null".to_string(),
                Timelock::Block(h) => h.to_string(),
                Timelock::Time(t) => t.to_string(),
            },
            o.subaddress_major,
            o.subaddress_minor,
            o.is_coinbase,
            o.amount
        );
    }
}

/// Minimum input amount (piconero) to include in "Send Max" (sweep).
///
/// Rationale: some very small outputs cost more to spend than they're worth (fee > amount).
/// Those should be excluded from sweep so "Send Max" succeeds and doesn't burn fees.
///
/// Env override: `WALLETCORE_SWEEP_MIN_INPUT_PICONERO`
/// Default: 50_000_000 (0.000050000000 XMR)
fn walletcore_sweep_min_input_piconero() -> u64 {
    std::env::var("WALLETCORE_SWEEP_MIN_INPUT_PICONERO")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .unwrap_or(50_000_000)
}

fn record_error(code: c_int, message: impl Into<String>) -> c_int {
    set_last_error(message);
    code
}

pub(crate) fn last_error_clone() -> Option<String> {
    THREAD_LAST_ERROR_MESSAGE
        .with(|slot| slot.borrow().clone())
        .or_else(|| LAST_ERROR_MESSAGE.lock().ok().and_then(|slot| slot.clone()))
}

pub(crate) fn update_scan_progress(
    id: &str,
    scanned_height: u64,
    chain_height: u64,
    chain_time: u64,
    restore_height: u64,
) {
    if let Ok(mut map) = WALLET_STORE.lock() {
        if let Some(state) = map.get_mut(id) {
            // Never report last_scanned past the height we actually walked.
            // Clamping up to chain_height is what made interrupted scans look complete.
            let normalized_scanned = scanned_height.max(restore_height);
            state.last_scanned = if chain_height > 0 {
                normalized_scanned.min(chain_height)
            } else {
                normalized_scanned
            };
            state.chain_height = chain_height;
            state.chain_time = chain_time;
        }
    }
}

// -------------------------
// Wallet2-style chain history helpers
// -------------------------

#[inline]
fn maybe_init_recent_hash_window(state: &mut StoredWallet) {
    // If this wallet was loaded from an older cache blob (serde default), start_height may be 0.
    // Initialize it defensively to restore_height so height math stays sane.
    if state.recent_block_hashes_start_height == 0 {
        state.recent_block_hashes_start_height = state.restore_height;
    }
}

#[inline]
fn recent_hashes_len(state: &StoredWallet) -> usize {
    state.recent_block_hashes.len()
}

#[inline]
fn recent_hash_height_range(state: &StoredWallet) -> Option<(u64, u64)> {
    if state.recent_block_hashes.is_empty() {
        None
    } else {
        let start = state.recent_block_hashes_start_height;
        let end_inclusive =
            start.saturating_add(state.recent_block_hashes.len().saturating_sub(1) as u64);
        Some((start, end_inclusive))
    }
}

/// Push a block hash into the bounded recent hash window.
///
/// Invariants:
/// - We only append hashes in increasing-height order.
/// - If a reorg or gap is detected, we reset the window to start at `height` with a single hash.
/// - The window is bounded to `RECENT_BLOCK_HASHES_MAX` by dropping from the front.
pub(crate) fn push_recent_block_hash_parts(
    restore_height: u64,
    start_height: &mut u64,
    hashes: &mut Vec<[u8; 32]>,
    height: u64,
    hash: [u8; 32],
) {
    if *start_height == 0 {
        *start_height = restore_height;
    }

    if hashes.is_empty() {
        *start_height = height;
        hashes.push(hash);
        return;
    }

    let start = *start_height;
    let expected_next_height = start.saturating_add(hashes.len() as u64);

    if height == expected_next_height {
        hashes.push(hash);
    } else if height < expected_next_height {
        // Possible reorg or duplicate update. If it overlaps our window, truncate to that height.
        if height >= start {
            let idx = (height - start) as usize;
            if idx < hashes.len() {
                hashes.truncate(idx);
                hashes.push(hash);
            } else {
                // Shouldn't happen, but reset defensively.
                *start_height = height;
                hashes.clear();
                hashes.push(hash);
            }
        } else {
            // Height is before our window; reset to avoid inconsistent state.
            *start_height = height;
            hashes.clear();
            hashes.push(hash);
        }
    } else {
        // Gap detected; reset window to this height.
        *start_height = height;
        hashes.clear();
        hashes.push(hash);
    }

    // Enforce bounded window size
    if hashes.len() > RECENT_BLOCK_HASHES_MAX {
        let overflow = hashes.len() - RECENT_BLOCK_HASHES_MAX;
        hashes.drain(0..overflow);
        *start_height = start_height.saturating_add(overflow as u64);
    }
}

pub(crate) fn push_recent_block_hash(state: &mut StoredWallet, height: u64, hash: [u8; 32]) {
    maybe_init_recent_hash_window(state);
    push_recent_block_hash_parts(
        state.restore_height,
        &mut state.recent_block_hashes_start_height,
        &mut state.recent_block_hashes,
        height,
        hash,
    );
}

/// Get a hash from a recent-hash window by height (if present).
pub(crate) fn recent_hash_at(
    start_height: u64,
    hashes: &[[u8; 32]],
    height: u64,
) -> Option<[u8; 32]> {
    if hashes.is_empty() || height < start_height {
        return None;
    }
    let idx = (height - start_height) as usize;
    hashes.get(idx).copied()
}

/// Get a hash from the recent hash window by height (if present).
fn get_recent_block_hash(state: &StoredWallet, height: u64) -> Option<[u8; 32]> {
    recent_hash_at(
        state.recent_block_hashes_start_height,
        &state.recent_block_hashes,
        height,
    )
}

/// Locate the exclusive rewind height after a reorg (`next height to scan`).
///
/// `get_daemon_hash(height)` should return the canonical hash at that height.
/// Returns:
/// - `Ok(None)` if the local tip matches the daemon (no reorg)
/// - `Ok(Some(h))` to rewind working state so scanning resumes at `h`
pub(crate) fn find_reorg_rewind_height<E>(
    restore_height: u64,
    recent_start: u64,
    recent_hashes: &[[u8; 32]],
    get_daemon_hash: impl Fn(u64) -> Result<[u8; 32], E>,
) -> Result<Option<u64>, E> {
    if recent_hashes.is_empty() {
        return Ok(None);
    }
    let tip_height = recent_start.saturating_add(recent_hashes.len() as u64 - 1);
    let local_tip = recent_hashes[recent_hashes.len() - 1];
    let remote_tip = get_daemon_hash(tip_height)?;
    if remote_tip == local_tip {
        return Ok(None);
    }

    // Walk newest→oldest for the highest common ancestor still in our window.
    for i in (0..recent_hashes.len() - 1).rev() {
        let height = recent_start.saturating_add(i as u64);
        let remote = get_daemon_hash(height)?;
        if remote == recent_hashes[i] {
            return Ok(Some(height.saturating_add(1).max(restore_height)));
        }
    }

    // No proven common ancestor inside the retained window: fork may predate the
    // window, so drop all scanned state back to restore_height and rescan.
    Ok(Some(restore_height))
}

/// Rewind in-memory scan artifacts so the next height scanned is `target_height`.
///
/// - Drops outputs received at height >= target
/// - Clears spends observed at height >= target
/// - Rebuilds `seen_outpoints` from remaining outputs
/// - Truncates recent hash window and block timestamps
pub(crate) fn rewind_working_state_to_height(
    restore_height: u64,
    target_height: u64,
    outputs: &mut Vec<TrackedOutput>,
    seen_outpoints: &mut HashSet<([u8; 32], u64)>,
    recent_start: &mut u64,
    recent_hashes: &mut Vec<[u8; 32]>,
    block_timestamps: &mut HashMap<u64, u64>,
) -> u64 {
    let h = target_height.max(restore_height);

    outputs.retain(|output| output.block_height < h);
    for output in outputs.iter_mut() {
        let spent_on_fork = output
            .spending_height
            .map(|spend_h| spend_h >= h)
            .unwrap_or(false);
        if spent_on_fork {
            output.spent = false;
            output.spending_txid = None;
            output.spending_height = None;
        }
    }

    seen_outpoints.clear();
    for output in outputs.iter() {
        seen_outpoints.insert((output.tx_hash, output.index_in_tx));
    }

    if !recent_hashes.is_empty() {
        if h <= *recent_start {
            recent_hashes.clear();
            *recent_start = restore_height;
        } else {
            let keep = (h - *recent_start) as usize;
            if keep < recent_hashes.len() {
                recent_hashes.truncate(keep);
            }
        }
    }

    block_timestamps.retain(|&height, _| height < h);
    h
}

/// Build a wallet2-style short chain history (`block_ids`) from the bounded recent hash window.
///
/// Wallet2 logic (conceptual):
/// - Take up to 10 recent sequential hashes
/// - Then take hashes at exponentially increasing distances (2,4,8,16,...) back
/// - Always include genesis (if available)
///
/// This list is used in `/getblocks.bin` requests to allow the daemon to handle reorgs.
fn build_short_chain_history(state: &StoredWallet) -> Vec<[u8; 32]> {
    let (start, end) = match recent_hash_height_range(state) {
        Some(r) => r,
        None => return Vec::new(),
    };

    let mut ids: Vec<[u8; 32]> = Vec::new();

    // Add up to 10 recent sequential hashes, newest-first.
    let mut h = end;
    for _ in 0..10 {
        if let Some(hash) = get_recent_block_hash(state, h) {
            ids.push(hash);
        }
        if h == 0 || h <= start {
            break;
        }
        h = h.saturating_sub(1);
    }

    // Exponential backoff from end height.
    let mut offset: u64 = 2;
    loop {
        // stop if we'd underflow past start
        if end < offset {
            break;
        }
        let target_h = end.saturating_sub(offset);
        if target_h < start {
            break;
        }
        if let Some(hash) = get_recent_block_hash(state, target_h) {
            ids.push(hash);
        }
        // cap offset growth to avoid overflow
        if offset > (u64::MAX / 2) {
            break;
        }
        offset *= 2;
    }

    // Always include genesis if present in our window.
    if start == 0 {
        if let Some(genesis) = state.recent_block_hashes.first().copied() {
            ids.push(genesis);
        }
    }

    // De-dup while preserving order (newest-first).
    let mut seen: HashSet<[u8; 32]> = HashSet::new();
    ids.retain(|h| seen.insert(*h));

    ids
}

// -------------------------
// Generic EPEE value skipping
// -------------------------
//
// `cuprate_epee_encoding` object builders call `add_field(name, reader)` for each field.
// If we encounter an unknown field, we MUST consume its value to keep the reader aligned.
// Otherwise subsequent reads can fail with "Marker does not match expected Marker".
//
// This helper implements a generic skipper for EPEE-encoded values.
//
// It is intentionally conservative and only supports the marker kinds we actually see from monerod.
// If we encounter an unsupported marker, we return a Format error so we can extend support safely.
// bulk-bin decoding helpers moved to `support::bulk_bin` (see `src/support/bulk_bin.rs`)

// bulk-bin decoding helpers moved to `support::bulk_bin` (see `src/support/bulk_bin.rs`)

// bulk-bin decoding helpers moved to `support::bulk_bin` (see `src/support/bulk_bin.rs`)

#[no_mangle]
pub extern "C" fn walletcore_last_error_message() -> *mut c_char {
    let snapshot = LAST_ERROR_MESSAGE
        .lock()
        .map(|slot| slot.clone())
        .unwrap_or(None);
    match snapshot {
        Some(text) => CString::new(text)
            .unwrap_or_else(|_| CString::new("error message encoding failure").unwrap())
            .into_raw(),
        None => std::ptr::null_mut(),
    }
}

/// Request cancellation of the in-flight refresh for a specific wallet.
///
/// This sets a per-wallet flag that the refresh loop checks frequently. The next
/// check will abort the refresh with a cancellation error.
///
/// Returns 0 on success.
#[no_mangle]
pub extern "C" fn wallet_refresh_cancel(wallet_id: *const c_char) -> c_int {
    clear_last_error();

    if wallet_id.is_null() {
        return record_error(-11, "wallet_refresh_cancel: wallet_id pointer was null");
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            return record_error(
                -10,
                "wallet_refresh_cancel: wallet_id contained invalid UTF-8",
            )
        }
    };

    if id.is_empty() {
        return record_error(-14, "wallet_refresh_cancel: wallet_id was empty");
    }

    set_refresh_cancel_for_wallet(id, true);
    0
}

#[derive(Clone)]
struct MasterKeys {
    // `entropy` is wrapped in `Zeroizing`, so it is wiped automatically when dropped.
    entropy: Zeroizing<[u8; 32]>,
    spend_scalar: curve25519_dalek::Scalar,
    view_scalar_dalek: curve25519_dalek::Scalar,
    view_scalar_ed: EdScalar,
}

impl Drop for MasterKeys {
    fn drop(&mut self) {
        use zeroize::Zeroize as _;
        // `entropy` is already zeroized via `Zeroizing`; explicitly wipe the derived
        // secret scalars so no plaintext key material lingers in freed memory.
        self.spend_scalar.zeroize();
        self.view_scalar_dalek.zeroize();
        self.view_scalar_ed.zeroize();
    }
}

#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
struct ZmqRuntime {
    endpoint: String,
    sequence: Arc<AtomicU64>,
    error: Arc<Mutex<Option<String>>>,
    stop_tx: mpsc::Sender<()>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
fn stop_zmq_runtime() {
    let runtime_opt = {
        let mut slot = ZMQ_RUNTIME.lock().expect("ZMQ runtime lock poisoned");
        slot.take()
    };

    if let Some(mut runtime) = runtime_opt {
        let _ = runtime.stop_tx.send(());
        if let Some(handle) = runtime.thread.take() {
            let _ = handle.join();
        }
    }
}

#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
fn ensure_zmq_runtime(endpoint: &str) -> Result<Arc<AtomicU64>, (c_int, String)> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() {
        stop_zmq_runtime();
        return Err((
            -14,
            "wallet_start_zmq_listener: endpoint is empty".to_string(),
        ));
    }

    {
        let slot = ZMQ_RUNTIME.lock().expect("ZMQ runtime lock poisoned");
        if let Some(runtime) = slot.as_ref() {
            if runtime.endpoint == trimmed {
                if let Ok(message) = runtime.error.lock() {
                    if let Some(message) = message.clone() {
                        return Err((-16, message));
                    }
                }
                return Ok(runtime.sequence.clone());
            }
        }
    }

    stop_zmq_runtime();

    let sequence = Arc::new(AtomicU64::new(0));
    let (stop_tx, stop_rx) = mpsc::channel::<()>();
    let (ready_tx, ready_rx) = mpsc::channel::<Result<(), String>>();
    let endpoint_owned = trimmed.to_string();
    let endpoint_for_thread = endpoint_owned.clone();
    let sequence_clone = sequence.clone();
    let error_slot = Arc::new(Mutex::new(None));
    let error_slot_clone = error_slot.clone();

    let handle = std::thread::spawn(move || {
        let endpoint = endpoint_for_thread;
        let context = zmq::Context::new();
        let socket = match context.socket(zmq::SUB) {
            Ok(sock) => sock,
            Err(err) => {
                let _ = ready_tx.send(Err(format!("socket init failed: {err}")));
                return;
            }
        };

        if let Err(err) = socket.connect(&endpoint) {
            let _ = ready_tx.send(Err(format!("connect failed: {err}")));
            return;
        }
        if let Err(err) = socket.set_subscribe(b"") {
            let _ = ready_tx.send(Err(format!("subscribe failed: {err}")));
            return;
        }

        let _ = ready_tx.send(Ok(()));
        loop {
            match stop_rx.try_recv() {
                Ok(_) | Err(TryRecvError::Disconnected) => break,
                Err(TryRecvError::Empty) => {}
            }

            match socket.recv_multipart(zmq::DONTWAIT) {
                Ok(frames) => {
                    if let Some(last) = frames.last() {
                        if let Ok(text) = std::str::from_utf8(last) {
                            if let Some(token) = text.split_whitespace().next() {
                                if let Ok(height) = token.parse::<u64>() {
                                    sequence_clone.store(height, Ordering::Relaxed);
                                    continue;
                                }
                            }
                        }
                    }
                    sequence_clone.fetch_add(1, Ordering::Relaxed);
                }
                Err(zmq::Error::EAGAIN) => {
                    std::thread::sleep(Duration::from_millis(50));
                }
                Err(err) => {
                    let message = format!("wallet_zmq_listener: recv failed ({err})");
                    if let Ok(mut slot) = error_slot_clone.lock() {
                        *slot = Some(message.clone());
                    }
                    set_last_error(message);
                    break;
                }
            }
        }
    });

    match ready_rx.recv_timeout(Duration::from_secs(5)) {
        Ok(Ok(())) => {
            let runtime = ZmqRuntime {
                endpoint: endpoint_owned,
                sequence: sequence.clone(),
                error: error_slot,
                stop_tx,
                thread: Some(handle),
            };
            let mut slot = ZMQ_RUNTIME.lock().expect("ZMQ runtime lock poisoned");
            *slot = Some(runtime);
            Ok(sequence)
        }
        Ok(Err(message)) => {
            let _ = stop_tx.send(());
            let _ = handle.join();
            Err((-15, message))
        }
        Err(_) => {
            let _ = stop_tx.send(());
            let _ = handle.join();
            Err((-15, "timed out waiting for ZMQ subscriber".to_string()))
        }
    }
}

impl MasterKeys {
    fn new(entropy: Zeroizing<[u8; 32]>) -> Result<Self, c_int> {
        let spend_scalar = curve25519_dalek::Scalar::from_canonical_bytes(*entropy)
            .into_option()
            .ok_or(-10)?;
        let view_scalar_ed = EdScalar::hash(entropy.as_ref());
        let view_scalar_dalek: curve25519_dalek::Scalar = view_scalar_ed.clone().into();
        Ok(Self {
            entropy,
            spend_scalar,
            view_scalar_dalek,
            view_scalar_ed,
        })
    }

    fn to_view_pair(&self) -> Result<ViewPair, c_int> {
        let spend_point = EdPoint::from(ED25519_BASEPOINT_POINT * self.spend_scalar);
        let view_scalar = Zeroizing::new(self.view_scalar_ed.clone());
        ViewPair::new(spend_point, view_scalar).map_err(|_| -16)
    }
}

fn zero_outputs(out_buf: *mut c_char, out_buf_len: usize, out_written: *mut usize) {
    unsafe {
        if !out_written.is_null() {
            *out_written = 0;
        }
        if !out_buf.is_null() && out_buf_len > 0 {
            *out_buf = 0;
        }
    }
}

fn write_address_to_buf(
    address: &str,
    out_buf: *mut c_char,
    out_buf_len: usize,
    out_written: *mut usize,
) -> c_int {
    let addr_bytes = address.as_bytes();
    let needed = addr_bytes.len();
    if out_buf.is_null() || out_buf_len == 0 || needed + 1 > out_buf_len {
        zero_outputs(out_buf, out_buf_len, out_written);
        return -12;
    }

    unsafe {
        std::ptr::copy_nonoverlapping(addr_bytes.as_ptr() as *const c_char, out_buf, needed);
        *out_buf.add(needed) = 0;
        if !out_written.is_null() {
            *out_written = needed;
        }
    }
    0
}

fn master_keys_from_seed_bytes(seed_ptr: *const u8, seed_len: usize) -> Result<MasterKeys, c_int> {
    if seed_ptr.is_null() {
        return Err(-11);
    }
    if seed_len != 32 {
        return Err(-10);
    }

    let seed_slice = unsafe { slice::from_raw_parts(seed_ptr, seed_len) };
    let entropy: [u8; 32] = seed_slice.try_into().map_err(|_| -10)?;
    MasterKeys::new(Zeroizing::new(entropy))
}

fn master_keys_from_mnemonic_str(mnemonic: &str) -> Result<MasterKeys, c_int> {
    let phrase = mnemonic.trim();
    if phrase.is_empty() {
        return Err(-10);
    }

    // English Monero seeds are 13 or 25 words (entropy + checksum). Reject truncations
    // such as a 24-word drop of the checksum word even if a parser would accept them.
    let word_count = phrase.split_whitespace().count();
    if word_count != 13 && word_count != 25 {
        return Err(-10);
    }

    let seed = MoneroSeed::from_string(
        MoneroSeedLanguage::English,
        Zeroizing::new(phrase.to_string()),
    )
    .map_err(|_| -10)?;

    MasterKeys::new(seed.entropy())
}

fn master_keys_from_mnemonic_ptr(mnemonic_ptr: *const c_char) -> Result<MasterKeys, c_int> {
    if mnemonic_ptr.is_null() {
        return Err(-11);
    }

    let mnemonic = unsafe { CStr::from_ptr(mnemonic_ptr) }
        .to_str()
        .map_err(|_| -10)?;

    master_keys_from_mnemonic_str(mnemonic)
}

fn network_from_flag(is_mainnet: u8) -> MoneroNetwork {
    if is_mainnet != 0 {
        MoneroNetwork::Mainnet
    } else {
        MoneroNetwork::Stagenet
    }
}

#[derive(Clone)]
// NOTE: Migrating to upstream daemon RPC (monero-daemon-rpc + monero-simple-request-rpc).
// Keep the old transport code in place for now, but stop constructing/using it in walletcore
// entrypoints. We'll delete this once the migration is complete.
struct BlockingRpcTransport {
    agent: Arc<ureq::Agent>,
    base_url: String,
    auth_header: Option<String>,
}

///
/// Wallet2-style `COMMAND_RPC_GET_BLOCKS_FAST` (`/get_blocks.bin`) request/response models.
///
/// This endpoint is what `wallet2`/Feather use for fast wallet sync: it returns both:
/// - `blocks` (block blobs + pruned tx blobs)
/// - `output_indices` (per-transaction output indices), eliminating the need for `/get_o_indexes.bin`
///
/// We implement only the subset we need for scanning.
///
/// NOTE: Monerod supports both `/get_blocks.bin` and `/getblocks.bin`.
/// We call `/getblocks.bin` to avoid colliding with the other (range-based) `get_blocks.bin` request
/// shape used elsewhere.
///

/// Bulk EPEE request/response model implementations were extracted to:
/// - `src/support/bulk_models.rs`
///
/// This keeps `src/lib.rs` from growing unmanageably large while preserving the same behavior.

impl BlockingRpcTransport {
    fn new(raw_url: &str) -> Result<Self, c_int> {
        let base_url = raw_url.trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err(-14);
        }

        // Build an HTTP client, optionally honoring proxy env vars (HTTP_PROXY/http_proxy/ALL_PROXY/all_proxy)
        let mut builder = ureq::AgentBuilder::new().timeout(Duration::from_secs(120));

        if let Ok(proxy) = std::env::var("HTTP_PROXY")
            .or_else(|_| std::env::var("http_proxy"))
            .or_else(|_| std::env::var("ALL_PROXY"))
            .or_else(|_| std::env::var("all_proxy"))
        {
            if let Ok(px) = ureq::Proxy::new(&proxy) {
                builder = builder.proxy(px);
            }
        }

        let agent = Arc::new(builder.build());

        Ok(Self {
            agent,
            base_url,
            auth_header: None,
        })
    }

    fn request_for(&self, route: &str) -> ureq::Request {
        let path = route.trim_start_matches('/');
        let url = format!("{}/{}", self.base_url, path);
        let mut request = self
            .agent
            .post(&url)
            .set("Content-Type", "application/json");
        if let Some(header) = &self.auth_header {
            request = request.set("Authorization", header);
        }
        request
    }

    fn request_for_bin(&self, route: &str) -> ureq::Request {
        let path = route.trim_start_matches('/');
        let url = format!("{}/{}", self.base_url, path);
        let mut request = self
            .agent
            .post(&url)
            .set("Content-Type", "application/octet-stream");
        if let Some(header) = &self.auth_header {
            request = request.set("Authorization", header);
        }
        request
    }

    fn post_bytes(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError> {
        let response = self
            .request_for(route)
            .send_bytes(&body)
            .map_err(|err| map_ureq_error(route, err))?;
        walletcore_diagnostic!("🧭 rpc HTTP status={} route={}", response.status(), route);
        read_response(response, MAX_JSON_RESPONSE_BYTES)
            .map_err(|err| RpcError::InterfaceError(err.to_string()))
    }

    fn post_bin(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError> {
        let request_bytes = body.len();
        let started = std::time::Instant::now();
        if bulk_bin_debug_enabled() {
            walletcore_diagnostic!("🧩 rpc(bin) POST route={}", route);
        }
        let response = match self.request_for_bin(route).send_bytes(&body) {
            Ok(response) => response,
            Err(err) => {
                let error = err.to_string();
                append_walletcore_rpc_telemetry(
                    "rpc_bin",
                    route,
                    request_bytes,
                    None,
                    started.elapsed().as_millis(),
                    None,
                    Some(&error),
                );
                return Err(map_ureq_error(route, err));
            }
        };
        let status = response.status();
        walletcore_diagnostic!("🧭 rpc(bin) HTTP status={} route={}", status, route);
        let buf = match read_response(response, MAX_BINARY_RESPONSE_BYTES) {
            Ok(buf) => buf,
            Err(err) => {
            let error = err.to_string();
            append_walletcore_rpc_telemetry(
                "rpc_bin",
                route,
                request_bytes,
                None,
                started.elapsed().as_millis(),
                Some(status),
                Some(&error),
            );
            return Err(RpcError::InterfaceError(error));
            }
        };
        append_walletcore_rpc_telemetry(
            "rpc_bin",
            route,
            request_bytes,
            Some(buf.len()),
            started.elapsed().as_millis(),
            Some(status),
            None,
        );
        Ok(buf)
    }

    fn get_blocks_by_height_bin(
        &self,
        heights: Vec<u64>,
        prune: bool,
    ) -> Result<GetBlocksByHeightBinResponse, RpcError> {
        let req = GetBlocksByHeightBinRequest { heights, prune };
        let body = to_bytes(req)
            .map(|b| b.to_vec())
            .map_err(|e| RpcError::InvalidInterface(format!("epee encode: {e}")))?;
        let resp_bytes = self.post_bin("get_blocks_by_height.bin", body)?;
        let mut reader: &[u8] = resp_bytes.as_slice();
        let resp: GetBlocksByHeightBinResponse = from_bytes(&mut reader)
            .map_err(|e| RpcError::InvalidInterface(format!("epee decode: {e}")))?;
        Ok(resp)
    }

    fn get_blocks_bin(
        &self,
        start_height: u64,
        count: u64,
        prune: bool,
    ) -> Result<GetBlocksBinResponse, RpcError> {
        // Monero's `/get_blocks.bin` does not accept the generic portable-storage framing emitted
        // by `cuprate_epee_encoding::to_bytes`. Walletcore's earlier telemetry and a standalone
        // local probe both confirm the daemon expects this exact field layout:
        //
        //   prune=<bool>
        //   start_height=<u64 little-endian>
        //   max_block_count=<u64 little-endian>
        //
        // encoded with Monero's historical on-wire prefix bytes.
        const GET_BLOCKS_BIN_PREFIX_BEFORE_PRUNE_VALUE: &[u8] = &[
            0x01, 0x11, 0x01, 0x01, 0x01, 0x01, 0x02, 0x01, 0x01, 0x0c, 0x05, 0x70, 0x72, 0x75,
            0x6e, 0x65, 0x0b,
        ];
        const GET_BLOCKS_BIN_PREFIX_AFTER_PRUNE_VALUE: &[u8] = &[
            0x0c, 0x73, 0x74, 0x61, 0x72, 0x74, 0x5f, 0x68, 0x65, 0x69, 0x67, 0x68, 0x74, 0x05,
        ];
        const GET_BLOCKS_BIN_MID: &[u8] = &[
            0x0f, 0x6d, 0x61, 0x78, 0x5f, 0x62, 0x6c, 0x6f, 0x63, 0x6b, 0x5f, 0x63, 0x6f, 0x75,
            0x6e, 0x74, 0x05,
        ];

        let mut body = Vec::with_capacity(
            GET_BLOCKS_BIN_PREFIX_BEFORE_PRUNE_VALUE.len()
                + 1
                + GET_BLOCKS_BIN_PREFIX_AFTER_PRUNE_VALUE.len()
                + 8
                + GET_BLOCKS_BIN_MID.len()
                + 8,
        );
        body.extend_from_slice(GET_BLOCKS_BIN_PREFIX_BEFORE_PRUNE_VALUE);
        body.push(if prune { 1 } else { 0 });
        body.extend_from_slice(GET_BLOCKS_BIN_PREFIX_AFTER_PRUNE_VALUE);
        body.extend_from_slice(&start_height.to_le_bytes());
        body.extend_from_slice(GET_BLOCKS_BIN_MID);
        body.extend_from_slice(&count.to_le_bytes());

        let resp_bytes = self.post_bin("get_blocks.bin", body)?;
        let mut reader: &[u8] = resp_bytes.as_slice();
        let resp: GetBlocksBinResponse = from_bytes(&mut reader)
            .map_err(|e| RpcError::InvalidInterface(format!("epee decode: {e}")))?;
        Ok(resp)
    }

    fn get_blocks_fast_bin(
        &self,
        block_ids: Vec<[u8; 32]>,
        start_height: u64,
        prune: bool,
    ) -> Result<GetBlocksFastBinResponse, RpcError> {
        // Match COMMAND_RPC_GET_BLOCKS_FAST::request_t defaults:
        // - requested_info defaults to 0 (BLOCKS_ONLY)
        // - no_miner_tx defaults to false
        // - pool_info_since defaults to 0
        // - max_block_count defaults to 0
        //
        // Wallet2-style: `block_ids` is KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids),
        // i.e. a single packed blob of 32-byte hashes.
        let mut block_ids_blob: Vec<u8> = Vec::with_capacity(block_ids.len().saturating_mul(32));
        for h in &block_ids {
            block_ids_blob.extend_from_slice(h);
        }

        // Wallet2-aligned defaults:
        //
        // - requested_info=BLOCKS_ONLY (0). This controls blocks vs pool inclusion and does NOT influence
        //   the block encoding variant in a reliable way.
        // - max_block_count: request a bounded number of blocks per call. Use the walletcore bulk batch as
        //   the effective limit (default 75) so performance tuning is centralized.
        let requested_info: u8 = 0;
        let max_block_count: u64 = bulk_fetch_batch_from_env() as u64;

        if bulk_bin_debug_enabled() {
            walletcore_diagnostic!(
                "🧩 getblocks.bin request: requested_info={} start_height={} prune={} max_block_count={} block_ids_bytes={}",
                requested_info,
                start_height,
                prune,
                max_block_count,
                block_ids_blob.len()
            );
        }

        let req = GetBlocksFastBinRequest {
            requested_info,
            block_ids: block_ids_blob,
            start_height,
            prune,
            no_miner_tx: false,
            pool_info_since: 0,
            max_block_count,
        };

        let body = to_bytes(req)
            .map(|b| b.to_vec())
            .map_err(|e| RpcError::InvalidInterface(format!("epee encode: {e}")))?;

        // Wallet2-style endpoint (underscored variant) to match wallet2/Feather behavior.
        //
        // Note: we also have a separate range-based `/get_blocks.bin` request shape (start_height/count/prune).
        // Monerod distinguishes these by the request body schema, not just the route string.
        let resp_bytes = self.post_bin("get_blocks.bin", body)?;
        let mut reader: &[u8] = resp_bytes.as_slice();
        let resp: GetBlocksFastBinResponse = from_bytes(&mut reader)
            .map_err(|e| RpcError::InvalidInterface(format!("epee decode: {e}")))?;
        Ok(resp)
    }

    fn json_rpc_call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, (c_int, String)> {
        let payload = serde_json::json!({
            "jsonrpc": "2.0",
            "id": "0",
            "method": method,
            "params": params
        });
        let response = self
            .request_for("json_rpc")
            .send_json(payload)
            .map_err(|err| {
                let detail = match map_ureq_error("json_rpc", err) {
                    RpcError::InterfaceError(msg) | RpcError::InvalidInterface(msg) => msg,
                    RpcError::InternalError(msg) => msg,
                };
                (-15, format!("json_rpc {method}: {detail}"))
            })?;
        let bytes = read_response(response, MAX_JSON_RESPONSE_BYTES)
            .map_err(|err| (-15, format!("json_rpc {method}: {err}")))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .map_err(|err| (-15, format!("json decode for {method}: {err}")))?;
        if let Some(error_obj) = value.get("error") {
            let msg = error_obj
                .get("message")
                .and_then(|m| m.as_str())
                .unwrap_or("daemon returned error");
            let code = error_obj.get("code").and_then(|c| c.as_i64()).unwrap_or(0);
            return Err((
                -15,
                format!("json_rpc {method} returned error {code}: {msg}"),
            ));
        }
        Ok(value)
    }

    /// Fetch a block hash by height via JSON-RPC `on_get_block_hash`.
    ///
    /// Monero expects params as a positional array: `[height]`.
    /// Returns the 32-byte block hash.
    fn get_block_hash_by_height_json(&self, height: u64) -> Result<[u8; 32], (c_int, String)> {
        let height_i64 = i64::try_from(height).map_err(|_| {
            (
                -16,
                format!("get_block_hash_by_height_json: height overflow: {height}"),
            )
        })?;

        let value = self.json_rpc_call("on_get_block_hash", serde_json::json!([height_i64]))?;

        let result = value
            .get("result")
            .ok_or_else(|| (-15, "on_get_block_hash response missing result".to_string()))?;

        let hash_hex = result
            .as_str()
            .ok_or_else(|| (-15, "on_get_block_hash result was not a string".to_string()))?;

        // Expect 64 hex chars (32 bytes)
        if hash_hex.len() != 64 {
            return Err((
                -15,
                format!(
                    "on_get_block_hash returned unexpected hash length {} (expected 64)",
                    hash_hex.len()
                ),
            ));
        }

        let mut out = [0u8; 32];
        for i in 0..32 {
            let byte_str = &hash_hex[i * 2..i * 2 + 2];
            out[i] = u8::from_str_radix(byte_str, 16).map_err(|e| {
                (
                    -15,
                    format!("on_get_block_hash returned invalid hex at byte {i}: {e}"),
                )
            })?;
        }

        Ok(out)
    }

    /// Seed the wallet2-style bounded chain history when it is empty.
    ///
    /// We fetch a small contiguous window of block hashes using `on_get_block_hash` so we can build
    /// `block_ids` for `/getblocks.bin` fast sync even after cache clear / first run.
    fn seed_recent_block_hashes_for_wallet2(
        &self,
        wallet_id: &str,
        start_h: u64,
    ) -> Result<(), (c_int, String)> {
        // Choose a small window ending at start_h-1 (if possible) so the daemon can anchor the chain.
        // Keep it small to avoid hammering JSON-RPC on first run.
        const SEED_COUNT: u64 = 64;

        let end_h = start_h.saturating_sub(1);
        let begin_h = end_h.saturating_sub(SEED_COUNT.saturating_sub(1));

        for h in begin_h..=end_h {
            let bh = self.get_block_hash_by_height_json(h)?;
            if let Ok(mut map) = WALLET_STORE.lock() {
                if let Some(state) = map.get_mut(wallet_id) {
                    push_recent_block_hash(state, h, bh);
                }
            }
        }
        Ok(())
    }
}

// NOTE: The upstream `Rpc` trait no longer exists in the latest monero-oxide split.
// We keep this commented block around to ease migration and to preserve context.
//
// impl Rpc for BlockingRpcTransport {
//     fn post(
//         &self,
//         route: &str,
//         body: Vec<u8>,
//     ) -> impl Future<Output = Result<Vec<u8>, RpcError>> + Send {
//         let client = self.clone();
//         let route_string = route.to_string();
//         async move { client.post_bytes(&route_string, body) }
//     }
// }
struct DaemonStatus {
    height: u64,
    top_block_timestamp: u64,
}

fn fetch_daemon_status(client: &BlockingRpcTransport) -> Result<DaemonStatus, (c_int, String)> {
    let info_err = match client.json_rpc_call("get_info", serde_json::json!({})) {
        Ok(info) => {
            if let Some(result) = info.get("result") {
                if let (Some(height), Some(ts)) = (
                    result.get("height").and_then(|h| h.as_u64()),
                    result.get("top_block_timestamp").and_then(|t| t.as_u64()),
                ) {
                    return Ok(DaemonStatus {
                        height,
                        top_block_timestamp: ts,
                    });
                }
                Some((
                    -15,
                    "daemon get_info response missing height/top_block_timestamp".to_string(),
                ))
            } else {
                Some((
                    -15,
                    "daemon get_info response missing result/error".to_string(),
                ))
            }
        }
        Err(err) => Some(err),
    };

    let block_count_status = match client.json_rpc_call("get_block_count", serde_json::json!({})) {
        Ok(response) => {
            if let Some(result) = response.get("result") {
                if let Some(height) = result.get("count").and_then(|h| h.as_u64()) {
                    Ok(DaemonStatus {
                        height,
                        top_block_timestamp: 0,
                    })
                } else {
                    Err((
                        -15,
                        "daemon get_block_count response missing count".to_string(),
                    ))
                }
            } else {
                Err((
                    -15,
                    "daemon get_block_count response missing result/error".to_string(),
                ))
            }
        }
        Err(err) => Err(err),
    };

    match block_count_status {
        Ok(status) => Ok(status),
        Err((code, message)) => {
            if let Some((_, first_message)) = info_err {
                Err((
                    code,
                    format!("{message}; initial get_info attempt also failed: {first_message}"),
                ))
            } else {
                Err((code, message))
            }
        }
    }
}

/// Best-effort tip timestamp from `get_info` (falls back to 0).
///
/// Used so time-based unlocks and pending timestamps are not stuck at zero when the
/// caller already knows the daemon height through another RPC.
pub(crate) fn resolve_daemon_tip_timestamp(base_url: &str) -> u64 {
    match BlockingRpcTransport::new(base_url) {
        Ok(transport) => match fetch_daemon_status(&transport) {
            Ok(status) => status.top_block_timestamp,
            Err(_) => 0,
        },
        Err(_) => 0,
    }
}

fn map_rpc_error(err: RpcError) -> c_int {
    match err {
        // monero-interface error kinds (temporary alias via `type RpcError = InterfaceError`)
        RpcError::InterfaceError(_) => -15,
        RpcError::InternalError(_) => -16,
        RpcError::InvalidInterface(_) => -16,
    }
}

fn derive_address_string(
    keys: &MasterKeys,
    account_index: u32,
    subaddress_index: u32,
    network: MoneroNetwork,
) -> String {
    if account_index == 0 && subaddress_index == 0 {
        let spend_pub = EdPoint::from(ED25519_BASEPOINT_POINT * keys.spend_scalar);
        let view_pub = EdPoint::from(ED25519_BASEPOINT_POINT * keys.view_scalar_dalek);
        MoneroAddress::new(network, MoneroAddressType::Legacy, spend_pub, view_pub).to_string()
    } else {
        // Monero wallet2 subaddress derivation:
        //
        // m = Hs("SubAddr\0" || a || major || minor)             where a = private view key (scalar bytes)
        // D = B + m*G                                            where B = spend public key
        // C = a*D                                                where a = private view key scalar
        //
        // Address = (D, C) encoded as a subaddress for the given network.
        let spend_pub = ED25519_BASEPOINT_POINT * keys.spend_scalar;
        let view_scalar = keys.view_scalar_dalek;

        let mut data = Vec::with_capacity(8 + 32 + 4 + 4);
        data.extend_from_slice(b"SubAddr\0");

        // Use the Monero ed25519 Scalar bytes directly to match wallet2 behavior.
        let view_key_bytes: [u8; 32] = <[u8; 32]>::from(keys.view_scalar_ed);
        data.extend_from_slice(&view_key_bytes);

        data.extend_from_slice(&account_index.to_le_bytes());
        data.extend_from_slice(&subaddress_index.to_le_bytes());

        let m_scalar: curve25519_dalek::Scalar = EdScalar::hash(&data).into();

        // D = B + m*G
        let d_dalek = spend_pub + (ED25519_BASEPOINT_POINT * m_scalar);

        // C = a*D
        let c_dalek = d_dalek * view_scalar;

        let d_point = EdPoint::from(d_dalek);
        let c_point = EdPoint::from(c_dalek);
        MoneroAddress::new(network, MoneroAddressType::Subaddress, d_point, c_point).to_string()
    }
}

#[no_mangle]
pub extern "C" fn walletcore_version() -> *mut c_char {
    CString::new(concat!("walletcore ", env!("CARGO_PKG_VERSION")))
        .unwrap()
        .into_raw()
}

#[no_mangle]
pub extern "C" fn walletcore_free_cstr(ptr: *mut c_char) -> c_int {
    if ptr.is_null() {
        return -1;
    }
    unsafe {
        let _ = CString::from_raw(ptr);
    }
    0
}

/// Derive a Monero address from a canonical 32-byte seed.
/// ABI contract:
/// - seed_ptr/seed_len: 32-byte seed (secret spend key).
/// - is_mainnet: 1 for mainnet, 0 for stagenet/testnet.
/// - account_index/subaddress_index: which account/subaddress to derive.
/// - out_buf/out_buf_len: caller-provided buffer for the ASCII address.
/// - out_written: number of bytes written (excluding NUL) if non-null.
/// Returns:
/// - 0 on success,
/// - negative error codes for invalid pointers, lengths, or insufficient buffers.
#[no_mangle]
pub extern "C" fn wallet_derive_address_from_seed(
    seed_ptr: *const u8,
    seed_len: usize,
    is_mainnet: u8,
    account_index: u32,
    subaddress_index: u32,
    out_buf: *mut c_char,
    out_buf_len: usize,
    out_written: *mut usize,
) -> c_int {
    let keys = match master_keys_from_seed_bytes(seed_ptr, seed_len) {
        Ok(k) => k,
        Err(code) => {
            zero_outputs(out_buf, out_buf_len, out_written);
            return code;
        }
    };

    let network = network_from_flag(is_mainnet);
    let address = derive_address_string(&keys, account_index, subaddress_index, network);
    write_address_to_buf(&address, out_buf, out_buf_len, out_written)
}

/// Scaffold: Derive the primary address (account 0, subaddress 0) from a seed (not implemented yet).
#[no_mangle]
pub extern "C" fn wallet_primary_address_from_seed(
    seed_ptr: *const u8,
    seed_len: usize,
    is_mainnet: u8,
    out_buf: *mut c_char,
    out_buf_len: usize,
    out_written: *mut usize,
) -> c_int {
    wallet_derive_address_from_seed(
        seed_ptr,
        seed_len,
        is_mainnet,
        0,
        0,
        out_buf,
        out_buf_len,
        out_written,
    )
}

/// Derive the primary address (account 0, subaddress 0) from a 25-word mnemonic.
/// Validates the mnemonic, derives master keys, and writes the resulting address
/// to the supplied buffer.
#[no_mangle]
pub extern "C" fn wallet_primary_address_from_mnemonic(
    mnemonic_ptr: *const c_char,
    is_mainnet: u8,
    out_buf: *mut c_char,
    out_buf_len: usize,
    out_written: *mut usize,
) -> c_int {
    let keys = match master_keys_from_mnemonic_ptr(mnemonic_ptr) {
        Ok(k) => k,
        Err(code) => {
            zero_outputs(out_buf, out_buf_len, out_written);
            return code;
        }
    };

    let network = network_from_flag(is_mainnet);
    let address = derive_address_string(&keys, 0, 0, network);
    write_address_to_buf(&address, out_buf, out_buf_len, out_written)
}

/// Derive a subaddress (account_index, subaddress_index) from a 25-word mnemonic.
/// Returns the derived base58 subaddress or a negative error code on validation failures.
#[no_mangle]
pub extern "C" fn wallet_derive_subaddress_from_mnemonic(
    mnemonic_ptr: *const c_char,
    account_index: u32,
    subaddress_index: u32,
    is_mainnet: u8,
    out_buf: *mut c_char,
    out_buf_len: usize,
    out_written: *mut usize,
) -> c_int {
    let keys = match master_keys_from_mnemonic_ptr(mnemonic_ptr) {
        Ok(k) => k,
        Err(code) => {
            zero_outputs(out_buf, out_buf_len, out_written);
            return code;
        }
    };

    let network = network_from_flag(is_mainnet);
    let address = derive_address_string(&keys, account_index, subaddress_index, network);
    write_address_to_buf(&address, out_buf, out_buf_len, out_written)
}

// =========================
// In-memory wallet registry
// =========================

#[derive(Clone, Debug)]
struct TrackedOutput {
    tx_hash: [u8; 32],
    index_in_tx: u64,
    /// Key image for this output (I = x * Hp(P)), used to detect on-chain spends.
    key_image: [u8; 32],
    amount: u64,
    block_height: u64,
    additional_timelock: Timelock,
    is_coinbase: bool,
    subaddress_major: u32,
    subaddress_minor: u32,
    spent: bool,
    /// If this output has been detected as spent, record the spending txid when known.
    spending_txid: Option<[u8; 32]>,
    /// Height where the spending tx was observed, if known.
    spending_height: Option<u64>,
}

fn mark_tracked_output_spent(output: &mut TrackedOutput, spending_txid: Option<[u8; 32]>) {
    output.spent = true;
    if output.spending_txid.is_none() {
        output.spending_txid = spending_txid;
    }
}

/// Minimal pending-outgoing record for UI history.
/// We add this when a send/sweep successfully broadcasts, and clear it once it is confirmed.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct PendingOutgoingTx {
    txid: String,
    amount: u64,
    fee: u64,
    created_at: u64,
}

/// Worker-mode spend detection record: one observed tx input key image attributed to a spending txid.
///
/// This is produced in the refresh worker thread and applied on the main thread to mark matching
/// tracked outputs as spent.
#[derive(Clone, Copy, Debug)]
struct RefreshWorkerSpend {
    spending_txid: [u8; 32],
    key_image: [u8; 32],
}

/// Worker-mode refresh payload: newly discovered outputs plus spend observations.
///
/// NOTE: Outgoing ledger attribution (fee/net) is handled on the main thread after applying spends.
//
// Debug controls for spend detection logging.
// We want always-on summaries (even when 0 spends found), but we must avoid log spam on mobile.
// Controls:
// - WALLETCORE_SPEND_LOG_EVERY_N_BLOCKS: emit per-block spend summary every N blocks (default 2048)
//
// Additional debug:
// - WALLETCORE_DEBUG_SPEND_DETECT=1: emit detailed spend-detection summary per refresh chunk (worker-side + apply-side)
// - WALLETCORE_SPEND_LOG_EVERY_N_BATCHES: emit per-batch output/key-image coverage summary every N batches (default 8)
//
// Targeted "watch" controls for diagnosing missing outgoing transactions:
// - WALLETCORE_DEBUG_WATCH_KEY_IMAGE_HEX: if set to a 64-hex key image, log when that KI is seen and whether it matches an owned output
// - WALLETCORE_DEBUG_WATCH_TXID_HEX: if set to a 64-hex txid, log when that spending txid is observed during spend scanning
pub(crate) fn spend_log_every_n_blocks_from_env() -> u64 {
    std::env::var("WALLETCORE_SPEND_LOG_EVERY_N_BLOCKS")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(2048)
}

pub(crate) fn spend_log_every_n_batches_from_env() -> u64 {
    std::env::var("WALLETCORE_SPEND_LOG_EVERY_N_BATCHES")
        .ok()
        .and_then(|s| s.trim().parse::<u64>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(8)
}

// NOTE: hex parsing helper `parse_hex_32` already exists near the top of this module.
// Reuse it for the watch env vars to avoid duplicate definitions.

pub(crate) fn watch_key_image_from_env() -> Option<[u8; 32]> {
    std::env::var("WALLETCORE_DEBUG_WATCH_KEY_IMAGE_HEX")
        .ok()
        .and_then(|s| parse_hex_32(&s))
}

pub(crate) fn watch_txid_from_env() -> Option<[u8; 32]> {
    std::env::var("WALLETCORE_DEBUG_WATCH_TXID_HEX")
        .ok()
        .and_then(|s| parse_hex_32(&s))
}

#[derive(Clone, Debug)]
struct RefreshWorkerResult {
    outputs: Vec<TrackedOutput>,
    spends: Vec<RefreshWorkerSpend>,
}

impl TrackedOutput {
    fn is_unlocked(&self, chain_height: u64, chain_time: u64) -> bool {
        let base_lock = if self.is_coinbase {
            COINBASE_LOCK_WINDOW
        } else {
            DEFAULT_LOCK_WINDOW
        };
        let mut required_height = self.block_height.saturating_add(base_lock);
        match self.additional_timelock {
            Timelock::None => {}
            Timelock::Block(height) => {
                required_height = required_height.max(height as u64);
            }
            Timelock::Time(timestamp) => {
                if chain_time < timestamp {
                    return false;
                }
            }
        }
        chain_height >= required_height
    }
}

#[derive(Clone, Debug, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ObservedTimelock {
    None,
    Block { height: u64 },
    Time { timestamp: u64 },
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ObservedOutput {
    tx_hash: String,
    index_in_tx: u64,
    amount: u64,
    block_height: u64,
    subaddress_major: u32,
    subaddress_minor: u32,
    is_coinbase: bool,
    spent: bool,
    confirmations: u64,

    /// Canonical lowercase hex key image for this owned output.
    /// Used for scanner idempotency / dedupe across rescans.
    key_image_hex: String,

    timelock: ObservedTimelock,
    unlock_height: u64,
    unlocked: bool,
    unlock_time: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ObservedOutputsEnvelope {
    wallet_id: String,
    restore_height: u64,
    last_scanned_height: u64,
    chain_height: u64,
    chain_time: u64,
    outputs: Vec<ObservedOutput>,
}

/// Transaction-level transfer row for UI history.
///
/// NOTE: This is the API-facing JSON row we return to Swift.
/// Internal, stable history is maintained in `LedgerEntry`.
#[derive(Clone, Debug, Serialize)]
pub(crate) struct ObservedTransfer {
    txid: String,
    direction: String, // "in" | "out" | "self"
    amount: u64,       // piconero (positive; interpret via direction)
    fee: Option<u64>,  // piconero (transaction network fee; informational for incoming)
    height: Option<u64>,
    timestamp: Option<u64>,
    confirmations: u64,
    is_pending: bool,
    // MVP choice (A): we do not attribute transfers to a specific subaddress because a tx can touch multiple.
    subaddress_major: Option<u32>,
    subaddress_minor: Option<u32>,
}

/// Version of the JSON contract returned by `wallet_list_transfers_json`.
///
/// Version 0 was the historical bare array. Version 1 wraps the rows with the
/// wallet/scan metadata needed to tell which snapshot a consumer decoded.
pub(crate) const TRANSFER_HISTORY_SCHEMA_VERSION: u32 = 1;

#[derive(Clone, Debug, Serialize)]
pub(crate) struct ObservedTransfersEnvelope {
    schema_version: u32,
    wallet_id: String,
    last_scanned_height: u64,
    chain_height: u64,
    chain_time: u64,
    transfers: Vec<ObservedTransfer>,
}

/// Persisted ledger entry used to build stable transfer history.
///
/// - Incoming ("in"): `amount` is the total received in that tx to this wallet (sum of outputs).
/// - Outgoing ("out"): `amount` is the wallet's net spend (`spent inputs − change`), i.e.
///   payment + fee, matching Feather `balanceDelta` magnitude. Fee is stored separately when known.
/// - Coinbase receives are included (as "in") with `is_coinbase = true`.
///
/// We keep this separate from `TrackedOutput` so history remains stable even after outputs are spent.
/// Rebuild it from tracked outputs each refresh — never clone-and-add, which double-counts.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
struct LedgerEntry {
    txid: String,
    direction: String, // "in" | "out" | "self"
    amount: u64,       // piconero (positive; interpret via direction)
    fee: Option<u64>,  // piconero (transaction network fee; informational for incoming)
    height: Option<u64>,
    timestamp: Option<u64>,
    is_pending: bool,
    is_coinbase: bool,
}

/// Outgoing ledger/history amount is always payment + fee.
///
/// `PendingOutgoingTx.amount` remains the payment (prepare/send JSON amount); fee is separate.
/// Ledger rows and transfer history must report the Feather-style net debit.
pub(crate) fn outgoing_ledger_amount(payment: u64, fee: u64) -> u64 {
    payment.saturating_add(fee)
}

#[derive(Default)]
struct TxLedgerAgg {
    incoming: u64,
    incoming_height: Option<u64>,
    is_coinbase: bool,
    spent: u64,
    spend_height: Option<u64>,
}

/// Return the network fee carried by transaction data that was already downloaded for scanning.
///
/// RingCT keeps the fee in the non-prunable proof base, while legacy v1 transactions expose
/// amounts publicly and require input-total minus output-total. Coinbase transactions pay no fee.
/// `None` is reserved for incomplete, malformed, or unsupported data.
pub(crate) fn transaction_network_fee(tx: &Transaction<Pruned>) -> Option<u64> {
    if matches!(tx.prefix().inputs.first(), Some(MoneroInput::Gen(_))) {
        return Some(0);
    }

    match tx {
        Transaction::V2 {
            proofs: Some(proofs),
            ..
        } => Some(proofs.base.fee),
        Transaction::V2 { proofs: None, .. } => None,
        Transaction::V1 { prefix, .. } => {
            let input_total = prefix.inputs.iter().try_fold(0u64, |total, input| {
                let MoneroInput::ToKey {
                    amount: Some(amount),
                    ..
                } = input
                else {
                    return None;
                };
                total.checked_add(*amount)
            })?;
            let output_total = prefix
                .outputs
                .iter()
                .try_fold(0u64, |total, output| total.checked_add(output.amount?))?;
            input_total.checked_sub(output_total)
        }
    }
}

/// Preserve fees already learned by a prior refresh or imported cache.
pub(crate) fn known_transaction_fees(
    ledger: &HashMap<String, LedgerEntry>,
) -> HashMap<String, u64> {
    ledger
        .iter()
        .filter_map(|(txid, entry)| entry.fee.map(|fee| (txid.clone(), fee)))
        .collect()
}

fn bump_height(slot: &mut Option<u64>, height: u64) {
    if height == 0 {
        return;
    }
    *slot = Some(slot.unwrap_or(0).max(height));
}

/// Rebuild transfer history from currently tracked outputs + pending local sends.
///
/// For each txid:
/// - incoming = sum of owned outputs created in that tx (receives and change)
/// - spent = sum of our inputs consumed by that tx (when `spending_txid` is known)
/// - if spent > 0 → `out` with amount = spent − incoming (payment + fee, not gross inputs)
/// - else → `in` with amount = incoming
///
/// Change-bearing spends therefore stay outgoing instead of being overwritten as a receive.
/// Spent outputs missing `spending_txid` still attach to same-height change when that
/// mapping is unambiguous (the interrupted-scan / bulk-index hole).
pub(crate) fn rebuild_transfer_ledger(
    outputs: &[TrackedOutput],
    pending_outgoing: &[PendingOutgoingTx],
    known_fees: &HashMap<String, u64>,
    chain_time: u64,
    height_timestamps: &HashMap<u64, u64>,
) -> HashMap<String, LedgerEntry> {
    let mut by_txid: HashMap<String, TxLedgerAgg> = HashMap::new();
    let mut unattributed: Vec<(u64, Option<u64>, String)> = Vec::new();

    for output in outputs {
        let recv_txid = hex_lowercase(&output.tx_hash);
        let recv = by_txid.entry(recv_txid.clone()).or_default();
        recv.incoming = recv.incoming.saturating_add(output.amount);
        recv.is_coinbase = recv.is_coinbase || output.is_coinbase;
        bump_height(&mut recv.incoming_height, output.block_height);

        if output.spent {
            if let Some(spend_bytes) = output.spending_txid {
                let spend_txid = hex_lowercase(&spend_bytes);
                let spend = by_txid.entry(spend_txid).or_default();
                spend.spent = spend.spent.saturating_add(output.amount);
                bump_height(&mut spend.spend_height, output.spending_height.unwrap_or(0));
            } else {
                unattributed.push((output.amount, output.spending_height, recv_txid));
            }
        }
    }

    if !unattributed.is_empty() {
        let mut spent_by_height: HashMap<u64, u64> = HashMap::new();
        let mut source_txids: HashSet<String> = HashSet::new();
        for (amount, height, source_txid) in &unattributed {
            source_txids.insert(source_txid.clone());
            if let Some(height) = height.filter(|h| *h > 0) {
                let slot = spent_by_height.entry(height).or_insert(0);
                *slot = slot.saturating_add(*amount);
            }
        }

        let mut incoming_at_height: HashMap<u64, Vec<String>> = HashMap::new();
        for (txid, agg) in &by_txid {
            if agg.incoming == 0 {
                continue;
            }
            if let Some(height) = agg.incoming_height.filter(|h| *h > 0) {
                incoming_at_height
                    .entry(height)
                    .or_default()
                    .push(txid.clone());
            }
        }

        for (height, spent_sum) in spent_by_height {
            let Some(txids) = incoming_at_height.get(&height) else {
                continue;
            };
            let candidates: Vec<&String> = txids
                .iter()
                .filter(|txid| !source_txids.contains(*txid))
                .filter(|txid| {
                    by_txid
                        .get(*txid)
                        .map(|agg| agg.incoming > 0 && agg.incoming < spent_sum && agg.spent == 0)
                        .unwrap_or(false)
                })
                .collect();
            if candidates.len() != 1 {
                continue;
            }
            let spend_txid = candidates[0].clone();
            if let Some(spend) = by_txid.get_mut(&spend_txid) {
                spend.spent = spend.spent.saturating_add(spent_sum);
                bump_height(&mut spend.spend_height, height);
            }
        }
    }

    let tip_timestamp = if chain_time > 0 { Some(chain_time) } else { None };
    let mut ledger: HashMap<String, LedgerEntry> = HashMap::new();

    for (txid, agg) in by_txid {
        let fee = known_fees.get(&txid).copied();
        if agg.spent > 0 {
            let height = agg.spend_height.or(agg.incoming_height);
            ledger.insert(
                txid.clone(),
                LedgerEntry {
                    txid,
                    direction: "out".to_string(),
                    amount: agg.spent.saturating_sub(agg.incoming),
                    fee,
                    height,
                    timestamp: ledger_timestamp_for_height(height, height_timestamps),
                    is_pending: false,
                    is_coinbase: false,
                },
            );
        } else if agg.incoming > 0 {
            let height = agg.incoming_height;
            ledger.insert(
                txid.clone(),
                LedgerEntry {
                    txid,
                    direction: "in".to_string(),
                    amount: agg.incoming,
                    fee,
                    height,
                    timestamp: ledger_timestamp_for_height(height, height_timestamps),
                    is_pending: false,
                    is_coinbase: agg.is_coinbase,
                },
            );
        }
    }

    for pending in pending_outgoing {
        let pending_amount = outgoing_ledger_amount(pending.amount, pending.fee);
        let pending_fee = if pending.fee > 0 {
            Some(pending.fee)
        } else {
            None
        };
        match ledger.get_mut(&pending.txid) {
            Some(entry) if entry.direction == "out" => {
                // Exact-send / relay may have inserted payment-only; normalize to payment+fee.
                entry.amount = pending_amount;
                if entry.fee.is_none() {
                    entry.fee = pending_fee;
                }
            }
            Some(entry) => {
                // Cache/interrupt path: change was recorded as a receive of our own send.
                entry.direction = "out".to_string();
                entry.amount = pending_amount;
                entry.fee = pending_fee;
                entry.is_pending = entry.height.is_none();
                entry.is_coinbase = false;
            }
            None => {
                ledger.insert(
                    pending.txid.clone(),
                    LedgerEntry {
                        txid: pending.txid.clone(),
                        direction: "out".to_string(),
                        amount: pending_amount,
                        fee: pending_fee,
                        height: None,
                        timestamp: if pending.created_at > 0 {
                            Some(pending.created_at)
                        } else {
                            tip_timestamp
                        },
                        is_pending: true,
                        is_coinbase: false,
                    },
                );
            }
        }
    }

    ledger
}

fn ledger_timestamp_for_height(
    height: Option<u64>,
    height_timestamps: &HashMap<u64, u64>,
) -> Option<u64> {
    height
        .filter(|h| *h > 0)
        .and_then(|h| height_timestamps.get(&h).copied())
        .filter(|t| *t > 0)
}

pub(crate) fn confirmations_for_height(chain_height: u64, tx_height: u64) -> u64 {
    if tx_height == 0 {
        0
    } else {
        chain_height.saturating_sub(tx_height).saturating_add(1)
    }
}

fn hex_lowercase(bytes: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        write!(&mut s, "{:02x}", byte).expect("hex_lowercase formatting failed");
    }
    s
}

impl ObservedTimelock {
    fn from_timelock(value: &Timelock) -> Self {
        match value {
            Timelock::None => ObservedTimelock::None,
            Timelock::Block(height) => ObservedTimelock::Block {
                height: *height as u64,
            },
            Timelock::Time(timestamp) => ObservedTimelock::Time {
                timestamp: *timestamp,
            },
        }
    }
}

impl ObservedOutput {
    pub(crate) fn from_tracked(output: &TrackedOutput, chain_height: u64, chain_time: u64) -> Self {
        let confirmations = if output.block_height == 0 {
            0
        } else {
            chain_height
                .saturating_sub(output.block_height)
                .saturating_add(1)
        };
        let base_lock = if output.is_coinbase {
            COINBASE_LOCK_WINDOW
        } else {
            DEFAULT_LOCK_WINDOW
        };
        let mut unlock_height = output.block_height.saturating_add(base_lock);
        let mut unlock_time: Option<u64> = None;
        let timelock = match output.additional_timelock {
            Timelock::None => ObservedTimelock::None,
            Timelock::Block(height) => {
                let h = height as u64;
                unlock_height = unlock_height.max(h);
                ObservedTimelock::Block { height: h }
            }
            Timelock::Time(timestamp) => {
                unlock_time = Some(timestamp);
                ObservedTimelock::Time { timestamp }
            }
        };
        let tx_hash = hex_lowercase(&output.tx_hash);
        let unlocked = output.is_unlocked(chain_height, chain_time);
        let key_image_hex = hex_lowercase(&output.key_image);
        Self {
            tx_hash,
            index_in_tx: output.index_in_tx,
            amount: output.amount,
            block_height: output.block_height,
            subaddress_major: output.subaddress_major,
            subaddress_minor: output.subaddress_minor,
            is_coinbase: output.is_coinbase,
            spent: output.spent,
            confirmations,
            key_image_hex,
            timelock,
            unlock_height,
            unlocked,
            unlock_time,
        }
    }
}

#[derive(Clone)]
struct StoredWallet {
    history_index: Option<Arc<ffi::history::HistoryIndex>>,
    keys: MasterKeys,
    restore_height: u64,
    network: MoneroNetwork,
    last_scanned: u64,
    total: u64,
    unlocked: u64,
    chain_height: u64,
    chain_time: u64,
    last_refresh_timestamp: u64,
    gap_limit: u32,
    tracked_outputs: Vec<TrackedOutput>,
    seen_outpoints: HashSet<([u8; 32], u64)>,
    pending_outgoing: Vec<PendingOutgoingTx>,
    tx_ledger: HashMap<String, LedgerEntry>,

    /// Outputs we have quarantined because the daemon rejected them with `invalid_input=true`
    /// during broadcast. Keyed by (tx_hash, index_in_tx).
    ///
    /// This is a safety net for cases where spend-detection is lagging or the node view is inconsistent.
    /// We exclude these from future input selection and persist them in the cache.
    invalid_input_quarantine: HashSet<([u8; 32], u64)>,

    // Wallet2-style bounded recent block-hash history used to build `block_ids` (short chain history)
    // for `/getblocks.bin` fast sync. This is intentionally bounded to keep cache size small.
    //
    // - `recent_block_hashes_start_height` is the height of the first hash in `recent_block_hashes`.
    // - `recent_block_hashes[i]` corresponds to height `recent_block_hashes_start_height + i`.
    recent_block_hashes_start_height: u64,
    recent_block_hashes: Vec<[u8; 32]>,

    /// Block height → header timestamp for transfers we have scanned.
    ///
    /// Used so ledger history can show per-transaction block times instead of stamping
    /// every row with the current tip time. Additive; older caches deserialize empty.
    block_timestamps: HashMap<u64, u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) enum PersistedTimelock {
    None,
    Block(u64),
    Time(u64),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PersistedOutput {
    tx_hash: [u8; 32],
    index_in_tx: u64,
    /// Key image for this output, persisted so we can detect spends on refresh.
    key_image: [u8; 32],
    amount: u64,
    block_height: u64,
    timelock: PersistedTimelock,
    is_coinbase: bool,
    subaddress_major: u32,
    subaddress_minor: u32,
    spent: bool,
    spending_txid: Option<[u8; 32]>,
    #[serde(default)]
    spending_height: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) enum PersistedNetwork {
    Mainnet,
    Stagenet,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct PersistedWallet {
    /// Cache compatibility version for this blob.
    ///
    /// Marked `serde(default)` so older cache blobs can still be deserialized; old blobs
    /// will deserialize with version 0 and be rejected by import logic.
    #[serde(default)]
    cache_version: u32,

    /// Primary address of the wallet that produced this cache.
    ///
    /// Import must match the open wallet's primary address (and therefore network).
    /// Empty on legacy blobs; version gate rejects those before binding is checked.
    #[serde(default)]
    bound_primary_address: String,

    network: PersistedNetwork,
    restore_height: u64,
    last_scanned: u64,
    total: u64,
    unlocked: u64,
    chain_height: u64,
    chain_time: u64,
    gap_limit: u32,
    tracked_outputs: Vec<PersistedOutput>,
    seen_outpoints: Vec<([u8; 32], u64)>,
    pending_outgoing: Vec<PendingOutgoingTx>,
    tx_ledger: HashMap<String, LedgerEntry>,

    /// Persisted invalid-input quarantine (see `StoredWallet.invalid_input_quarantine`).
    /// Marked `serde(default)` so older cache blobs can still be deserialized.
    #[serde(default)]
    invalid_input_quarantine: Vec<([u8; 32], u64)>,

    // Bounded recent block-hash history (see `StoredWallet` for details).
    // Marked `serde(default)` so older cache blobs (which don't have these fields yet)
    // can still be deserialized safely.
    #[serde(default)]
    recent_block_hashes_start_height: u64,
    #[serde(default)]
    recent_block_hashes: Vec<[u8; 32]>,

    /// Height → block header timestamp for accurate transfer history.
    #[serde(default)]
    block_timestamps: HashMap<u64, u64>,
}

impl From<&Timelock> for PersistedTimelock {
    fn from(value: &Timelock) -> Self {
        match value {
            Timelock::None => PersistedTimelock::None,
            Timelock::Block(height) => PersistedTimelock::Block(*height as u64),
            Timelock::Time(timestamp) => PersistedTimelock::Time(*timestamp),
        }
    }
}

impl From<PersistedTimelock> for Timelock {
    fn from(value: PersistedTimelock) -> Self {
        match value {
            PersistedTimelock::None => Timelock::None,
            PersistedTimelock::Block(height) => {
                let block_height: usize = height.try_into().unwrap_or(usize::MAX);
                Timelock::Block(block_height)
            }
            PersistedTimelock::Time(timestamp) => Timelock::Time(timestamp),
        }
    }
}

impl From<&TrackedOutput> for PersistedOutput {
    fn from(output: &TrackedOutput) -> Self {
        Self {
            tx_hash: output.tx_hash,
            index_in_tx: output.index_in_tx,
            key_image: output.key_image,
            amount: output.amount,
            block_height: output.block_height,
            timelock: PersistedTimelock::from(&output.additional_timelock),
            is_coinbase: output.is_coinbase,
            subaddress_major: output.subaddress_major,
            subaddress_minor: output.subaddress_minor,
            spent: output.spent,
            spending_txid: output.spending_txid,
            spending_height: output.spending_height,
        }
    }
}

impl From<PersistedOutput> for TrackedOutput {
    fn from(output: PersistedOutput) -> Self {
        Self {
            tx_hash: output.tx_hash,
            index_in_tx: output.index_in_tx,
            key_image: output.key_image,
            amount: output.amount,
            block_height: output.block_height,
            additional_timelock: output.timelock.into(),
            is_coinbase: output.is_coinbase,
            subaddress_major: output.subaddress_major,
            subaddress_minor: output.subaddress_minor,
            spent: output.spent,
            spending_txid: output.spending_txid,
            spending_height: output.spending_height,
        }
    }
}

impl From<MoneroNetwork> for PersistedNetwork {
    fn from(network: MoneroNetwork) -> Self {
        match network {
            MoneroNetwork::Mainnet => PersistedNetwork::Mainnet,
            MoneroNetwork::Stagenet | MoneroNetwork::Testnet => PersistedNetwork::Stagenet,
        }
    }
}

impl From<&PersistedNetwork> for MoneroNetwork {
    fn from(network: &PersistedNetwork) -> Self {
        match network {
            PersistedNetwork::Mainnet => MoneroNetwork::Mainnet,
            PersistedNetwork::Stagenet => MoneroNetwork::Stagenet,
        }
    }
}

impl From<&StoredWallet> for PersistedWallet {
    fn from(wallet: &StoredWallet) -> Self {
        Self {
            cache_version: WALLETCORE_CACHE_VERSION,
            bound_primary_address: wallet_cache_binding(wallet),

            network: wallet.network.into(),
            restore_height: wallet.restore_height,
            last_scanned: wallet.last_scanned,
            total: wallet.total,
            unlocked: wallet.unlocked,
            chain_height: wallet.chain_height,
            chain_time: wallet.chain_time,
            gap_limit: wallet.gap_limit,
            tracked_outputs: wallet
                .tracked_outputs
                .iter()
                .map(PersistedOutput::from)
                .collect(),
            seen_outpoints: wallet.seen_outpoints.iter().copied().collect(),
            pending_outgoing: wallet.pending_outgoing.clone(),
            tx_ledger: wallet.tx_ledger.clone(),
            invalid_input_quarantine: wallet.invalid_input_quarantine.iter().copied().collect(),

            recent_block_hashes_start_height: wallet.recent_block_hashes_start_height,
            recent_block_hashes: wallet.recent_block_hashes.clone(),
            block_timestamps: wallet.block_timestamps.clone(),
        }
    }
}

/// Stable public identity for cache binding: primary address (encodes network).
pub(crate) fn wallet_cache_binding(wallet: &StoredWallet) -> String {
    derive_address_string(&wallet.keys, 0, 0, wallet.network)
}

/// Reject caches that do not belong to the open wallet / network.
pub(crate) fn cache_identity_matches(
    persisted: &PersistedWallet,
    open_wallet: &StoredWallet,
) -> Result<(), String> {
    let expected_address = wallet_cache_binding(open_wallet);
    if persisted.bound_primary_address.is_empty() {
        return Err(
            "wallet_import_cache: cache is missing bound_primary_address".to_string(),
        );
    }
    if persisted.bound_primary_address != expected_address {
        return Err(format!(
            "wallet_import_cache: cache identity mismatch (cache bound to {}, open wallet is {})",
            persisted.bound_primary_address, expected_address
        ));
    }
    let expected_network = PersistedNetwork::from(open_wallet.network);
    if persisted.network != expected_network {
        return Err(format!(
            "wallet_import_cache: cache network mismatch (cache {:?}, open wallet {:?})",
            persisted.network, expected_network
        ));
    }
    Ok(())
}

impl PersistedWallet {
    pub(crate) fn apply_to_state(self, state: &mut StoredWallet) {
        // Cache compatibility gate:
        // If the cache version is missing (older blob => 0) or doesn't match our current schema,
        // reject applying it to avoid subtle corruption (e.g. stale/wrong key images).
        if self.cache_version != WALLETCORE_CACHE_VERSION {
            // Use last-error channel so callers (Swift) can surface it and delete the on-disk cache.
            record_error(
                -16,
                format!(
                    "wallet_import_cache: incompatible cache version (have {}, want {})",
                    self.cache_version, WALLETCORE_CACHE_VERSION
                ),
            );
            return;
        }

        state.last_scanned = self.last_scanned.max(state.restore_height);
        state.total = self.total;
        state.unlocked = self.unlocked;
        state.chain_height = self.chain_height;
        state.chain_time = self.chain_time;
        state.gap_limit = self.gap_limit;
        state.tracked_outputs = self
            .tracked_outputs
            .into_iter()
            .map(TrackedOutput::from)
            .collect();
        state.seen_outpoints = self.seen_outpoints.into_iter().collect();
        state.pending_outgoing = self.pending_outgoing;
        state.tx_ledger = self.tx_ledger;
        state.invalid_input_quarantine = self.invalid_input_quarantine.into_iter().collect();
        state.recent_block_hashes_start_height = self.recent_block_hashes_start_height;
        state.recent_block_hashes = self.recent_block_hashes;
        state.block_timestamps = self.block_timestamps;
        state.network = (&self.network).into();
        state.restore_height = self.restore_height;
    }
}

static WALLET_STORE: Lazy<Mutex<HashMap<String, StoredWallet>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
#[no_mangle]
pub extern "C" fn wallet_start_zmq_listener(endpoint: *const c_char) -> c_int {
    clear_last_error();
    if endpoint.is_null() {
        return record_error(-11, "wallet_start_zmq_listener: endpoint pointer was null");
    }
    let endpoint_str = match unsafe { CStr::from_ptr(endpoint) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            return record_error(
                -10,
                "wallet_start_zmq_listener: endpoint contained invalid UTF-8",
            );
        }
    };
    match ensure_zmq_runtime(endpoint_str) {
        Ok(_) => {
            clear_last_error();
            0
        }
        Err((code, message)) => record_error(code, message),
    }
}

#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
#[no_mangle]
pub extern "C" fn wallet_stop_zmq_listener() -> c_int {
    clear_last_error();
    stop_zmq_runtime();
    0
}

#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos"))]
#[no_mangle]
pub extern "C" fn wallet_stop_zmq_listener() -> c_int {
    0
}

#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
#[no_mangle]
pub extern "C" fn wallet_zmq_sequence(out_sequence: *mut u64) -> c_int {
    clear_last_error();
    if out_sequence.is_null() {
        return record_error(-11, "wallet_zmq_sequence: out_sequence pointer was null");
    }
    let (sequence, error_slot) = {
        let slot = ZMQ_RUNTIME.lock().expect("ZMQ runtime lock poisoned");
        match slot.as_ref() {
            Some(runtime) => (runtime.sequence.clone(), runtime.error.clone()),
            None => {
                return record_error(-13, "wallet_zmq_sequence: ZMQ listener not started");
            }
        }
    };
    if let Ok(message) = error_slot.lock() {
        if let Some(message) = message.clone() {
            return record_error(-16, message);
        }
    }
    let value = sequence.load(Ordering::Relaxed);
    unsafe { *out_sequence = value };
    0
}

#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos"))]
#[no_mangle]
pub extern "C" fn wallet_zmq_sequence(out_sequence: *mut u64) -> c_int {
    clear_last_error();
    if !out_sequence.is_null() {
        unsafe { *out_sequence = 0 };
    }
    0
}

#[cfg(any(target_os = "ios", target_os = "tvos", target_os = "watchos"))]
#[no_mangle]
pub extern "C" fn wallet_start_zmq_listener(_endpoint: *const c_char) -> c_int {
    clear_last_error();
    0
}

/// Open (or register) a wallet from a 25-word mnemonic and initial restore height.
/// Stores basic state in-memory for subsequent refresh/balance calls.
/// Returns:
/// - 0 on success
/// - -10 invalid mnemonic encoding/empty
/// - -11 invalid argument (null pointers)
#[no_mangle]
pub extern "C" fn wallet_open_from_mnemonic(
    wallet_id: *const c_char,
    mnemonic_ptr: *const c_char,
    restore_height: u64,
    is_mainnet: u8,
) -> c_int {
    if wallet_id.is_null() || mnemonic_ptr.is_null() {
        return -11;
    }

    // Convert inputs
    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return -10,
    };
    let mnemonic = match unsafe { CStr::from_ptr(mnemonic_ptr) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return -10,
    };
    if id.is_empty() || mnemonic.is_empty() {
        return -10;
    }

    // Derive the master keys once. This also validates the mnemonic (English),
    // so obviously bad inputs fail fast without a separate parse step.
    let keys = match master_keys_from_mnemonic_str(mnemonic) {
        Ok(keys) => keys,
        Err(_) => return -10,
    };

    let network = if is_mainnet != 0 {
        MoneroNetwork::Mainnet
    } else {
        MoneroNetwork::Stagenet
    };

    match crate::ffi::refresh::with_refresh_stopped(id, || {
        let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
        match map.entry(id.to_string()) {
            Entry::Occupied(mut slot) => {
                let state = slot.get_mut();
                state.keys = keys;
                state.network = network;
                if restore_height < state.restore_height {
                    state.restore_height = restore_height;
                }
                if state.last_scanned < state.restore_height {
                    state.last_scanned = state.restore_height;
                }
                if state.gap_limit == 0 {
                    state.gap_limit = 50;
                }
            }
            Entry::Vacant(slot) => {
                slot.insert(StoredWallet {
                    history_index: None,
                    keys,
                    restore_height,
                    network,
                    last_scanned: restore_height,
                    total: 0,
                    unlocked: 0,
                    chain_height: restore_height,
                    chain_time: 0,
                    last_refresh_timestamp: 0,
                    gap_limit: 50,
                    tracked_outputs: Vec::new(),
                    seen_outpoints: HashSet::<([u8; 32], u64)>::new(),
                    pending_outgoing: Vec::new(),
                    tx_ledger: HashMap::new(),
                    invalid_input_quarantine: HashSet::<([u8; 32], u64)>::new(),

                    // Start empty; will be populated during refresh.
                    recent_block_hashes_start_height: restore_height,
                    recent_block_hashes: Vec::new(),
                    block_timestamps: HashMap::new(),
                });
            }
        }
        0
    }) {
        Ok(code) => code,
        Err(()) => record_error(
            -31,
            format!("wallet_open_from_mnemonic: refresh already running for wallet '{id}'"),
        ),
    }
}

#[no_mangle]
pub extern "C" fn wallet_set_gap_limit(wallet_id: *const c_char, gap_limit: u32) -> c_int {
    clear_last_error();

    if wallet_id.is_null() {
        return record_error(-11, "wallet_set_gap_limit: wallet_id pointer was null");
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            return record_error(
                -10,
                "wallet_set_gap_limit: wallet_id contained invalid UTF-8",
            )
        }
    };

    let normalized = gap_limit.clamp(1, 100_000);
    match crate::ffi::refresh::with_refresh_stopped(id, || {
        let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
        match map.get_mut(id) {
            Some(state) => {
                state.gap_limit = normalized;
                clear_last_error();
                0
            }
            None => record_error(
                -13,
                format!("wallet_set_gap_limit: wallet '{id}' not opened"),
            ),
        }
    }) {
        Ok(code) => code,
        Err(()) => record_error(
            -31,
            format!("wallet_set_gap_limit: refresh already running for wallet '{id}'"),
        ),
    }
}

// (moved to src/ffi/refresh.rs)

// (moved to src/ffi/refresh.rs)

// (moved to src/ffi/refresh.rs)

/// Get wallet balance (stub).
/// Writes total and unlocked balances from in-memory state (both 0 by default in this stub).
/// Returns:
/// - 0 on success
/// - -11 invalid argument
/// - -13 not found
#[no_mangle]
pub extern "C" fn wallet_get_balance(
    wallet_id: *const c_char,
    out_total_piconero: *mut u64,
    out_unlocked_piconero: *mut u64,
) -> c_int {
    if wallet_id.is_null() || out_total_piconero.is_null() || out_unlocked_piconero.is_null() {
        return -11;
    }
    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return -11,
    };
    let map = WALLET_STORE.lock().expect("wallet store poisoned");
    let Some(state) = map.get(id) else {
        return -13;
    };

    unsafe {
        *out_total_piconero = state.total;
        *out_unlocked_piconero = state.unlocked;
    }
    0
}

/// Get wallet balance with an optional input filter (e.g., constrain to a subaddress).
/// filter_json is a JSON object (or NULL). Currently supported schema:
///   { "subaddress_minor": 12 }
///
/// Returns:
/// - 0 on success
/// - -10 invalid UTF-8 / invalid JSON
/// - -11 invalid argument
/// - -13 wallet not found
#[no_mangle]
pub extern "C" fn wallet_get_balance_with_filter(
    wallet_id: *const c_char,
    filter_json: *const c_char,
    out_total_piconero: *mut u64,
    out_unlocked_piconero: *mut u64,
) -> c_int {
    clear_last_error();

    if wallet_id.is_null() || out_total_piconero.is_null() || out_unlocked_piconero.is_null() {
        return record_error(-11, "wallet_get_balance_with_filter: null argument(s)");
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            return record_error(
                -10,
                "wallet_get_balance_with_filter: wallet_id contained invalid UTF-8",
            );
        }
    };

    #[derive(Deserialize)]
    struct InputFilter {
        subaddress_minor: Option<u32>,
    }

    let filt_str_opt = if !filter_json.is_null() {
        unsafe { CStr::from_ptr(filter_json) }.to_str().ok()
    } else {
        None
    };

    let filter: Option<InputFilter> = match filt_str_opt {
        Some(s) if !s.trim().is_empty() => match serde_json::from_str(s) {
            Ok(f) => Some(f),
            Err(err) => {
                return record_error(
                    -10,
                    format!("wallet_get_balance_with_filter: invalid filter JSON ({err})"),
                );
            }
        },
        _ => None,
    };

    let map = WALLET_STORE.lock().expect("wallet store poisoned");
    let Some(state) = map.get(id) else {
        return record_error(
            -13,
            format!("wallet_get_balance_with_filter: wallet '{id}' not opened"),
        );
    };

    let chain_height = state.chain_height;
    let chain_time = state.chain_time;

    let mut total: u64 = 0;
    let mut unlocked: u64 = 0;

    for o in state.tracked_outputs.iter() {
        if let Some(f) = &filter {
            if let Some(minor) = f.subaddress_minor {
                // Account 0 only for now
                if !(o.subaddress_major == 0 && o.subaddress_minor == minor) {
                    continue;
                }
            }
        }
        if o.spent {
            continue;
        }

        total = total.saturating_add(o.amount);
        if o.is_unlocked(chain_height, chain_time) {
            unlocked = unlocked.saturating_add(o.amount);
        }
    }

    unsafe {
        *out_total_piconero = total;
        *out_unlocked_piconero = unlocked;
    }

    clear_last_error();
    0
}

#[no_mangle]
pub extern "C" fn wallet_force_rescan_from_height(
    wallet_id: *const c_char,
    new_restore_height: u64,
) -> c_int {
    clear_last_error();
    if wallet_id.is_null() {
        return record_error(
            -11,
            "wallet_force_rescan_from_height: wallet_id pointer was null",
        );
    }
    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            return record_error(
                -10,
                "wallet_force_rescan_from_height: wallet_id contained invalid UTF-8",
            );
        }
    };
    match crate::ffi::refresh::with_refresh_stopped(id, || {
        let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
        match map.get_mut(id) {
            Some(state) => {
                // Reset scanning window to the requested restore height
                state.restore_height = new_restore_height;
                state.last_scanned = new_restore_height;

                // Clear balances; they will be recomputed on next refresh
                state.total = 0;
                state.unlocked = 0;

                // Normalize chain markers; keep at least restore height
                state.chain_height = state.chain_height.max(new_restore_height);
                state.chain_time = 0;
                state.last_refresh_timestamp = 0;

                // Drop tracked outputs and chain history to force a clean rescan.
                state.tracked_outputs.clear();
                state.seen_outpoints.clear();
                state.invalid_input_quarantine.clear();
                state.recent_block_hashes_start_height = new_restore_height;
                state.recent_block_hashes.clear();
                state.block_timestamps.clear();

                // IMPORTANT: a forced rescan resets our view of wallet state. Any "pending outgoing"
                // records are now untrustworthy (they may refer to txs we won't rediscover until refresh,
                // or may cause us to exclude/consider outputs incorrectly). Clear them so sweep/input
                // selection doesn't accidentally treat unconfirmed change as safely spendable.
                state.pending_outgoing.clear();
                state.tx_ledger.clear();

                clear_last_error();
                0
            }
            None => record_error(
                -13,
                format!("wallet_force_rescan_from_height: wallet '{id}' not opened"),
            ),
        }
    }) {
        Ok(code) => code,
        Err(()) => record_error(
            -31,
            format!("wallet_force_rescan_from_height: refresh still running for wallet '{id}'"),
        ),
    }
}

// (moved to src/ffi/cache.rs)

// (moved to src/ffi/transfers.rs)

// (moved to src/ffi/sweep.rs)

pub use crate::ffi::cache::wallet_export_cache;
pub use crate::ffi::cache::wallet_import_cache;
pub use crate::ffi::preview_fee::wallet_preview_fee;
pub use crate::ffi::preview_fee::wallet_preview_fee_with_filter;
pub use crate::ffi::refresh::wallet_refresh;
pub use crate::ffi::refresh::wallet_refresh_async;
pub use crate::ffi::refresh::wallet_refresh_job_status_json;
pub use crate::ffi::refresh::wallet_sync_status;
pub use crate::ffi::send::wallet_prepare_send;
pub use crate::ffi::send::wallet_prepare_send_with_filter;
pub use crate::ffi::send::wallet_relay_prepared;
pub use crate::ffi::send::wallet_send;
pub use crate::ffi::send::wallet_send_with_filter;
pub use crate::ffi::sweep::wallet_prepare_sweep;
pub use crate::ffi::sweep::wallet_prepare_sweep_with_filter;
pub use crate::ffi::sweep::wallet_preview_sweep;
pub use crate::ffi::sweep::wallet_preview_sweep_with_filter;
pub use crate::ffi::sweep::wallet_sweep;
pub use crate::ffi::sweep::wallet_sweep_with_filter;
pub use crate::ffi::transfers::wallet_export_outputs_json;
pub use crate::ffi::transfers::wallet_list_transfers_json;
pub use crate::ffi::history::wallet_query_transfers_json;

#[no_mangle]
pub extern "C" fn wallet_reset_tracked_outputs(wallet_id: *const c_char) -> c_int {
    clear_last_error();

    if wallet_id.is_null() {
        return record_error(
            -11,
            "wallet_reset_tracked_outputs: wallet_id pointer was null",
        );
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            return record_error(
                -10,
                "wallet_reset_tracked_outputs: wallet_id contained invalid UTF-8",
            );
        }
    };

    match crate::ffi::refresh::with_refresh_stopped(id, || {
        let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
        match map.get_mut(id) {
            Some(state) => {
                // Drop output bookkeeping and quarantine without changing restore height.
                // This allows the app to "heal" after derivation changes or inconsistent node behavior,
                // while keeping the user's restore height hint intact.
                state.tracked_outputs.clear();
                state.seen_outpoints.clear();
                state.invalid_input_quarantine.clear();

                // Pending outgoing may refer to now-untracked outputs/change; clear for safety.
                state.pending_outgoing.clear();
                // Stale ledger rows would otherwise survive the next refresh as ghost history.
                state.tx_ledger.clear();
                // Drop height→timestamp map; it will be rebuilt on the next scan.
                state.block_timestamps.clear();

                // Balances will be recomputed on next refresh.
                state.total = 0;
                state.unlocked = 0;

                clear_last_error();
                0
            }
            None => record_error(
                -13,
                format!("wallet_reset_tracked_outputs: wallet '{id}' not opened"),
            ),
        }
    }) {
        Ok(code) => code,
        Err(()) => record_error(
            -31,
            format!("wallet_reset_tracked_outputs: refresh still running for wallet '{id}'"),
        ),
    }
}

// (moved to src/ffi/sweep.rs)

// (moved to src/ffi/sweep.rs)

// (moved to src/ffi/preview_fee.rs)

#[cfg(test)]
mod ledger_rebuild_tests {
    use super::*;
    use monero_wallet::{
        ed25519::CompressedPoint,
        ringct::{PrunedRctProofs, RctBase, RctType},
        transaction::{Input, Output, Timelock, TransactionPrefix},
    };

    fn prefix(inputs: Vec<Input>, output_amounts: Vec<Option<u64>>) -> TransactionPrefix {
        TransactionPrefix {
            additional_timelock: Timelock::None,
            inputs,
            outputs: output_amounts
                .into_iter()
                .map(|amount| Output {
                    amount,
                    key: CompressedPoint::G,
                    view_tag: None,
                })
                .collect(),
            extra: vec![],
        }
    }

    fn public_input(amount: Option<u64>) -> Input {
        Input::ToKey {
            amount,
            key_offsets: vec![1],
            key_image: CompressedPoint::H,
        }
    }

    fn out(
        tx_hash: [u8; 32],
        amount: u64,
        spent: bool,
        spending_txid: Option<[u8; 32]>,
        spending_height: Option<u64>,
    ) -> TrackedOutput {
        TrackedOutput {
            tx_hash,
            index_in_tx: 0,
            key_image: [0u8; 32],
            amount,
            block_height: 10,
            additional_timelock: Timelock::None,
            is_coinbase: false,
            subaddress_major: 0,
            subaddress_minor: 0,
            spent,
            spending_txid,
            spending_height,
        }
    }

    #[test]
    fn receive_is_not_double_counted() {
        let tx = [1u8; 32];
        let outputs = vec![out(tx, 1_427_934_399, false, None, None)];
        let txid = hex_lowercase(&tx);
        let known_fees = HashMap::from([(txid.clone(), 24_680_000)]);
        let first = rebuild_transfer_ledger(&outputs, &[], &known_fees, 0, &HashMap::new());
        let second = rebuild_transfer_ledger(&outputs, &[], &known_fees, 0, &HashMap::new());
        assert_eq!(first.get(&txid).map(|e| e.amount), Some(1_427_934_399));
        assert_eq!(second.get(&txid).map(|e| e.amount), Some(1_427_934_399));
        assert_eq!(first.get(&txid).map(|e| e.direction.as_str()), Some("in"));
        assert_eq!(first.get(&txid).and_then(|e| e.fee), Some(24_680_000));
    }

    #[test]
    fn spend_with_change_is_outgoing_net_not_gross_or_change() {
        let incoming_tx = [2u8; 32];
        let spend_tx = [3u8; 32];
        // Spent a 0.008042 input, got 0.006998 change, paid ~0.001044 (payment+fee).
        let outputs = vec![
            out(incoming_tx, 8_042_082_635, true, Some(spend_tx), Some(20)),
            out(spend_tx, 6_997_642_635, false, None, None),
        ];
        let in_id = hex_lowercase(&incoming_tx);
        let out_id = hex_lowercase(&spend_tx);
        let known_fees = HashMap::from([(out_id.clone(), 44_440_000)]);
        let ledger = rebuild_transfer_ledger(&outputs, &[], &known_fees, 0, &HashMap::new());
        assert_eq!(ledger.get(&in_id).map(|e| e.direction.as_str()), Some("in"));
        assert_eq!(ledger.get(&in_id).map(|e| e.amount), Some(8_042_082_635));
        assert_eq!(
            ledger.get(&out_id).map(|e| e.direction.as_str()),
            Some("out")
        );
        assert_eq!(ledger.get(&out_id).map(|e| e.amount), Some(1_044_440_000));
        assert_eq!(ledger.get(&out_id).and_then(|e| e.fee), Some(44_440_000));
    }

    #[test]
    fn spend_without_txid_same_height_change_is_outgoing_not_receive() {
        let incoming_tx = [2u8; 32];
        let spend_tx = [3u8; 32];
        let outputs = vec![
            out(incoming_tx, 8_042_082_635, true, None, Some(20)),
            out(spend_tx, 6_997_642_635, false, None, None),
        ];
        // Change output is created in the spend block.
        let mut outputs = outputs;
        outputs[1].block_height = 20;
        let ledger = rebuild_transfer_ledger(&outputs, &[], &HashMap::new(), 0, &HashMap::new());
        let in_id = hex_lowercase(&incoming_tx);
        let out_id = hex_lowercase(&spend_tx);
        assert_eq!(ledger.get(&in_id).map(|e| e.direction.as_str()), Some("in"));
        assert_eq!(
            ledger.get(&out_id).map(|e| e.direction.as_str()),
            Some("out")
        );
        assert_eq!(ledger.get(&out_id).map(|e| e.amount), Some(1_044_440_000));
    }

    #[test]
    fn pending_send_converts_change_receive_into_outgoing() {
        let incoming_tx = [4u8; 32];
        let spend_tx = [5u8; 32];
        let outputs = vec![
            out(incoming_tx, 8_042_082_635, true, None, None),
            out(spend_tx, 6_997_642_635, false, None, None),
        ];
        let pending = [PendingOutgoingTx {
            txid: hex_lowercase(&spend_tx),
            amount: 1_000_000_000,
            fee: 44_440_000,
            created_at: 0,
        }];
        let out_id = hex_lowercase(&spend_tx);
        let known_fees = HashMap::from([(out_id.clone(), 44_440_000)]);
        let ledger = rebuild_transfer_ledger(&outputs, &pending, &known_fees, 0, &HashMap::new());
        assert_eq!(
            ledger.get(&out_id).map(|e| e.direction.as_str()),
            Some("out")
        );
        assert_eq!(ledger.get(&out_id).map(|e| e.amount), Some(1_044_440_000));
        assert_eq!(ledger.get(&out_id).and_then(|e| e.fee), Some(44_440_000));
        assert_eq!(ledger.get(&out_id).map(|e| e.is_pending), Some(false));
    }

    #[test]
    fn outgoing_ledger_amount_is_payment_plus_fee() {
        assert_eq!(outgoing_ledger_amount(1_000_000_000, 44_440_000), 1_044_440_000);
        assert_eq!(outgoing_ledger_amount(u64::MAX, 1), u64::MAX);
    }

    #[test]
    fn pending_outgoing_normalizes_payment_only_preinserted_ledger_row() {
        // Exact-send previously inserted payment-only ledger rows. Rebuild must coerce
        // them to payment+fee while the send is still pending.
        let spend_tx = [6u8; 32];
        let out_id = hex_lowercase(&spend_tx);
        let payment = 1_000_000_000u64;
        let fee = 44_440_000u64;
        let pending = [PendingOutgoingTx {
            txid: out_id.clone(),
            amount: payment,
            fee,
            created_at: 1_700_000_000,
        }];
        let mut ledger = rebuild_transfer_ledger(&[], &pending, &HashMap::new(), 0, &HashMap::new());
        assert_eq!(ledger.get(&out_id).map(|e| e.amount), Some(payment + fee));

        // Simulate a stale payment-only row already present (relay insert before this fix).
        ledger.insert(
            out_id.clone(),
            LedgerEntry {
                txid: out_id.clone(),
                direction: "out".to_string(),
                amount: payment,
                fee: Some(fee),
                height: None,
                timestamp: Some(1_700_000_000),
                is_pending: true,
                is_coinbase: false,
            },
        );
        // Re-run only the pending merge path by rebuilding with empty outputs again.
        let normalized = rebuild_transfer_ledger(&[], &pending, &HashMap::new(), 0, &HashMap::new());
        assert_eq!(
            normalized.get(&out_id).map(|e| e.amount),
            Some(payment + fee)
        );
        assert_eq!(normalized.get(&out_id).and_then(|e| e.fee), Some(fee));
        assert_eq!(normalized.get(&out_id).map(|e| e.is_pending), Some(true));
    }

    #[test]
    fn pruned_ringct_fee_comes_from_proof_base() {
        let tx = Transaction::<Pruned>::V2 {
            prefix: prefix(vec![public_input(None)], vec![None]),
            proofs: Some(PrunedRctProofs {
                rct_type: RctType::ClsagBulletproofPlus,
                base: RctBase {
                    fee: 31_240_000,
                    pseudo_outs: vec![],
                    encrypted_amounts: vec![],
                    commitments: vec![],
                },
            }),
        };
        assert_eq!(transaction_network_fee(&tx), Some(31_240_000));
    }

    #[test]
    fn legacy_v1_fee_is_public_inputs_minus_outputs() {
        let tx = Transaction::<Pruned>::V1 {
            prefix: prefix(
                vec![public_input(Some(9_000)), public_input(Some(3_000))],
                vec![Some(10_750), Some(1_000)],
            ),
            signatures: (),
        };
        assert_eq!(transaction_network_fee(&tx), Some(250));
    }

    #[test]
    fn coinbase_fee_is_zero() {
        let tx = Transaction::<Pruned>::V1 {
            prefix: prefix(vec![Input::Gen(100)], vec![Some(600_000_000_000)]),
            signatures: (),
        };
        assert_eq!(transaction_network_fee(&tx), Some(0));
    }

    #[test]
    fn malformed_or_incomplete_transaction_fee_is_none() {
        let missing_ringct_proofs = Transaction::<Pruned>::V2 {
            prefix: prefix(vec![public_input(None)], vec![None]),
            proofs: None,
        };
        let legacy_underflow = Transaction::<Pruned>::V1 {
            prefix: prefix(vec![public_input(Some(10))], vec![Some(11)]),
            signatures: (),
        };
        assert_eq!(transaction_network_fee(&missing_ringct_proofs), None);
        assert_eq!(transaction_network_fee(&legacy_underflow), None);
    }

    #[test]
    fn cache_round_trip_preserves_fee_during_ledger_rebuild() {
        let tx = [9u8; 32];
        let txid = hex_lowercase(&tx);
        let output = out(tx, 4_200_000_000, false, None, None);
        let ledger = rebuild_transfer_ledger(
            std::slice::from_ref(&output),
            &[],
            &HashMap::from([(txid.clone(), 28_760_000)]),
            1_700_000_000,
            &HashMap::from([(10u64, 1_700_000_000u64)]),
        );
        let persisted = PersistedWallet {
            cache_version: WALLETCORE_CACHE_VERSION,
            bound_primary_address: String::new(), // filled below after open wallet in dedicated tests
            network: PersistedNetwork::Mainnet,
            restore_height: 1,
            last_scanned: 10,
            total: output.amount,
            unlocked: output.amount,
            chain_height: 20,
            chain_time: 1_700_000_000,
            gap_limit: 50,
            tracked_outputs: vec![PersistedOutput::from(&output)],
            seen_outpoints: vec![(output.tx_hash, output.index_in_tx)],
            pending_outgoing: vec![],
            tx_ledger: ledger,
            invalid_input_quarantine: vec![],
            recent_block_hashes_start_height: 1,
            recent_block_hashes: vec![],
            block_timestamps: HashMap::from([(10u64, 1_700_000_000u64)]),
        };

        let bytes = bincode::serialize(&persisted).expect("serialize cache");
        let decoded: PersistedWallet = bincode::deserialize(&bytes).expect("deserialize cache");
        let known_fees = known_transaction_fees(&decoded.tx_ledger);
        let outputs: Vec<TrackedOutput> = decoded
            .tracked_outputs
            .into_iter()
            .map(TrackedOutput::from)
            .collect();
        let rebuilt = rebuild_transfer_ledger(
            &outputs,
            &decoded.pending_outgoing,
            &known_fees,
            decoded.chain_time,
            &decoded.block_timestamps,
        );
        assert_eq!(
            rebuilt.get(&txid).and_then(|entry| entry.fee),
            Some(28_760_000)
        );
        assert_eq!(
            rebuilt.get(&txid).and_then(|entry| entry.timestamp),
            Some(1_700_000_000)
        );
    }

    #[test]
    fn ledger_uses_per_block_timestamps_not_tip_time() {
        let tx_a = [11u8; 32];
        let tx_b = [12u8; 32];
        let mut older = out(tx_a, 1_000, false, None, None);
        older.block_height = 100;
        let mut newer = out(tx_b, 2_000, false, None, None);
        newer.block_height = 200;
        let height_times = HashMap::from([(100u64, 1_111), (200u64, 2_222)]);
        let tip = 9_999u64;
        let ledger = rebuild_transfer_ledger(
            &[older, newer],
            &[],
            &HashMap::new(),
            tip,
            &height_times,
        );
        assert_eq!(
            ledger
                .get(&hex_lowercase(&tx_a))
                .and_then(|e| e.timestamp),
            Some(1_111)
        );
        assert_eq!(
            ledger
                .get(&hex_lowercase(&tx_b))
                .and_then(|e| e.timestamp),
            Some(2_222)
        );
    }

    #[test]
    fn timelock_time_requires_nonzero_chain_time() {
        let mut output = out([13u8; 32], 5_000, false, None, None);
        output.additional_timelock = Timelock::Time(1_700_000_100);
        assert!(!output.is_unlocked(100, 0));
        assert!(!output.is_unlocked(100, 1_700_000_099));
        assert!(output.is_unlocked(100, 1_700_000_100));
        assert!(output.is_unlocked(100, 1_700_000_200));
    }

    #[test]
    fn find_reorg_rewind_height_detects_shallow_and_deep_forks() {
        let restore = 100u64;
        let start = 110u64;
        let hashes = vec![[1; 32], [2; 32], [3; 32], [4; 32]]; // heights 110..113

        // Tip matches → no rewind.
        let tip_ok = find_reorg_rewind_height(restore, start, &hashes, |h| {
            Ok::<_, ()>(hashes[(h - start) as usize])
        })
        .unwrap();
        assert_eq!(tip_ok, None);

        // Shallow fork at tip only → rewind to 113.
        let shallow = find_reorg_rewind_height(restore, start, &hashes, |h| {
            if h == 113 {
                Ok::<_, ()>([9; 32])
            } else {
                Ok(hashes[(h - start) as usize])
            }
        })
        .unwrap();
        assert_eq!(shallow, Some(113));

        // Deeper fork: mismatch from 112 upward → common at 111 → rewind to 112.
        let deep = find_reorg_rewind_height(restore, start, &hashes, |h| {
            if h >= 112 {
                Ok::<_, ()>([9; 32])
            } else {
                Ok(hashes[(h - start) as usize])
            }
        })
        .unwrap();
        assert_eq!(deep, Some(112));

        // No overlap in window → must rewind to restore_height (not window start).
        let none = find_reorg_rewind_height(restore, start, &hashes, |_h| Ok::<_, ()>([9; 32]))
            .unwrap();
        assert_eq!(none, Some(restore));
    }

    #[test]
    fn rewind_working_state_drops_fork_outputs_and_unspends() {
        let restore = 100u64;
        let keep_tx = [1u8; 32];
        let drop_tx = [2u8; 32];
        let spend_tx = [3u8; 32];

        let mut outputs = vec![
            out(keep_tx, 1_000, false, None, None),
            out(drop_tx, 2_000, false, None, None),
            {
                let mut spent = out(keep_tx, 500, true, Some(spend_tx), Some(150));
                spent.index_in_tx = 1;
                spent.block_height = 120;
                spent
            },
        ];
        outputs[0].block_height = 120;
        outputs[1].block_height = 140;

        let mut seen = HashSet::from([
            (keep_tx, 0),
            (drop_tx, 0),
            (keep_tx, 1),
        ]);
        let mut recent_start = 120u64;
        let mut recent: Vec<[u8; 32]> = (120..145).map(|h| [h as u8; 32]).collect();
        let mut times = HashMap::from([(120u64, 1), (140u64, 2), (150u64, 3)]);

        let next = rewind_working_state_to_height(
            restore,
            130,
            &mut outputs,
            &mut seen,
            &mut recent_start,
            &mut recent,
            &mut times,
        );
        assert_eq!(next, 130);
        assert_eq!(outputs.len(), 2); // drop_tx gone; keep receive + the spent one unspent
        assert!(outputs.iter().all(|o| o.block_height < 130));
        assert!(outputs.iter().any(|o| o.index_in_tx == 1 && !o.spent));
        assert!(!seen.contains(&(drop_tx, 0)));
        assert!(!times.contains_key(&140));
        assert!(!times.contains_key(&150));
        assert_eq!(recent_start, 120);
        assert_eq!(recent.len(), 10); // heights 120..129
    }

    #[test]
    fn reorg_scenario_shallow_deep_restore_and_cache_round_trip() {
        let restore = 1_000u64;
        // Window holds 1_100..1_103 (4 hashes) — deeper-than-window means no common ancestor.
        let window_start = 1_100u64;
        let hashes = vec![[1; 32], [2; 32], [3; 32], [4; 32]];

        // Shallow: tip diverges, common at 1_102 → rewind to 1_103.
        let shallow = find_reorg_rewind_height(restore, window_start, &hashes, |h| {
            if h == 1_103 {
                Ok::<_, ()>([9; 32])
            } else {
                Ok(hashes[(h - window_start) as usize])
            }
        })
        .unwrap();
        assert_eq!(shallow, Some(1_103));

        // Deep-within-window: common at 1_100 → rewind to 1_101.
        let mid = find_reorg_rewind_height(restore, window_start, &hashes, |h| {
            if h >= 1_101 {
                Ok::<_, ()>([9; 32])
            } else {
                Ok(hashes[(h - window_start) as usize])
            }
        })
        .unwrap();
        assert_eq!(mid, Some(1_101));

        // Deeper than window: no common → restore_height (not window start).
        let deep = find_reorg_rewind_height(restore, window_start, &hashes, |_| {
            Ok::<_, ()>([9; 32])
        })
        .unwrap();
        assert_eq!(deep, Some(restore));

        // Apply deep rewind: fork outputs/spends/hashes/timestamps must vanish.
        let pre_fork = [10u8; 32];
        let fork_recv = [11u8; 32];
        let fork_spend = [12u8; 32];
        let mut outputs = vec![
            {
                let mut o = out(pre_fork, 7_000, false, None, None);
                o.block_height = restore; // at restore height boundary — kept if height < rewind target
                o
            },
            {
                let mut o = out(fork_recv, 3_000, false, None, None);
                o.block_height = 1_050;
                o
            },
            {
                let mut o = out(pre_fork, 1_000, true, Some(fork_spend), Some(1_080));
                o.index_in_tx = 1;
                o.block_height = restore + 1;
                o
            },
        ];
        // First output at restore height: rewind_to restore keeps height < restore? No —
        // retain is block_height < h, so restore-height outputs are dropped when h==restore.
        // That's correct for a full rescan from restore_height.
        let mut seen = HashSet::new();
        let mut recent_start = window_start;
        let mut recent = hashes.clone();
        let mut times = HashMap::from([
            (restore, 10u64),
            (1_050, 20),
            (1_080, 30),
        ]);
        let next = rewind_working_state_to_height(
            restore,
            deep.unwrap(),
            &mut outputs,
            &mut seen,
            &mut recent_start,
            &mut recent,
            &mut times,
        );
        assert_eq!(next, restore);
        assert!(outputs.is_empty(), "all outputs at/after restore must be cleared");
        assert!(seen.is_empty());
        assert!(recent.is_empty());
        assert_eq!(recent_start, restore);
        assert!(times.is_empty());

        // Replacement-chain discovery path: after rewind, a shallow common ancestor keeps
        // pre-fork receives and unspends fork spends.
        let mut outputs = vec![
            {
                let mut o = out(pre_fork, 7_000, false, None, None);
                o.block_height = 1_090;
                o
            },
            {
                let mut o = out(fork_recv, 3_000, false, None, None);
                o.block_height = 1_102;
                o
            },
            {
                let mut o = out(pre_fork, 500, true, Some(fork_spend), Some(1_102));
                o.index_in_tx = 1;
                o.block_height = 1_090;
                o
            },
        ];
        let mut seen = HashSet::from([(pre_fork, 0), (fork_recv, 0), (pre_fork, 1)]);
        let mut recent_start = window_start;
        let mut recent = hashes.clone();
        let mut times = HashMap::from([(1_090u64, 1), (1_102u64, 2)]);
        let next = rewind_working_state_to_height(
            restore,
            mid.unwrap(),
            &mut outputs,
            &mut seen,
            &mut recent_start,
            &mut recent,
            &mut times,
        );
        assert_eq!(next, 1_101);
        assert_eq!(outputs.len(), 2);
        assert!(outputs.iter().all(|o| o.block_height < 1_101));
        assert!(outputs.iter().any(|o| o.index_in_tx == 1 && !o.spent));
        assert!(!seen.contains(&(fork_recv, 0)));
        assert!(!times.contains_key(&1_102));

        // Cache round-trip after rewind preserves the truncated window / cleared ledger inputs.
        let ledger = rebuild_transfer_ledger(
            &outputs,
            &[],
            &HashMap::new(),
            1_700_000_000,
            &times,
        );
        assert!(ledger.values().all(|e| e.height.unwrap_or(0) < 1_101));
        let persisted = PersistedWallet {
            cache_version: WALLETCORE_CACHE_VERSION,
            bound_primary_address: "test".into(),
            network: PersistedNetwork::Mainnet,
            restore_height: restore,
            last_scanned: next,
            total: outputs.iter().filter(|o| !o.spent).map(|o| o.amount).sum(),
            unlocked: 0,
            chain_height: 1_200,
            chain_time: 1_700_000_000,
            gap_limit: 50,
            tracked_outputs: outputs.iter().map(PersistedOutput::from).collect(),
            seen_outpoints: seen.iter().copied().collect(),
            pending_outgoing: vec![],
            tx_ledger: ledger,
            invalid_input_quarantine: vec![],
            recent_block_hashes_start_height: recent_start,
            recent_block_hashes: recent.clone(),
            block_timestamps: times.clone(),
        };
        let bytes = bincode::serialize(&persisted).expect("serialize");
        let decoded: PersistedWallet = bincode::deserialize(&bytes).expect("deserialize");
        assert_eq!(decoded.last_scanned, next);
        assert_eq!(decoded.tracked_outputs.len(), 2);
        assert_eq!(decoded.recent_block_hashes.len(), recent.len());
        assert!(!decoded.block_timestamps.contains_key(&1_102));
    }

    #[test]
    fn reorg_probe_failure_is_distinct_from_no_reorg() {
        // Daemon hash probe errors must surface as Err, not Ok(None).
        let err = find_reorg_rewind_height(10, 20, &[[1; 32]], |_h| {
            Err("probe failed")
        });
        assert!(err.is_err());
    }
}

#[cfg(test)]
mod vector_tests;
