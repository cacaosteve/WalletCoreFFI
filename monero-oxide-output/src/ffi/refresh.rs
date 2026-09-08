//! Refresh-related FFI surface extracted from the historical mega-`lib.rs`.
//!
//! This module is intentionally "mechanical": it mirrors the previous inlined behavior
//! as closely as possible while using `crate::support` for shared globals/helpers.
//!
//! Exposes:
//! - `wallet_refresh`
//! - `wallet_refresh_async`
//! - `wallet_refresh_job_status_json`
//! - `wallet_sync_status`

#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_return)]
#![allow(clippy::let_and_return)]
#![allow(clippy::type_complexity)]

use crate::support::*;

use core::ffi::{c_char, c_int};
use once_cell::sync::Lazy;
use rayon::prelude::*;
use std::{
    collections::{HashMap, HashSet, VecDeque},
    ffi::{CStr, CString},
    sync::Mutex,
    time::{Duration, Instant},
};

fn next_height_after_response(start_height: u64, returned_blocks: usize) -> u64 {
    start_height.saturating_add(u64::try_from(returned_blocks).unwrap_or(u64::MAX))
}

#[cfg(not(target_os = "android"))]
fn clear_stale_prefetches<Ready, Pending>(
    ready: &mut VecDeque<Ready>,
    in_flight: &mut VecDeque<tokio::task::JoinHandle<Pending>>,
) -> (usize, usize) {
    let discarded_ready = ready.len();
    ready.clear();

    let aborted_in_flight = in_flight.len();
    for handle in in_flight.drain(..) {
        handle.abort();
    }

    (discarded_ready, aborted_in_flight)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RefreshJob {
    Idle,
    Running,
    Failed(String),
}

static REFRESH_JOBS: Lazy<Mutex<HashMap<String, RefreshJob>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

fn set_refresh_job(id: &str, job: RefreshJob) {
    if let Ok(mut map) = REFRESH_JOBS.lock() {
        map.insert(id.to_string(), job);
    }
}

fn try_start_refresh_job(id: &str) -> bool {
    let Ok(mut map) = REFRESH_JOBS.lock() else {
        return false;
    };
    if matches!(map.get(id), Some(RefreshJob::Running)) {
        return false;
    }
    map.insert(id.to_string(), RefreshJob::Running);
    true
}

/// Run a state mutation only while no refresh owns this wallet. Holding the job
/// registry lock across the operation closes the check-then-start race: a new
/// scanner cannot claim the wallet until the mutation has finished.
pub(crate) fn with_refresh_stopped<T>(id: &str, operation: impl FnOnce() -> T) -> Result<T, ()> {
    let map = REFRESH_JOBS.lock().map_err(|_| ())?;
    if matches!(map.get(id), Some(RefreshJob::Running)) {
        return Err(());
    }
    Ok(operation())
}

fn finish_refresh_job(id: &str, rc: c_int) {
    if rc == 0 || rc == -30 {
        set_refresh_job(id, RefreshJob::Idle);
    } else {
        let message = last_error_clone().unwrap_or_else(|| format!("refresh stopped ({rc})"));
        set_refresh_job(id, RefreshJob::Failed(message));
    }
}

pub fn refresh_job(id: &str) -> RefreshJob {
    REFRESH_JOBS
        .lock()
        .ok()
        .and_then(|map| map.get(id).cloned())
        .unwrap_or(RefreshJob::Idle)
}

fn refresh_job_status_json(id: &str) -> String {
    let job = refresh_job(id);
    let (state, error): (&str, Option<&str>) = match &job {
        RefreshJob::Idle => ("idle", None),
        RefreshJob::Running => ("running", None),
        RefreshJob::Failed(message) => ("failed", Some(message.as_str())),
    };
    serde_json::json!({
        "state": state,
        "error": error,
    })
    .to_string()
}

#[allow(clippy::too_many_arguments)]
fn commit_refresh_checkpoint(
    id: &str,
    scan_cursor: u64,
    chain_height: u64,
    chain_time: u64,
    working_outputs: &[TrackedOutput],
    seen_outpoints: &HashSet<([u8; 32], u64)>,
    known_tx_fees: &HashMap<String, u64>,
    recent_block_hashes_start_height: u64,
    recent_block_hashes: &[[u8; 32]],
    block_timestamps: &HashMap<u64, u64>,
) -> Result<(), c_int> {
    let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
    let Some(state) = map.get_mut(id) else {
        return Err(-13);
    };

    let computed_ledger = rebuild_transfer_ledger(
        working_outputs,
        &state.pending_outgoing,
        known_tx_fees,
        chain_time,
        block_timestamps,
    );
    let mut pending_outgoing = state.pending_outgoing.clone();
    pending_outgoing.retain(|pending| match computed_ledger.get(&pending.txid) {
        Some(entry) => entry.direction == "out" && entry.is_pending,
        None => true,
    });

    let mut total = 0u64;
    let mut unlocked = 0u64;
    for output in working_outputs {
        if output.spent {
            continue;
        }
        total = total.saturating_add(output.amount);
        if output.is_unlocked(chain_height, chain_time) {
            unlocked = unlocked.saturating_add(output.amount);
        }
    }

    let normalized_cursor = scan_cursor.max(state.restore_height);
    state.last_scanned = if chain_height > 0 {
        normalized_cursor.min(chain_height)
    } else {
        normalized_cursor
    };
    state.total = total;
    state.unlocked = unlocked;
    state.chain_height = chain_height;
    state.chain_time = chain_time;
    if chain_time > 0 {
        state.last_refresh_timestamp = chain_time;
    }
    state.tracked_outputs = working_outputs.to_vec();
    state.seen_outpoints = seen_outpoints.clone();
    state.tx_ledger = computed_ledger;
    state.pending_outgoing = pending_outgoing;
    state.recent_block_hashes_start_height = recent_block_hashes_start_height;
    state.recent_block_hashes = recent_block_hashes.to_vec();
    state.block_timestamps = block_timestamps.clone();
    Ok(())
}

fn is_channel_closed_error(err: &str) -> bool {
    let m = err.to_ascii_lowercase();
    m.contains("channelclosed") || m.contains("channel closed")
}

fn is_transient_block_fetch_error(err: &str) -> bool {
    let m = err.to_ascii_lowercase();
    is_channel_closed_error(err)
        || m.contains("connection error")
        || m.contains("internal error")
        || m.contains("timeout")
        || m.contains("timed out")
        || m.contains("reset")
        || m.contains("broken pipe")
        || m.contains("temporarily")
        || m.contains("try again")
}

fn connect_rpc_client(base_url: &str) -> Result<RpcClient, String> {
    TOKIO_RUNTIME
        .block_on(monero_simple_request_rpc::SimpleRequestTransport::new(
            base_url.to_string(),
        ))
        .map_err(|e| e.to_string())
}

/// Prefetch abort / node bounce can leave Hyper with a dead connection (ChannelClosed in 0ms).
/// Android rebuilds the worker client; desktop must too or the next sync fetch aborts.
fn rebuild_rpc_client_if_channel_closed(base_url: &str, err: &str) -> Option<RpcClient> {
    if !is_channel_closed_error(err) {
        return None;
    }
    wc_log_line_android_or_stdout(
        "🧭 wallet_refresh stage=rpc_client_rebuild reason=ChannelClosed",
    );
    match connect_rpc_client(base_url) {
        Ok(c) => Some(c),
        Err(e) => {
            wc_log_line_android_or_stdout(&format!(
                "🧭 wallet_refresh stage=rpc_client_rebuild_error err={}",
                e
            ));
            None
        }
    }
}

/// Cuprate public RPC (`rpc.nexatrode.com`) rejects JSON-RPC *batches* with HTTP 422.
/// Binary `/getblocks.bin` can also come back as a JSON error body. Retrying the same
/// 25-block call does not help; one `get_block` at a time does.
fn is_json_batch_or_shape_error(err: &str) -> bool {
    let m = err.to_ascii_lowercase();
    m.contains("response wasn't the expected json")
        || m.contains("wasn't the expected json")
        || m.contains("unprocessable")
        || m.contains("422")
}

fn fetch_scannable_blocks_one_by_one(
    rpc_client: &RpcClient,
    start_bn: usize,
    end_bn_inclusive: usize,
) -> Result<Vec<ScannableBlock>, RpcError> {
    wc_log_line_android_or_stdout(&format!(
        "🧭 wallet_refresh stage=fetch_one_by_one start={} end={}",
        start_bn, end_bn_inclusive
    ));
    let mut out = Vec::with_capacity(end_bn_inclusive.saturating_sub(start_bn).saturating_add(1));
    for height in start_bn..=end_bn_inclusive {
        let batch =
            TOKIO_RUNTIME.block_on(rpc_client.contiguous_scannable_blocks(height..=height))?;
        out.extend(batch);
    }
    Ok(out)
}

/// Cuprate rejects JSON-RPC batches (HTTP 422). Retrying the same 25-block call cannot
/// succeed. Try range `get_blocks.bin` first (cheap, one RPC), then one `get_block` at a time.
fn try_json_batch_error_fallback(
    rpc_client: &RpcClient,
    base_url: &str,
    start_bn: usize,
    end_bn_inclusive: usize,
    bulk_fetch_mode: BulkFetchMode,
    err_s: &str,
    decode_pool: Option<&rayon::ThreadPool>,
) -> Option<(Vec<ScannableBlock>, bool)> {
    if !is_json_batch_or_shape_error(err_s) {
        return None;
    }

    if !matches!(bulk_fetch_mode, BulkFetchMode::RangeBlocks) {
        wc_log_line_android_or_stdout(&format!(
            "🧭 wallet_refresh stage=fetch_range_bin_fallback start={} end={}",
            start_bn, end_bn_inclusive
        ));
        match fetch_scannable_blocks_range_bin(
            rpc_client,
            base_url,
            start_bn,
            end_bn_inclusive,
            decode_pool,
        ) {
            Ok(blocks) if !blocks.is_empty() => {
                wc_log_line_android_or_stdout(&format!(
                    "🧭 wallet_refresh stage=fetch_range_bin_fallback_ok blocks={}",
                    blocks.len()
                ));
                return Some((blocks, true));
            }
            Ok(_) => {
                wc_log_line_android_or_stdout(
                    "🧭 wallet_refresh stage=fetch_range_bin_fallback empty; trying one-by-one",
                );
            }
            Err(range_err) => {
                wc_log_line_android_or_stdout(&format!(
                    "🧭 wallet_refresh stage=fetch_range_bin_fallback_error err={}; trying one-by-one",
                    range_err
                ));
            }
        }
    }

    match fetch_scannable_blocks_one_by_one(rpc_client, start_bn, end_bn_inclusive) {
        Ok(blocks) if !blocks.is_empty() => {
            wc_log_line_android_or_stdout(&format!(
                "🧭 wallet_refresh stage=fetch_one_by_one_ok blocks={}",
                blocks.len()
            ));
            Some((blocks, false))
        }
        Ok(_) => {
            wc_log_line_android_or_stdout("🧭 wallet_refresh stage=fetch_one_by_one empty");
            None
        }
        Err(one_err) => {
            wc_log_line_android_or_stdout(&format!(
                "🧭 wallet_refresh stage=fetch_one_by_one_error err={}",
                one_err
            ));
            None
        }
    }
}

const BLOCK_FETCH_RETRY_LIMIT: u32 = 5;
/// Parent-hash / reorg-probe failures before aborting refresh with a recoverable error.
const REORG_PROBE_RETRY_LIMIT: u32 = 3;

/// Resume-time daemon tip probe runs only when cached recent hashes exist.
/// Continuous batch continuity uses returned block parent links — never a per-batch tip RPC.
pub(crate) fn should_probe_reorg_on_resume(recent_hashes_len: usize) -> bool {
    recent_hashes_len > 0
}

/// Intentionally false: the range-refresh loop must not call `on_get_block_hash` every batch.
pub(crate) const PER_BATCH_TIP_PROBE_ENABLED: bool = false;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ResumeReorgAction {
    /// Local tip matches daemon (or empty window) — keep scanning from `scan_cursor`.
    KeepCursor,
    /// Rewind working state so the next scanned height is `scan_from`.
    Rewind { scan_from: u64 },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParentMismatchAction {
    /// Parent hash matches local tip — process this batch.
    Continue,
    /// Fork proven — cancel prefetch, rewind, continue from replacement chain.
    Rewind {
        scan_from: u64,
        cancel_prefetch: bool,
    },
    /// Probe inconclusive — cancel prefetch, bound-retry with backoff.
    Retry {
        failures: u32,
        cancel_prefetch: bool,
    },
    /// Retry budget exhausted — abort refresh with a recoverable error.
    Abort {
        failures: u32,
        cancel_prefetch: bool,
    },
}

/// Decision for the one-time resume tip probe (`Ok(None)` = no reorg).
pub(crate) fn decide_resume_reorg_action(
    scan_cursor: u64,
    probe: Result<Option<u64>, String>,
) -> Result<ResumeReorgAction, String> {
    match probe {
        Ok(Some(rewind_to)) if rewind_to < scan_cursor => {
            Ok(ResumeReorgAction::Rewind {
                scan_from: rewind_to,
            })
        }
        Ok(_) => Ok(ResumeReorgAction::KeepCursor),
        Err(message) => Err(message),
    }
}

/// Decision for a first-block parent-hash mismatch against the local recent-hash tip.
pub(crate) fn decide_parent_mismatch_action(
    expected_prev: Option<[u8; 32]>,
    actual_prev: [u8; 32],
    probe: Result<Option<u64>, ()>,
    prior_failures: u32,
    limit: u32,
) -> ParentMismatchAction {
    let Some(expected) = expected_prev else {
        return ParentMismatchAction::Continue;
    };
    if actual_prev == expected {
        return ParentMismatchAction::Continue;
    }
    match probe {
        Ok(Some(scan_from)) => ParentMismatchAction::Rewind {
            scan_from,
            cancel_prefetch: true,
        },
        Ok(None) | Err(()) => {
            let failures = prior_failures.saturating_add(1);
            if failures > limit {
                ParentMismatchAction::Abort {
                    failures,
                    cancel_prefetch: true,
                }
            } else {
                ParentMismatchAction::Retry {
                    failures,
                    cancel_prefetch: true,
                }
            }
        }
    }
}

fn block_fetch_retry_delay(attempt: u32) -> Duration {
    Duration::from_millis(250u64.saturating_mul(1u64 << attempt.min(3)))
}

fn maybe_retry_block_fetch(id: &str, err: &str, fetch_retries: &mut u32) -> bool {
    if is_transient_block_fetch_error(err) && *fetch_retries < BLOCK_FETCH_RETRY_LIMIT {
        *fetch_retries += 1;
        append_walletcore_rpc_telemetry(
            "retry",
            "contiguous_scannable_blocks",
            0,
            None,
            0,
            None,
            Some(err),
        );
        wc_log_line_android_or_stdout(&format!(
            "🧭 wallet_refresh stage=contiguous_scannable_blocks_retry wallet_id={} attempt={} err={}",
            id, fetch_retries, err
        ));
        std::thread::sleep(block_fetch_retry_delay((*fetch_retries).saturating_sub(1)));
        true
    } else {
        false
    }
}

#[cfg(target_os = "android")]
mod android_log {
    use std::ffi::CString;

    // Android log priorities from <android/log.h>
    const ANDROID_LOG_INFO: i32 = 4;

    extern "C" {
        fn __android_log_write(prio: i32, tag: *const i8, text: *const i8) -> i32;
    }

    pub fn info(msg: &str) {
        // Best-effort: if CString conversion fails (interior NUL), replace with a safe placeholder.
        let tag =
            CString::new("walletcore").unwrap_or_else(|_| CString::new("walletcore").unwrap());
        let text = CString::new(msg)
            .unwrap_or_else(|_| CString::new("<walletcore log: interior NUL>").unwrap());
        unsafe {
            let _ = __android_log_write(
                ANDROID_LOG_INFO,
                tag.as_ptr() as *const i8,
                text.as_ptr() as *const i8,
            );
        }
    }
}

fn wc_log_line_android_or_stdout(msg: &str) {
    if !crate::diagnostics_enabled() { return; }
    #[cfg(target_os = "android")]
    {
        android_log::info(msg);
        return;
    }
    #[cfg(not(target_os = "android"))]
    {
        walletcore_diagnostic!("{msg}");
    }
}

#[cfg(target_os = "android")]
fn wc_android_force_env_default(key: &str, value: &str) {
    // Best-effort: only set if currently unset/empty.
    // SAFETY: setenv expects NUL-terminated strings; CString enforces that.
    if std::env::var(key)
        .ok()
        .is_some_and(|v| !v.trim().is_empty())
    {
        return;
    }

    let k = std::ffi::CString::new(key)
        .unwrap_or_else(|_| std::ffi::CString::new("<bad-key>").unwrap());
    let v = std::ffi::CString::new(value)
        .unwrap_or_else(|_| std::ffi::CString::new("<bad-value>").unwrap());

    unsafe {
        // int setenv(const char *name, const char *value, int overwrite);
        extern "C" {
            fn setenv(name: *const i8, value: *const i8, overwrite: i32) -> i32;
        }
        let _ = setenv(k.as_ptr() as *const i8, v.as_ptr() as *const i8, 0);
    }
}

// External types used by refresh.
use crate::BlockingRpcTransport;
use monero_interface::{PrunedTransactionWithPrunableHash, ScannableBlock};
use monero_wallet::{
    block::Block as MoneroBlock,
    transaction::{NotPruned, Pruned, Transaction},
    ScanError, Scanner, WalletOutput,
};

// scanner micro-profiler is feature-gated by monero-wallet.
#[cfg(feature = "scanner-microprof")]
use monero_wallet::scanner_microprof_snapshot;

// Bring crate-local alias into scope for prefetch JoinHandle result typing.
use crate::BulkFetchMode;
use crate::RpcError;

// Hard timeout to prevent indefinite hangs when fetching scannable blocks.
// This is intentionally enforced at the walletcore layer so we can always surface a diagnostic.
const CONTIGUOUS_BLOCKS_TIMEOUT_SECS: u64 = 30;

const DESKTOP_SCAN_THREADS_CAP: usize = 8;
const MOBILE_SCAN_THREADS_CAP: usize = 4;
const MAX_UPSTREAM_BLOCK_BATCH: u64 = 1_000;

fn automatic_scan_parallelism(available: usize) -> usize {
    let available = available.max(1);
    let cap = if cfg!(any(target_os = "android", target_os = "ios")) {
        MOBILE_SCAN_THREADS_CAP
    } else {
        DESKTOP_SCAN_THREADS_CAP
    };
    available.min(cap).max(1)
}

fn configured_scan_parallelism(available: usize, configured: Option<&str>) -> usize {
    let automatic = automatic_scan_parallelism(available);
    let Some(configured) = configured.map(str::trim).filter(|value| !value.is_empty()) else {
        return automatic;
    };
    if configured.eq_ignore_ascii_case("auto") {
        return automatic;
    }
    match configured.parse::<usize>() {
        // Zero explicitly disables the parallel scanner. One is the serial baseline.
        Ok(0 | 1) => 1,
        Ok(requested) => requested.min(available.max(1)).max(1),
        Err(_) => automatic,
    }
}

fn configured_upstream_block_batch(configured: Option<&str>) -> u64 {
    configured
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or_else(|| crate::default_range_block_batch() as u64)
        .clamp(1, MAX_UPSTREAM_BLOCK_BATCH)
}

fn scan_parallelism_from_env() -> usize {
    let available = std::thread::available_parallelism()
        .map(std::num::NonZeroUsize::get)
        .unwrap_or(1);
    configured_scan_parallelism(
        available,
        std::env::var("WALLETCORE_SCAN_PAR").ok().as_deref(),
    )
}

const fn default_range_decode_parallel_enabled() -> bool {
    !cfg!(any(
        target_os = "android",
        target_os = "ios",
        target_os = "tvos",
        target_os = "watchos"
    ))
}

fn configured_range_decode_parallel(configured: Option<&str>, default: bool) -> bool {
    configured
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(|value| {
            value != "0"
                && !value.eq_ignore_ascii_case("false")
                && !value.eq_ignore_ascii_case("off")
        })
        .unwrap_or(default)
}

fn range_decode_parallel_enabled() -> bool {
    configured_range_decode_parallel(
        std::env::var("WALLETCORE_RANGE_DECODE_PAR").ok().as_deref(),
        default_range_decode_parallel_enabled(),
    )
}

/// Perform only monero-oxide's read-only ownership scan in parallel. Results are flattened in
/// input order so the caller can apply outputs, spends, fees, and checkpoints sequentially.
fn scan_blocks_parallel_ordered(
    pool: &rayon::ThreadPool,
    scanner: &Scanner,
    scannables: &[ScannableBlock],
) -> VecDeque<Result<Vec<WalletOutput>, ScanError>> {
    if scannables.is_empty() {
        return VecDeque::new();
    }

    let worker_count = pool.current_num_threads().min(scannables.len()).max(1);
    let chunk_size = scannables.len().div_ceil(worker_count);
    pool.install(|| {
        scannables
            .par_chunks(chunk_size)
            .map(|chunk| {
                let mut scanner = scanner.clone();
                chunk
                    .iter()
                    .map(|block| {
                        scanner
                            .scan(block.clone())
                            .map(|outputs| outputs.ignore_additional_timelock())
                    })
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>()
    })
    .into_iter()
    .flatten()
    .collect()
}

#[derive(serde::Deserialize)]
struct GetTransactionsOutputIndicesResponse {
    txs: Vec<GetTransactionsOutputIndicesEntry>,
}

#[derive(serde::Deserialize)]
struct GetTransactionsOutputIndicesEntry {
    tx_hash: String,
    output_indices: Vec<u64>,
}

fn fetch_output_indexes_via_get_transactions(
    base_url: &str,
    tx_hash: [u8; 32],
) -> Result<Vec<u64>, RpcError> {
    let tx_hash_hex: String = tx_hash.iter().map(|b| format!("{b:02x}")).collect();
    let body = serde_json::json!({
        "txs_hashes": [tx_hash_hex],
        "decode_as_json": false,
        "prune": false,
        "split": false,
    })
    .to_string();

    // Share the bounded reader, timeout and configured proxy with the main scan transport.
    let bytes = BlockingRpcTransport::new(base_url)
        .map_err(|_| RpcError::InvalidInterface("invalid fallback node URL".to_string()))?
        .post_bytes("get_transactions", body.into_bytes())?;

    let parsed: GetTransactionsOutputIndicesResponse =
        serde_json::from_slice(&bytes).map_err(|e| {
            RpcError::InvalidInterface(format!("get_transactions fallback json decode failed: {e}"))
        })?;

    parsed
        .txs
        .into_iter()
        .find(|tx| tx.tx_hash.eq_ignore_ascii_case(&tx_hash_hex))
        .map(|tx| tx.output_indices)
        .ok_or_else(|| {
            RpcError::InvalidInterface(
                "get_transactions fallback did not return requested tx output indices".to_string(),
            )
        })
}

fn get_output_indexes_from_block_response(
    block_idx: usize,
    miner_tx: &Transaction<Pruned>,
    transactions: &[Transaction<Pruned>],
    block_output_indices: Option<&crate::support::bulk_models::BlockOutputIndices>,
) -> Result<Option<Vec<u64>>, RpcError> {
    let Some(block_output_indices) = block_output_indices else {
        return Ok(None);
    };

    let txs_with_miner = 1usize.saturating_add(transactions.len());
    let tx_entries = &block_output_indices.indices;

    let pair_mode = if tx_entries.len() == txs_with_miner {
        Some(true)
    } else if tx_entries.len() == transactions.len() {
        Some(false)
    } else {
        None
    };

    let Some(include_miner) = pair_mode else {
        return Err(RpcError::InvalidInterface(format!(
            "range get_blocks.bin block[{block_idx}] output_indices had {} tx entries, expected {} (with miner) or {} (without miner)",
            tx_entries.len(),
            txs_with_miner,
            transactions.len()
        )));
    };

    if include_miner {
        for (tx, tx_output_indices) in std::iter::once(miner_tx)
            .chain(transactions.iter())
            .zip(tx_entries.iter())
        {
            if matches!(tx, Transaction::V1 { .. }) || tx.prefix().outputs.is_empty() {
                continue;
            }

            if tx_output_indices.indices.len() != tx.prefix().outputs.len() {
                return Err(RpcError::InvalidInterface(format!(
                    "range get_blocks.bin block[{block_idx}] output_indices count {} did not match tx outputs {}",
                    tx_output_indices.indices.len(),
                    tx.prefix().outputs.len()
                )));
            }

            return Ok(Some(tx_output_indices.indices.clone()));
        }
    } else {
        for (tx, tx_output_indices) in transactions.iter().zip(tx_entries.iter()) {
            if matches!(tx, Transaction::V1 { .. }) || tx.prefix().outputs.is_empty() {
                continue;
            }

            if tx_output_indices.indices.len() != tx.prefix().outputs.len() {
                return Err(RpcError::InvalidInterface(format!(
                    "range get_blocks.bin block[{block_idx}] output_indices count {} did not match tx outputs {}",
                    tx_output_indices.indices.len(),
                    tx.prefix().outputs.len()
                )));
            }

            return Ok(Some(tx_output_indices.indices.clone()));
        }
    }

    Ok(None)
}

#[derive(Debug)]
enum RangeFetchError {
    Rpc(RpcError),
    RetryUnpruned(RpcError),
}

impl From<RpcError> for RangeFetchError {
    fn from(error: RpcError) -> Self {
        Self::Rpc(error)
    }
}

fn decode_range_transaction(
    blob: &[u8],
    prunable_hash: Option<[u8; 32]>,
    expected_hash: [u8; 32],
    block_idx: usize,
    tx_idx: usize,
) -> Result<Transaction<Pruned>, RangeFetchError> {
    let mut pruned_reader = blob;
    let pruned_decode_detail = match Transaction::<Pruned>::read(&mut pruned_reader) {
        Ok(tx_pruned) if pruned_reader.is_empty() => {
            let usable_prunable_hash = match &tx_pruned {
                Transaction::V1 { .. } => None,
                Transaction::V2 { proofs, .. } => {
                    if proofs.is_some() && prunable_hash == Some([0; 32]) {
                        return Err(RangeFetchError::RetryUnpruned(
                            RpcError::InvalidInterface(format!(
                                "range get_blocks.bin block[{block_idx}] tx[{tx_idx}] pruned response had an uninitialized prunable_hash"
                            )),
                        ));
                    }
                    prunable_hash
                }
            };

            let Some(tx_with_hash) =
                PrunedTransactionWithPrunableHash::new(tx_pruned, usable_prunable_hash)
            else {
                return Err(RangeFetchError::RetryUnpruned(
                    RpcError::InvalidInterface(format!(
                        "range get_blocks.bin block[{block_idx}] tx[{tx_idx}] pruned response was missing a usable prunable_hash"
                    )),
                ));
            };

            return tx_with_hash.verify_as_possible(expected_hash).map_err(|_| {
                RangeFetchError::Rpc(RpcError::InvalidInterface(format!(
                    "range get_blocks.bin block[{block_idx}] tx[{tx_idx}] pruned transaction hash mismatch"
                )))
            });
        }
        Ok(_) => format!("pruned decode left {} trailing bytes", pruned_reader.len()),
        Err(error) => format!("pruned decode failed: {error}"),
    };

    // A daemon is allowed to ignore the requested pruning mode. Preserve compatibility by
    // accepting and validating a complete transaction blob when one is returned.
    let mut full_reader = blob;
    let tx_full = Transaction::<NotPruned>::read(&mut full_reader).map_err(|error| {
        RangeFetchError::Rpc(RpcError::InvalidInterface(format!(
            "range get_blocks.bin block[{block_idx}] tx[{tx_idx}] decode failed ({pruned_decode_detail}; full decode failed: {error})"
        )))
    })?;
    if !full_reader.is_empty() {
        return Err(RangeFetchError::Rpc(RpcError::InvalidInterface(format!(
            "range get_blocks.bin block[{block_idx}] tx[{tx_idx}] full transaction had {} trailing bytes",
            full_reader.len()
        ))));
    }

    if tx_full.hash() != expected_hash {
        return Err(RangeFetchError::Rpc(RpcError::InvalidInterface(format!(
            "range get_blocks.bin block[{block_idx}] tx[{tx_idx}] full transaction hash mismatch"
        ))));
    }

    if let (Some(expected_prunable_hash), Some(actual_prunable_hash)) =
        (prunable_hash, tx_full.prunable_hash())
    {
        if actual_prunable_hash != expected_prunable_hash {
            return Err(RangeFetchError::Rpc(RpcError::InvalidInterface(format!(
                "range get_blocks.bin block[{block_idx}] tx[{tx_idx}] prunable_hash mismatch"
            ))));
        }
    }

    Ok(Transaction::from(tx_full))
}

struct DecodedRangeBlock {
    block: MoneroBlock,
    transactions: Vec<Transaction<Pruned>>,
}

/// Decode one block entry without touching shared wallet state or making fallback RPC calls.
/// Keeping this phase pure allows a response's blocks to be decoded concurrently while the
/// indexed parallel iterator preserves daemon order for the sequential finalization phase.
fn decode_range_block_entry(
    block_idx: usize,
    entry: crate::support::bulk_models::BlockCompleteEntry,
) -> Result<DecodedRangeBlock, RangeFetchError> {
    let mut block_reader: &[u8] = entry.block.as_slice();
    let block = MoneroBlock::read(&mut block_reader).map_err(|error| {
        RpcError::InvalidInterface(format!(
            "range get_blocks.bin block[{block_idx}] decode failed: {error}"
        ))
    })?;
    if !block_reader.is_empty() {
        return Err(RpcError::InvalidInterface(format!(
            "range get_blocks.bin block[{block_idx}] had {} trailing bytes",
            block_reader.len()
        ))
        .into());
    }

    if block.transactions.len() != entry.txs.len() {
        return Err(RpcError::InvalidInterface(format!(
            "range get_blocks.bin block[{block_idx}] had {} tx hashes but {} tx blobs",
            block.transactions.len(),
            entry.txs.len()
        ))
        .into());
    }

    let mut transactions = Vec::with_capacity(entry.txs.len());
    for (tx_idx, (expected_hash, tx_entry)) in block
        .transactions
        .iter()
        .zip(entry.txs.into_iter())
        .enumerate()
    {
        transactions.push(decode_range_transaction(
            &tx_entry.blob,
            tx_entry.prunable_hash,
            *expected_hash,
            block_idx,
            tx_idx,
        )?);
    }

    Ok(DecodedRangeBlock {
        block,
        transactions,
    })
}

fn fetch_scannable_blocks_range_bin_with_prune(
    rpc_client: &RpcClient,
    base_url: &str,
    start_bn: usize,
    end_bn_inclusive: usize,
    prune: bool,
    decode_pool: Option<&rayon::ThreadPool>,
) -> Result<Vec<ScannableBlock>, RangeFetchError> {
    let requested_blocks = end_bn_inclusive
        .checked_sub(start_bn)
        .and_then(|n| n.checked_add(1))
        .ok_or_else(|| RpcError::InternalError("range fetch block count overflow".to_string()))?;

    let start_height = u64::try_from(start_bn)
        .map_err(|_| RpcError::InternalError("range fetch start height overflow".to_string()))?;
    let count = u64::try_from(requested_blocks)
        .map_err(|_| RpcError::InternalError("range fetch count overflow".to_string()))?;

    let transport = BlockingRpcTransport::new(base_url).map_err(|code| {
        RpcError::InternalError(format!(
            "range fetch transport init failed for '{base_url}' (code={code})"
        ))
    })?;

    let resp = transport.get_blocks_bin(start_height, count, prune)?;

    wc_log_line_android_or_stdout(&format!(
        "🧭 range_get_blocks_bin rpc_ok start_height={} count={} prune={} returned_blocks={}",
        start_height,
        count,
        prune,
        resp.blocks.len()
    ));

    if let Some(status) = resp.status.as_deref() {
        if !status.eq_ignore_ascii_case("OK") {
            return Err(RpcError::InvalidInterface(format!(
                "range get_blocks.bin returned status={status}"
            ))
            .into());
        }
    }

    if resp.blocks.is_empty() {
        return Err(RpcError::InvalidInterface(format!(
            "range get_blocks.bin returned 0 blocks, expected up to {} for heights {}..={}",
            requested_blocks, start_bn, end_bn_inclusive
        ))
        .into());
    }
    if resp.blocks.len() > requested_blocks {
        return Err(RpcError::InvalidInterface(format!(
            "range get_blocks.bin returned {} blocks, requested {} for heights {}..={}",
            resp.blocks.len(),
            requested_blocks,
            start_bn,
            end_bn_inclusive
        ))
        .into());
    }
    if resp.blocks.len() < requested_blocks {
        let actual_end = start_bn.saturating_add(resp.blocks.len()).saturating_sub(1);
        wc_log_line_android_or_stdout(&format!(
            "🧭 range_get_blocks_bin partial start_height={} requested={} returned_blocks={} actual_range={}..={}",
            start_height,
            requested_blocks,
            resp.blocks.len(),
            start_bn,
            actual_end
        ));
    }

    let output_indices_by_block = resp.output_indices.unwrap_or_default();
    let decode_started = Instant::now();
    let decode_threads = decode_pool
        .map(rayon::ThreadPool::current_num_threads)
        .unwrap_or(1);
    let decode_mode = if decode_pool.is_some() {
        "parallel-shared"
    } else {
        "serial"
    };
    let decoded_results: Vec<Result<DecodedRangeBlock, RangeFetchError>> =
        if let Some(pool) = decode_pool {
            pool.install(|| {
                resp.blocks
                    .into_par_iter()
                    .enumerate()
                    .map(|(block_idx, entry)| decode_range_block_entry(block_idx, entry))
                    .collect()
            })
        } else {
            resp.blocks
                .into_iter()
                .enumerate()
                .map(|(block_idx, entry)| decode_range_block_entry(block_idx, entry))
                .collect()
        };
    let mut decoded_blocks = Vec::with_capacity(decoded_results.len());
    for result in decoded_results {
        decoded_blocks.push(result?);
    }
    let decode_ms = decode_started.elapsed().as_millis();
    let transaction_count = decoded_blocks
        .iter()
        .map(|decoded| decoded.transactions.len())
        .sum::<usize>();
    let finalize_started = Instant::now();
    let mut out = Vec::with_capacity(decoded_blocks.len());

    for (block_idx, decoded) in decoded_blocks.into_iter().enumerate() {
        let DecodedRangeBlock {
            block,
            transactions,
        } = decoded;

        if block_idx == 0 {
            wc_log_line_android_or_stdout(&format!(
                "🧭 range_get_blocks_bin decoded block_idx=0 tx_hashes={} txs={}",
                block.transactions.len(),
                transactions.len()
            ));
        }

        let mut output_index_for_first_ringct_output = None;

        let miner_tx_hash = block.miner_transaction().hash();
        let miner_tx = Transaction::from(block.miner_transaction().clone());

        if let Some(output_indexes) = get_output_indexes_from_block_response(
            block_idx,
            &miner_tx,
            &transactions,
            output_indices_by_block.get(block_idx),
        )? {
            output_index_for_first_ringct_output = output_indexes.first().copied();
            let log_scan_details = std::env::var("WALLETCORE_SCAN_LOG")
                .ok()
                .map(|s| s != "0")
                .unwrap_or(false);
            if log_scan_details {
                wc_log_line_android_or_stdout(&format!(
                    "🧭 range_get_blocks_bin output_indices_inline block_idx={} count={} first={:?}",
                    block_idx,
                    output_indexes.len(),
                    output_index_for_first_ringct_output
                ));
            }
        }

        if output_index_for_first_ringct_output.is_none() {
            for (tx_hash, tx) in std::iter::once((miner_tx_hash, &miner_tx))
                .chain(block.transactions.iter().copied().zip(transactions.iter()))
            {
                if matches!(tx, Transaction::V1 { .. }) || tx.prefix().outputs.is_empty() {
                    continue;
                }

                wc_log_line_android_or_stdout(&format!(
                    "🧭 range_get_blocks_bin output_indexes_start block_idx={} outputs={} tx_hash_prefix={:02x}{:02x}{:02x}{:02x}",
                    block_idx,
                    tx.prefix().outputs.len(),
                    tx_hash[0],
                    tx_hash[1],
                    tx_hash[2],
                    tx_hash[3]
                ));

                let output_indexes = match TOKIO_RUNTIME.block_on(
                    monero_interface::ProvidesOutputs::output_indexes(rpc_client, tx_hash),
                ) {
                    Ok(v) => v,
                    Err(primary_err) => {
                        wc_log_line_android_or_stdout(&format!(
                            "🧭 range_get_blocks_bin output_indexes_fallback block_idx={} reason={}",
                            block_idx, primary_err
                        ));
                        fetch_output_indexes_via_get_transactions(base_url, tx_hash).map_err(
                            |fallback_err| {
                                RpcError::InvalidInterface(format!(
                                    "range get_blocks.bin block[{block_idx}] output_indexes failed: primary={primary_err}; fallback={fallback_err}"
                                ))
                            },
                        )?
                    }
                };

                if output_indexes.len() != tx.prefix().outputs.len() {
                    return Err(RpcError::InvalidInterface(format!(
                        "range get_blocks.bin returned {} output indexes for {} outputs",
                        output_indexes.len(),
                        tx.prefix().outputs.len()
                    ))
                    .into());
                }

                output_index_for_first_ringct_output = output_indexes.first().copied();
                wc_log_line_android_or_stdout(&format!(
                    "🧭 range_get_blocks_bin output_indexes_ok block_idx={} count={} first={:?}",
                    block_idx,
                    output_indexes.len(),
                    output_index_for_first_ringct_output
                ));
                break;
            }
        }

        out.push(ScannableBlock {
            block,
            transactions,
            output_index_for_first_ringct_output,
        });
    }

    let finalize_ms = finalize_started.elapsed().as_millis();
    append_walletcore_range_decode_telemetry(
        decode_mode,
        decode_threads,
        out.len(),
        transaction_count,
        decode_ms,
        finalize_ms,
    );
    wc_log_line_android_or_stdout(&format!(
        "⏱️ range_get_blocks_bin stage=decode_timing mode={} threads={} blocks={} txs={} decode_ms={} finalize_ms={} total_ms={}",
        decode_mode,
        decode_threads,
        out.len(),
        transaction_count,
        decode_ms,
        finalize_ms,
        decode_ms.saturating_add(finalize_ms)
    ));

    Ok(out)
}

fn fetch_scannable_blocks_range_bin(
    rpc_client: &RpcClient,
    base_url: &str,
    start_bn: usize,
    end_bn_inclusive: usize,
    decode_pool: Option<&rayon::ThreadPool>,
) -> Result<Vec<ScannableBlock>, RpcError> {
    match fetch_scannable_blocks_range_bin_with_prune(
        rpc_client,
        base_url,
        start_bn,
        end_bn_inclusive,
        true,
        decode_pool,
    ) {
        Ok(blocks) => Ok(blocks),
        Err(RangeFetchError::RetryUnpruned(pruned_error)) => {
            wc_log_line_android_or_stdout(&format!(
                "🧭 range_get_blocks_bin retry_unpruned start_height={} end_height={} reason={}",
                start_bn, end_bn_inclusive, pruned_error
            ));
            match fetch_scannable_blocks_range_bin_with_prune(
                rpc_client,
                base_url,
                start_bn,
                end_bn_inclusive,
                false,
                decode_pool,
            ) {
                Ok(blocks) => Ok(blocks),
                Err(RangeFetchError::Rpc(error) | RangeFetchError::RetryUnpruned(error)) => {
                    Err(error)
                }
            }
        }
        Err(RangeFetchError::Rpc(error)) => Err(error),
    }
}

// ===== Android-only: dedicated contiguous block fetch worker (no per-batch thread spawning) =====
//
// Motivation:
// - Our previous timeout helper spawned a new OS thread per batch; Android can degrade/stall under
//   sustained thread churn.
// - Tokio timeouts are not available here (no timer driver/reactor), so we implement bounded waiting
//   via std::sync::mpsc + recv_timeout.
// - The worker executes requests sequentially on a single long-lived OS thread.
// - IMPORTANT: build and own the RPC client *inside* the worker thread. Sharing a transport/client
//   across OS threads can lead to Hyper ChannelClosed on Android.
// - Also: Hyper can still surface ChannelClosed sporadically; on Android we rebuild the client and
//   retry once when we detect ChannelClosed.
#[cfg(target_os = "android")]
struct AndroidContiguousFetchWorker {
    tx: std::sync::mpsc::Sender<AndroidFetchReq>,
    thread: Option<std::thread::JoinHandle<()>>,
}

#[cfg(target_os = "android")]
struct AndroidFetchReq {
    start_bn: usize,
    end_bn_inclusive: usize,
    resp_tx: std::sync::mpsc::Sender<Result<Vec<ScannableBlock>, RpcError>>,
}

#[cfg(target_os = "android")]
struct AndroidPendingFetch {
    resp_rx: std::sync::mpsc::Receiver<Result<Vec<ScannableBlock>, RpcError>>,
    /// When the request was queued on the worker (for RPC wall time vs main-thread wait).
    started_at: Instant,
}

#[cfg(target_os = "android")]
impl AndroidContiguousFetchWorker {
    fn start(base_url: String, bulk_fetch_mode: BulkFetchMode) -> Self {
        use std::sync::mpsc;

        let (tx, rx) = mpsc::channel::<AndroidFetchReq>();

        let thread = std::thread::spawn(move || {
            fn build_client(base_url: &str) -> Result<RpcClient, RpcError> {
                TOKIO_RUNTIME.block_on(async {
                    monero_simple_request_rpc::SimpleRequestTransport::new(base_url.to_string())
                        .await
                        .map_err(Into::into)
                })
            }

            fn is_channel_closed(err: &RpcError) -> bool {
                // Best-effort detection by string match; we don't want to depend on hyper error types here.
                // Expected formatting seen in logs: "interface error (Hyper(hyper::Error(ChannelClosed)))"
                let s = err.to_string();
                s.contains("ChannelClosed")
            }

            // Build the transport/client on this worker thread so hyper state is not shared across
            // threads.
            let mut client = match build_client(&base_url) {
                Ok(c) => c,
                Err(e) => {
                    while let Ok(req) = rx.recv() {
                        let _ = req.resp_tx.send(Err(e.clone()));
                    }
                    return;
                }
            };

            while let Ok(req) = rx.recv() {
                let start_bn = req.start_bn;
                let end_bn_inclusive = req.end_bn_inclusive;
                let resp_tx = req.resp_tx;

                // First attempt with current client
                let mut res: Result<Vec<ScannableBlock>, RpcError> = match bulk_fetch_mode {
                    BulkFetchMode::RangeBlocks => fetch_scannable_blocks_range_bin(
                        &client,
                        &base_url,
                        start_bn,
                        end_bn_inclusive,
                        None,
                    ),
                    _ => TOKIO_RUNTIME.block_on(async {
                        client
                            .contiguous_scannable_blocks(start_bn..=end_bn_inclusive)
                            .await
                            .map_err(Into::into)
                    }),
                };

                // If Hyper channel got closed, rebuild client and retry once.
                if res.as_ref().is_err_and(is_channel_closed) {
                    if let Ok(new_client) = build_client(&base_url) {
                        client = new_client;

                        res = match bulk_fetch_mode {
                            BulkFetchMode::RangeBlocks => fetch_scannable_blocks_range_bin(
                                &client,
                                &base_url,
                                start_bn,
                                end_bn_inclusive,
                                None,
                            ),
                            _ => TOKIO_RUNTIME.block_on(async {
                                client
                                    .contiguous_scannable_blocks(start_bn..=end_bn_inclusive)
                                    .await
                                    .map_err(Into::into)
                            }),
                        };
                    }
                }

                let _ = resp_tx.send(res);
            }
        });

        Self {
            tx,
            thread: Some(thread),
        }
    }

    /// Queue a contiguous fetch on the worker without waiting (one-ahead prefetch).
    fn begin_fetch(
        &self,
        start_bn: usize,
        end_bn_inclusive: usize,
    ) -> Result<AndroidPendingFetch, &'static str> {
        use std::sync::mpsc;

        let (resp_tx, resp_rx) = mpsc::channel::<Result<Vec<ScannableBlock>, RpcError>>();
        let req = AndroidFetchReq {
            start_bn,
            end_bn_inclusive,
            resp_tx,
        };
        if self.tx.send(req).is_err() {
            return Err("disconnected");
        }
        Ok(AndroidPendingFetch {
            resp_rx,
            started_at: Instant::now(),
        })
    }

    fn wait_pending(
        pending: AndroidPendingFetch,
        timeout_secs: u64,
    ) -> Result<Result<Vec<ScannableBlock>, RpcError>, &'static str> {
        use std::sync::mpsc;
        use std::time::Duration;

        match pending
            .resp_rx
            .recv_timeout(Duration::from_secs(timeout_secs))
        {
            Ok(v) => Ok(v),
            Err(mpsc::RecvTimeoutError::Timeout) => Err("timeout"),
            Err(mpsc::RecvTimeoutError::Disconnected) => Err("disconnected"),
        }
    }

    fn fetch_with_timeout(
        &self,
        timeout_secs: u64,
        start_bn: usize,
        end_bn_inclusive: usize,
    ) -> Result<Result<Vec<ScannableBlock>, RpcError>, &'static str> {
        let pending = self.begin_fetch(start_bn, end_bn_inclusive)?;
        Self::wait_pending(pending, timeout_secs)
    }

    fn shutdown(mut self) {
        // Dropping tx closes the channel; worker exits its recv() loop.
        drop(self.tx);
        if let Some(h) = self.thread.take() {
            let _ = h.join();
        }
    }
}

// Non-Android builds keep the existing per-call helper for now.
#[cfg(not(target_os = "android"))]
// FFI-safe timeout wrapper for async RPC futures without relying on tokio::time (reactor),
// which can panic when called outside an entered runtime context.
//
// This variant takes a closure producing the future so all captures can be moved into the
// spawned worker thread cleanly.
fn recv_timeout_block_on<T, MakeFut, Fut>(
    timeout_secs: u64,
    make_fut: MakeFut,
) -> Result<T, &'static str>
where
    MakeFut: FnOnce() -> Fut + Send + 'static,
    Fut: std::future::Future<Output = T> + Send + 'static,
    T: Send + 'static,
{
    use std::sync::mpsc;
    use std::time::Duration;

    let (tx, rx) = mpsc::channel::<T>();

    std::thread::spawn(move || {
        let fut = make_fut();
        let res = TOKIO_RUNTIME.block_on(fut);
        let _ = tx.send(res);
    });

    match rx.recv_timeout(Duration::from_secs(timeout_secs)) {
        Ok(v) => Ok(v),
        Err(mpsc::RecvTimeoutError::Timeout) => Err("timeout"),
        Err(mpsc::RecvTimeoutError::Disconnected) => Err("disconnected"),
    }
}

#[no_mangle]
pub extern "C" fn wallet_refresh(
    wallet_id: *const c_char,
    node_url: *const c_char,
    out_last_scanned: *mut u64,
) -> c_int {
    let id = if wallet_id.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(wallet_id) }
            .to_str()
            .ok()
            .map(str::trim)
            .filter(|id| !id.is_empty())
            .map(ToOwned::to_owned)
    };
    let Some(id) = id else {
        return wallet_refresh_caught(wallet_id, node_url, out_last_scanned);
    };
    if !try_start_refresh_job(&id) {
        return record_error(
            -31,
            format!("wallet_refresh: refresh already running for wallet '{id}'"),
        );
    }
    set_refresh_cancel_for_wallet(&id, false);
    let rc = wallet_refresh_caught(wallet_id, node_url, out_last_scanned);
    finish_refresh_job(&id, rc);
    rc
}

fn wallet_refresh_caught(
    wallet_id: *const c_char,
    node_url: *const c_char,
    out_last_scanned: *mut u64,
) -> c_int {
    // NOTE:
    // Android builds often end up with panic=abort, which turns Rust panics into SIGABRT with no
    // useful message in logcat. Wrap the entire implementation so we can surface panics via
    // walletcore lastError + logcat.
    let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        wallet_refresh_impl(wallet_id, node_url, out_last_scanned)
    }));

    match result {
        Ok(code) => code,
        Err(panic_payload) => {
            let msg = if let Some(s) = panic_payload.downcast_ref::<&str>() {
                format!("wallet_refresh panic: {s}")
            } else if let Some(s) = panic_payload.downcast_ref::<String>() {
                format!("wallet_refresh panic: {s}")
            } else {
                "wallet_refresh panic: <non-string payload>".to_string()
            };

            wc_log_line_android_or_stdout(&format!("🧨 {msg}"));
            record_error(-16, msg)
        }
    }
}

fn wallet_refresh_impl(
    wallet_id: *const c_char,
    node_url: *const c_char,
    out_last_scanned: *mut u64,
) -> c_int {
    clear_last_error();

    if wallet_id.is_null() {
        return record_error(-11, "wallet_refresh: wallet_id pointer was null");
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return record_error(-11, "wallet_refresh: wallet_id contained invalid UTF-8"),
    };

    if id.is_empty() {
        return record_error(-14, "wallet_refresh: wallet_id was empty");
    }

    // Install panic hook once per process for better crash diagnostics.
    let _ = &*PANIC_HOOK_INSTALLED;

    // Stage logging to diagnose early refresh termination.
    // IMPORTANT: on Android, stdout/stderr is often not captured, so emit directly to logcat.
    wc_log_line_android_or_stdout(&format!("🧭 wallet_refresh stage=init wallet_id={}", id));

    // Debug/perf logging is opt-in via WALLETCORE_SCAN_LOG=1. Do not force it on Android.

    // Build/runtime sanity logs (once per process).
    static BUILD_INFO_LOGGED: std::sync::Once = std::sync::Once::new();
    BUILD_INFO_LOGGED.call_once(|| {
        wc_log_line_android_or_stdout(&format!(
            "🧭 walletcore_build target_os={} target_arch={} compile_time_generators={} scanner_microprof_feature={}",
            std::env::consts::OS,
            std::env::consts::ARCH,
            cfg!(feature = "compile-time-generators"),
            cfg!(feature = "scanner-microprof")
        ));
    });

    let arg_url = if !node_url.is_null() {
        unsafe { CStr::from_ptr(node_url) }
            .to_str()
            .ok()
            .map(|s| s.trim().to_string())
    } else {
        None
    };
    let env_url = std::env::var("MONERO_URL").ok();
    let base_url = arg_url
        .filter(|s| !s.is_empty())
        .or(env_url)
        .unwrap_or_else(|| "http://127.0.0.1:18081".to_string());

    // Refresh entry stamp
    let env_par = std::env::var("WALLETCORE_SCAN_PAR")
        .ok()
        .unwrap_or_else(|| "(unset)".to_string());
    let env_batch = std::env::var("WALLETCORE_SCAN_BATCH")
        .ok()
        .unwrap_or_else(|| "(unset)".to_string());
    let env_bulk_fetch = std::env::var("WALLETCORE_BULK_FETCH")
        .ok()
        .unwrap_or_else(|| "(unset)".to_string());
    let env_bulk_mode = std::env::var("WALLETCORE_BULK_MODE")
        .ok()
        .unwrap_or_else(|| "(default=range)".to_string());
    let env_bulk_fetch_batch = std::env::var("WALLETCORE_BULK_FETCH_BATCH")
        .ok()
        .unwrap_or_else(|| format!("(default={})", crate::default_range_block_batch()));

    wc_log_line_android_or_stdout(&format!(
        "🧩 walletcore refresh entry: version={} build={} wallet_id={} node_url={} env{{scan_par={} scan_batch={} bulk_fetch={} bulk_mode={} bulk_fetch_batch={}}}",
        WALLETCORE_LOG_VERSION,
        build_stamp(),
        id,
        base_url,
        env_par,
        env_batch,
        env_bulk_fetch,
        env_bulk_mode,
        env_bulk_fetch_batch
    ));

    wc_log_line_android_or_stdout(&format!(
        "🧭 wallet_refresh stage=after_entry_stamp wallet_id={} node_url={}",
        id, base_url
    ));

    // Snapshot
    let snapshot = {
        let map = WALLET_STORE.lock().expect("wallet store poisoned");
        match map.get(id) {
            Some(state) => state.clone(),
            None => {
                return record_error(-13, format!("wallet_refresh: wallet '{id}' not registered"))
            }
        }
    };

    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧭 wallet_refresh stage=snapshot_loaded wallet_id={} network={:?}",
            id, snapshot.network
        ),
    );

    let refresh_t0 = Instant::now();

    let mut refresh_scan_ms_total: u128 = 0;
    let mut refresh_persist_ms_total: u128 = 0;
    // Main-thread time blocked waiting for the current batch's blocks.
    let mut refresh_fetch_wait_ms_total: u128 = 0;
    // Worker/RPC wall time for those fetches (includes overlap with prior scan on prefetch hit).
    let mut refresh_fetch_rpc_ms_total: u128 = 0;
    let mut refresh_blocks_total: usize = 0;
    let mut refresh_outputs_added_total: usize = 0;
    let mut refresh_batches_total: usize = 0;

    let mut persist_span_start: Option<Instant> = None;

    let refresh_telemetry_enabled: bool = std::env::var("WALLETCORE_REFRESH_TELEMETRY")
        .ok()
        .and_then(|s| s.parse::<u8>().ok())
        .map(|v| v != 0)
        .unwrap_or(false);

    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧭 wallet_refresh stage=after_entry_stamp wallet_id={} node_url={}",
            id, base_url
        ),
    );

    // Connect daemon clients
    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧭 wallet_refresh stage=daemon_connect_start wallet_id={}",
            id
        ),
    );

    let mut rpc_client: RpcClient = match connect_rpc_client(&base_url) {
        Ok(d) => d,
        Err(e) => {
            walletcore_log_line(
                id,
                snapshot.network,
                &format!(
                    "🧭 wallet_refresh stage=daemon_connect_error wallet_id={} err={}",
                    id, e
                ),
            );
            return record_error(
                -16,
                format!("wallet_refresh: failed to connect daemon '{base_url}': {e}"),
            );
        }
    };

    #[cfg(not(target_os = "android"))]
    let prefetch_rpc_client: RpcClient = match connect_rpc_client(&base_url) {
        Ok(d) => d,
        Err(e) => {
            walletcore_log_line(
                id,
                snapshot.network,
                &format!(
                    "🧭 wallet_refresh stage=daemon_connect_error wallet_id={} err={}",
                    id, e
                ),
            );
            return record_error(
                -16,
                format!("wallet_refresh: failed to connect daemon (prefetch) '{base_url}': {e}"),
            );
        }
    };

    walletcore_log_line(
        id,
        snapshot.network,
        &format!("🧭 wallet_refresh stage=daemon_connect_ok wallet_id={}", id),
    );
    wc_log_line_android_or_stdout(&format!(
        "🧭 wallet_refresh stage=daemon_connect_ok wallet_id={}",
        id
    ));

    // Daemon height
    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧭 wallet_refresh stage=daemon_height_start wallet_id={}",
            id
        ),
    );
    wc_log_line_android_or_stdout(&format!(
        "🧭 wallet_refresh stage=daemon_height_start wallet_id={}",
        id
    ));

    let daemon_height = match TOKIO_RUNTIME.block_on(rpc_client.latest_block_number()) {
        Ok(n) => {
            let h = n.saturating_add(1) as u64;
            walletcore_log_line(
                id,
                snapshot.network,
                &format!(
                    "🧭 wallet_refresh stage=daemon_height_ok wallet_id={} height={}",
                    id, h
                ),
            );
            wc_log_line_android_or_stdout(&format!(
                "🧭 wallet_refresh stage=daemon_height_ok wallet_id={} height={}",
                id, h
            ));
            h
        }
        Err(e) => {
            walletcore_log_line(
                id,
                snapshot.network,
                &format!(
                    "🧭 wallet_refresh stage=daemon_height_error wallet_id={} err={}",
                    id, e
                ),
            );
            return record_error(
                -16,
                format!("wallet_refresh: failed to query daemon height '{base_url}': {e}"),
            );
        }
    };

    let configured_upstream_batch = std::env::var("WALLETCORE_UPSTREAM_BLOCK_BATCH").ok();
    let upstream_block_batch =
        configured_upstream_block_batch(configured_upstream_batch.as_deref());

    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧭 wallet_refresh stage=upstream_batch_config wallet_id={} upstream_block_batch={}",
            id, upstream_block_batch
        ),
    );
    wc_log_line_android_or_stdout(&format!(
        "🧭 wallet_refresh stage=upstream_batch_config wallet_id={} upstream_block_batch={}",
        id, upstream_block_batch
    ));

    let tip_timestamp = resolve_daemon_tip_timestamp(&base_url);
    let mut daemon = DaemonStatus {
        height: daemon_height,
        top_block_timestamp: tip_timestamp,
    };
    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧭 wallet_refresh stage=daemon_tip_time wallet_id={} tip_timestamp={}",
            id, daemon.top_block_timestamp
        ),
    );

    // Keys + scanner
    let master = snapshot.keys.clone();
    let view_pair = match master.to_view_pair() {
        Ok(pair) => pair,
        Err(code) => {
            return record_error(
                code,
                format!("wallet_refresh: failed to construct view pair ({code})"),
            )
        }
    };

    let mut scanner = Scanner::new(view_pair.clone());
    let gap_limit = snapshot.gap_limit.max(1);

    let account_gap: u32 = std::env::var("WALLETCORE_ACCOUNT_GAP")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .map(|v| v.max(1))
        .unwrap_or(1);

    // Fingerprints + derived address logs
    let spend_scalar_bytes = master.spend_scalar.to_bytes();
    let view_scalar_bytes = master.view_scalar_dalek.to_bytes();
    if walletcore_debug_input_dump_enabled() {
        walletcore_log_line(
            id,
            snapshot.network,
            &format!(
                "🔐 wallet_fingerprint wallet_id={} spend_scalar_fpr={} view_scalar_fpr={} entropy_fpr={}",
                id,
                fingerprint32("spend_scalar", &spend_scalar_bytes),
                fingerprint32("view_scalar", &view_scalar_bytes),
                fingerprint32("entropy", master.entropy.as_ref()),
            ),
        );
    }

    let derived_primary_address = derive_address_string(&master, 0, 0, snapshot.network);
    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🏠 derived_primary_address wallet_id={} address={}",
            id, derived_primary_address
        ),
    );

    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧭 scanner_subaddress_plan wallet_id={} account_gap={} gap_limit={} majors=[0..{}) minors=[0..={}]",
            id, account_gap, gap_limit, account_gap, gap_limit
        ),
    );

    let mut registered: u64 = 0;
    let mut failed: u64 = 0;
    let mut first_failed: Option<(u32, u32)> = None;
    let mut last_failed: Option<(u32, u32)> = None;

    for major in 0..account_gap {
        for minor in 1..=gap_limit {
            if let Some(idx) = SubaddressIndex::new(major, minor) {
                scanner.register_subaddress(idx);
                registered = registered.saturating_add(1);
            } else {
                failed = failed.saturating_add(1);
                first_failed = first_failed.or(Some((major, minor)));
                last_failed = Some((major, minor));
            }
        }
    }

    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧭 scanner_subaddress_registered wallet_id={} registered_count={} failed_count={} first_failed={:?} last_failed={:?}",
            id, registered, failed, first_failed, last_failed
        ),
    );

    // Debug controls
    let debug_txid = walletcore_debug_target_txid();
    let debug_height = walletcore_debug_target_height();
    let debug_height_window = walletcore_debug_target_window();

    // Working state
    let mut working_outputs = snapshot.tracked_outputs.clone();
    let mut seen_outpoints = snapshot.seen_outpoints.clone();
    let mut known_tx_fees = known_transaction_fees(&snapshot.tx_ledger);
    let mut working_recent_block_hashes_start_height = snapshot.recent_block_hashes_start_height;
    let mut working_recent_block_hashes = snapshot.recent_block_hashes.clone();
    let mut working_block_timestamps = snapshot.block_timestamps.clone();
    let mut scan_cursor = snapshot.last_scanned.max(snapshot.restore_height);

    update_scan_progress(
        id,
        scan_cursor.min(daemon.height),
        daemon.height,
        daemon.top_block_timestamp,
        snapshot.restore_height,
    );

    // Perf logging controls
    let log_perf: bool = std::env::var("WALLETCORE_SCAN_LOG")
        .ok()
        .map(|s| s != "0")
        .unwrap_or(false);
    let log_batch_events = log_perf;
    let overall_start: Option<Instant> = if log_perf { Some(Instant::now()) } else { None };
    let initial_outputs: usize = working_outputs.len();

    let requested_scan_parallelism = scan_parallelism_from_env();
    let scan_pool = if requested_scan_parallelism > 1 {
        match rayon::ThreadPoolBuilder::new()
            .num_threads(requested_scan_parallelism)
            .thread_name(|index| format!("walletcore-scan-{index}"))
            .build()
        {
            Ok(pool) => Some(std::sync::Arc::new(pool)),
            Err(err) => {
                wc_log_line_android_or_stdout(&format!(
                    "⚠️ wallet_refresh stage=parallel_scan_pool_failed wallet_id={} requested_threads={} err={} fallback=serial",
                    id, requested_scan_parallelism, err
                ));
                None
            }
        }
    } else {
        None
    };
    let effective_scan_parallelism = scan_pool
        .as_ref()
        .map(|pool| pool.current_num_threads())
        .unwrap_or(1);
    let range_decode_pool = if !cfg!(target_os = "android") && range_decode_parallel_enabled() {
        scan_pool.clone()
    } else {
        None
    };
    let scan_parallelism_line = format!(
        "🧵 wallet_refresh stage=parallel_scan_config wallet_id={} threads={} mode={}",
        id,
        effective_scan_parallelism,
        if effective_scan_parallelism > 1 {
            "ordered-batch"
        } else {
            "serial"
        }
    );
    walletcore_log_line(id, snapshot.network, &scan_parallelism_line);
    wc_log_line_android_or_stdout(&scan_parallelism_line);
    let range_decode_line = format!(
        "🧵 wallet_refresh stage=range_decode_config wallet_id={} mode={} threads={}",
        id,
        if range_decode_pool.is_some() {
            "parallel-shared"
        } else {
            "serial"
        },
        range_decode_pool
            .as_ref()
            .map(|pool| pool.current_num_threads())
            .unwrap_or(1)
    );
    walletcore_log_line(id, snapshot.network, &range_decode_line);
    wc_log_line_android_or_stdout(&range_decode_line);

    // Legacy batch/RPC env plumbing retained for compatibility with existing test plans.
    let _batch: usize = std::env::var("WALLETCORE_SCAN_BATCH")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or_else(crate::default_range_block_batch);
    let _bulk_rpc: bool = std::env::var("WALLETCORE_BULK_RPC")
        .ok()
        .map(|s| s != "0")
        .unwrap_or(true);

    let mut bulk_fetch_mode = bulk_fetch_mode_from_env();
    let bulk_fetch_batch = bulk_fetch_batch_from_env();

    print!(
        "🧱 bulk-fetch mode resolved: requested={} batch={} (pre-clearnet-gating)\n",
        bulk_mode_str(bulk_fetch_mode),
        bulk_fetch_batch
    );
    wc_log_line_android_or_stdout(&format!(
        "🧱 bulk-fetch mode resolved: requested={} batch={} (pre-clearnet-gating)",
        bulk_mode_str(bulk_fetch_mode),
        bulk_fetch_batch
    ));

    if scan_cursor < daemon.height {
        // Android: keep Hyper on one dedicated worker thread (avoids ChannelClosed from
        // sharing transports across OS threads). Still overlap the *next* batch fetch with
        // the current batch scan via one-ahead prefetch on that same worker.
        let prefetch_depth: usize = std::env::var("WALLETCORE_PREFETCH_DEPTH")
            .ok()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(1)
            .clamp(1, 2);

        #[cfg(not(target_os = "android"))]
        let mut next_scannables_q: VecDeque<(u64, u64, u128, Vec<ScannableBlock>)> =
            VecDeque::new();

        #[cfg(not(target_os = "android"))]
        let mut prefetch_in_flight: VecDeque<
            tokio::task::JoinHandle<(u64, u64, u128, Result<Vec<ScannableBlock>, RpcError>)>,
        > = VecDeque::new();

        #[cfg(not(target_os = "android"))]
        let mut prefetch_rpc_client = std::sync::Arc::new(prefetch_rpc_client);

        // Android-only: single dedicated fetch worker for contiguous_scannable_blocks.
        // Build and own the RPC client inside the worker thread to avoid Hyper ChannelClosed.
        #[cfg(target_os = "android")]
        let android_fetch_worker =
            AndroidContiguousFetchWorker::start(base_url.clone(), bulk_fetch_mode);

        // Ensure the Android worker thread is always shut down, even on early returns.
        // Keep the worker inside an Option so Drop can move it out and join the thread.
        #[cfg(target_os = "android")]
        struct AndroidFetchWorkerGuard(Option<AndroidContiguousFetchWorker>);
        #[cfg(target_os = "android")]
        impl Drop for AndroidFetchWorkerGuard {
            fn drop(&mut self) {
                if let Some(w) = self.0.take() {
                    w.shutdown();
                }
            }
        }

        #[cfg(target_os = "android")]
        let mut _android_fetch_worker_guard = AndroidFetchWorkerGuard(Some(android_fetch_worker));
        #[cfg(target_os = "android")]
        let android_fetch_worker = _android_fetch_worker_guard.0.as_ref().unwrap();

        // One-ahead prefetch: (start_bn_u64, end_bn_inclusive_u64, pending response).
        #[cfg(target_os = "android")]
        let mut android_next_prefetch: Option<(u64, u64, AndroidPendingFetch)> = None;

        // Silence unused on Android (prefetch_depth reserved for future depth>1).
        #[cfg(target_os = "android")]
        let _ = prefetch_depth;

        let mut fetch_retries = 0u32;
        let mut reorg_probe_failures = 0u32;

        // Validate cached chain tip once when resuming existing state. Continuous batch
        // anchoring uses returned block parent links below — not a per-batch RPC probe.
        debug_assert!(!PER_BATCH_TIP_PROBE_ENABLED);
        if should_probe_reorg_on_resume(working_recent_block_hashes.len()) {
            match BlockingRpcTransport::new(&base_url) {
                Ok(transport) => {
                    match find_reorg_rewind_height(
                        snapshot.restore_height,
                        working_recent_block_hashes_start_height,
                        &working_recent_block_hashes,
                        |height| transport.get_block_hash_by_height_json(height),
                    ) {
                        Ok(opt) => match decide_resume_reorg_action(scan_cursor, Ok(opt))
                            .expect("Ok probe cannot fail decide_resume")
                        {
                            ResumeReorgAction::KeepCursor => {}
                            ResumeReorgAction::Rewind { scan_from: rewind_to } => {
                                walletcore_log_line(
                                    id,
                                    snapshot.network,
                                    &format!(
                                        "♻️ wallet_refresh stage=resume_reorg_rewind wallet_id={} from={} to={}",
                                        id, scan_cursor, rewind_to
                                    ),
                                );
                                scan_cursor = rewind_working_state_to_height(
                                    snapshot.restore_height,
                                    rewind_to,
                                    &mut working_outputs,
                                    &mut seen_outpoints,
                                    &mut working_recent_block_hashes_start_height,
                                    &mut working_recent_block_hashes,
                                    &mut working_block_timestamps,
                                );
                                if let Err(code) = commit_refresh_checkpoint(
                                    id,
                                    scan_cursor,
                                    daemon.height,
                                    daemon.top_block_timestamp,
                                    &working_outputs,
                                    &seen_outpoints,
                                    &known_tx_fees,
                                    working_recent_block_hashes_start_height,
                                    &working_recent_block_hashes,
                                    &working_block_timestamps,
                                ) {
                                    return code;
                                }
                            }
                        },
                        Err((code, message)) => {
                            return record_error(
                                code,
                                format!(
                                    "wallet_refresh: resume reorg probe failed ({message})"
                                ),
                            );
                        }
                    }
                }
                Err(code) => {
                    return record_error(
                        code,
                        "wallet_refresh: failed to open transport for resume reorg probe",
                    );
                }
            }
        }

        while scan_cursor < daemon.height {
            if refresh_cancelled_for_wallet(id) {
                if let Some(p0) = persist_span_start.take() {
                    refresh_persist_ms_total =
                        refresh_persist_ms_total.saturating_add(p0.elapsed().as_millis());
                }

                let total_ms = refresh_t0.elapsed().as_millis();
                walletcore_log_line(
                    id,
                    snapshot.network,
                    &format!(
                        "📈 wallet_refresh summary wallet_id={} status=cancelled total_ms={} batches={} blocks={} outputs_added={} scan_ms_total={} fetch_wait_ms_total={} fetch_rpc_ms_total={} persist_ms_total={}",
                        id,
                        total_ms,
                        refresh_batches_total,
                        refresh_blocks_total,
                        refresh_outputs_added_total,
                        refresh_scan_ms_total,
                        refresh_fetch_wait_ms_total,
                        refresh_fetch_rpc_ms_total,
                        refresh_persist_ms_total
                    ),
                );
                wc_log_line_android_or_stdout(&format!(
                    "📈 wallet_refresh summary wallet_id={} status=cancelled total_ms={} batches={} blocks={} outputs_added={} scan_ms_total={} fetch_wait_ms_total={} fetch_rpc_ms_total={} persist_ms_total={}",
                    id,
                    total_ms,
                    refresh_batches_total,
                    refresh_blocks_total,
                    refresh_outputs_added_total,
                    refresh_scan_ms_total,
                    refresh_fetch_wait_ms_total,
                    refresh_fetch_rpc_ms_total,
                    refresh_persist_ms_total
                ));
                return record_error(-30, "wallet_refresh: cancelled");
            }

            let end_exclusive = core::cmp::min(
                daemon.height,
                scan_cursor.saturating_add(upstream_block_batch),
            );
            if end_exclusive <= scan_cursor {
                break;
            }

            let start_bn_u64 = scan_cursor;
            let end_bn_inclusive_u64 = end_exclusive.saturating_sub(1);

            let start_bn = match usize::try_from(start_bn_u64) {
                Ok(v) => v,
                Err(_) => {
                    return record_error(-16, "wallet_refresh: block number conversion overflow")
                }
            };
            let end_bn_inclusive = match usize::try_from(end_bn_inclusive_u64) {
                Ok(v) => v,
                Err(_) => {
                    return record_error(-16, "wallet_refresh: block number conversion overflow")
                }
            };

            if let Some(p0) = persist_span_start.take() {
                refresh_persist_ms_total =
                    refresh_persist_ms_total.saturating_add(p0.elapsed().as_millis());
            }

            if log_batch_events {
                walletcore_log_line(
                    id,
                    snapshot.network,
                    &format!(
                        "🧭 wallet_refresh stage=contiguous_scannable_blocks_start wallet_id={} range={}..={}",
                        id, start_bn, end_bn_inclusive
                    ),
                );
                wc_log_line_android_or_stdout(&format!(
                    "🧭 wallet_refresh stage=contiguous_scannable_blocks_start wallet_id={} range={}..={}",
                    id, start_bn, end_bn_inclusive
                ));
            }

            let mut batch_fetch_wait_ms: u128 = 0;
            let mut batch_fetch_rpc_ms: u128 = 0;
            let mut batch_prefetch: &'static str = "n/a";

            let scannables: Vec<ScannableBlock> = {
                #[cfg(not(target_os = "android"))]
                {
                    if let Some((pf_start, pf_end, pf_rpc_ms, pf_vec)) =
                        next_scannables_q.pop_front()
                    {
                        if pf_start == start_bn_u64 && pf_end == end_bn_inclusive_u64 {
                            batch_prefetch = "hit";
                            batch_fetch_wait_ms = 0;
                            batch_fetch_rpc_ms = pf_rpc_ms;
                            pf_vec
                        } else {
                            // Every later speculative range was based on the same stale cursor.
                            // Drop it before fetching from the actual scan cursor.
                            let (discarded_ready, aborted_in_flight) = clear_stale_prefetches(
                                &mut next_scannables_q,
                                &mut prefetch_in_flight,
                            );
                            if log_batch_events {
                                wc_log_line_android_or_stdout(&format!(
                                    "🧭 wallet_refresh stage=prefetch_rebase wallet_id={} reason=range_mismatch expected={}..={} received={}..={} discarded_ready={} aborted_in_flight={}",
                                    id,
                                    start_bn_u64,
                                    end_bn_inclusive_u64,
                                    pf_start,
                                    pf_end,
                                    discarded_ready,
                                    aborted_in_flight
                                ));
                            }

                            // Prefetch mismatch; fetch synchronously (with hard timeout).
                            let fetch_t0 = Instant::now();
                            let start_bn_local = start_bn;
                            let end_bn_inclusive_local = end_bn_inclusive;
                            batch_prefetch = "miss";

                            let fetch_res = {
                                // Clone outside the timeout closure so we don't move `rpc_client` into the closure
                                // (the closure must be 'static and would otherwise capture/move `rpc_client`,
                                // which is reused across loop iterations).
                                let rpc_client_for_timeout = rpc_client.clone();
                                let base_url_for_timeout = base_url.clone();
                                let bulk_fetch_mode_for_timeout = bulk_fetch_mode;
                                let decode_pool_for_timeout = range_decode_pool.clone();
                                recv_timeout_block_on(
                                    CONTIGUOUS_BLOCKS_TIMEOUT_SECS,
                                    move || async move {
                                        match bulk_fetch_mode_for_timeout {
                                            BulkFetchMode::RangeBlocks => {
                                                fetch_scannable_blocks_range_bin(
                                                    &rpc_client_for_timeout,
                                                    &base_url_for_timeout,
                                                    start_bn_local,
                                                    end_bn_inclusive_local,
                                                    decode_pool_for_timeout.as_deref(),
                                                )
                                            }
                                            _ => rpc_client_for_timeout
                                                .contiguous_scannable_blocks(
                                                    start_bn_local..=end_bn_inclusive_local,
                                                )
                                                .await
                                                .map_err(Into::into),
                                        }
                                    },
                                )
                            };

                            match fetch_res {
                                Ok(Ok(v)) => {
                                    let fetch_ms = fetch_t0.elapsed().as_millis();
                                    batch_fetch_wait_ms = fetch_ms;
                                    batch_fetch_rpc_ms = fetch_ms;
                                    if log_batch_events {
                                        walletcore_log_line(
                                            id,
                                            snapshot.network,
                                            &format!(
                                                "🧭 wallet_refresh stage=contiguous_scannable_blocks_ok wallet_id={} blocks={} fetch_ms={} blocks_per_s={:.2}",
                                                id,
                                                v.len(),
                                                fetch_ms,
                                                if fetch_ms > 0 {
                                                    (v.len() as f64) / (fetch_ms as f64 / 1000.0)
                                                } else {
                                                    0.0
                                                }
                                            ),
                                        );
                                        wc_log_line_android_or_stdout(&format!(
                                            "🧭 wallet_refresh stage=contiguous_scannable_blocks_ok wallet_id={} blocks={} fetch_ms={} blocks_per_s={:.2}",
                                            id,
                                            v.len(),
                                            fetch_ms,
                                            if fetch_ms > 0 {
                                                (v.len() as f64) / (fetch_ms as f64 / 1000.0)
                                            } else {
                                                0.0
                                            }
                                        ));
                                    }
                                    v
                                }
                                Ok(Err(err)) => {
                                    let fetch_ms = fetch_t0.elapsed().as_millis();
                                    let err_s = err.to_string();
                                    walletcore_log_line(
                                        id,
                                        snapshot.network,
                                        &format!(
                                            "🧭 wallet_refresh stage=contiguous_scannable_blocks_error wallet_id={} fetch_ms={} err={}",
                                            id, fetch_ms, err_s
                                        ),
                                    );
                                    wc_log_line_android_or_stdout(&format!(
                                        "🧭 wallet_refresh stage=contiguous_scannable_blocks_error wallet_id={} fetch_ms={} err={}",
                                        id, fetch_ms, err_s
                                    ));
                                    if let Some(c) =
                                        rebuild_rpc_client_if_channel_closed(&base_url, &err_s)
                                    {
                                        rpc_client = c;
                                        #[cfg(not(target_os = "android"))]
                                        if let Ok(c2) = connect_rpc_client(&base_url) {
                                            prefetch_rpc_client = std::sync::Arc::new(c2);
                                        }
                                    }
                                    if let Some((v, used_range)) = try_json_batch_error_fallback(
                                        &rpc_client,
                                        &base_url,
                                        start_bn_local,
                                        end_bn_inclusive_local,
                                        bulk_fetch_mode,
                                        &err_s,
                                        range_decode_pool.as_deref(),
                                    ) {
                                        if used_range {
                                            bulk_fetch_mode = BulkFetchMode::RangeBlocks;
                                            wc_log_line_android_or_stdout(
                                                "🧭 wallet_refresh stage=bulk_mode_switched_to_range reason=cuprate_json_batch",
                                            );
                                        }
                                        let fetch_ms = fetch_t0.elapsed().as_millis();
                                        batch_fetch_wait_ms = fetch_ms;
                                        batch_fetch_rpc_ms = fetch_ms;
                                        if log_batch_events {
                                            walletcore_log_line(
                                                id,
                                                snapshot.network,
                                                &format!(
                                                    "🧭 wallet_refresh stage=contiguous_scannable_blocks_ok wallet_id={} blocks={} fetch_ms={} blocks_per_s={:.2}",
                                                    id,
                                                    v.len(),
                                                    fetch_ms,
                                                    if fetch_ms > 0 {
                                                        (v.len() as f64) / (fetch_ms as f64 / 1000.0)
                                                    } else {
                                                        0.0
                                                    }
                                                ),
                                            );
                                            wc_log_line_android_or_stdout(&format!(
                                                "🧭 wallet_refresh stage=contiguous_scannable_blocks_ok wallet_id={} blocks={} fetch_ms={} blocks_per_s={:.2}",
                                                id,
                                                v.len(),
                                                fetch_ms,
                                                if fetch_ms > 0 {
                                                    (v.len() as f64) / (fetch_ms as f64 / 1000.0)
                                                } else {
                                                    0.0
                                                }
                                            ));
                                        }
                                        v
                                    } else if maybe_retry_block_fetch(
                                        id,
                                        &err_s,
                                        &mut fetch_retries,
                                    ) {
                                        continue;
                                    } else {
                                        return record_error(
                                            -16,
                                            format!(
                                                "wallet_refresh: contiguous_scannable_blocks failed: {}",
                                                err_s
                                            ),
                                        );
                                    }
                                }
                                Err(msg) => {
                                    let fetch_ms = fetch_t0.elapsed().as_millis();
                                    let msg = format!(
                                        "wallet_refresh: contiguous_scannable_blocks timeout/disconnect ({}) after {}s for heights {}..{}",
                                        msg,
                                        CONTIGUOUS_BLOCKS_TIMEOUT_SECS,
                                        start_bn_local,
                                        end_bn_inclusive_local
                                    );
                                    walletcore_log_line(
                                        id,
                                        snapshot.network,
                                        &format!(
                                            "🧭 wallet_refresh stage=contiguous_scannable_blocks_timeout wallet_id={} fetch_ms={} err={}",
                                            id, fetch_ms, msg
                                        ),
                                    );
                                    wc_log_line_android_or_stdout(&format!(
                                        "🧭 wallet_refresh stage=contiguous_scannable_blocks_timeout wallet_id={} fetch_ms={} err={}",
                                        id, fetch_ms, msg
                                    ));
                                    if maybe_retry_block_fetch(id, &msg, &mut fetch_retries) {
                                        continue;
                                    }
                                    return record_error(-16, msg);
                                }
                            }
                        }
                    } else {
                        let fetch_t0 = Instant::now();
                        let start_bn_local = start_bn;
                        let end_bn_inclusive_local = end_bn_inclusive;
                        batch_prefetch = "sync";

                        let fetch_res = {
                            // Clone outside the timeout closure so we don't move `rpc_client` into the closure
                            // (the closure must be 'static and would otherwise capture/move `rpc_client`,
                            // which is reused across loop iterations).
                            let rpc_client_for_timeout = rpc_client.clone();
                            let base_url_for_timeout = base_url.clone();
                            let bulk_fetch_mode_for_timeout = bulk_fetch_mode;
                            let decode_pool_for_timeout = range_decode_pool.clone();
                            recv_timeout_block_on(
                                CONTIGUOUS_BLOCKS_TIMEOUT_SECS,
                                move || async move {
                                    match bulk_fetch_mode_for_timeout {
                                        BulkFetchMode::RangeBlocks => {
                                            fetch_scannable_blocks_range_bin(
                                                &rpc_client_for_timeout,
                                                &base_url_for_timeout,
                                                start_bn_local,
                                                end_bn_inclusive_local,
                                                decode_pool_for_timeout.as_deref(),
                                            )
                                        }
                                        _ => rpc_client_for_timeout
                                            .contiguous_scannable_blocks(
                                                start_bn_local..=end_bn_inclusive_local,
                                            )
                                            .await
                                            .map_err(Into::into),
                                    }
                                },
                            )
                        };

                        match fetch_res {
                            Ok(Ok(v)) => {
                                let fetch_ms = fetch_t0.elapsed().as_millis();
                                batch_fetch_wait_ms = fetch_ms;
                                batch_fetch_rpc_ms = fetch_ms;
                                if log_batch_events {
                                    walletcore_log_line(
                                        id,
                                        snapshot.network,
                                        &format!(
                                            "🧭 wallet_refresh stage=contiguous_scannable_blocks_ok wallet_id={} blocks={} fetch_ms={} blocks_per_s={:.2}",
                                            id,
                                            v.len(),
                                            fetch_ms,
                                            if fetch_ms > 0 {
                                                (v.len() as f64) / (fetch_ms as f64 / 1000.0)
                                            } else {
                                                0.0
                                            }
                                        ),
                                    );
                                    wc_log_line_android_or_stdout(&format!(
                                        "🧭 wallet_refresh stage=contiguous_scannable_blocks_ok wallet_id={} blocks={} fetch_ms={} blocks_per_s={:.2}",
                                        id,
                                        v.len(),
                                        fetch_ms,
                                        if fetch_ms > 0 {
                                            (v.len() as f64) / (fetch_ms as f64 / 1000.0)
                                        } else {
                                            0.0
                                        }
                                    ));
                                }
                                v
                            }
                            Ok(Err(err)) => {
                                let fetch_ms = fetch_t0.elapsed().as_millis();
                                let err_s = err.to_string();
                                walletcore_log_line(
                                    id,
                                    snapshot.network,
                                    &format!(
                                        "🧭 wallet_refresh stage=contiguous_scannable_blocks_error wallet_id={} fetch_ms={} err={}",
                                        id, fetch_ms, err_s
                                    ),
                                );
                                wc_log_line_android_or_stdout(&format!(
                                    "🧭 wallet_refresh stage=contiguous_scannable_blocks_error wallet_id={} fetch_ms={} err={}",
                                    id, fetch_ms, err_s
                                ));
                                if let Some(c) =
                                    rebuild_rpc_client_if_channel_closed(&base_url, &err_s)
                                {
                                    rpc_client = c;
                                    #[cfg(not(target_os = "android"))]
                                    if let Ok(c2) = connect_rpc_client(&base_url) {
                                        prefetch_rpc_client = std::sync::Arc::new(c2);
                                    }
                                }
                                if let Some((v, used_range)) = try_json_batch_error_fallback(
                                    &rpc_client,
                                    &base_url,
                                    start_bn_local,
                                    end_bn_inclusive_local,
                                    bulk_fetch_mode,
                                    &err_s,
                                    range_decode_pool.as_deref(),
                                ) {
                                    if used_range {
                                        bulk_fetch_mode = BulkFetchMode::RangeBlocks;
                                        wc_log_line_android_or_stdout(
                                            "🧭 wallet_refresh stage=bulk_mode_switched_to_range reason=cuprate_json_batch",
                                        );
                                    }
                                    let fetch_ms = fetch_t0.elapsed().as_millis();
                                    batch_fetch_wait_ms = fetch_ms;
                                    batch_fetch_rpc_ms = fetch_ms;
                                    if log_batch_events {
                                        walletcore_log_line(
                                            id,
                                            snapshot.network,
                                            &format!(
                                                "🧭 wallet_refresh stage=contiguous_scannable_blocks_ok wallet_id={} blocks={} fetch_ms={} blocks_per_s={:.2}",
                                                id,
                                                v.len(),
                                                fetch_ms,
                                                if fetch_ms > 0 {
                                                    (v.len() as f64) / (fetch_ms as f64 / 1000.0)
                                                } else {
                                                    0.0
                                                }
                                            ),
                                        );
                                        wc_log_line_android_or_stdout(&format!(
                                            "🧭 wallet_refresh stage=contiguous_scannable_blocks_ok wallet_id={} blocks={} fetch_ms={} blocks_per_s={:.2}",
                                            id,
                                            v.len(),
                                            fetch_ms,
                                            if fetch_ms > 0 {
                                                (v.len() as f64) / (fetch_ms as f64 / 1000.0)
                                            } else {
                                                0.0
                                            }
                                        ));
                                    }
                                    v
                                } else if maybe_retry_block_fetch(id, &err_s, &mut fetch_retries) {
                                    continue;
                                } else {
                                    return record_error(
                                        -16,
                                        format!(
                                            "wallet_refresh: contiguous_scannable_blocks failed: {}",
                                            err_s
                                        ),
                                    );
                                }
                            }
                            Err(msg) => {
                                let fetch_ms = fetch_t0.elapsed().as_millis();
                                let msg = format!(
                                    "wallet_refresh: contiguous_scannable_blocks timeout/disconnect ({}) after {}s for heights {}..{}",
                                    msg,
                                    CONTIGUOUS_BLOCKS_TIMEOUT_SECS,
                                    start_bn_local,
                                    end_bn_inclusive_local
                                );
                                walletcore_log_line(
                                    id,
                                    snapshot.network,
                                    &format!(
                                        "🧭 wallet_refresh stage=contiguous_scannable_blocks_timeout wallet_id={} fetch_ms={} err={}",
                                        id, fetch_ms, msg
                                    ),
                                );
                                wc_log_line_android_or_stdout(&format!(
                                    "🧭 wallet_refresh stage=contiguous_scannable_blocks_timeout wallet_id={} fetch_ms={} err={}",
                                    id, fetch_ms, msg
                                ));
                                if maybe_retry_block_fetch(id, &msg, &mut fetch_retries) {
                                    continue;
                                }
                                return record_error(-16, msg);
                            }
                        }
                    }
                }

                #[cfg(target_os = "android")]
                {
                    // Prefer one-ahead prefetch when the pending range matches; otherwise drain and
                    // fetch synchronously. Hyper stays on the dedicated worker thread either way.
                    let fetch_wait_t0 = Instant::now();
                    let start_bn_local = start_bn;
                    let end_bn_inclusive_local = end_bn_inclusive;
                    let mut fetch_started_at = fetch_wait_t0;

                    let fetch_res = match android_next_prefetch.take() {
                        Some((pf_start, pf_end, pending))
                            if pf_start == start_bn_u64 && pf_end == end_bn_inclusive_u64 =>
                        {
                            batch_prefetch = "hit";
                            fetch_started_at = pending.started_at;
                            if log_batch_events {
                                wc_log_line_android_or_stdout(&format!(
                                    "🧭 wallet_refresh stage=android_prefetch_hit wallet_id={} range={}..={}",
                                    id, start_bn_local, end_bn_inclusive_local
                                ));
                            }
                            AndroidContiguousFetchWorker::wait_pending(
                                pending,
                                CONTIGUOUS_BLOCKS_TIMEOUT_SECS,
                            )
                        }
                        Some((pf_start, pf_end, pending)) => {
                            batch_prefetch = "miss";
                            if log_batch_events {
                                wc_log_line_android_or_stdout(&format!(
                                    "🧭 wallet_refresh stage=android_prefetch_miss wallet_id={} wanted={}..={} pending={}..={}",
                                    id,
                                    start_bn_u64,
                                    end_bn_inclusive_u64,
                                    pf_start,
                                    pf_end
                                ));
                            }
                            let _ = AndroidContiguousFetchWorker::wait_pending(
                                pending,
                                CONTIGUOUS_BLOCKS_TIMEOUT_SECS,
                            );
                            fetch_started_at = Instant::now();
                            android_fetch_worker.fetch_with_timeout(
                                CONTIGUOUS_BLOCKS_TIMEOUT_SECS,
                                start_bn_local,
                                end_bn_inclusive_local,
                            )
                        }
                        None => {
                            batch_prefetch = "sync";
                            fetch_started_at = Instant::now();
                            android_fetch_worker.fetch_with_timeout(
                                CONTIGUOUS_BLOCKS_TIMEOUT_SECS,
                                start_bn_local,
                                end_bn_inclusive_local,
                            )
                        }
                    };

                    match fetch_res {
                        Ok(Ok(v)) => {
                            let fetch_wait_ms = fetch_wait_t0.elapsed().as_millis();
                            let fetch_rpc_ms = fetch_started_at.elapsed().as_millis();
                            batch_fetch_wait_ms = fetch_wait_ms;
                            batch_fetch_rpc_ms = fetch_rpc_ms;
                            if log_batch_events {
                                walletcore_log_line(
                                    id,
                                    snapshot.network,
                                    &format!(
                                        "🧭 wallet_refresh stage=contiguous_scannable_blocks_ok wallet_id={} blocks={} fetch_wait_ms={} fetch_rpc_ms={} prefetch={} blocks_per_s={:.2}",
                                        id,
                                        v.len(),
                                        fetch_wait_ms,
                                        fetch_rpc_ms,
                                        batch_prefetch,
                                        if fetch_wait_ms > 0 {
                                            (v.len() as f64) / (fetch_wait_ms as f64 / 1000.0)
                                        } else {
                                            0.0
                                        }
                                    ),
                                );
                                wc_log_line_android_or_stdout(&format!(
                                    "🧭 wallet_refresh stage=contiguous_scannable_blocks_ok wallet_id={} blocks={} fetch_wait_ms={} fetch_rpc_ms={} prefetch={} blocks_per_s={:.2}",
                                    id,
                                    v.len(),
                                    fetch_wait_ms,
                                    fetch_rpc_ms,
                                    batch_prefetch,
                                    if fetch_wait_ms > 0 {
                                        (v.len() as f64) / (fetch_wait_ms as f64 / 1000.0)
                                    } else {
                                        0.0
                                    }
                                ));
                            }
                            v
                        }
                        Ok(Err(err)) => {
                            let fetch_ms = fetch_wait_t0.elapsed().as_millis();
                            walletcore_log_line(
                                id,
                                snapshot.network,
                                &format!(
                                    "🧭 wallet_refresh stage=contiguous_scannable_blocks_error wallet_id={} fetch_ms={} err={}",
                                    id, fetch_ms, err
                                ),
                            );
                            wc_log_line_android_or_stdout(&format!(
                                "🧭 wallet_refresh stage=contiguous_scannable_blocks_error wallet_id={} fetch_ms={} err={}",
                                id, fetch_ms, err
                            ));
                            return record_error(
                                -16,
                                format!(
                                    "wallet_refresh: contiguous_scannable_blocks failed: {}",
                                    err
                                ),
                            );
                        }
                        Err(msg) => {
                            let fetch_ms = fetch_wait_t0.elapsed().as_millis();
                            let msg = format!(
                                "wallet_refresh: contiguous_scannable_blocks timeout/disconnect ({}) after {}s for heights {}..{}",
                                msg,
                                CONTIGUOUS_BLOCKS_TIMEOUT_SECS,
                                start_bn_local,
                                end_bn_inclusive_local
                            );
                            walletcore_log_line(
                                id,
                                snapshot.network,
                                &format!(
                                    "🧭 wallet_refresh stage=contiguous_scannable_blocks_timeout wallet_id={} fetch_ms={} err={}",
                                    id, fetch_ms, msg
                                ),
                            );
                            wc_log_line_android_or_stdout(&format!(
                                "🧭 wallet_refresh stage=contiguous_scannable_blocks_timeout wallet_id={} fetch_ms={} err={}",
                                id, fetch_ms, msg
                            ));
                            return record_error(-16, msg);
                        }
                    }
                }
            };
            // Do not reset fetch_retries here — parent-hash / reorg handling below uses a
            // separate bounded counter so probe failures cannot loop forever.

            if scannables.is_empty() {
                return record_error(
                    -16,
                    format!(
                        "wallet_refresh: contiguous_scannable_blocks returned 0 blocks for heights {}..{}",
                        scan_cursor,
                        end_exclusive.saturating_sub(1)
                    ),
                );
            }

            // Parent-hash anchor for the first returned block against our local tip.
            let expected_prev = recent_hash_at(
                working_recent_block_hashes_start_height,
                &working_recent_block_hashes,
                start_bn_u64.saturating_sub(1),
            );
            let actual_prev = scannables[0].block.header.previous;
            // Only open a probe transport when the parent actually diverges.
            let parent_probe = if expected_prev.is_some_and(|expected| expected != actual_prev) {
                walletcore_log_line(
                    id,
                    snapshot.network,
                    &format!(
                        "♻️ wallet_refresh stage=parent_hash_mismatch wallet_id={} height={} — probing reorg",
                        id, start_bn_u64
                    ),
                );
                match BlockingRpcTransport::new(&base_url) {
                    Ok(transport) => find_reorg_rewind_height(
                        snapshot.restore_height,
                        working_recent_block_hashes_start_height,
                        &working_recent_block_hashes,
                        |height| transport.get_block_hash_by_height_json(height),
                    )
                    .map_err(|_| ()),
                    Err(_) => Err(()),
                }
            } else {
                Ok(None)
            };
            match decide_parent_mismatch_action(
                expected_prev,
                actual_prev,
                parent_probe,
                reorg_probe_failures,
                REORG_PROBE_RETRY_LIMIT,
            ) {
                ParentMismatchAction::Continue => {}
                ParentMismatchAction::Rewind {
                    scan_from: rewind_to,
                    cancel_prefetch,
                } => {
                    scan_cursor = rewind_working_state_to_height(
                        snapshot.restore_height,
                        rewind_to,
                        &mut working_outputs,
                        &mut seen_outpoints,
                        &mut working_recent_block_hashes_start_height,
                        &mut working_recent_block_hashes,
                        &mut working_block_timestamps,
                    );
                    if cancel_prefetch {
                        #[cfg(not(target_os = "android"))]
                        {
                            let _ = clear_stale_prefetches(
                                &mut next_scannables_q,
                                &mut prefetch_in_flight,
                            );
                        }
                        #[cfg(target_os = "android")]
                        {
                            android_next_prefetch = None;
                        }
                    }
                    if let Err(code) = commit_refresh_checkpoint(
                        id,
                        scan_cursor,
                        daemon.height,
                        daemon.top_block_timestamp,
                        &working_outputs,
                        &seen_outpoints,
                        &known_tx_fees,
                        working_recent_block_hashes_start_height,
                        &working_recent_block_hashes,
                        &working_block_timestamps,
                    ) {
                        return code;
                    }
                    fetch_retries = 0;
                    reorg_probe_failures = 0;
                    continue;
                }
                ParentMismatchAction::Retry {
                    failures,
                    cancel_prefetch,
                } => {
                    reorg_probe_failures = failures;
                    if cancel_prefetch {
                        #[cfg(not(target_os = "android"))]
                        {
                            let _ = clear_stale_prefetches(
                                &mut next_scannables_q,
                                &mut prefetch_in_flight,
                            );
                        }
                        #[cfg(target_os = "android")]
                        {
                            android_next_prefetch = None;
                        }
                    }
                    std::thread::sleep(block_fetch_retry_delay(
                        reorg_probe_failures.saturating_sub(1),
                    ));
                    continue;
                }
                ParentMismatchAction::Abort {
                    failures,
                    cancel_prefetch,
                } => {
                    if cancel_prefetch {
                        #[cfg(not(target_os = "android"))]
                        {
                            let _ = clear_stale_prefetches(
                                &mut next_scannables_q,
                                &mut prefetch_in_flight,
                            );
                        }
                        #[cfg(target_os = "android")]
                        {
                            android_next_prefetch = None;
                        }
                    }
                    return record_error(
                        -16,
                        format!(
                            "wallet_refresh: parent hash mismatch at height {} and reorg probe failed after {} attempts",
                            start_bn_u64, failures
                        ),
                    );
                }
            }

            fetch_retries = 0;
            reorg_probe_failures = 0;

            let actual_end_bn_inclusive =
                start_bn.saturating_add(scannables.len().saturating_sub(1));
            let actual_next_height = next_height_after_response(start_bn_u64, scannables.len());

            // Daemons may legally stop get_blocks.bin before the requested end because of
            // response-size or transaction-count limits. Any deeper speculative requests were
            // calculated from the requested end and now leave a gap, so cancel them and rebase
            // the pipeline on the first height the daemon did not return.
            #[cfg(not(target_os = "android"))]
            if actual_next_height != end_exclusive {
                let (discarded_ready, aborted_in_flight) =
                    clear_stale_prefetches(&mut next_scannables_q, &mut prefetch_in_flight);
                if log_batch_events || discarded_ready > 0 || aborted_in_flight > 0 {
                    wc_log_line_android_or_stdout(&format!(
                        "🧭 wallet_refresh stage=prefetch_rebase wallet_id={} reason=partial_response requested_next={} actual_next={} returned_blocks={} discarded_ready={} aborted_in_flight={}",
                        id,
                        end_exclusive,
                        actual_next_height,
                        scannables.len(),
                        discarded_ready,
                        aborted_in_flight
                    ));
                }
            }

            // Ensure prefetch depth (non-Android only).
            #[cfg(not(target_os = "android"))]
            {
                let mut cursor_for_prefetch = actual_next_height;
                for _ in next_scannables_q.iter() {
                    cursor_for_prefetch = cursor_for_prefetch.saturating_add(upstream_block_batch);
                }
                for _ in prefetch_in_flight.iter() {
                    cursor_for_prefetch = cursor_for_prefetch.saturating_add(upstream_block_batch);
                }

                while prefetch_in_flight.len() + next_scannables_q.len() < prefetch_depth {
                    let next_start = cursor_for_prefetch;
                    let next_end_exclusive = core::cmp::min(
                        daemon.height,
                        next_start.saturating_add(upstream_block_batch),
                    );
                    if next_end_exclusive <= next_start {
                        break;
                    }
                    let next_end_inclusive = next_end_exclusive.saturating_sub(1);

                    let next_start_bn = match usize::try_from(next_start) {
                        Ok(v) => v,
                        Err(_) => {
                            return record_error(
                                -16,
                                "wallet_refresh: block number conversion overflow",
                            )
                        }
                    };
                    let next_end_bn = match usize::try_from(next_end_inclusive) {
                        Ok(v) => v,
                        Err(_) => {
                            return record_error(
                                -16,
                                "wallet_refresh: block number conversion overflow",
                            )
                        }
                    };

                    let prefetch_client = prefetch_rpc_client.clone();
                    let prefetch_base_url = base_url.clone();
                    let prefetch_mode = bulk_fetch_mode;
                    let prefetch_decode_pool = range_decode_pool.clone();
                    let handle = TOKIO_RUNTIME.spawn(async move {
                        let t0 = Instant::now();
                        let res = match prefetch_mode {
                            BulkFetchMode::RangeBlocks => fetch_scannable_blocks_range_bin(
                                &prefetch_client,
                                &prefetch_base_url,
                                next_start_bn,
                                next_end_bn,
                                prefetch_decode_pool.as_deref(),
                            ),
                            _ => prefetch_client
                                .contiguous_scannable_blocks(next_start_bn..=next_end_bn)
                                .await
                                .map_err(Into::into),
                        };
                        let prefetch_ms = t0.elapsed().as_millis();
                        (next_start, next_end_inclusive, prefetch_ms, res)
                    });
                    prefetch_in_flight.push_back(handle);

                    cursor_for_prefetch = next_end_exclusive;
                }
            }

            // Android one-ahead: start next fetch on the worker before scanning this batch.
            #[cfg(target_os = "android")]
            {
                if let Some((_, _, pending)) = android_next_prefetch.take() {
                    let _ = AndroidContiguousFetchWorker::wait_pending(
                        pending,
                        CONTIGUOUS_BLOCKS_TIMEOUT_SECS,
                    );
                }
                let next_start = (actual_end_bn_inclusive as u64).saturating_add(1);
                let next_end_exclusive = core::cmp::min(
                    daemon.height,
                    next_start.saturating_add(upstream_block_batch),
                );
                if next_end_exclusive > next_start {
                    let next_end_inclusive = next_end_exclusive.saturating_sub(1);
                    if let (Ok(next_start_bn), Ok(next_end_bn)) = (
                        usize::try_from(next_start),
                        usize::try_from(next_end_inclusive),
                    ) {
                        match android_fetch_worker.begin_fetch(next_start_bn, next_end_bn) {
                            Ok(pending) => {
                                if log_batch_events {
                                    wc_log_line_android_or_stdout(&format!(
                                        "🧭 wallet_refresh stage=android_prefetch_start wallet_id={} range={}..={}",
                                        id, next_start_bn, next_end_bn
                                    ));
                                }
                                android_next_prefetch =
                                    Some((next_start, next_end_inclusive, pending));
                            }
                            Err(msg) => {
                                wc_log_line_android_or_stdout(&format!(
                                    "🧭 wallet_refresh stage=android_prefetch_begin_failed wallet_id={} err={}",
                                    id, msg
                                ));
                            }
                        }
                    }
                }
            }

            // ---- Scan batch ----
            if log_batch_events {
                walletcore_log_line(
                    id,
                    snapshot.network,
                    &format!(
                        "🧪 wallet_refresh stage=scan_start wallet_id={} range={}..={} blocks={}",
                        id,
                        start_bn,
                        actual_end_bn_inclusive,
                        scannables.len()
                    ),
                );
                wc_log_line_android_or_stdout(&format!(
                    "🧪 wallet_refresh stage=scan_start wallet_id={} range={}..={} blocks={}",
                    id,
                    start_bn,
                    actual_end_bn_inclusive,
                    scannables.len()
                ));
            }

            let scan_t0 = Instant::now();
            let mut outputs_added_in_batch: usize = 0;
            let blocks_in_batch: usize = scannables.len();

            if refresh_cancelled_for_wallet(id) {
                return record_error(-30, "wallet_refresh: cancelled");
            }

            // Ownership scanning is independent per block. Compute it on the bounded pool, but
            // retain the original ScannableBlocks for ordered spend/fee/state application below.
            let mut parallel_scan_results = scan_pool.as_ref().and_then(|pool| {
                (scannables.len() > 1)
                    .then(|| scan_blocks_parallel_ordered(pool, &scanner, &scannables))
            });

            // Android-only: scan heartbeat (detect if we're CPU-bound vs deadlocked inside scan).
            #[cfg(target_os = "android")]
            let mut last_scan_heartbeat = Instant::now();

            // per-batch scannable completeness stats (optional)
            let mut batch_txs_total: usize = 0;
            let mut batch_txs_v1: usize = 0;
            let mut batch_txs_v2: usize = 0;
            let mut batch_txs_v2_proofs_some: usize = 0;
            let mut batch_txs_v2_proofs_none: usize = 0;
            let mut batch_txs_extra_nonempty: usize = 0;
            let mut batch_txs_outputs_nonzero: usize = 0;
            let mut batch_outputs_total: usize = 0;

            let mut th = scan_cursor;

            // Read watch controls once per batch.
            let watch_ki = watch_key_image_from_env();
            let watch_txid = watch_txid_from_env();

            for scannable in scannables {
                if refresh_cancelled_for_wallet(id) {
                    return record_error(-30, "wallet_refresh: cancelled");
                }

                // Android-only: heartbeat every ~5s during scan loop.
                #[cfg(target_os = "android")]
                {
                    if log_batch_events && last_scan_heartbeat.elapsed().as_secs() >= 5 {
                        last_scan_heartbeat = Instant::now();
                        walletcore_log_line(
                            id,
                            snapshot.network,
                            &format!(
                                "🧪 wallet_refresh stage=scan_heartbeat wallet_id={} height={} range={}..={} outputs_added_so_far={}",
                                id, th, start_bn, actual_end_bn_inclusive, outputs_added_in_batch
                            ),
                        );
                        wc_log_line_android_or_stdout(&format!(
                            "🧪 wallet_refresh stage=scan_heartbeat wallet_id={} height={} range={}..={} outputs_added_so_far={}",
                            id, th, start_bn, actual_end_bn_inclusive, outputs_added_in_batch
                        ));
                    }
                }

                // Recent hash history is part of the same working snapshot as outputs and
                // spends. Publish it only at a completed batch boundary.
                push_recent_block_hash_parts(
                    snapshot.restore_height,
                    &mut working_recent_block_hashes_start_height,
                    &mut working_recent_block_hashes,
                    th,
                    scannable.block.hash(),
                );

                let block_timestamp = scannable.block.header.timestamp;
                if block_timestamp > 0 && block_timestamp > daemon.top_block_timestamp {
                    daemon.top_block_timestamp = block_timestamp;
                }
                // Timestamps for history are recorded only when this height produces
                // wallet-relevant receives or spends (see after scan application below).

                let miner_hash = scannable.block.miner_transaction().hash();

                // Spend detection: build KI map from current working_outputs
                let mut key_image_to_output_index: HashMap<[u8; 32], usize> = HashMap::new();
                for (i, o) in working_outputs.iter().enumerate() {
                    if o.key_image != [0u8; 32] {
                        key_image_to_output_index.entry(o.key_image).or_insert(i);
                    }
                }

                // Aggregate gross spent per spending txid in this block (debug)
                let mut spent_inputs_by_txid: HashMap<[u8; 32], u64> = HashMap::new();

                // Miner tx inputs
                {
                    let tx = scannable.block.miner_transaction();
                    for input in &tx.prefix().inputs {
                        if let monero_wallet::transaction::Input::ToKey { key_image, .. } = input {
                            let ki_bytes = key_image.to_bytes();
                            if let Some(out_idx) = key_image_to_output_index.get(&ki_bytes).copied()
                            {
                                let spent_amount = working_outputs[out_idx].amount;
                                working_outputs[out_idx].spent = true;

                                let spend_txid = tx.hash();
                                working_outputs[out_idx].spending_txid = Some(spend_txid);
                                working_outputs[out_idx].spending_height = Some(th);
                                let e = spent_inputs_by_txid.entry(spend_txid).or_insert(0);
                                *e = e.saturating_add(spent_amount);

                                if walletcore_debug_spend_detect_enabled() {
                                    walletcore_log_line(
                                        id,
                                        snapshot.network,
                                        &format!(
                                            "🧾 spend_detected wallet_id={} spending_txid={} key_image={} spent_amount_piconero={} source_out_txid={} source_out_index={}",
                                            id,
                                            hex_dump_prefix(&spend_txid, 32),
                                            hex_dump_prefix(&ki_bytes, 32),
                                            spent_amount,
                                            hex_dump_prefix(&working_outputs[out_idx].tx_hash, 32),
                                            working_outputs[out_idx].index_in_tx
                                        ),
                                    );
                                }
                            }
                        }
                    }
                }

                // Non-miner tx inputs. Pair decoded txs with the block hash list — pruned
                // txs cannot be hashed, so `get(index)` going None used to mark our spend
                // without a txid and the later change output looked like a receive.
                fn is_miner_decoded(
                    tx: &monero_wallet::transaction::Transaction<
                        monero_wallet::transaction::Pruned,
                    >,
                ) -> bool {
                    tx.prefix()
                        .inputs
                        .first()
                        .map(|input| matches!(input, monero_wallet::transaction::Input::Gen(_)))
                        .unwrap_or(false)
                }

                let decoded_non_miner: &[monero_wallet::transaction::Transaction<
                    monero_wallet::transaction::Pruned,
                >] = match scannable.transactions.split_first() {
                    Some((first, rest))
                        if is_miner_decoded(first)
                            && scannable.transactions.len()
                                == scannable.block.transactions.len().saturating_add(1) =>
                    {
                        rest
                    }
                    _ => scannable.transactions.as_slice(),
                };

                // Fees are part of the pruned transaction data already fetched for scanning.
                // Keep only this block's compact txid -> fee lookup; values are promoted to the
                // wallet-level map only when a transaction receives to or spends from this wallet.
                let mut block_tx_fees: HashMap<[u8; 32], u64> =
                    HashMap::with_capacity(decoded_non_miner.len().saturating_add(1));
                block_tx_fees.insert(miner_hash, 0);
                for (txid, tx_ref) in scannable
                    .block
                    .transactions
                    .iter()
                    .copied()
                    .zip(decoded_non_miner.iter())
                {
                    if let Some(fee) = transaction_network_fee(tx_ref) {
                        block_tx_fees.insert(txid, fee);
                    }
                }

                let apply_spend =
                    |tx_ref: &monero_wallet::transaction::Transaction<
                        monero_wallet::transaction::Pruned,
                    >,
                     spend_txid: Option<[u8; 32]>,
                     working_outputs: &mut Vec<TrackedOutput>,
                     key_image_to_output_index: &HashMap<[u8; 32], usize>,
                     spent_inputs_by_txid: &mut HashMap<[u8; 32], u64>,
                     known_tx_fees: &mut HashMap<String, u64>| {
                        for input in &tx_ref.prefix().inputs {
                            if let monero_wallet::transaction::Input::ToKey { key_image, .. } =
                                input
                            {
                                let ki_bytes = key_image.to_bytes();

                                if let Some(watch) = watch_ki {
                                    if watch == ki_bytes && walletcore_debug_spend_detect_enabled()
                                    {
                                        let matched = key_image_to_output_index
                                            .get(&ki_bytes)
                                            .copied()
                                            .is_some();
                                        walletcore_log_line(
                                        id,
                                        snapshot.network,
                                        &format!(
                                            "🕵️ watch_key_image_seen wallet_id={} height={} spending_txid={} key_image={} matched_owned_output={}",
                                            id,
                                            th,
                                            match spend_txid {
                                                Some(txid) => hex_dump_prefix(&txid, 32),
                                                None => "(unknown)".to_string(),
                                            },
                                            hex_dump_prefix(&ki_bytes, 32),
                                            matched
                                        ),
                                    );
                                    }
                                }

                                if let Some(out_idx) =
                                    key_image_to_output_index.get(&ki_bytes).copied()
                                {
                                    let spent_amount = working_outputs[out_idx].amount;
                                    working_outputs[out_idx].spent = true;
                                    working_outputs[out_idx].spending_height = Some(th);
                                    if let Some(spend_txid) = spend_txid {
                                        if working_outputs[out_idx].spending_txid.is_none() {
                                            working_outputs[out_idx].spending_txid =
                                                Some(spend_txid);
                                        }
                                        let e = spent_inputs_by_txid.entry(spend_txid).or_insert(0);
                                        *e = e.saturating_add(spent_amount);
                                        if let Some(fee) = block_tx_fees.get(&spend_txid) {
                                            known_tx_fees
                                                .entry(hex_lowercase(&spend_txid))
                                                .or_insert(*fee);
                                        }
                                    }
                                    if walletcore_debug_spend_detect_enabled() {
                                        walletcore_log_line(
                                        id,
                                        snapshot.network,
                                        &format!(
                                            "🧾 spend_detected wallet_id={} spending_txid={} key_image={} spent_amount_piconero={} source_out_txid={} source_out_index={}",
                                            id,
                                            match spend_txid {
                                                Some(txid) => hex_dump_prefix(&txid, 32),
                                                None => "(unknown)".to_string(),
                                            },
                                            hex_dump_prefix(&ki_bytes, 32),
                                            spent_amount,
                                            hex_dump_prefix(&working_outputs[out_idx].tx_hash, 32),
                                            working_outputs[out_idx].index_in_tx
                                        ),
                                    );
                                    }
                                }
                            }
                        }
                    };

                for (spend_txid, tx_ref) in scannable
                    .block
                    .transactions
                    .iter()
                    .copied()
                    .zip(decoded_non_miner.iter())
                {
                    if let Some(watch) = watch_txid {
                        if watch == spend_txid {
                            walletcore_log_line(
                                id,
                                snapshot.network,
                                &format!(
                                    "🕵️ watch_spend_txid_seen wallet_id={} height={} spending_txid={}",
                                    id,
                                    th,
                                    hex_dump_prefix(&spend_txid, 32)
                                ),
                            );
                        }
                    }
                    apply_spend(
                        tx_ref,
                        Some(spend_txid),
                        &mut working_outputs,
                        &key_image_to_output_index,
                        &mut spent_inputs_by_txid,
                        &mut known_tx_fees,
                    );
                }

                if decoded_non_miner.len() > scannable.block.transactions.len() {
                    for tx_ref in decoded_non_miner
                        .iter()
                        .skip(scannable.block.transactions.len())
                    {
                        apply_spend(
                            tx_ref,
                            None,
                            &mut working_outputs,
                            &key_image_to_output_index,
                            &mut spent_inputs_by_txid,
                            &mut known_tx_fees,
                        );
                    }
                }

                // Spend summary throttling
                let spend_log_every_n_blocks = spend_log_every_n_blocks_from_env();
                if spend_log_every_n_blocks > 0 && (th % spend_log_every_n_blocks == 0) {
                    walletcore_log_line(
                        id,
                        snapshot.network,
                        &format!(
                            "🧾 spend_detection_summary wallet_id={} height={} distinct_spend_txs={}",
                            id,
                            th,
                            spent_inputs_by_txid.len(),
                        ),
                    );
                } else if !spent_inputs_by_txid.is_empty() {
                    walletcore_log_line(
                        id,
                        snapshot.network,
                        &format!(
                            "🧾 spend_detection_summary wallet_id={} height={} distinct_spend_txs={}",
                            id,
                            th,
                            spent_inputs_by_txid.len(),
                        ),
                    );
                }

                // Transaction completeness stats
                {
                    batch_txs_total = batch_txs_total.saturating_add(1);
                    match scannable.block.miner_transaction() {
                        Transaction::V1 { .. } => batch_txs_v1 = batch_txs_v1.saturating_add(1),
                        Transaction::V2 { proofs, .. } => {
                            batch_txs_v2 = batch_txs_v2.saturating_add(1);
                            if proofs.is_some() {
                                batch_txs_v2_proofs_some =
                                    batch_txs_v2_proofs_some.saturating_add(1);
                            } else {
                                batch_txs_v2_proofs_none =
                                    batch_txs_v2_proofs_none.saturating_add(1);
                            }
                        }
                    }
                    let miner_prefix = scannable.block.miner_transaction().prefix();
                    if !miner_prefix.extra.is_empty() {
                        batch_txs_extra_nonempty = batch_txs_extra_nonempty.saturating_add(1);
                    }
                    if !miner_prefix.outputs.is_empty() {
                        batch_txs_outputs_nonzero = batch_txs_outputs_nonzero.saturating_add(1);
                        batch_outputs_total =
                            batch_outputs_total.saturating_add(miner_prefix.outputs.len());
                    }
                }
                for tx_ref in &scannable.transactions {
                    batch_txs_total = batch_txs_total.saturating_add(1);
                    match tx_ref {
                        Transaction::V1 { .. } => batch_txs_v1 = batch_txs_v1.saturating_add(1),
                        Transaction::V2 { proofs, .. } => {
                            batch_txs_v2 = batch_txs_v2.saturating_add(1);
                            if proofs.is_some() {
                                batch_txs_v2_proofs_some =
                                    batch_txs_v2_proofs_some.saturating_add(1);
                            } else {
                                batch_txs_v2_proofs_none =
                                    batch_txs_v2_proofs_none.saturating_add(1);
                            }
                        }
                    }
                    let prefix = tx_ref.prefix();
                    if !prefix.extra.is_empty() {
                        batch_txs_extra_nonempty = batch_txs_extra_nonempty.saturating_add(1);
                    }
                    if !prefix.outputs.is_empty() {
                        batch_txs_outputs_nonzero = batch_txs_outputs_nonzero.saturating_add(1);
                        batch_outputs_total =
                            batch_outputs_total.saturating_add(prefix.outputs.len());
                    }
                }

                let dbg_this_height = debug_height
                    .map(|h| {
                        let w = debug_height_window;
                        th >= h.saturating_sub(w) && th <= h.saturating_add(w)
                    })
                    .unwrap_or(false);

                let should_log_this_height = if debug_height.is_some() {
                    dbg_this_height
                } else {
                    debug_txid.is_some()
                };

                if should_log_this_height {
                    if dbg_this_height {
                        walletcore_log_line(
                            id,
                            snapshot.network,
                            &format!(
                                "🧪 debug_target height={} txs_in_block={} (non_miner) miner_tx_hash={}",
                                th,
                                scannable.transactions.len(),
                                hex_dump_prefix(&scannable.block.miner_transaction().hash(), 32)
                            ),
                        );
                    }
                    if let Some(target) = debug_txid {
                        let mut contains = false;
                        for h in &scannable.block.transactions {
                            if *h == target {
                                contains = true;
                                break;
                            }
                        }
                        walletcore_log_line(
                            id,
                            snapshot.network,
                            &format!(
                                "🧪 debug_target_txid height={} target_txid={} block_contains={}",
                                th,
                                hex_dump_prefix(&target, 32),
                                contains
                            ),
                        );
                    }
                }

                let scan_result = match parallel_scan_results.as_mut() {
                    Some(results) => results.pop_front().unwrap_or_else(|| {
                        Err(ScanError::InvalidScannableBlock(
                            "parallel scanner returned too few results",
                        ))
                    }),
                    None => scanner
                        .scan(scannable)
                        .map(|result| result.ignore_additional_timelock()),
                };
                let outputs = match scan_result {
                    Ok(outputs) => outputs,
                    Err(err) => {
                        return record_error(
                            -16,
                            format!("wallet_refresh: scanner failed at height {}: {}", th, err),
                        );
                    }
                };

                for output in outputs {
                    let key = (output.transaction(), output.index_in_transaction());
                    if !seen_outpoints.insert(key) {
                        continue;
                    }

                    if let Some(target) = debug_txid {
                        if output.transaction() == target {
                            let (maj, min) = output
                                .subaddress()
                                .map(|idx| (idx.account(), idx.address()))
                                .unwrap_or((0, 0));
                            walletcore_log_line(
                                id,
                                snapshot.network,
                                &format!(
                                    "🧪 debug_target_match height={} txid={} out_index={} subaddr=({}, {}) amount_piconero={}",
                                    th,
                                    hex_dump_prefix(&target, 32),
                                    output.index_in_transaction(),
                                    maj,
                                    min,
                                    output.commitment().amount
                                ),
                            );
                        }
                    }

                    let (major, minor) = output
                        .subaddress()
                        .map(|idx| (idx.account(), idx.address()))
                        .unwrap_or((0, 0));

                    // Compute key image for this owned output so we can detect on-chain spends.
                    //
                    // IMPORTANT: We must use the exact same derivation as the send path; otherwise
                    // we cannot correlate daemon `is_key_image_spent` results back to tracked outputs,
                    // and sends can fail with confusing double_spend/invalid_input behavior.
                    //
                    // Use the shared helper (also used by send) to keep this consistent.
                    let key_image_bytes: [u8; 32] = derive_key_image_bytes(
                        &output,
                        master.spend_scalar,
                        master.view_scalar_ed,
                        major,
                        minor,
                    );

                    working_outputs.push(TrackedOutput {
                        tx_hash: output.transaction(),
                        index_in_tx: output.index_in_transaction(),
                        key_image: key_image_bytes,
                        amount: output.commitment().amount,
                        block_height: th,
                        additional_timelock: output.additional_timelock(),
                        is_coinbase: output.transaction() == miner_hash,
                        subaddress_major: major,
                        subaddress_minor: minor,
                        spent: false,
                        spending_txid: None,
                        spending_height: None,
                    });

                    if let Some(fee) = block_tx_fees.get(&output.transaction()) {
                        known_tx_fees
                            .entry(hex_lowercase(&output.transaction()))
                            .or_insert(*fee);
                    }

                    outputs_added_in_batch = outputs_added_in_batch.saturating_add(1);
                }

                // If a spend in this block was seen without a txid (hash list shorter than
                // decoded txs), attach it to the unique same-height change output.
                {
                    let mut unattr_idxs: Vec<usize> = Vec::new();
                    let mut unattr_spent: u64 = 0;
                    let mut change_txids: HashSet<[u8; 32]> = HashSet::new();
                    for (i, o) in working_outputs.iter().enumerate() {
                        if o.spent && o.spending_txid.is_none() && o.spending_height == Some(th) {
                            unattr_idxs.push(i);
                            unattr_spent = unattr_spent.saturating_add(o.amount);
                        } else if !o.spent && o.block_height == th {
                            change_txids.insert(o.tx_hash);
                        }
                    }
                    for i in &unattr_idxs {
                        change_txids.remove(&working_outputs[*i].tx_hash);
                    }
                    change_txids.retain(|txid| {
                        let incoming: u64 = working_outputs
                            .iter()
                            .filter(|o| !o.spent && o.block_height == th && o.tx_hash == *txid)
                            .map(|o| o.amount)
                            .sum();
                        incoming > 0 && incoming < unattr_spent
                    });
                    if !unattr_idxs.is_empty() && change_txids.len() == 1 {
                        let spend_txid = *change_txids.iter().next().expect("len == 1");
                        for i in unattr_idxs {
                            working_outputs[i].spending_txid = Some(spend_txid);
                        }
                    }
                }

                // Persist timestamps only for heights that touched this wallet.
                if block_timestamp > 0
                    && working_outputs.iter().any(|o| {
                        o.block_height == th || o.spending_height == Some(th)
                    })
                {
                    working_block_timestamps.insert(th, block_timestamp);
                }

                th = th.saturating_add(1);
            }

            let scan_ms = scan_t0.elapsed().as_millis();
            refresh_scan_ms_total = refresh_scan_ms_total.saturating_add(scan_ms);
            refresh_fetch_wait_ms_total =
                refresh_fetch_wait_ms_total.saturating_add(batch_fetch_wait_ms);
            refresh_fetch_rpc_ms_total =
                refresh_fetch_rpc_ms_total.saturating_add(batch_fetch_rpc_ms);
            refresh_blocks_total = refresh_blocks_total.saturating_add(blocks_in_batch);
            refresh_outputs_added_total =
                refresh_outputs_added_total.saturating_add(outputs_added_in_batch);
            refresh_batches_total = refresh_batches_total.saturating_add(1);

            let overlapped_ms = batch_fetch_rpc_ms.saturating_sub(batch_fetch_wait_ms);
            let likely_bound = if batch_fetch_wait_ms >= scan_ms {
                "fetch"
            } else if scan_ms > batch_fetch_wait_ms.saturating_mul(2) {
                "scan"
            } else {
                "balanced"
            };
            let timing_line = format!(
                "⏱️ wallet_refresh stage=batch_timing wallet_id={} range={}..={} blocks={} prefetch={} fetch_wait_ms={} fetch_rpc_ms={} overlapped_ms={} scan_ms={} likely_bound={}",
                id,
                start_bn,
                actual_end_bn_inclusive,
                blocks_in_batch,
                batch_prefetch,
                batch_fetch_wait_ms,
                batch_fetch_rpc_ms,
                overlapped_ms,
                scan_ms,
                likely_bound
            );
            walletcore_log_line(id, snapshot.network, &timing_line);
            wc_log_line_android_or_stdout(&timing_line);

            if log_batch_events {
                walletcore_log_line(
                    id,
                    snapshot.network,
                    &format!(
                        "🧪 wallet_refresh stage=scan_done wallet_id={} range={}..={} blocks={} outputs_added={} scan_ms={}",
                        id,
                        start_bn,
                        actual_end_bn_inclusive,
                        blocks_in_batch,
                        outputs_added_in_batch,
                        scan_ms
                    ),
                );
                wc_log_line_android_or_stdout(&format!(
                    "🧪 wallet_refresh stage=scan_done wallet_id={} range={}..={} blocks={} outputs_added={} scan_ms={}",
                    id,
                    start_bn,
                    actual_end_bn_inclusive,
                    blocks_in_batch,
                    outputs_added_in_batch,
                    scan_ms
                ));
            }

            if refresh_telemetry_enabled {
                walletcore_log_line(
                    id,
                    snapshot.network,
                    &format!(
                        "🧪 scannable_completeness wallet_id={} range={}..={} blocks={} txs_total={} txs_v1={} txs_v2={} v2_proofs_some={} v2_proofs_none={} txs_extra_nonempty={} txs_outputs_nonzero={} outputs_total={}",
                        id,
                        start_bn,
                        actual_end_bn_inclusive,
                        blocks_in_batch,
                        batch_txs_total,
                        batch_txs_v1,
                        batch_txs_v2,
                        batch_txs_v2_proofs_some,
                        batch_txs_v2_proofs_none,
                        batch_txs_extra_nonempty,
                        batch_txs_outputs_nonzero,
                        batch_outputs_total
                    ),
                );

                walletcore_log_line(
                    id,
                    snapshot.network,
                    &format!(
                        "📊 wallet_refresh batch_stats wallet_id={} range={}..={} blocks={} outputs_added={} scan_ms={} blocks_per_s={:.2} outputs_per_s={:.2}",
                        id,
                        start_bn,
                        actual_end_bn_inclusive,
                        blocks_in_batch,
                        outputs_added_in_batch,
                        scan_ms,
                        if scan_ms > 0 {
                            (blocks_in_batch as f64) / (scan_ms as f64 / 1000.0)
                        } else {
                            0.0
                        },
                        if scan_ms > 0 {
                            (outputs_added_in_batch as f64) / (scan_ms as f64 / 1000.0)
                        } else {
                            0.0
                        }
                    ),
                );
            }

            if log_batch_events {
                walletcore_log_line(
                    id,
                    snapshot.network,
                    &format!(
                        "💾 wallet_refresh stage=persist_start wallet_id={} range={}..={} next_scan_cursor={}",
                        id, start_bn, actual_end_bn_inclusive, th
                    ),
                );
                wc_log_line_android_or_stdout(&format!(
                    "💾 wallet_refresh stage=persist_start wallet_id={} range={}..={} next_scan_cursor={}",
                    id, start_bn, actual_end_bn_inclusive, th
                ));
            }

            persist_span_start = Some(Instant::now());

            // Drain prefetch tasks into ready queue (only await enough to keep moving).
            // Non-Android only; Android prefetch pipeline is disabled.
            #[cfg(not(target_os = "android"))]
            while next_scannables_q.is_empty() {
                let Some(handle) = prefetch_in_flight.pop_front() else {
                    break;
                };

                let join_wait_t0 = Instant::now();
                match TOKIO_RUNTIME.block_on(handle) {
                    Ok((pf_start, pf_end, pf_ms, Ok(v))) => {
                        let _ = join_wait_t0.elapsed().as_millis();
                        next_scannables_q.push_back((pf_start, pf_end, pf_ms, v));
                    }
                    Ok((_pf_start, _pf_end, _pf_ms, Err(err))) => {
                        let _ = join_wait_t0.elapsed().as_millis();
                        let err_s = err.to_string();
                        let msg = format!(
                            "🧭 wallet_refresh stage=contiguous_scannable_blocks_error wallet_id={} err={} (prefetch; falling back to sync fetch)",
                            id, err_s
                        );
                        walletcore_log_line(id, snapshot.network, &msg);
                        wc_log_line_android_or_stdout(&msg);
                        if is_json_batch_or_shape_error(&err_s)
                            && !matches!(bulk_fetch_mode, BulkFetchMode::RangeBlocks)
                        {
                            bulk_fetch_mode = BulkFetchMode::RangeBlocks;
                            wc_log_line_android_or_stdout(
                                "🧭 wallet_refresh stage=bulk_mode_switched_to_range reason=prefetch_json_batch",
                            );
                        }
                        if let Some(c) = rebuild_rpc_client_if_channel_closed(&base_url, &err_s) {
                            rpc_client = c;
                            if let Ok(c2) = connect_rpc_client(&base_url) {
                                prefetch_rpc_client = std::sync::Arc::new(c2);
                            }
                        }
                        prefetch_in_flight.clear();
                        break;
                    }
                    Err(join_err) => {
                        let _ = join_wait_t0.elapsed().as_millis();
                        wc_log_line_android_or_stdout(&format!(
                            "🧭 wallet_refresh stage=prefetch_join_error wallet_id={} err={} (falling back to sync fetch)",
                            id, join_err
                        ));
                        prefetch_in_flight.clear();
                        break;
                    }
                }
            }

            scan_cursor = th;

            // Commit a coherent restart point. The public cursor must never move ahead of the
            // outputs, spends, fees, ledger, balances, and hash history represented by a cache
            // export. If cancellation happens inside the next batch, this complete batch remains
            // the durable in-memory checkpoint and the partial batch is discarded.
            if let Err(code) = commit_refresh_checkpoint(
                id,
                scan_cursor,
                daemon.height,
                daemon.top_block_timestamp,
                &working_outputs,
                &seen_outpoints,
                &known_tx_fees,
                working_recent_block_hashes_start_height,
                &working_recent_block_hashes,
                &working_block_timestamps,
            ) {
                return code;
            }

            // Close this persist span now that we've advanced the cursor (per-batch persist boundary).
            if let Some(p0) = persist_span_start.take() {
                let persist_ms = p0.elapsed().as_millis();
                refresh_persist_ms_total = refresh_persist_ms_total.saturating_add(persist_ms);

                if log_batch_events {
                    walletcore_log_line(
                        id,
                        snapshot.network,
                        &format!(
                            "💾 wallet_refresh stage=persist_done wallet_id={} range={}..={} persist_ms={} new_last_scanned={}",
                            id, start_bn, actual_end_bn_inclusive, persist_ms, scan_cursor
                        ),
                    );
                    wc_log_line_android_or_stdout(&format!(
                        "💾 wallet_refresh stage=persist_done wallet_id={} range={}..={} persist_ms={} new_last_scanned={}",
                        id, start_bn, actual_end_bn_inclusive, persist_ms, scan_cursor
                    ));
                }
            }

            if log_batch_events {
                walletcore_log_line(
                    id,
                    snapshot.network,
                    &format!(
                        "✅ wallet_refresh stage=cursor_advance wallet_id={} last_scanned={}",
                        id, scan_cursor
                    ),
                );
                wc_log_line_android_or_stdout(&format!(
                    "✅ wallet_refresh stage=cursor_advance wallet_id={} last_scanned={}",
                    id, scan_cursor
                ));
            }
        }

        if scan_cursor < daemon.height {
            walletcore_log_line(
                id,
                snapshot.network,
                &format!(
                    "⚠️ wallet_refresh stopped before tip wallet_id={} last_scanned={} tip={}",
                    id, scan_cursor, daemon.height
                ),
            );
            wc_log_line_android_or_stdout(&format!(
                "⚠️ wallet_refresh stopped before tip wallet_id={} last_scanned={} tip={}",
                id, scan_cursor, daemon.height
            ));
        }
    }

    // Close trailing persist span.
    if let Some(p0) = persist_span_start.take() {
        refresh_persist_ms_total =
            refresh_persist_ms_total.saturating_add(p0.elapsed().as_millis());
    }

    // Final refresh summary
    {
        let total_ms = refresh_t0.elapsed().as_millis();
        let total_ms_u128: u128 = total_ms;

        let other_ms = total_ms_u128
            .saturating_sub(refresh_scan_ms_total)
            .saturating_sub(refresh_persist_ms_total)
            .saturating_sub(refresh_fetch_wait_ms_total);

        let likely_bound = if refresh_fetch_wait_ms_total >= refresh_scan_ms_total {
            "fetch"
        } else if refresh_scan_ms_total > refresh_fetch_wait_ms_total.saturating_mul(2) {
            "scan"
        } else {
            "balanced"
        };

        walletcore_log_line(
            id,
            snapshot.network,
            &format!(
                "📈 wallet_refresh summary wallet_id={} status=ok total_ms={} batches={} blocks={} outputs_added={} scan_ms_total={} fetch_wait_ms_total={} fetch_rpc_ms_total={} persist_ms_total={} other_ms={} likely_bound={}",
                id,
                total_ms,
                refresh_batches_total,
                refresh_blocks_total,
                refresh_outputs_added_total,
                refresh_scan_ms_total,
                refresh_fetch_wait_ms_total,
                refresh_fetch_rpc_ms_total,
                refresh_persist_ms_total,
                other_ms,
                likely_bound
            ),
        );
        wc_log_line_android_or_stdout(&format!(
            "📈 wallet_refresh summary wallet_id={} status=ok total_ms={} batches={} blocks={} outputs_added={} scan_ms_total={} fetch_wait_ms_total={} fetch_rpc_ms_total={} persist_ms_total={} other_ms={} likely_bound={}",
            id,
            total_ms,
            refresh_batches_total,
            refresh_blocks_total,
            refresh_outputs_added_total,
            refresh_scan_ms_total,
            refresh_fetch_wait_ms_total,
            refresh_fetch_rpc_ms_total,
            refresh_persist_ms_total,
            other_ms,
            likely_bound
        ));

        #[cfg(feature = "scanner-microprof")]
        {
            if let Some(mp) = scanner_microprof_snapshot(true) {
                let ns_to_ms = |ns: u64| -> u64 { ns / 1_000_000 };
                let ecdh_mul_us_per_miss = if mp.ecdh_cache_misses > 0 {
                    (mp.ns_ecdh_mul as f64) / (mp.ecdh_cache_misses as f64) / 1_000.0
                } else {
                    0.0
                };
                let scan_us_per_output = if mp.outputs_visited > 0 {
                    (mp.ns_scan_transaction as f64) / (mp.outputs_visited as f64) / 1_000.0
                } else {
                    0.0
                };

                walletcore_log_line(
                    id,
                    snapshot.network,
                    &format!(
                        "🧬 scanner_microprof wallet_id={} blocks={} txs_scanned={} outputs_visited={} ecdh_derivations={} ecdh_cache_hits={} ecdh_cache_misses={} viewtag_mismatch={} commitment_verify_attempts={} commitment_verify_fail={} outputs_matched={} extra_parse_fail={} tx_keys_missing={} ms_block_setup={} ms_scan_transaction={} ms_commitment_verify={} ms_ecdh_mul={} ms_ecdh_cache_lookup_hit={} ms_ecdh_cache_lookup_miss={} ms_output_derivations={} ms_subaddress_lookup={} ecdh_mul_us_per_miss={:.3} scan_us_per_output={:.3}",
                        id,
                        mp.blocks,
                        mp.txs_scanned,
                        mp.outputs_visited,
                        mp.ecdh_derivations,
                        mp.ecdh_cache_hits,
                        mp.ecdh_cache_misses,
                        mp.viewtag_mismatch,
                        mp.commitment_verify_attempts,
                        mp.commitment_verify_fail,
                        mp.outputs_matched,
                        mp.extra_parse_fail,
                        mp.tx_keys_missing,
                        ns_to_ms(mp.ns_block_setup),
                        ns_to_ms(mp.ns_scan_transaction),
                        ns_to_ms(mp.ns_commitment_verify),
                        ns_to_ms(mp.ns_ecdh_mul),
                        ns_to_ms(mp.ns_ecdh_cache_lookup_hit),
                        ns_to_ms(mp.ns_ecdh_cache_lookup_miss),
                        ns_to_ms(mp.ns_output_derivations),
                        ns_to_ms(mp.ns_subaddress_lookup),
                        ecdh_mul_us_per_miss,
                        scan_us_per_output
                    ),
                );
            }
        }
    }

    // Overall perf log
    if log_perf {
        let blocks_scanned =
            scan_cursor.saturating_sub(snapshot.last_scanned.max(snapshot.restore_height));
        let new_outputs = working_outputs.len().saturating_sub(initial_outputs);
        if let Some(start) = overall_start {
            let secs = start.elapsed().as_secs_f64();
            walletcore_diagnostic!(
                "wallet_refresh: scanned {} blocks; new_outputs={}; elapsed={:.3}s",
                blocks_scanned, new_outputs, secs
            );
        }
    }

    // Ensure even a zero-block refresh publishes a coherent chain/timestamp snapshot. Normal
    // scans already committed at every complete batch above, so this is cheap and idempotent.
    if let Err(code) = commit_refresh_checkpoint(
        id,
        scan_cursor,
        daemon.height,
        daemon.top_block_timestamp,
        &working_outputs,
        &seen_outpoints,
        &known_tx_fees,
        working_recent_block_hashes_start_height,
        &working_recent_block_hashes,
        &working_block_timestamps,
    ) {
        return code;
    }

    if !out_last_scanned.is_null() {
        unsafe {
            *out_last_scanned = scan_cursor.max(snapshot.restore_height);
        }
    }

    clear_last_error();
    0
}

#[cfg(test)]
mod tests {
    #[cfg(not(target_os = "android"))]
    use super::clear_stale_prefetches;
    use super::{
        automatic_scan_parallelism, commit_refresh_checkpoint, configured_range_decode_parallel,
        configured_scan_parallelism, configured_upstream_block_batch, decode_range_block_entry,
        decode_range_transaction, decide_parent_mismatch_action, decide_resume_reorg_action,
        default_range_decode_parallel_enabled, fetch_scannable_blocks_range_bin,
        finish_refresh_job, is_json_batch_or_shape_error, is_transient_block_fetch_error,
        next_height_after_response, scan_blocks_parallel_ordered, should_probe_reorg_on_resume,
        try_start_refresh_job, wallet_refresh_job_status_json, with_refresh_stopped,
        ParentMismatchAction, RangeFetchError, RefreshJob, ResumeReorgAction,
        PER_BATCH_TIP_PROBE_ENABLED, REORG_PROBE_RETRY_LIMIT,
    };
    use crate::support::{
        clear_last_error, last_error_clone, record_error, refresh_cancelled_for_wallet,
        set_refresh_cancel_for_wallet, RpcClient, TrackedOutput, WALLET_STORE,
    };
    use crate::{BlockingRpcTransport, PersistedWallet};
    use monero_interface::ScannableBlock;
    use monero_wallet::block::{Block as MoneroBlock, BlockHeader};
    use monero_wallet::transaction::{Input, Pruned, Timelock, Transaction, TransactionPrefix};
    use monero_wallet::{ScanError, Scanner};
    use rayon::prelude::*;
    use std::collections::{HashMap, HashSet, VecDeque};
    use std::ffi::CString;

    const TEST_MNEMONIC: &str =
        "ability pockets lordship tomorrow gypsy match neutral uncle avatar \
        betting bicycle junk unzip pyramid lynx mammal edgy empty uneven knowledge juvenile wiring \
        paradise psychic betting";

    fn open_test_wallet(id: &str, restore_height: u64) {
        let id = CString::new(id).expect("wallet id");
        let mnemonic = CString::new(TEST_MNEMONIC).expect("mnemonic");
        assert_eq!(
            crate::wallet_open_from_mnemonic(id.as_ptr(), mnemonic.as_ptr(), restore_height, 1,),
            0
        );
    }

    fn tracked_output(tag: u8, amount: u64, height: u64) -> TrackedOutput {
        TrackedOutput {
            tx_hash: [tag; 32],
            index_in_tx: 0,
            key_image: [tag.wrapping_add(1); 32],
            amount,
            block_height: height,
            additional_timelock: Timelock::None,
            is_coinbase: false,
            subaddress_major: 0,
            subaddress_minor: 0,
            spent: false,
            spending_txid: None,
            spending_height: None,
        }
    }

    fn unsupported_scannable_block(hardfork_version: u8, height: usize) -> ScannableBlock {
        let miner_transaction = Transaction::V1 {
            prefix: TransactionPrefix {
                additional_timelock: Timelock::None,
                inputs: vec![Input::Gen(height)],
                outputs: vec![],
                extra: vec![],
            },
            signatures: vec![],
        };
        let block = MoneroBlock::new(
            BlockHeader {
                hardfork_version,
                hardfork_signal: hardfork_version,
                timestamp: 0,
                previous: [0; 32],
                nonce: 0,
            },
            miner_transaction,
            vec![],
        )
        .expect("synthetic block");
        ScannableBlock {
            block,
            transactions: vec![],
            output_index_for_first_ringct_output: Some(0),
        }
    }

    #[test]
    fn scan_parallelism_defaults_and_override_are_bounded() {
        let automatic = automatic_scan_parallelism(64);
        assert!((1..=8).contains(&automatic));
        assert_eq!(configured_scan_parallelism(8, Some("0")), 1);
        assert_eq!(configured_scan_parallelism(8, Some("1")), 1);
        assert_eq!(configured_scan_parallelism(8, Some("3")), 3);
        assert_eq!(configured_scan_parallelism(4, Some("99")), 4);
        assert_eq!(
            configured_scan_parallelism(8, Some("auto")),
            automatic_scan_parallelism(8)
        );
        assert_eq!(
            configured_scan_parallelism(8, Some("invalid")),
            automatic_scan_parallelism(8)
        );
    }

    #[test]
    fn upstream_block_batch_defaults_and_override_are_bounded() {
        let default = crate::default_range_block_batch() as u64;
        assert_eq!(configured_upstream_block_batch(None), default);
        assert_eq!(configured_upstream_block_batch(Some("invalid")), default);
        assert_eq!(configured_upstream_block_batch(Some("0")), 1);
        assert_eq!(configured_upstream_block_batch(Some("750")), 750);
        assert_eq!(configured_upstream_block_batch(Some("1000")), 1_000);
        assert_eq!(configured_upstream_block_batch(Some("2000")), 1_000);
    }

    #[test]
    fn range_decode_parallel_default_and_override_are_explicit() {
        let default = default_range_decode_parallel_enabled();
        assert_eq!(configured_range_decode_parallel(None, default), default);
        assert_eq!(configured_range_decode_parallel(Some(""), default), default);
        assert!(configured_range_decode_parallel(Some("1"), false));
        assert!(configured_range_decode_parallel(Some("true"), false));
        assert!(!configured_range_decode_parallel(Some("0"), true));
        assert!(!configured_range_decode_parallel(Some("false"), true));
        assert!(!configured_range_decode_parallel(Some("off"), true));
    }

    #[test]
    fn partial_response_rebases_prefetch_on_actual_next_height() {
        let start = 3_519_450;
        let requested_end_exclusive = start + 500;

        assert_eq!(
            next_height_after_response(start, 500),
            requested_end_exclusive
        );
        assert_eq!(next_height_after_response(start, 287), start + 287);
        assert_ne!(
            next_height_after_response(start, 287),
            requested_end_exclusive
        );
        assert_eq!(next_height_after_response(u64::MAX - 1, 2), u64::MAX);
    }

    #[cfg(not(target_os = "android"))]
    #[test]
    fn stale_prefetch_pipeline_is_discarded_and_aborted() {
        let mut ready = VecDeque::from([1u8, 2u8]);
        let mut in_flight = VecDeque::from([
            crate::TOKIO_RUNTIME.spawn(std::future::pending::<()>()),
            crate::TOKIO_RUNTIME.spawn(std::future::pending::<()>()),
        ]);

        let counts = clear_stale_prefetches(&mut ready, &mut in_flight);

        assert_eq!(counts, (2, 2));
        assert!(ready.is_empty());
        assert!(in_flight.is_empty());
    }

    #[test]
    fn parallel_scan_results_remain_in_block_order() {
        let scanner = Scanner::new(
            crate::master_keys_from_mnemonic_str(TEST_MNEMONIC)
                .expect("keys")
                .to_view_pair()
                .expect("view pair"),
        );
        let blocks = (17u8..=20)
            .enumerate()
            .map(|(offset, version)| unsupported_scannable_block(version, 100 + offset))
            .collect::<Vec<_>>();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("scan pool");
        let results = scan_blocks_parallel_ordered(&pool, &scanner, &blocks);
        let errors = results
            .into_iter()
            .map(Result::unwrap_err)
            .collect::<Vec<_>>();
        assert_eq!(
            errors,
            vec![
                ScanError::UnsupportedProtocol(17),
                ScanError::UnsupportedProtocol(18),
                ScanError::UnsupportedProtocol(19),
                ScanError::UnsupportedProtocol(20),
            ]
        );
    }

    #[test]
    fn parallel_range_decode_results_remain_in_block_order() {
        let entries = (17u8..=20)
            .enumerate()
            .map(|(offset, version)| {
                let scannable = unsupported_scannable_block(version, 100 + offset);
                crate::support::bulk_models::BlockCompleteEntry {
                    block: scannable.block.serialize(),
                    txs: vec![],
                    pruned: true,
                }
            })
            .collect::<Vec<_>>();
        let expected_hashes = entries
            .iter()
            .map(|entry| {
                let mut reader = entry.block.as_slice();
                MoneroBlock::read(&mut reader)
                    .expect("synthetic block")
                    .hash()
            })
            .collect::<Vec<_>>();
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(2)
            .build()
            .expect("decode pool");

        let decoded = pool.install(|| {
            entries
                .into_par_iter()
                .enumerate()
                .map(|(index, entry)| {
                    decode_range_block_entry(index, entry)
                        .expect("range decode")
                        .block
                        .hash()
                })
                .collect::<Vec<_>>()
        });

        assert_eq!(decoded, expected_hashes);
    }

    #[test]
    #[ignore = "requires a live wallet RPC node"]
    fn live_parallel_scan_matches_serial_and_reports_speedup() {
        let base_url = std::env::var("WALLETCORE_TEST_NODE")
            .unwrap_or_else(|_| "https://rpc.nexatrode.com".to_string());
        let start = std::env::var("WALLETCORE_TEST_START_HEIGHT")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(3_519_450);
        let block_count = std::env::var("WALLETCORE_TEST_BLOCKS")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(300)
            .clamp(2, 500);
        let client: RpcClient = crate::TOKIO_RUNTIME
            .block_on(async {
                monero_simple_request_rpc::SimpleRequestTransport::new(base_url.clone()).await
            })
            .expect("failed to build rpc client");
        let blocks = fetch_scannable_blocks_range_bin(
            &client,
            &base_url,
            start,
            start.saturating_add(block_count).saturating_sub(1),
            None,
        )
        .expect("range fetch");

        let scanner = Scanner::new(
            crate::master_keys_from_mnemonic_str(TEST_MNEMONIC)
                .expect("keys")
                .to_view_pair()
                .expect("view pair"),
        );
        let serial_started = std::time::Instant::now();
        let mut serial_scanner = scanner.clone();
        let serial = blocks
            .iter()
            .cloned()
            .map(|block| {
                serial_scanner
                    .scan(block)
                    .map(|outputs| outputs.ignore_additional_timelock())
            })
            .collect::<Vec<_>>();
        let serial_elapsed = serial_started.elapsed();

        let threads = automatic_scan_parallelism(
            std::thread::available_parallelism()
                .map(std::num::NonZeroUsize::get)
                .unwrap_or(1),
        );
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(threads)
            .build()
            .expect("scan pool");
        let parallel_started = std::time::Instant::now();
        let parallel = scan_blocks_parallel_ordered(&pool, &scanner, &blocks)
            .into_iter()
            .collect::<Vec<_>>();
        let parallel_elapsed = parallel_started.elapsed();

        assert_eq!(parallel, serial);
        walletcore_diagnostic!(
            "live scan comparison: blocks={} threads={} serial_ms={} parallel_ms={} speedup={:.2}x",
            blocks.len(),
            threads,
            serial_elapsed.as_millis(),
            parallel_elapsed.as_millis(),
            serial_elapsed.as_secs_f64() / parallel_elapsed.as_secs_f64()
        );
    }

    #[test]
    fn completed_batch_checkpoint_is_cache_coherent() {
        let id = "checkpoint-cache-coherent";
        open_test_wallet(id, 100);
        let output = tracked_output(7, 42_000, 125);
        let outputs = vec![output.clone()];
        let seen = HashSet::from([(output.tx_hash, output.index_in_tx)]);
        let fees = HashMap::from([(crate::hex_lowercase(&output.tx_hash), 9_000)]);
        let hashes = vec![[3; 32], [4; 32]];

        commit_refresh_checkpoint(
            id,
            150,
            200,
            1_700_000_000,
            &outputs,
            &seen,
            &fees,
            149,
            &hashes,
            &HashMap::from([(125u64, 1_700_000_000u64)]),
        )
        .expect("checkpoint");

        let persisted = {
            let map = WALLET_STORE.lock().expect("wallet store");
            let state = map.get(id).expect("wallet");
            assert_eq!(state.last_scanned, 150);
            assert_eq!(state.total, 42_000);
            assert_eq!(state.tracked_outputs.len(), 1);
            assert_eq!(state.seen_outpoints, seen);
            assert_eq!(state.recent_block_hashes_start_height, 149);
            assert_eq!(state.recent_block_hashes, hashes);
            assert_eq!(
                state.block_timestamps.get(&125),
                Some(&1_700_000_000)
            );
            let ledger = state
                .tx_ledger
                .get(&crate::hex_lowercase(&output.tx_hash))
                .expect("incoming ledger row");
            assert_eq!(ledger.fee, Some(9_000));
            assert_eq!(ledger.timestamp, Some(1_700_000_000));
            PersistedWallet::from(state)
        };
        assert_eq!(persisted.last_scanned, 150);
        assert_eq!(persisted.tracked_outputs.len(), 1);
        WALLET_STORE.lock().expect("wallet store").remove(id);
    }

    #[test]
    fn uncommitted_partial_batch_cannot_advance_exported_cursor() {
        let id = "checkpoint-partial-discard";
        open_test_wallet(id, 100);
        let first = tracked_output(11, 10_000, 125);
        let committed_outputs = vec![first.clone()];
        let committed_seen = HashSet::from([(first.tx_hash, first.index_in_tx)]);
        commit_refresh_checkpoint(
            id,
            150,
            250,
            1_700_000_000,
            &committed_outputs,
            &committed_seen,
            &HashMap::new(),
            149,
            &[[1; 32], [2; 32]],
            &HashMap::new(),
        )
        .expect("first checkpoint");

        // Model cancellation halfway through the next batch: working state changes locally, but
        // no checkpoint call occurs. Cache export must still describe the complete first batch.
        let mut partial_outputs = committed_outputs;
        partial_outputs.push(tracked_output(12, 20_000, 175));
        assert_eq!(partial_outputs.len(), 2);
        let persisted = {
            let map = WALLET_STORE.lock().expect("wallet store");
            PersistedWallet::from(map.get(id).expect("wallet"))
        };
        assert_eq!(persisted.last_scanned, 150);
        assert_eq!(persisted.tracked_outputs.len(), 1);
        WALLET_STORE.lock().expect("wallet store").remove(id);
    }

    #[test]
    fn refresh_job_claim_prevents_cancel_token_revival() {
        let id = "refresh-job-exclusive";
        super::set_refresh_job(id, RefreshJob::Idle);
        set_refresh_cancel_for_wallet(id, false);
        assert!(try_start_refresh_job(id));
        set_refresh_cancel_for_wallet(id, true);
        assert!(!try_start_refresh_job(id));
        assert!(with_refresh_stopped(id, || ()).is_err());
        assert!(refresh_cancelled_for_wallet(id));

        finish_refresh_job(id, -30);
        assert_eq!(super::refresh_job(id), RefreshJob::Idle);
        assert!(try_start_refresh_job(id));
        finish_refresh_job(id, -30);
        assert!(with_refresh_stopped(id, || 42).is_ok_and(|value| value == 42));
    }

    #[test]
    fn refresh_job_status_retains_wallet_failure() {
        let id = "refresh-job-status-failure";
        super::set_refresh_job(id, RefreshJob::Failed("daemon rejected batch".into()));
        let id = CString::new(id).expect("wallet id");
        let pointer = wallet_refresh_job_status_json(id.as_ptr());
        assert!(!pointer.is_null());
        let json = unsafe { std::ffi::CStr::from_ptr(pointer) }
            .to_str()
            .expect("status utf8")
            .to_string();
        assert_eq!(
            serde_json::from_str::<serde_json::Value>(&json).expect("status json"),
            serde_json::json!({
                "state": "failed",
                "error": "daemon rejected batch",
            })
        );
        assert_eq!(crate::walletcore_free_cstr(pointer), 0);
        super::set_refresh_job(id.to_str().expect("wallet id utf8"), RefreshJob::Idle);
    }

    #[test]
    fn worker_error_survives_global_clear_from_polling_thread() {
        let (ready_tx, ready_rx) = std::sync::mpsc::channel();
        let (continue_tx, continue_rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || {
            clear_last_error();
            record_error(-16, "worker-owned failure");
            ready_tx.send(()).expect("signal ready");
            continue_rx.recv().expect("continue worker");
            last_error_clone()
        });

        ready_rx.recv().expect("worker ready");
        clear_last_error();
        continue_tx.send(()).expect("continue worker");
        assert_eq!(
            worker.join().expect("worker join").as_deref(),
            Some("worker-owned failure")
        );
    }

    fn synthetic_pruned_v2() -> (Vec<u8>, [u8; 32], [u8; 32]) {
        let transaction = Transaction::<Pruned>::V2 {
            prefix: TransactionPrefix {
                additional_timelock: Timelock::None,
                inputs: vec![Input::Gen(1)],
                outputs: vec![],
                extra: vec![],
            },
            proofs: None,
        };
        let prunable_hash = [0; 32];
        let transaction_hash = transaction
            .hash_with_prunable_hash(prunable_hash)
            .expect("v2 transaction should hash with a prunable hash");
        (transaction.serialize(), prunable_hash, transaction_hash)
    }
    #[test]
    fn decodes_and_verifies_pruned_range_transaction() {
        let (blob, prunable_hash, transaction_hash) = synthetic_pruned_v2();
        let decoded = decode_range_transaction(&blob, Some(prunable_hash), transaction_hash, 0, 0)
            .expect("valid pruned transaction should decode");

        assert_eq!(decoded.serialize(), blob);
    }

    #[test]
    fn requests_unpruned_retry_when_prunable_hash_is_missing() {
        let (blob, _, transaction_hash) = synthetic_pruned_v2();
        let result = decode_range_transaction(&blob, None, transaction_hash, 0, 0);

        assert!(matches!(result, Err(RangeFetchError::RetryUnpruned(_))));
    }

    #[test]
    fn rejects_pruned_transaction_hash_mismatch() {
        let (blob, prunable_hash, mut transaction_hash) = synthetic_pruned_v2();
        transaction_hash[0] ^= 1;
        let result = decode_range_transaction(&blob, Some(prunable_hash), transaction_hash, 0, 0);

        assert!(matches!(result, Err(RangeFetchError::Rpc(_))));
    }

    #[test]
    fn cuprate_json_batch_error_is_not_transient() {
        let err = "invalid node (response wasn't the expected json)";
        assert!(is_json_batch_or_shape_error(err));
        assert!(!is_transient_block_fetch_error(err));
        assert!(is_json_batch_or_shape_error(
            "HTTP 422 Unprocessable Entity"
        ));
        assert!(is_transient_block_fetch_error(
            "interface error (Hyper(hyper::Error(ChannelClosed)))"
        ));
        assert!(!is_json_batch_or_shape_error(
            "interface error (Hyper(hyper::Error(ChannelClosed)))"
        ));
    }

    #[test]
    #[ignore = "requires a live wallet RPC node"]
    fn debug_live_range_fetch_against_local_daemon() {
        let base_url = std::env::var("WALLETCORE_TEST_NODE")
            .unwrap_or_else(|_| "http://127.0.0.1:18092".to_string());
        let client: RpcClient = crate::TOKIO_RUNTIME
            .block_on(async {
                monero_simple_request_rpc::SimpleRequestTransport::new(base_url.clone()).await
            })
            .expect("failed to build rpc client");

        let blocks =
            fetch_scannable_blocks_range_bin(&client, &base_url, 3_630_413, 3_630_437, None)
                .unwrap_or_else(|e| panic!("range fetch failed: {e}"));

        walletcore_diagnostic!("fetched scannable blocks={}", blocks.len());
        assert_eq!(blocks.len(), 25);
    }

    #[test]
    #[ignore = "requires a live wallet RPC node"]
    fn debug_live_range_fetch_ios_window_against_local_daemon() {
        let base_url = "http://127.0.0.1:18092";
        let client: RpcClient = crate::TOKIO_RUNTIME
            .block_on(async {
                monero_simple_request_rpc::SimpleRequestTransport::new(base_url.to_string()).await
            })
            .expect("failed to build rpc client");

        let blocks =
            fetch_scannable_blocks_range_bin(&client, base_url, 3_519_450, 3_519_474, None)
                .unwrap_or_else(|e| panic!("range fetch failed: {e}"));

        walletcore_diagnostic!("fetched iOS-window scannable blocks={}", blocks.len());
        assert_eq!(blocks.len(), 25);
    }

    #[test]
    #[ignore = "requires a live wallet RPC node"]
    fn debug_live_get_o_indexes_response_shape() {
        let base_url = "http://127.0.0.1:18092";
        let transport = BlockingRpcTransport::new(base_url).expect("transport init failed");
        let resp = transport
            .get_blocks_bin(3_630_413, 25, true)
            .expect("get_blocks_bin failed");

        let first = resp.blocks.first().expect("missing first block");
        let mut block_reader: &[u8] = first.block.as_slice();
        let block = MoneroBlock::read(&mut block_reader).expect("block decode failed");
        let tx_hash = *block.transactions.first().expect("missing first tx hash");

        let request = [
            b"\x01\x11\x01\x01\x01\x01\x02\x01".as_slice(),
            &[1u8],
            &[1 << 2],
            &[4u8],
            b"txid".as_slice(),
            &[10u8],
            &[32 << 2],
            &tx_hash,
        ]
        .concat();

        let tx_hash_hex: String = tx_hash.iter().map(|b| format!("{b:02x}")).collect();
        match ureq::post(&format!("{base_url}/get_o_indexes.bin"))
            .set("Content-Type", "application/octet-stream")
            .send(std::io::Cursor::new(&request))
        {
            Ok(response) => {
                let mut reader = response.into_reader();
                let mut response = Vec::new();
                std::io::Read::read_to_end(&mut reader, &mut response)
                    .expect("read response failed");

                std::fs::write("/tmp/get_o_indexes_first_tx.bin", &response)
                    .expect("write sample failed");
                walletcore_diagnostic!(
                    "get_o_indexes response bytes={} tx_hash={} prefix={}",
                    response.len(),
                    tx_hash_hex,
                    crate::support::bulk_bin::hex_dump_prefix(&response, 96)
                );
            }
            Err(ureq::Error::Status(code, response)) => {
                walletcore_diagnostic!(
                    "get_o_indexes unavailable status={} tx_hash={} url={}",
                    code,
                    tx_hash_hex,
                    response.get_url()
                );
                assert_eq!(code, 404);
            }
            Err(err) => panic!("get_o_indexes.bin request failed: {err}"),
        }
    }

    /// Exercises the same control decisions the range-refresh loop uses for reorgs:
    /// one-time resume probe, parent mismatch, prefetch cancellation, bounded probe
    /// failure, rewind, and replacement-chain continuation — without a live daemon.
    #[test]
    fn range_refresh_reorg_control_path_resume_parent_prefetch_and_bound() {
        assert!(!PER_BATCH_TIP_PROBE_ENABLED);
        assert!(!should_probe_reorg_on_resume(0));
        assert!(should_probe_reorg_on_resume(4));

        let restore = 1_000u64;
        let window_start = 1_100u64;
        let local_hashes = vec![[1; 32], [2; 32], [3; 32], [4; 32]]; // 1100..1103
        let mut tip_rpc_calls = 0u32;

        // --- Resume: one tip probe finds shallow fork, rewind below cursor. ---
        let mut scan_cursor = 1_104u64;
        let resume_probe = {
            tip_rpc_calls += 1;
            crate::find_reorg_rewind_height(restore, window_start, &local_hashes, |h| {
                if h == 1_103 {
                    Ok::<_, ()>([9; 32])
                } else {
                    Ok(local_hashes[(h - window_start) as usize])
                }
            })
            .unwrap()
        };
        assert_eq!(tip_rpc_calls, 1, "resume must probe exactly once");
        let resume = decide_resume_reorg_action(scan_cursor, Ok(resume_probe)).unwrap();
        assert_eq!(
            resume,
            ResumeReorgAction::Rewind { scan_from: 1_103 }
        );

        let keep_tx = [10u8; 32];
        let drop_tx = [11u8; 32];
        let spend_tx = [12u8; 32];
        let mut outputs = vec![
            {
                let mut o = tracked_output(10, 7_000, 1_090);
                o.tx_hash = keep_tx;
                o
            },
            {
                let mut o = tracked_output(11, 3_000, 1_103);
                o.tx_hash = drop_tx;
                o
            },
            {
                let mut o = tracked_output(10, 500, 1_090);
                o.tx_hash = keep_tx;
                o.index_in_tx = 1;
                o.spent = true;
                o.spending_txid = Some(spend_tx);
                o.spending_height = Some(1_103);
                o
            },
        ];
        let mut seen = HashSet::from([(keep_tx, 0), (drop_tx, 0), (keep_tx, 1)]);
        let mut recent_start = window_start;
        let mut recent = local_hashes.clone();
        let mut times = HashMap::from([(1_090u64, 1), (1_103u64, 2)]);
        if let ResumeReorgAction::Rewind { scan_from } = resume {
            scan_cursor = crate::rewind_working_state_to_height(
                restore,
                scan_from,
                &mut outputs,
                &mut seen,
                &mut recent_start,
                &mut recent,
                &mut times,
            );
        }
        assert_eq!(scan_cursor, 1_103);
        assert_eq!(outputs.len(), 2);
        assert!(outputs.iter().any(|o| o.index_in_tx == 1 && !o.spent));
        assert!(!seen.contains(&(drop_tx, 0)));

        // --- Steady batches: matching parent → Continue; no tip RPC. ---
        let tip_before_batches = tip_rpc_calls;
        let local_tip = *recent.last().unwrap();
        for _ in 0..3 {
            let action = decide_parent_mismatch_action(
                Some(local_tip),
                local_tip,
                Ok(None), // unused when parents match
                0,
                REORG_PROBE_RETRY_LIMIT,
            );
            assert_eq!(action, ParentMismatchAction::Continue);
        }
        assert_eq!(
            tip_rpc_calls, tip_before_batches,
            "matching parents must not add tip probes"
        );

        // --- Parent mismatch: cancel prefetch, rewind onto replacement chain. ---
        #[cfg(not(target_os = "android"))]
        let mut ready = VecDeque::from([1u8, 2, 3]);
        #[cfg(not(target_os = "android"))]
        let mut in_flight: VecDeque<tokio::task::JoinHandle<()>> = VecDeque::new();
        let fork_parent = [0xEE; 32];
        tip_rpc_calls += 1;
        let mid_probe = crate::find_reorg_rewind_height(restore, recent_start, &recent, |h| {
            if h >= 1_102 {
                Ok::<_, ()>([9; 32])
            } else {
                Ok(recent[(h - recent_start) as usize])
            }
        })
        .unwrap();
        let mismatch = decide_parent_mismatch_action(
            Some(local_tip),
            fork_parent,
            Ok(mid_probe),
            0,
            REORG_PROBE_RETRY_LIMIT,
        );
        match mismatch {
            ParentMismatchAction::Rewind {
                scan_from,
                cancel_prefetch,
            } => {
                assert!(cancel_prefetch);
                assert_eq!(scan_from, 1_102);
                #[cfg(not(target_os = "android"))]
                {
                    let (discarded, aborted) = clear_stale_prefetches(&mut ready, &mut in_flight);
                    assert_eq!(discarded, 3);
                    assert_eq!(aborted, 0);
                    assert!(ready.is_empty());
                }
                scan_cursor = crate::rewind_working_state_to_height(
                    restore,
                    scan_from,
                    &mut outputs,
                    &mut seen,
                    &mut recent_start,
                    &mut recent,
                    &mut times,
                );
            }
            other => panic!("expected rewind, got {other:?}"),
        }
        assert_eq!(scan_cursor, 1_102);
        // Replacement-chain continuation: cursor is at fork point; pre-fork outputs remain.
        assert!(outputs.iter().all(|o| o.block_height < 1_102));
        assert!(outputs.iter().any(|o| o.tx_hash == keep_tx && o.amount == 7_000));

        // --- Bounded probe failure: retries then Abort (never infinite). ---
        let mut failures = 0u32;
        let mut saw_abort = false;
        for _ in 0..(REORG_PROBE_RETRY_LIMIT + 2) {
            match decide_parent_mismatch_action(
                Some([1; 32]),
                [2; 32],
                Err(()),
                failures,
                REORG_PROBE_RETRY_LIMIT,
            ) {
                ParentMismatchAction::Retry {
                    failures: next,
                    cancel_prefetch,
                } => {
                    assert!(cancel_prefetch);
                    failures = next;
                }
                ParentMismatchAction::Abort {
                    failures: next,
                    cancel_prefetch,
                } => {
                    assert!(cancel_prefetch);
                    assert!(next > REORG_PROBE_RETRY_LIMIT);
                    saw_abort = true;
                    break;
                }
                other => panic!("expected retry/abort, got {other:?}"),
            }
        }
        assert!(saw_abort, "probe failures must abort after the bound");

        // Resume probe hard failure surfaces as Err (refresh returns recoverable error).
        let resume_err = decide_resume_reorg_action(scan_cursor, Err("daemon 502".into()));
        assert!(resume_err.is_err());
    }
}

#[no_mangle]
pub extern "C" fn wallet_refresh_async(wallet_id: *const c_char, node_url: *const c_char) -> c_int {
    clear_last_error();

    if wallet_id.is_null() {
        return record_error(-11, "wallet_refresh_async: wallet_id pointer was null");
    }

    let id_str = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            return record_error(
                -10,
                "wallet_refresh_async: wallet_id contained invalid UTF-8",
            )
        }
    };

    if id_str.is_empty() {
        return record_error(-14, "wallet_refresh_async: wallet_id was empty");
    }

    let id_owned = id_str.to_string();

    let node_owned = if node_url.is_null() {
        None
    } else {
        match unsafe { CStr::from_ptr(node_url) }.to_str() {
            Ok(s) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            Err(_) => {
                return record_error(
                    -10,
                    "wallet_refresh_async: node_url contained invalid UTF-8",
                )
            }
        }
    };

    if !try_start_refresh_job(&id_owned) {
        return record_error(
            -31,
            format!(
                "wallet_refresh_async: refresh already running for wallet '{}'",
                id_owned
            ),
        );
    }
    // Only the job that successfully claimed this wallet may clear its cancellation token.
    // A racing restart must not revive the previous worker before it observes cancellation.
    set_refresh_cancel_for_wallet(&id_owned, false);
    std::thread::spawn(move || {
        if let Ok(wallet_cstr) = CString::new(id_owned.clone()) {
            let node_cstr = node_owned.and_then(|url| CString::new(url).ok());
            let mut last_scanned: u64 = 0;
            let node_ptr = node_cstr
                .as_ref()
                .map(|c| c.as_ptr())
                .unwrap_or(std::ptr::null::<c_char>());
            let rc = wallet_refresh_caught(
                wallet_cstr.as_ptr(),
                node_ptr,
                &mut last_scanned as *mut u64,
            );
            if rc != 0 && rc != -30 {
                let msg = last_error_clone().unwrap_or_else(|| format!("refresh stopped ({rc})"));
                wc_log_line_android_or_stdout(&format!(
                    "🧭 wallet_refresh_async finished wallet_id={} rc={} err={}",
                    id_owned, rc, msg
                ));
            }
            finish_refresh_job(&id_owned, rc);
        } else {
            set_refresh_job(
                &id_owned,
                RefreshJob::Failed("wallet_id contained an interior NUL".into()),
            );
        }
    });

    0
}

/// Return the authoritative per-wallet async refresh state as JSON.
///
/// The returned string has the shape `{ "state": "idle|running|failed", "error": string|null }`
/// and must be released with `walletcore_free_cstr`. Unlike the legacy process-global last-error
/// slot, a failed state remains attached to this wallet until its next refresh starts.
#[no_mangle]
pub extern "C" fn wallet_refresh_job_status_json(wallet_id: *const c_char) -> *mut c_char {
    clear_last_error();

    if wallet_id.is_null() {
        record_error(
            -11,
            "wallet_refresh_job_status_json: wallet_id pointer was null",
        );
        return std::ptr::null_mut();
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(value) if !value.trim().is_empty() => value.trim(),
        Ok(_) => {
            record_error(-14, "wallet_refresh_job_status_json: wallet_id was empty");
            return std::ptr::null_mut();
        }
        Err(_) => {
            record_error(
                -10,
                "wallet_refresh_job_status_json: wallet_id contained invalid UTF-8",
            );
            return std::ptr::null_mut();
        }
    };

    match CString::new(refresh_job_status_json(id)) {
        Ok(value) => value.into_raw(),
        Err(_) => {
            record_error(
                -20,
                "wallet_refresh_job_status_json: status contained an interior NUL",
            );
            std::ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn wallet_sync_status(
    wallet_id: *const c_char,
    out_chain_height: *mut u64,
    out_chain_time: *mut u64,
    out_last_refresh_timestamp: *mut u64,
    out_last_scanned: *mut u64,
    out_restore_height: *mut u64,
) -> c_int {
    clear_last_error();

    if wallet_id.is_null() {
        return record_error(-11, "wallet_sync_status: wallet_id pointer was null");
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            return record_error(-10, "wallet_sync_status: wallet_id contained invalid UTF-8")
        }
    };

    let map = WALLET_STORE.lock().expect("wallet store poisoned");
    let Some(state) = map.get(id) else {
        return record_error(-13, format!("wallet_sync_status: wallet '{id}' not opened"));
    };

    if !out_chain_height.is_null() {
        unsafe {
            *out_chain_height = state.chain_height;
        }
    }
    if !out_chain_time.is_null() {
        unsafe {
            *out_chain_time = state.chain_time;
        }
    }
    if !out_last_refresh_timestamp.is_null() {
        unsafe {
            *out_last_refresh_timestamp = state.last_refresh_timestamp;
        }
    }
    if !out_last_scanned.is_null() {
        unsafe {
            *out_last_scanned = state.last_scanned;
        }
    }
    if !out_restore_height.is_null() {
        unsafe {
            *out_restore_height = state.restore_height;
        }
    }

    0
}
