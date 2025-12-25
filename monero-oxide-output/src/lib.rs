use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    convert::TryInto,
    ffi::{CStr, CString},
    future::Future,
    io::Read,
    os::raw::{c_char, c_int},
    ptr, slice,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Duration,
};

// (moved into the main std::sync import above)

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

fn build_stamp() -> &'static str {
    // Prefer a compile-time stamp if provided by the build system.
    //
    // Fallback: "unknown" (still useful to prove whether you're running a build that includes this log).
    option_env!("WALLETCORE_BUILD_STAMP").unwrap_or("unknown")
}

fn bulk_mode_str(mode: BulkFetchMode) -> &'static str {
    match mode {
        BulkFetchMode::Wallet2FastBlocks => "wallet2(getblocks.bin)",
        BulkFetchMode::RangeBlocks => "range(get_blocks.bin)",
        BulkFetchMode::PerBlock => "per_block",
    }
}

fn read_epee_field_name<B: Buf>(r: &mut B) -> cuprate_epee_encoding::error::Result<String> {
    let name_len = skip_epee_varint_u64(r)?;
    let name_len_usize = usize::try_from(name_len).map_err(|_| {
        cuprate_epee_encoding::error::Error::Format("read_epee_field_name: name length overflow")
    })?;
    if r.remaining() < name_len_usize {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "read_epee_field_name: EOF reading field name",
        ));
    }
    let bytes = r.copy_to_bytes(name_len_usize);
    let s = std::str::from_utf8(&bytes).map_err(|_| {
        cuprate_epee_encoding::error::Error::Format("read_epee_field_name: invalid UTF-8")
    })?;
    Ok(s.to_string())
}

fn read_epee_len_prefixed_bytes<B: Buf>(
    r: &mut B,
    ctx: &'static str,
) -> cuprate_epee_encoding::error::Result<Vec<u8>> {
    let len = skip_epee_varint_u64(r)?;
    let len_usize = usize::try_from(len).map_err(|_| {
        cuprate_epee_encoding::error::Error::Format(Box::leak(
            format!("{ctx}: length overflow").into_boxed_str(),
        ))
    })?;
    if r.remaining() < len_usize {
        return Err(cuprate_epee_encoding::error::Error::Format(Box::leak(
            format!("{ctx}: EOF reading bytes").into_boxed_str(),
        )));
    }
    Ok(r.copy_to_bytes(len_usize).to_vec())
}

// Non-destructive peek of Monero portable_storage varint (LEB128-style) from a byte slice.
// Returns (value, bytes_used) if the varint is well-formed and fits in u64.
fn peek_epee_varint_u64(bytes: &[u8]) -> Option<(u64, usize)> {
    let mut out: u64 = 0;
    let mut shift: u32 = 0;

    for (i, &b) in bytes.iter().enumerate() {
        let low = (b & 0x7f) as u64;

        // Prevent overflow / nonsense shifts
        if shift >= 64 {
            return None;
        }

        out |= low.checked_shl(shift)? as u64;

        if (b & 0x80) == 0 {
            return Some((out, i + 1));
        }

        shift = shift.saturating_add(7);

        // Monero varints are small; cap to a sane maximum number of bytes for u64.
        if i >= 9 {
            return None;
        }
    }

    None
}

fn hex_dump_prefix(bytes: &[u8], max_len: usize) -> String {
    let dump_len = std::cmp::min(max_len, bytes.len());
    let mut hex = String::new();
    for (i, b) in bytes[..dump_len].iter().enumerate() {
        if i > 0 {
            hex.push(' ');
        }
        hex.push_str(&format!("{:02x}", b));
    }
    hex
}

fn is_supported_blob_marker(marker: u8) -> bool {
    // Portable storage "string/blob-like" markers we have observed from monerod in the wild.
    // `0x0a` / `0x0b` are the classic ones. We also treat `0xba` / `0xcf` as blob-like
    // based on previous observations in getblocks.bin tx blobs.
    matches!(marker, 0x0a | 0x0b | 0xba | 0xcf)
}

/// Try to decode a `BlockCompleteEntry` object from a blob payload.
///
/// Some daemons appear to encode `blocks` as a typed array whose elements are *blobs*, where each blob
/// is itself a portable_storage object payload for `block_complete_entry`.
///
/// Returns:
/// - `Ok(Some(entry))` if the blob payload decodes as a `BlockCompleteEntry`
/// - `Ok(None)` if it does not look like a valid entry (so caller can treat payload as raw bytes)
/// - `Err(e)` only for hard format errors we want to surface
fn try_decode_block_complete_entry_from_blob_payload(
    payload: &[u8],
) -> cuprate_epee_encoding::error::Result<Option<BlockCompleteEntry>> {
    if payload.is_empty() {
        return Ok(None);
    }

    // Attempt to decode as an object payload:
    // [field_count varint] then repeated [field_name][field_value]
    let mut r: &[u8] = payload;

    let fields = match skip_epee_varint_u64(&mut r) {
        Ok(v) => v,
        Err(_) => return Ok(None),
    };

    // Defensive: reject obviously insane field counts (avoid huge loops on garbage data).
    if fields > 1000 {
        return Ok(None);
    }

    let mut builder = BlockCompleteEntryBuilder::default();

    for _ in 0..fields {
        let name = match read_epee_field_name(&mut r) {
            Ok(v) => v,
            Err(_) => return Ok(None),
        };

        // If the blob isn't actually a `block_complete_entry`, the builder should return `Ok(false)`
        // for unknown fields; that’s fine — we still want to skip the value correctly.
        match <BlockCompleteEntryBuilder as cuprate_epee_encoding::EpeeObjectBuilder<
            BlockCompleteEntry,
        >>::add_field(&mut builder, &name, &mut r)
        {
            Ok(true) => {}
            Ok(false) => {
                // Unknown field: we must still skip its value. The builder didn't consume it,
                // so consume it here by reading the marker and skipping the value.
                if !r.has_remaining() {
                    return Ok(None);
                }
                let marker = r.get_u8();
                skip_epee_value_with_known_marker(&mut r, marker)?;
            }
            Err(_) => return Ok(None),
        }
    }

    match <BlockCompleteEntryBuilder as cuprate_epee_encoding::EpeeObjectBuilder<
        BlockCompleteEntry,
    >>::finish(builder)
    {
        Ok(entry) => Ok(Some(entry)),
        Err(_) => Ok(None),
    }
}

/// Spec-driven typed-array parser for the observed `txs` encoding in wallet2 `/getblocks.bin`.
///
/// Observed on your daemon:
/// - marker 0x8c
/// - varint count
/// - small schema header that includes an element type name (e.g. "blob")
/// - then N elements encoded as length-prefixed byte blobs
///
/// Instead of guessing multiple blob markers (0xba/0xcf/...), we rely on the embedded element type name.
/// For element_type="blob", we decode each element as a length-prefixed byte sequence.
///
/// If we encounter an unexpected element type, we skip elements generically to keep the cursor aligned.
fn read_txs_typed_array_0x8c<B: Buf>(
    r: &mut B,
) -> cuprate_epee_encoding::error::Result<Vec<Vec<u8>>> {
    // Dump 1: container start (includes 0x8c marker) – helps reverse-engineer the full container layout.
    if bulk_bin_debug_enabled() {
        let chunk0 = r.chunk();
        if !chunk0.is_empty() {
            let hex = hex_dump_prefix(chunk0, 64);
            println!(
                "🧩 txs(0x8c) dump@container_start bytes[0..{}]={}",
                std::cmp::min(64, chunk0.len()),
                hex
            );
        } else {
            println!("🧩 txs(0x8c) dump@container_start: (unavailable)");
        }
    }

    if !r.has_remaining() {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "read_txs_typed_array_0x8c: EOF (missing marker)",
        ));
    }
    let marker = r.get_u8();
    if marker != 0x8c {
        return Err(cuprate_epee_encoding::error::Error::Format(Box::leak(
            format!("read_txs_typed_array_0x8c: unexpected marker=0x{marker:02x}").into_boxed_str(),
        )));
    }

    // 1) Element count
    let n_u64 = skip_epee_varint_u64(r)?;
    let n = usize::try_from(n_u64).map_err(|_| {
        cuprate_epee_encoding::error::Error::Format("read_txs_typed_array_0x8c: count overflow")
    })?;

    // 2) Typed-array schema header:
    // We observed bytes like: 08 04 'blob' ...
    // Interpret this as: <schema_marker:u8> <type_name_len:varint> <type_name_bytes>.
    if !r.has_remaining() {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "read_txs_typed_array_0x8c: EOF (missing schema marker)",
        ));
    }
    let _schema_marker = r.get_u8();
    let type_name_len = skip_epee_varint_u64(r)?;
    let type_name_len_usize = usize::try_from(type_name_len).map_err(|_| {
        cuprate_epee_encoding::error::Error::Format(
            "read_txs_typed_array_0x8c: type name length overflow",
        )
    })?;
    if r.remaining() < type_name_len_usize {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "read_txs_typed_array_0x8c: EOF reading type name",
        ));
    }
    let type_name_bytes = r.copy_to_bytes(type_name_len_usize);
    let elem_type = std::str::from_utf8(&type_name_bytes)
        .unwrap_or("")
        .to_string();

    // Dump 2: element stream start (right after marker + count + schema header).
    // This is the most important dump for implementing a correct parser.
    if bulk_bin_debug_enabled() {
        let chunk1 = r.chunk();
        if !chunk1.is_empty() {
            let hex = hex_dump_prefix(chunk1, 64);
            println!(
                "🧩 txs(0x8c) dump@element_stream_start elem_type={:?} count={} bytes[0..{}]={}",
                elem_type,
                n,
                std::cmp::min(64, chunk1.len()),
                hex
            );
        } else {
            println!(
                "🧩 txs(0x8c) dump@element_stream_start elem_type={:?} count={}: (unavailable)",
                elem_type, n
            );
        }
    }

    // Instrumentation: treat the element stream as a *single packed blob* candidate.
    //
    // Some daemons appear to encode txs(0x8c,"blob") such that the post-header stream begins with a
    // blob/string marker + length, followed by packed bytes (not N independent EPEE values).
    // We log the first blob's marker, length, and a prefix of its bytes without committing to a full unpacking yet.
    if bulk_bin_debug_enabled() && elem_type == "blob" {
        let chunk = r.chunk();
        if !chunk.is_empty() {
            let first = chunk[0];
            let mut logged = false;

            // Try marker + varint_len form: [marker][varint_len][bytes...]
            if chunk.len() >= 2 {
                if let Some((len, used)) = peek_epee_varint_u64(&chunk[1..]) {
                    let rem_after_marker = r.remaining().saturating_sub(1);
                    if (used as u64) <= rem_after_marker as u64
                        && len <= rem_after_marker.saturating_sub(used) as u64
                    {
                        println!(
                            "🧩 txs(0x8c) packed-blob candidate: marker=0x{:02x} len={} (count={})",
                            first, len, n
                        );

                        // Prefix of payload (best-effort, from current chunk). This is purely diagnostic.
                        let payload_offset = 1 + used;
                        if chunk.len() > payload_offset {
                            let payload = &chunk[payload_offset..];
                            let hex = hex_dump_prefix(payload, 64);
                            println!(
                                "🧩 txs(0x8c) packed-blob candidate: payload_prefix bytes[0..{}]={}",
                                std::cmp::min(64, payload.len()),
                                hex
                            );
                        }

                        logged = true;
                    }
                }
            }

            // Try markerless varint_len form: [varint_len][bytes...]
            if !logged {
                if let Some((len, used)) = peek_epee_varint_u64(chunk) {
                    let rem = r.remaining();
                    if (used as u64) <= rem as u64 && len <= rem.saturating_sub(used) as u64 {
                        println!(
                            "🧩 txs(0x8c) packed-blob candidate (markerless): len={} (count={})",
                            len, n
                        );

                        if chunk.len() > used {
                            let payload = &chunk[used..];
                            let hex = hex_dump_prefix(payload, 64);
                            println!(
                                "🧩 txs(0x8c) packed-blob candidate (markerless): payload_prefix bytes[0..{}]={}",
                                std::cmp::min(64, payload.len()),
                                hex
                            );
                        }
                    }
                }
            }
        }
    }

    // 3) Decode elements.
    // For elem_type == "blob": parse each element as a length-prefixed byte array.
    let mut out: Vec<Vec<u8>> = Vec::with_capacity(n);

    if elem_type == "blob" {
        // IMPORTANT (wallet2-like):
        // The element type is already declared by the typed-array header ("blob"), so elements are expected
        // to be encoded as markerless length-prefixed byte sequences:
        //
        //   [varint_len][bytes] repeated N times
        //
        // The element stream dump you captured starts with `0a 91 05 ...`, which is consistent with an
        // EPEE "blob/string" marker (0x0a) preceding the length. We support both forms:
        //   - markerless:        [varint_len][bytes]
        //   - marker + length:   [marker][varint_len][bytes]  (marker may be 0x0a/0x0b; others are treated as invalid)
        //
        // Crucially: we DO NOT try to treat arbitrary bytes as "unknown element markers", because that
        // quickly desynchronizes and produces absurd lengths (as seen in logs).
        for _ in 0..n {
            if !r.has_remaining() {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "read_txs_typed_array_0x8c(blob): EOF reading element",
                ));
            }

            let chunk = r.chunk();
            if chunk.is_empty() {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "read_txs_typed_array_0x8c(blob): unable to peek element bytes",
                ));
            }

            // Marker-agnostic blob decoding (wallet2-like):
            //
            // The typed-array header already declares elem_type="blob". Daemons may choose different
            // legal blob/string marker bytes per element, so we do NOT enumerate marker values.
            //
            // We accept either:
            //   A) marker + varint_len + bytes  (marker can be any u8, as long as the following varint is plausible)
            //   B) markerless varint_len + bytes
            //
            // We validate lengths against the remaining buffer to avoid desync.
            let first = chunk[0];

            // A) marker-present: [marker][varint_len][bytes...]
            if chunk.len() >= 2 {
                if let Some((len, used)) = peek_epee_varint_u64(&chunk[1..]) {
                    let rem_after_marker = r.remaining().saturating_sub(1);
                    if (used as u64) <= rem_after_marker as u64
                        && len <= rem_after_marker.saturating_sub(used) as u64
                    {
                        let _ = r.get_u8(); // consume marker (whatever it is)
                        let b = read_epee_len_prefixed_bytes(
                            r,
                            "read_txs_typed_array_0x8c(blob,marker_any)",
                        )?;
                        out.push(b);
                        continue;
                    }
                }
            }

            // B) markerless: [varint_len][bytes...]
            if let Some((len, used)) = peek_epee_varint_u64(chunk) {
                let rem = r.remaining();
                if (used as u64) <= rem as u64 && len <= rem.saturating_sub(used) as u64 {
                    let b = read_epee_len_prefixed_bytes(
                        r,
                        "read_txs_typed_array_0x8c(blob,markerless)",
                    )?;
                    out.push(b);
                    continue;
                }
            }

            // If neither matches, fail fast (do not desync). This will force bulk fallback to per-block.
            //
            // Diagnostic: dump bytes at the exact failure point so we can reverse-engineer the true element encoding.
            if bulk_bin_debug_enabled() {
                let dump0 = hex_dump_prefix(chunk, 64);
                let dump1 = if chunk.len() > 1 {
                    hex_dump_prefix(&chunk[1..], 64)
                } else {
                    String::new()
                };
                println!(
                    "🧩 txs(0x8c) element decode failed: next_byte=0x{:02x} remaining={} dump[0..]={} dump[1..]={}",
                    first,
                    r.remaining(),
                    dump0,
                    dump1
                );
            }

            return Err(cuprate_epee_encoding::error::Error::Format(Box::leak(
                format!(
                    "read_txs_typed_array_0x8c(blob): unrecognized element encoding (next_byte=0x{:02x})",
                    first
                )
                .into_boxed_str(),
            )));
        }
    } else {
        for _ in 0..n {
            if !r.has_remaining() {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "read_txs_typed_array_0x8c: EOF skipping element",
                ));
            }
            let chunk = r.chunk();
            if chunk.is_empty() {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "read_txs_typed_array_0x8c: unable to peek element marker",
                ));
            }
            let m = chunk[0];
            let _ = r.get_u8();
            skip_epee_value_with_known_marker(r, m)?;
            out.push(Vec::new());
        }
    }

    Ok(out)
}

#[inline]
fn bulk_fetch_mode_from_env() -> BulkFetchMode {
    // Bulk mode selection:
    //
    // - WALLETCORE_BULK_MODE=wallet2  => Wallet2FastBlocks (default)
    // - WALLETCORE_BULK_MODE=range    => RangeBlocks
    // - WALLETCORE_BULK_MODE=off      => PerBlock
    //
    // Back-compat:
    // - WALLETCORE_BULK_FETCH=0 disables bulk (PerBlock)
    // - WALLETCORE_BULK_FETCH=1 enables bulk and uses WALLETCORE_BULK_MODE (or default)
    let bulk_enabled = std::env::var("WALLETCORE_BULK_FETCH")
        .ok()
        .map(|s| s != "0")
        .unwrap_or(true);

    if !bulk_enabled {
        return BulkFetchMode::PerBlock;
    }

    match std::env::var("WALLETCORE_BULK_MODE")
        .ok()
        .unwrap_or_else(|| "wallet2".to_string())
        .to_lowercase()
        .as_str()
    {
        "off" | "0" | "false" => BulkFetchMode::PerBlock,
        "range" | "get_blocks" | "get_blocks.bin" => BulkFetchMode::RangeBlocks,
        "wallet2" | "getblocks" | "getblocks.bin" => BulkFetchMode::Wallet2FastBlocks,
        _ => BulkFetchMode::Wallet2FastBlocks,
    }
}

#[inline]
fn bulk_fetch_batch_from_env() -> usize {
    // Default 200, clamped to a sane range
    let v = std::env::var("WALLETCORE_BULK_FETCH_BATCH")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(200);
    v.clamp(10, 2000)
}

#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
use std::sync::{
    atomic::AtomicU64,
    mpsc::{self, TryRecvError},
};

use bincode;
use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
use futures::executor::block_on;
use monero_address::{
    AddressType as MoneroAddressType, MoneroAddress, Network as MoneroNetwork, SubaddressIndex,
};
use monero_ed25519::{Point as EdPoint, Scalar as EdScalar};
use monero_seed::{Language as MoneroSeedLanguage, Seed as MoneroSeed};
use monero_wallet::{
    block::Block,
    rpc::{Rpc, RpcError, ScannableBlock},
    transaction::{Pruned, Timelock, Transaction},
    Scanner, ViewPair,
};

use serde::{Deserialize, Serialize};
// Keccak256 is used via EdScalar::hash(), no direct import needed
use once_cell::sync::Lazy;
use rand::{rngs::OsRng, RngCore};

use ureq::serde_json;
use zeroize::Zeroizing;

use bytes::{Buf, BufMut};
use cuprate_epee_encoding::{from_bytes, to_bytes, write_field, EpeeObject};

#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
use zmq;

const DEFAULT_LOCK_WINDOW: u64 = 10;
const COINBASE_LOCK_WINDOW: u64 = 60;

// Bounded number of recent block hashes to keep in the wallet cache (wallet2-style chain history).
// 4096 hashes = 4096 * 32 bytes ~= 128 KiB raw, small enough for iOS while still providing
// a good short-chain-history window.
const RECENT_BLOCK_HASHES_MAX: usize = 4096;

static LAST_ERROR_MESSAGE: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

/// One-time debug logging for `get_blocks.bin` / `get_blocks_by_height.bin` response schema discovery.
/// We log unknown fields in `block_complete_entry` once so we can learn the actual tx blob field name.
static BULK_BIN_UNKNOWN_FIELD_LOGGED: AtomicBool = AtomicBool::new(false);

/// When enabled, we emit extra diagnostics about the decoded `block_complete_entry` fields
/// to help debug daemons which omit/rename tx blob fields in `get_blocks.bin`.
///
/// Enable in Xcode Scheme env vars:
/// - WALLETCORE_BULK_BIN_DEBUG=1
static BULK_BIN_DEBUG: AtomicBool = AtomicBool::new(false);

#[inline]
fn bulk_bin_debug_enabled() -> bool {
    // Cache env var read so we don't hit std::env on hot paths repeatedly.
    if BULK_BIN_DEBUG.load(Ordering::Relaxed) {
        return true;
    }
    let enabled = std::env::var("WALLETCORE_BULK_BIN_DEBUG")
        .ok()
        .map(|s| s != "0")
        .unwrap_or(false);
    if enabled {
        BULK_BIN_DEBUG.store(true, Ordering::Relaxed);
    }
    enabled
}

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

fn is_transient_oindexes_error(err: &RpcError) -> bool {
    let s = err.to_string().to_lowercase();
    s.contains("connection reset")
        || s.contains("reset by peer")
        || s.contains("broken pipe")
        || s.contains("timed out")
        || s.contains("network error")
}

fn get_o_indexes_limited<R: Rpc>(rpc: &R, tx_hash: [u8; 32]) -> Result<Vec<u64>, RpcError> {
    // Throttle + retry transient transport errors.
    let retries = oindexes_retries_from_env();
    for attempt in 0..=retries {
        acquire_oindexes_slot();
        let res = block_on(rpc.get_o_indexes(tx_hash));
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
    Err(RpcError::InternalError(
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
fn refresh_cancelled_for_wallet(wallet_id: &str) -> bool {
    refresh_cancel_flag_for_wallet(wallet_id).load(Ordering::Relaxed)
}

#[inline]
fn set_refresh_cancel_for_wallet(wallet_id: &str, cancelled: bool) {
    refresh_cancel_flag_for_wallet(wallet_id).store(cancelled, Ordering::Relaxed);
}

fn set_last_error<S: Into<String>>(message: S) {
    if let Ok(mut slot) = LAST_ERROR_MESSAGE.lock() {
        *slot = Some(message.into());
    }
}

fn clear_last_error() {
    if let Ok(mut slot) = LAST_ERROR_MESSAGE.lock() {
        *slot = None;
    }
}

fn record_error(code: c_int, message: impl Into<String>) -> c_int {
    set_last_error(message);
    code
}

fn update_scan_progress(
    id: &str,
    scanned_height: u64,
    chain_height: u64,
    chain_time: u64,
    restore_height: u64,
) {
    if let Ok(mut map) = WALLET_STORE.lock() {
        if let Some(state) = map.get_mut(id) {
            let normalized_scanned = scanned_height.max(restore_height).min(chain_height);
            state.last_scanned = normalized_scanned;
            state.chain_height = chain_height;
            state.chain_time = chain_time;
            if chain_time > 0 {
                state.last_refresh_timestamp = chain_time;
            }
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
fn push_recent_block_hash(state: &mut StoredWallet, height: u64, hash: [u8; 32]) {
    maybe_init_recent_hash_window(state);

    if state.recent_block_hashes.is_empty() {
        state.recent_block_hashes_start_height = height;
        state.recent_block_hashes.push(hash);
        return;
    }

    let start = state.recent_block_hashes_start_height;
    let expected_next_height = start.saturating_add(state.recent_block_hashes.len() as u64);

    if height == expected_next_height {
        state.recent_block_hashes.push(hash);
    } else if height < expected_next_height {
        // Possible reorg or duplicate update. If it overlaps our window, truncate to that height.
        if height >= start {
            let idx = (height - start) as usize;
            if idx < state.recent_block_hashes.len() {
                state.recent_block_hashes.truncate(idx);
                state.recent_block_hashes.push(hash);
            } else {
                // Shouldn't happen, but reset defensively.
                state.recent_block_hashes_start_height = height;
                state.recent_block_hashes.clear();
                state.recent_block_hashes.push(hash);
            }
        } else {
            // Height is before our window; reset to avoid inconsistent state.
            state.recent_block_hashes_start_height = height;
            state.recent_block_hashes.clear();
            state.recent_block_hashes.push(hash);
        }
    } else {
        // Gap detected; reset window to this height.
        state.recent_block_hashes_start_height = height;
        state.recent_block_hashes.clear();
        state.recent_block_hashes.push(hash);
    }

    // Enforce bounded window size
    if state.recent_block_hashes.len() > RECENT_BLOCK_HASHES_MAX {
        let overflow = state.recent_block_hashes.len() - RECENT_BLOCK_HASHES_MAX;
        state.recent_block_hashes.drain(0..overflow);
        state.recent_block_hashes_start_height = state
            .recent_block_hashes_start_height
            .saturating_add(overflow as u64);
    }
}

/// Get a hash from the recent hash window by height (if present).
fn get_recent_block_hash(state: &StoredWallet, height: u64) -> Option<[u8; 32]> {
    let start = state.recent_block_hashes_start_height;
    if height < start {
        return None;
    }
    let idx = (height - start) as usize;
    state.recent_block_hashes.get(idx).copied()
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
fn skip_epee_value<B: Buf>(r: &mut B) -> cuprate_epee_encoding::error::Result<()> {
    // EPEE values begin with a one-byte "type marker".
    // We don't have a public marker enum here, so we parse conservatively based on monerod usage.
    //
    // Marker reference (Monero portable_storage):
    // - integer, bool, string/blob, object, array, etc.
    //
    // We only need to be able to advance the cursor, not interpret the value.
    if !r.has_remaining() {
        return Err(cuprate_epee_encoding::error::Error::Format(
            "skip_epee_value: unexpected EOF (no marker)",
        ));
    }

    let marker = r.get_u8();

    // Most primitive markers are followed by a fixed-size payload.
    // NOTE: These marker values are not guaranteed stable across implementations; this is best-effort.
    // If we hit an unknown marker in practice, we'll fail fast and extend this.
    match marker {
        // Booleans are encoded as 1 byte
        0x01 => {
            if r.remaining() < 1 {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "skip_epee_value: EOF reading bool",
                ));
            }
            let _ = r.get_u8();
            Ok(())
        }

        // Signed/unsigned integers (fixed width). Monero portable_storage uses 8-byte integers frequently.
        // These markers are best-effort; if they don't match a given daemon, we'll fail fast and extend.
        0x02 | 0x03 => {
            if r.remaining() < 8 {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "skip_epee_value: EOF reading int64",
                ));
            }
            r.advance(8);
            Ok(())
        }

        // Strings / blobs: varint length + bytes.
        // We treat both as "length-prefixed byte sequences".
        //
        // Observed in the wild (monerod wallet2 `/getblocks.bin`): markers 0xba and 0xcf can appear for blob-like
        // data (e.g., tx blobs). Treat them the same as string/blob.
        0x0a | 0x0b | 0xba | 0xcf => {
            let len = skip_epee_varint_u64(r)?;
            let len_usize = usize::try_from(len).map_err(|_| {
                cuprate_epee_encoding::error::Error::Format("skip_epee_value: length overflow")
            })?;
            if r.remaining() < len_usize {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "skip_epee_value: EOF reading bytes",
                ));
            }
            r.advance(len_usize);
            Ok(())
        }

        // Object: varint field count + repeated (name,value) pairs.
        0x0c => {
            let fields = skip_epee_varint_u64(r)?;
            for _ in 0..fields {
                // Field name is a length-prefixed string
                let name_len = skip_epee_varint_u64(r)?;
                let name_len_usize = usize::try_from(name_len).map_err(|_| {
                    cuprate_epee_encoding::error::Error::Format(
                        "skip_epee_value: name length overflow",
                    )
                })?;
                if r.remaining() < name_len_usize {
                    return Err(cuprate_epee_encoding::error::Error::Format(
                        "skip_epee_value: EOF reading field name",
                    ));
                }
                r.advance(name_len_usize);

                // Field type marker + value
                skip_epee_value(r)?;
            }
            Ok(())
        }

        // Array: marker for element type + varint length + elements.
        //
        // Observed in the wild (monerod `/getblocks.bin`): `txs` can start with marker 0x8c.
        // Treat it as an "array-like" container marker and skip identically to 0x0d.
        0x0d | 0x8c => {
            if !r.has_remaining() {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "skip_epee_value: EOF reading array element marker",
                ));
            }
            let elem_marker = r.get_u8();
            let n = skip_epee_varint_u64(r)?;
            for _ in 0..n {
                // For arrays, each element is encoded without its own marker in Monero portable_storage,
                // because the element marker is provided once. We therefore skip based on elem_marker.
                skip_epee_value_with_known_marker(r, elem_marker)?;
            }
            Ok(())
        }

        _ => {
            // Include the actual marker byte to make it diagnosable when daemons use markers we
            // haven't covered yet.
            Err(cuprate_epee_encoding::error::Error::Format(Box::leak(
                format!("skip_epee_value: unsupported marker=0x{marker:02x} (extend decoder)")
                    .into_boxed_str(),
            )))
        }
    }
}

fn skip_epee_value_with_known_marker<B: Buf>(
    r: &mut B,
    marker: u8,
) -> cuprate_epee_encoding::error::Result<()> {
    // Same as skip_epee_value, but the marker byte is already known/consumed by the array header.
    match marker {
        0x01 => {
            if r.remaining() < 1 {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "skip_epee_value_with_known_marker: EOF reading bool",
                ));
            }
            let _ = r.get_u8();
            Ok(())
        }
        0x02 | 0x03 => {
            if r.remaining() < 8 {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "skip_epee_value_with_known_marker: EOF reading int64",
                ));
            }
            r.advance(8);
            Ok(())
        }
        0x0a | 0x0b | 0xba | 0xcf => {
            let len = skip_epee_varint_u64(r)?;
            let len_usize = usize::try_from(len).map_err(|_| {
                cuprate_epee_encoding::error::Error::Format(
                    "skip_epee_value_with_known_marker: length overflow",
                )
            })?;
            if r.remaining() < len_usize {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "skip_epee_value_with_known_marker: EOF reading bytes",
                ));
            }
            r.advance(len_usize);
            Ok(())
        }
        0x0c => {
            // Object elements in arrays are still full objects (field count + pairs)
            let fields = skip_epee_varint_u64(r)?;
            for _ in 0..fields {
                let name_len = skip_epee_varint_u64(r)?;
                let name_len_usize = usize::try_from(name_len).map_err(|_| {
                    cuprate_epee_encoding::error::Error::Format(
                        "skip_epee_value_with_known_marker: name length overflow",
                    )
                })?;
                if r.remaining() < name_len_usize {
                    return Err(cuprate_epee_encoding::error::Error::Format(
                        "skip_epee_value_with_known_marker: EOF reading field name",
                    ));
                }
                r.advance(name_len_usize);

                skip_epee_value(r)?;
            }
            Ok(())
        }
        0x0d | 0x8c => {
            // Nested array: marker + length + elements
            if !r.has_remaining() {
                return Err(cuprate_epee_encoding::error::Error::Format(
                    "skip_epee_value_with_known_marker: EOF reading nested array elem marker",
                ));
            }
            let elem_marker = r.get_u8();
            let n = skip_epee_varint_u64(r)?;
            for _ in 0..n {
                skip_epee_value_with_known_marker(r, elem_marker)?;
            }
            Ok(())
        }
        _ => Err(cuprate_epee_encoding::error::Error::Format(Box::leak(
            format!(
                "skip_epee_value_with_known_marker: unsupported marker=0x{marker:02x} (extend decoder)"
            )
            .into_boxed_str(),
        ))),
    }
}

fn skip_epee_varint_u64<B: Buf>(r: &mut B) -> cuprate_epee_encoding::error::Result<u64> {
    // Monero portable_storage uses a LEB128-style varint.
    let mut out: u64 = 0;
    let mut shift: u32 = 0;
    loop {
        if !r.has_remaining() {
            return Err(cuprate_epee_encoding::error::Error::Format(
                "skip_epee_varint_u64: EOF",
            ));
        }
        let b = r.get_u8();
        out |= u64::from(b & 0x7f) << shift;

        if (b & 0x80) == 0 {
            return Ok(out);
        }
        shift += 7;
        if shift >= 64 {
            return Err(cuprate_epee_encoding::error::Error::Format(
                "skip_epee_varint_u64: varint overflow",
            ));
        }
    }
}

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

struct MasterKeys {
    entropy: Zeroizing<[u8; 32]>,
    spend_scalar: curve25519_dalek::Scalar,
    view_scalar_dalek: curve25519_dalek::Scalar,
    view_scalar_ed: EdScalar,
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

#[derive(Clone, Debug)]
struct GetBlocksFastBinRequest {
    // COMMAND_RPC_GET_BLOCKS_FAST::request_t fields
    // See monero/src/rpc/core_rpc_server_commands_defs.h (KV_SERIALIZE_* map)
    requested_info: u8,

    // IMPORTANT: In Monero C++ this is serialized with `KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids)`.
    // That means it's encoded as a single blob of bytes (32 * N) rather than a normal EPEE array.
    // We represent it as a packed blob to match daemon expectations and avoid HTTP 400.
    block_ids: Vec<u8>,

    start_height: u64,
    prune: bool,
    no_miner_tx: bool,
    pool_info_since: u64,
    max_block_count: u64,
}

#[derive(Default)]
struct GetBlocksFastBinRequestBuilder {
    requested_info: Option<u8>,
    block_ids: Option<Vec<u8>>,
    start_height: Option<u64>,
    prune: Option<bool>,
    no_miner_tx: Option<bool>,
    pool_info_since: Option<u64>,
    max_block_count: Option<u64>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<GetBlocksFastBinRequest>
    for GetBlocksFastBinRequestBuilder
{
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "requested_info" => {
                self.requested_info = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "block_ids" => {
                // Packed POD blob (32 * N bytes)
                self.block_ids = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "start_height" => {
                self.start_height = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "prune" => {
                self.prune = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "no_miner_tx" => {
                self.no_miner_tx = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "pool_info_since" => {
                self.pool_info_since = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "max_block_count" => {
                self.max_block_count = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<GetBlocksFastBinRequest> {
        Ok(GetBlocksFastBinRequest {
            requested_info: self.requested_info.unwrap_or(0),
            block_ids: self.block_ids.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field block_ids missing")
            })?,
            start_height: self.start_height.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field start_height missing")
            })?,
            prune: self.prune.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field prune missing")
            })?,
            no_miner_tx: self.no_miner_tx.unwrap_or(false),
            pool_info_since: self.pool_info_since.unwrap_or(0),
            max_block_count: self.max_block_count.unwrap_or(0),
        })
    }
}

impl EpeeObject for GetBlocksFastBinRequest {
    type Builder = GetBlocksFastBinRequestBuilder;

    fn number_of_fields(&self) -> u64 {
        7
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.requested_info, "requested_info", w)?;
        // Packed POD blob (32 * N bytes), matching KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids)
        write_field(self.block_ids, "block_ids", w)?;
        write_field(self.start_height, "start_height", w)?;
        write_field(self.prune, "prune", w)?;
        write_field(self.no_miner_tx, "no_miner_tx", w)?;
        write_field(self.pool_info_since, "pool_info_since", w)?;
        write_field(self.max_block_count, "max_block_count", w)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct TxOutputIndices {
    indices: Vec<u64>,
}

#[derive(Default)]
struct TxOutputIndicesBuilder {
    indices: Option<Vec<u64>>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<TxOutputIndices> for TxOutputIndicesBuilder {
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "indices" => {
                self.indices = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<TxOutputIndices> {
        Ok(TxOutputIndices {
            indices: self.indices.unwrap_or_default(),
        })
    }
}

impl EpeeObject for TxOutputIndices {
    type Builder = TxOutputIndicesBuilder;

    fn number_of_fields(&self) -> u64 {
        1
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.indices, "indices", w)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct BlockOutputIndices {
    indices: Vec<TxOutputIndices>,
}

#[derive(Default)]
struct BlockOutputIndicesBuilder {
    indices: Option<Vec<TxOutputIndices>>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<BlockOutputIndices> for BlockOutputIndicesBuilder {
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "indices" => {
                self.indices = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<BlockOutputIndices> {
        Ok(BlockOutputIndices {
            indices: self.indices.unwrap_or_default(),
        })
    }
}

impl EpeeObject for BlockOutputIndices {
    type Builder = BlockOutputIndicesBuilder;

    fn number_of_fields(&self) -> u64 {
        1
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.indices, "indices", w)?;
        Ok(())
    }
}

#[derive(Clone, Debug)]
struct GetBlocksFastBinResponse {
    // Required fields per COMMAND_RPC_GET_BLOCKS_FAST::response_t
    blocks: Vec<BlockCompleteEntry>,
    start_height: u64,
    current_height: u64,
    output_indices: Vec<BlockOutputIndices>,
    // Optional fields (we ignore pool info for wallet sync)
    daemon_time: Option<u64>,
    pool_info_extent: Option<u8>,
    status: Option<String>,
    untrusted: Option<bool>,
}

#[derive(Default)]
struct GetBlocksFastBinResponseBuilder {
    blocks: Option<Vec<BlockCompleteEntry>>,
    start_height: Option<u64>,
    current_height: Option<u64>,
    output_indices: Option<Vec<BlockOutputIndices>>,
    daemon_time: Option<u64>,
    pool_info_extent: Option<u8>,
    status: Option<String>,
    untrusted: Option<bool>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<GetBlocksFastBinResponse>
    for GetBlocksFastBinResponseBuilder
{
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        // Targeted schema debugging for `/getblocks.bin` response decoding.
        // This lets us pinpoint which specific field triggers the EPEE marker mismatch.
        if bulk_bin_debug_enabled() {
            println!("🧩 getblocks.bin response: decoding field={:?}", name);
        }

        match name {
            "blocks" => {
                // Manual parse of the `blocks` container so we can log the failing entry index.
                //
                // Daemons may encode `blocks` either as:
                // - plain array marker 0x0d, or
                // - typed array marker 0x8c (portable_storage typed array; includes an embedded type name)
                //
                // We decode the container header ourselves, then decode each element and annotate errors with `blocks[i]`.
                if !r.has_remaining() {
                    return Err(cuprate_epee_encoding::error::Error::Format(
                        "getblocks.bin decode failed in field 'blocks': EOF (missing container marker)",
                    ));
                }

                let container_marker = r.get_u8();

                // Determine element count and (optional) typed-array element type name.
                let (n, typed_elem_type): (u64, Option<String>) = match container_marker {
                    // Plain array: [0x0d][elem_marker][len][elements...]
                    0x0d => {
                        if !r.has_remaining() {
                            return Err(cuprate_epee_encoding::error::Error::Format(
                                "getblocks.bin decode failed in field 'blocks': EOF (missing element marker)",
                            ));
                        }
                        let elem_marker = r.get_u8();
                        if elem_marker != 0x0c {
                            return Err(cuprate_epee_encoding::error::Error::Format(Box::leak(
                                format!(
                                    "getblocks.bin decode failed in field 'blocks': unexpected element marker=0x{elem_marker:02x} (expected object marker 0x0c)"
                                )
                                .into_boxed_str(),
                            )));
                        }

                        let n = skip_epee_varint_u64(r).map_err(|e| {
                            cuprate_epee_encoding::error::Error::Format(Box::leak(
                                format!("getblocks.bin decode failed in field 'blocks': failed to read array length: {e}")
                                    .into_boxed_str(),
                            ))
                        })?;

                        (n, None)
                    }

                    // Typed array: [0x8c][len][schema_marker][type_name_len][type_name_bytes][elem_marker][elements...]
                    //
                    // IMPORTANT: In Monero portable_storage, arrays provide the element marker once, and elements
                    // are then encoded WITHOUT their own markers.
                    0x8c => {
                        let n = skip_epee_varint_u64(r).map_err(|e| {
                            cuprate_epee_encoding::error::Error::Format(Box::leak(
                                format!("getblocks.bin decode failed in field 'blocks': failed to read typed-array length: {e}")
                                    .into_boxed_str(),
                            ))
                        })?;

                        if !r.has_remaining() {
                            return Err(cuprate_epee_encoding::error::Error::Format(
                                "getblocks.bin decode failed in field 'blocks': EOF (missing typed-array schema marker)",
                            ));
                        }
                        let _schema_marker = r.get_u8();

                        let type_name_len = skip_epee_varint_u64(r).map_err(|e| {
                            cuprate_epee_encoding::error::Error::Format(Box::leak(
                                format!("getblocks.bin decode failed in field 'blocks': failed to read typed-array type name length: {e}")
                                    .into_boxed_str(),
                            ))
                        })?;
                        let type_name_len_usize = usize::try_from(type_name_len).map_err(|_| {
                            cuprate_epee_encoding::error::Error::Format(
                                "getblocks.bin decode failed in field 'blocks': typed-array type name length overflow",
                            )
                        })?;
                        if r.remaining() < type_name_len_usize {
                            return Err(cuprate_epee_encoding::error::Error::Format(
                                "getblocks.bin decode failed in field 'blocks': EOF reading typed-array type name",
                            ));
                        }
                        let type_name_bytes = r.copy_to_bytes(type_name_len_usize);
                        let type_name = std::str::from_utf8(&type_name_bytes)
                            .unwrap_or("")
                            .to_string();

                        if !r.has_remaining() {
                            return Err(cuprate_epee_encoding::error::Error::Format(
                                "getblocks.bin decode failed in field 'blocks': EOF (missing typed-array element marker)",
                            ));
                        }
                        let elem_marker = r.get_u8();

                        // Pass the element marker to the decoder by appending it to the type name in a stable way.
                        // This avoids widening the match tuple and keeps changes localized.
                        (
                            n,
                            Some(format!("{type_name}|elem_marker=0x{elem_marker:02x}")),
                        )
                    }

                    _ => {
                        return Err(cuprate_epee_encoding::error::Error::Format(Box::leak(
                            format!(
                                "getblocks.bin decode failed in field 'blocks': unexpected container marker=0x{container_marker:02x} (expected 0x0d or 0x8c)"
                            )
                            .into_boxed_str(),
                        )));
                    }
                };

                if bulk_bin_debug_enabled() {
                    if let Some(ref ty) = typed_elem_type {
                        println!(
                            "🧩 getblocks.bin blocks container: typed_array marker=0x8c elem_type={:?} len={}",
                            ty, n
                        );

                        // Dump the element stream start right after the typed-array header so we can
                        // determine whether elements are object payloads, blobs, or another encoding.
                        let chunk = r.chunk();
                        if !chunk.is_empty() {
                            let hex = hex_dump_prefix(chunk, 64);
                            println!(
                                "🧩 getblocks.bin blocks element_stream_start bytes[0..{}]={}",
                                std::cmp::min(64, chunk.len()),
                                hex
                            );
                        } else {
                            println!("🧩 getblocks.bin blocks element_stream_start: (unavailable)");
                        }
                    } else {
                        println!(
                            "🧩 getblocks.bin blocks container: plain_array marker=0x0d len={}",
                            n
                        );
                    }
                }

                // Decode elements.
                //
                // For typed arrays, Monero portable_storage supplies the element marker ONCE in the header.
                // Elements are then encoded WITHOUT per-element markers.
                //
                // We therefore:
                // - extract the shared element marker from `typed_elem_type` (encoded as `|elem_marker=0x..`)
                // - decode `n` elements using that marker
                let blocks_elem_marker: u8 = typed_elem_type
                    .as_deref()
                    .and_then(|s| s.split("|elem_marker=0x").nth(1))
                    .and_then(|hex| u8::from_str_radix(&hex[..2.min(hex.len())], 16).ok())
                    .unwrap_or(0x0a);

                // Savepoint slice right after the typed-array header (including elem_marker already consumed).
                let savepoint: &[u8] = r.chunk();

                // --- Attempt 1: decode as `BlockCompleteEntry` objects ---
                let mut reader_obj: &[u8] = savepoint;
                let mut obj_out: Vec<BlockCompleteEntry> = Vec::with_capacity(n as usize);
                let mut object_decode_ok = true;

                for i in 0..n {
                    if bulk_bin_debug_enabled() {
                        println!(
                            "🧩 getblocks.bin blocks[{}]: object-decode start (remaining={})",
                            i,
                            reader_obj.len()
                        );
                        if !reader_obj.is_empty() {
                            let hex = hex_dump_prefix(reader_obj, 32);
                            println!(
                                "🧩 getblocks.bin blocks[{}]: object-decode peek bytes[0..{}]={}",
                                i,
                                std::cmp::min(32, reader_obj.len()),
                                hex
                            );
                        }
                    }

                    // Each element is an EPEE object payload:
                    // [field_count varint] then repeated [field_name][field_value]
                    let fields = match skip_epee_varint_u64(&mut reader_obj) {
                        Ok(v) => v,
                        Err(e) => {
                            object_decode_ok = false;
                            if bulk_bin_debug_enabled() {
                                println!(
                                    "🧩 getblocks.bin blocks[{}]: object-decode failed reading field_count: {}",
                                    i, e
                                );
                            }
                            break;
                        }
                    };

                    let mut builder = BlockCompleteEntryBuilder::default();
                    for _ in 0..fields {
                        let name = match read_epee_field_name(&mut reader_obj) {
                            Ok(v) => v,
                            Err(e) => {
                                object_decode_ok = false;
                                if bulk_bin_debug_enabled() {
                                    println!(
                                        "🧩 getblocks.bin blocks[{}]: object-decode failed reading field name: {}",
                                        i, e
                                    );
                                }
                                break;
                            }
                        };

                        if let Err(e) = builder.add_field(&name, &mut reader_obj) {
                            object_decode_ok = false;
                            if bulk_bin_debug_enabled() {
                                println!(
                                    "🧩 getblocks.bin blocks[{}]: object-decode add_field({:?}) failed: {}",
                                    i, name, e
                                );
                            }
                            break;
                        }
                    }

                    if !object_decode_ok {
                        break;
                    }

                    let entry = match builder.finish() {
                        Ok(v) => v,
                        Err(e) => {
                            object_decode_ok = false;
                            if bulk_bin_debug_enabled() {
                                println!(
                                    "🧩 getblocks.bin blocks[{}]: object-decode finish failed: {}",
                                    i, e
                                );
                            }
                            break;
                        }
                    };

                    if bulk_bin_debug_enabled() {
                        println!(
                            "🧩 getblocks.bin blocks[{}]: object-decode ok (block_bytes={} tx_blobs={} pruned={})",
                            i,
                            entry.block.len(),
                            entry.txs.len(),
                            entry.pruned
                        );
                    }

                    obj_out.push(entry);
                }

                if object_decode_ok && obj_out.len() == n as usize {
                    // Commit consumption: advance the original Buf by the bytes we consumed in the temp reader.
                    let consumed = savepoint.len().saturating_sub(reader_obj.len());
                    r.advance(consumed);
                    self.blocks = Some(obj_out);
                    return Ok(true);
                }

                if bulk_bin_debug_enabled() {
                    println!(
                        "🧩 getblocks.bin blocks: object-decode failed; attempting blob fallback from savepoint (remaining={})",
                        savepoint.len()
                    );
                }

                // --- Attempt 2: decode as length-prefixed blob bytes (shared element marker) ---
                //
                // For a typed array, `blocks_elem_marker` applies to ALL elements, and elements do NOT include
                // a per-element marker.
                const MAX_BLOCK_BYTES: usize = 10 * 1024 * 1024; // 10 MiB cap (defensive)

                if !is_supported_blob_marker(blocks_elem_marker) {
                    return Err(cuprate_epee_encoding::error::Error::Format(Box::leak(
                        format!(
                            "getblocks.bin decode failed in field 'blocks': unsupported typed-array elem_marker=0x{blocks_elem_marker:02x}"
                        )
                        .into_boxed_str(),
                    )));
                }

                let mut reader_blob: &[u8] = savepoint;
                let mut out: Vec<BlockCompleteEntry> = Vec::with_capacity(n as usize);

                for i in 0..n {
                    if bulk_bin_debug_enabled() {
                        println!(
                            "🧩 getblocks.bin blocks[{}]: blob-decode(shared_marker=0x{:02x}) start (remaining={})",
                            i,
                            blocks_elem_marker,
                            reader_blob.len()
                        );
                        if !reader_blob.is_empty() {
                            let hex = hex_dump_prefix(reader_blob, 32);
                            println!(
                                "🧩 getblocks.bin blocks[{}]: blob-decode peek bytes[0..{}]={}",
                                i,
                                std::cmp::min(32, reader_blob.len()),
                                hex
                            );
                        }
                    }

                    // Each element is just a length-prefixed byte array: [varint_len][payload...]
                    if let Some((len_u64, used)) = peek_epee_varint_u64(reader_blob) {
                        let len_usize = usize::try_from(len_u64).map_err(|_| {
                            cuprate_epee_encoding::error::Error::Format(Box::leak(
                                format!("getblocks.bin decode failed in field 'blocks': blocks[{i}] length overflow ({len_u64})")
                                    .into_boxed_str(),
                            ))
                        })?;

                        if len_usize > MAX_BLOCK_BYTES {
                            return Err(cuprate_epee_encoding::error::Error::Format(Box::leak(
                                format!("getblocks.bin decode failed in field 'blocks': blocks[{i}] element too large (len={len_usize} > {MAX_BLOCK_BYTES})")
                                    .into_boxed_str(),
                            )));
                        }

                        let rem = reader_blob.len();
                        if rem < used + len_usize {
                            return Err(cuprate_epee_encoding::error::Error::Format(Box::leak(
                                format!("getblocks.bin decode failed in field 'blocks': blocks[{i}] element length out of bounds (len={len_usize}, overhead={used}, remaining={rem})")
                                    .into_boxed_str(),
                            )));
                        }
                    } else {
                        return Err(cuprate_epee_encoding::error::Error::Format(Box::leak(
                            format!("getblocks.bin decode failed in field 'blocks': blocks[{i}] invalid varint length (shared marker)")
                                .into_boxed_str(),
                        )));
                    }

                    let blob_payload = read_epee_len_prefixed_bytes(
                        &mut reader_blob,
                        "getblocks.bin blocks(blob_payload/shared_marker)",
                    )?;

                    if bulk_bin_debug_enabled() {
                        println!(
                            "🧩 getblocks.bin blocks[{}]: blob-decode ok (payload_len={})",
                            i,
                            blob_payload.len()
                        );
                        if !blob_payload.is_empty() {
                            let hex = hex_dump_prefix(&blob_payload, 32);
                            println!(
                                "🧩 getblocks.bin blocks[{}]: blob payload peek bytes[0..{}]={}",
                                i,
                                std::cmp::min(32, blob_payload.len()),
                                hex
                            );
                        }
                    }

                    if let Some(entry) =
                        try_decode_block_complete_entry_from_blob_payload(&blob_payload)?
                    {
                        if bulk_bin_debug_enabled() {
                            println!(
                                "🧩 getblocks.bin blocks[{}]: inner object-decode from blob payload ok (block_bytes={} tx_blobs={} pruned={})",
                                i,
                                entry.block.len(),
                                entry.txs.len(),
                                entry.pruned
                            );
                        }
                        out.push(entry);
                    } else {
                        out.push(BlockCompleteEntry {
                            block: blob_payload,
                            txs: Vec::new(),
                            pruned: true,
                        });
                    }
                }

                // Commit consumption: advance the original Buf by the bytes we consumed in the temp reader.
                let consumed = savepoint.len().saturating_sub(reader_blob.len());
                r.advance(consumed);

                self.blocks = Some(out);
                return Ok(true);
            }
            "start_height" => {
                self.start_height =
                    Some(cuprate_epee_encoding::read_epee_value(r).map_err(|e| {
                        cuprate_epee_encoding::error::Error::Format(Box::leak(
                            format!("getblocks.bin decode failed in field 'start_height': {e}")
                                .into_boxed_str(),
                        ))
                    })?);
            }
            "current_height" => {
                self.current_height =
                    Some(cuprate_epee_encoding::read_epee_value(r).map_err(|e| {
                        cuprate_epee_encoding::error::Error::Format(Box::leak(
                            format!("getblocks.bin decode failed in field 'current_height': {e}")
                                .into_boxed_str(),
                        ))
                    })?);
            }
            "output_indices" => {
                self.output_indices =
                    Some(cuprate_epee_encoding::read_epee_value(r).map_err(|e| {
                        cuprate_epee_encoding::error::Error::Format(Box::leak(
                            format!("getblocks.bin decode failed in field 'output_indices': {e}")
                                .into_boxed_str(),
                        ))
                    })?);
            }
            "daemon_time" => {
                self.daemon_time =
                    Some(cuprate_epee_encoding::read_epee_value(r).map_err(|e| {
                        cuprate_epee_encoding::error::Error::Format(Box::leak(
                            format!("getblocks.bin decode failed in field 'daemon_time': {e}")
                                .into_boxed_str(),
                        ))
                    })?);
            }
            "pool_info_extent" => {
                self.pool_info_extent =
                    Some(cuprate_epee_encoding::read_epee_value(r).map_err(|e| {
                        cuprate_epee_encoding::error::Error::Format(Box::leak(
                            format!("getblocks.bin decode failed in field 'pool_info_extent': {e}")
                                .into_boxed_str(),
                        ))
                    })?);
            }
            "status" => {
                self.status = Some(cuprate_epee_encoding::read_epee_value(r).map_err(|e| {
                    cuprate_epee_encoding::error::Error::Format(Box::leak(
                        format!("getblocks.bin decode failed in field 'status': {e}")
                            .into_boxed_str(),
                    ))
                })?);
            }
            "untrusted" => {
                self.untrusted = Some(cuprate_epee_encoding::read_epee_value(r).map_err(|e| {
                    cuprate_epee_encoding::error::Error::Format(Box::leak(
                        format!("getblocks.bin decode failed in field 'untrusted': {e}")
                            .into_boxed_str(),
                    ))
                })?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<GetBlocksFastBinResponse> {
        Ok(GetBlocksFastBinResponse {
            blocks: self.blocks.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("response missing 'blocks'")
            })?,
            start_height: self.start_height.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("response missing 'start_height'")
            })?,
            current_height: self.current_height.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("response missing 'current_height'")
            })?,
            output_indices: self.output_indices.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("response missing 'output_indices'")
            })?,
            daemon_time: self.daemon_time,
            pool_info_extent: self.pool_info_extent,
            status: self.status,
            untrusted: self.untrusted,
        })
    }
}

impl EpeeObject for GetBlocksFastBinResponse {
    type Builder = GetBlocksFastBinResponseBuilder;

    fn number_of_fields(&self) -> u64 {
        8
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.blocks, "blocks", w)?;
        write_field(self.start_height, "start_height", w)?;
        write_field(self.current_height, "current_height", w)?;
        write_field(self.output_indices, "output_indices", w)?;
        if let Some(daemon_time) = self.daemon_time {
            write_field(daemon_time, "daemon_time", w)?;
        }
        if let Some(pool_info_extent) = self.pool_info_extent {
            write_field(pool_info_extent, "pool_info_extent", w)?;
        }
        if let Some(status) = self.status {
            write_field(status, "status", w)?;
        }
        if let Some(untrusted) = self.untrusted {
            write_field(untrusted, "untrusted", w)?;
        }
        Ok(())
    }
}

/// Request for monerod `/get_blocks_by_height.bin` (portable_storage / EPEE encoded).
#[derive(Clone, Debug)]
struct GetBlocksByHeightBinRequest {
    heights: Vec<u64>,
    prune: bool,
}

#[derive(Default)]
struct GetBlocksByHeightBinRequestBuilder {
    heights: Option<Vec<u64>>,
    prune: Option<bool>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<GetBlocksByHeightBinRequest>
    for GetBlocksByHeightBinRequestBuilder
{
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "heights" => {
                self.heights = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "prune" => {
                self.prune = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<GetBlocksByHeightBinRequest> {
        Ok(GetBlocksByHeightBinRequest {
            heights: self.heights.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field heights missing")
            })?,
            prune: self.prune.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field prune missing")
            })?,
        })
    }
}

impl EpeeObject for GetBlocksByHeightBinRequest {
    type Builder = GetBlocksByHeightBinRequestBuilder;

    fn number_of_fields(&self) -> u64 {
        2
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.heights, "heights", w)?;
        write_field(self.prune, "prune", w)?;
        Ok(())
    }
}

/*
 * Request for monerod `/get_blocks.bin` (portable_storage / EPEE encoded).
 *
 * We only support contiguous ranges for fast scanning:
 * - start_height: u64
 * - count: u64
 * - prune: bool
 */
#[derive(Clone, Debug)]
struct GetBlocksBinRequest {
    start_height: u64,
    count: u64,
    prune: bool,
}

#[derive(Default)]
struct GetBlocksBinRequestBuilder {
    start_height: Option<u64>,
    count: Option<u64>,
    prune: Option<bool>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<GetBlocksBinRequest> for GetBlocksBinRequestBuilder {
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "start_height" => {
                self.start_height = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "count" => {
                self.count = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "prune" => {
                self.prune = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<GetBlocksBinRequest> {
        Ok(GetBlocksBinRequest {
            start_height: self.start_height.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field start_height missing")
            })?,
            count: self.count.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field count missing")
            })?,
            prune: self.prune.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("Required field prune missing")
            })?,
        })
    }
}

impl EpeeObject for GetBlocksBinRequest {
    type Builder = GetBlocksBinRequestBuilder;

    fn number_of_fields(&self) -> u64 {
        3
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.start_height, "start_height", w)?;
        write_field(self.count, "count", w)?;
        write_field(self.prune, "prune", w)?;
        Ok(())
    }
}

/// Shared block entry for `get_blocks_by_height.bin` and (typically) `get_blocks.bin`.
#[derive(Clone, Debug)]
struct BlockCompleteEntry {
    block: Vec<u8>,
    // Some daemons (or prune modes) omit tx blobs in certain responses.
    // When omitted, we treat it as an empty list and let the caller decide whether to fall back.
    txs: Vec<Vec<u8>>,
    // In Monero `block_complete_entry`, daemons include whether the entry is pruned.
    // Wallet2 `/getblocks.bin` responses commonly include this field.
    pruned: bool,
}

#[derive(Default)]
struct BlockCompleteEntryBuilder {
    block: Option<Vec<u8>>,
    txs: Option<Vec<Vec<u8>>>,
    pruned: Option<bool>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<BlockCompleteEntry> for BlockCompleteEntryBuilder {
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "block" => {
                if bulk_bin_debug_enabled() {
                    let rem_before = r.remaining();
                    println!(
                        "🧩 get_blocks(.bin) block_complete_entry: field='block' remaining_before={}",
                        rem_before
                    );
                }

                self.block = Some(cuprate_epee_encoding::read_epee_value(r)?);

                if bulk_bin_debug_enabled() {
                    let rem_after = r.remaining();
                    println!(
                        "🧩 get_blocks(.bin) block_complete_entry: field='block' remaining_after={}",
                        rem_after
                    );
                }
            }
            "txs" => {
                if bulk_bin_debug_enabled() {
                    let rem_before = r.remaining();
                    let chunk = r.chunk();

                    let peek_marker = if rem_before > 0 && !chunk.is_empty() {
                        format!("0x{:02x}", chunk[0])
                    } else if rem_before > 0 {
                        "(unavailable)".to_string()
                    } else {
                        "(eof)".to_string()
                    };

                    // Dump leading bytes when we see the observed txs marker (0x8c) so we can
                    // reverse-engineer the actual container encoding on this daemon.
                    if rem_before > 0 && !chunk.is_empty() && chunk[0] == 0x8c {
                        let dump_len = std::cmp::min(16, chunk.len());
                        let mut hex = String::new();
                        for (i, b) in chunk[..dump_len].iter().enumerate() {
                            if i > 0 {
                                hex.push(' ');
                            }
                            hex.push_str(&format!("{:02x}", b));
                        }
                        println!(
                            "🧩 get_blocks(.bin) block_complete_entry: field='txs' marker=0x8c leading_bytes[0..{}]={}",
                            dump_len, hex
                        );
                    }

                    println!(
                        "🧩 get_blocks(.bin) block_complete_entry: field='txs' remaining_before={} next_marker={}",
                        rem_before, peek_marker
                    );
                }

                // Some daemons encode `txs` with a typed-array marker (observed 0x8c + element type name "blob").
                // Parse it in a spec-driven way keyed by the embedded element type name.
                // Fall back to cuprate's generic decoder for other encodings.
                let txs_value = {
                    let chunk = r.chunk();
                    if !chunk.is_empty() && chunk[0] == 0x8c {
                        read_txs_typed_array_0x8c(r)?
                    } else {
                        cuprate_epee_encoding::read_epee_value(r)?
                    }
                };
                self.txs = Some(txs_value);

                if bulk_bin_debug_enabled() {
                    let rem_after = r.remaining();
                    let chunk = r.chunk();
                    let peek_marker = if rem_after > 0 && !chunk.is_empty() {
                        format!("0x{:02x}", chunk[0])
                    } else if rem_after > 0 {
                        "(unavailable)".to_string()
                    } else {
                        "(eof)".to_string()
                    };

                    println!(
                        "🧩 get_blocks(.bin) block_complete_entry: field='txs' remaining_after={} next_marker={}",
                        rem_after, peek_marker
                    );
                }
            }

            // Be permissive with common field name variants observed across daemons / implementations.
            // We normalize them into our internal `txs` list.
            "txs_blob" | "txs_blobs" | "txs_bytes" | "txs_byte" | "txs_data" | "transactions" => {
                if bulk_bin_debug_enabled() {
                    println!(
                        "🧩 get_blocks(.bin) block_complete_entry: field={:?} (normalized to 'txs')",
                        name
                    );
                }
                self.txs = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }

            "pruned" => {
                if bulk_bin_debug_enabled() {
                    let rem_before = r.remaining();
                    let peek_marker = if rem_before > 0 {
                        let chunk = r.chunk();
                        if !chunk.is_empty() {
                            format!("0x{:02x}", chunk[0])
                        } else {
                            "(unavailable)".to_string()
                        }
                    } else {
                        "(eof)".to_string()
                    };

                    println!(
                        "🧩 get_blocks(.bin) block_complete_entry: field='pruned' remaining_before={} next_marker={}",
                        rem_before, peek_marker
                    );
                }

                self.pruned = Some(cuprate_epee_encoding::read_epee_value(r)?);

                if bulk_bin_debug_enabled() {
                    let rem_after = r.remaining();
                    let peek_marker = if rem_after > 0 {
                        let chunk = r.chunk();
                        if !chunk.is_empty() {
                            format!("0x{:02x}", chunk[0])
                        } else {
                            "(unavailable)".to_string()
                        }
                    } else {
                        "(eof)".to_string()
                    };

                    println!(
                        "🧩 get_blocks(.bin) block_complete_entry: field='pruned' remaining_after={} next_marker={}",
                        rem_after, peek_marker
                    );
                }
            }

            _ => {
                // IMPORTANT:
                // For `/getblocks.bin`, Monero's `block_complete_entry` may contain additional fields
                // (beyond `block`, `txs`, `pruned`). If we return `Ok(false)` without consuming the
                // field value, the decoder cursor becomes misaligned and we can hit:
                // "Marker does not match expected Marker".
                //
                // Therefore: read and discard unknown field values to keep decoding aligned.
                //
                // Additional diagnostics:
                // - Log the *next marker byte* (peek) and remaining buffer size BEFORE skipping.
                //   This helps identify which portable_storage marker type we failed to handle.
                let rem_before = r.remaining();
                let peek_marker = if rem_before > 0 {
                    // We can't peek without consuming; read then immediately re-insert is not possible with Buf.
                    // So we log the first byte via a best-effort: if the Buf implementation supports chunk(),
                    // use it; otherwise log "(unavailable)".
                    let chunk = r.chunk();
                    if !chunk.is_empty() {
                        format!("0x{:02x}", chunk[0])
                    } else {
                        "(unavailable)".to_string()
                    }
                } else {
                    "(eof)".to_string()
                };

                if bulk_bin_debug_enabled() {
                    println!(
                        "🧩 get_blocks(.bin) block_complete_entry: skipping unknown field {:?} (next_marker={} remaining_before_skip={})",
                        name, peek_marker, rem_before
                    );
                } else if !BULK_BIN_UNKNOWN_FIELD_LOGGED.swap(true, Ordering::Relaxed) {
                    println!(
                        "🧩 get_blocks(.bin) block_complete_entry: skipping unknown field {:?} (next_marker={} remaining_before_skip={})",
                        name, peek_marker, rem_before
                    );
                }

                // Discard unknown value while advancing the buffer cursor.
                //
                // NOTE: Decoding as `Bytes` is NOT safe here because unknown fields may be bool/int/array/object.
                // We must skip any EPEE value generically.
                skip_epee_value(r)?;
            }
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<BlockCompleteEntry> {
        let block = self.block.ok_or_else(|| {
            cuprate_epee_encoding::error::Error::Format("block_complete_entry missing 'block'")
        })?;

        let txs = self.txs.unwrap_or_default();
        let pruned = self.pruned.unwrap_or(false);

        if bulk_bin_debug_enabled() {
            println!(
                "🧩 get_blocks(.bin) block_complete_entry: decoded block_bytes={} tx_blobs={} pruned={}",
                block.len(),
                txs.len(),
                pruned
            );
        }

        Ok(BlockCompleteEntry { block, txs, pruned })
    }
}

impl EpeeObject for BlockCompleteEntry {
    type Builder = BlockCompleteEntryBuilder;

    fn number_of_fields(&self) -> u64 {
        3
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.block, "block", w)?;
        write_field(self.txs, "txs", w)?;
        write_field(self.pruned, "pruned", w)?;
        Ok(())
    }
}

/// Minimal response model for monerod `/get_blocks_by_height.bin`.
/// We only decode the fields we need for scanning: `blocks`, `status`, and `untrusted`.
#[derive(Clone, Debug)]
struct GetBlocksByHeightBinResponse {
    blocks: Vec<BlockCompleteEntry>,
    status: Option<String>,
    untrusted: Option<bool>,
}

#[derive(Default)]
struct GetBlocksByHeightBinResponseBuilder {
    blocks: Option<Vec<BlockCompleteEntry>>,
    status: Option<String>,
    untrusted: Option<bool>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<GetBlocksByHeightBinResponse>
    for GetBlocksByHeightBinResponseBuilder
{
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "blocks" => {
                self.blocks = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "status" => {
                self.status = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "untrusted" => {
                self.untrusted = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<GetBlocksByHeightBinResponse> {
        Ok(GetBlocksByHeightBinResponse {
            blocks: self.blocks.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("response missing 'blocks'")
            })?,
            status: self.status,
            untrusted: self.untrusted,
        })
    }
}

impl EpeeObject for GetBlocksByHeightBinResponse {
    type Builder = GetBlocksByHeightBinResponseBuilder;

    fn number_of_fields(&self) -> u64 {
        3
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.blocks, "blocks", w)?;
        if let Some(status) = self.status {
            write_field(status, "status", w)?;
        }
        if let Some(untrusted) = self.untrusted {
            write_field(untrusted, "untrusted", w)?;
        }
        Ok(())
    }
}

/*
 * Minimal response model for monerod `/get_blocks.bin`.
 * We only decode what we need: `blocks`, `status`, `untrusted`.
 */
#[derive(Clone, Debug)]
struct GetBlocksBinResponse {
    blocks: Vec<BlockCompleteEntry>,
    status: Option<String>,
    untrusted: Option<bool>,
}

#[derive(Default)]
struct GetBlocksBinResponseBuilder {
    blocks: Option<Vec<BlockCompleteEntry>>,
    status: Option<String>,
    untrusted: Option<bool>,
}

impl cuprate_epee_encoding::EpeeObjectBuilder<GetBlocksBinResponse>
    for GetBlocksBinResponseBuilder
{
    fn add_field<B: Buf>(
        &mut self,
        name: &str,
        r: &mut B,
    ) -> cuprate_epee_encoding::error::Result<bool> {
        match name {
            "blocks" => {
                self.blocks = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "status" => {
                self.status = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            "untrusted" => {
                self.untrusted = Some(cuprate_epee_encoding::read_epee_value(r)?);
            }
            _ => return Ok(false),
        }
        Ok(true)
    }

    fn finish(self) -> cuprate_epee_encoding::error::Result<GetBlocksBinResponse> {
        Ok(GetBlocksBinResponse {
            blocks: self.blocks.ok_or_else(|| {
                cuprate_epee_encoding::error::Error::Format("response missing 'blocks'")
            })?,
            status: self.status,
            untrusted: self.untrusted,
        })
    }
}

impl EpeeObject for GetBlocksBinResponse {
    type Builder = GetBlocksBinResponseBuilder;

    fn number_of_fields(&self) -> u64 {
        3
    }

    fn write_fields<B: BufMut>(self, w: &mut B) -> cuprate_epee_encoding::error::Result<()> {
        write_field(self.blocks, "blocks", w)?;
        if let Some(status) = self.status {
            write_field(status, "status", w)?;
        }
        if let Some(untrusted) = self.untrusted {
            write_field(untrusted, "untrusted", w)?;
        }
        Ok(())
    }
}

impl BlockingRpcTransport {
    fn new(raw_url: &str) -> Result<Self, c_int> {
        let base_url = raw_url.trim_end_matches('/').to_string();
        if base_url.is_empty() {
            return Err(-14);
        }

        // Build an HTTP client, optionally honoring proxy env vars (HTTP_PROXY/http_proxy/ALL_PROXY/all_proxy)
        let mut builder = ureq::AgentBuilder::new().timeout(Duration::from_secs(30));

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
            .map_err(|err| RpcError::ConnectionError(err.to_string()))?;
        let mut reader = response.into_reader();
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|err| RpcError::ConnectionError(err.to_string()))?;
        Ok(buf)
    }

    fn post_bin(&self, route: &str, body: Vec<u8>) -> Result<Vec<u8>, RpcError> {
        let response = self
            .request_for_bin(route)
            .send_bytes(&body)
            .map_err(|err| RpcError::ConnectionError(err.to_string()))?;
        let mut reader = response.into_reader();
        let mut buf = Vec::new();
        reader
            .read_to_end(&mut buf)
            .map_err(|err| RpcError::ConnectionError(err.to_string()))?;
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
            .map_err(|e| RpcError::InvalidNode(format!("epee encode: {e}")))?;
        let resp_bytes = self.post_bin("get_blocks_by_height.bin", body)?;
        let mut reader: &[u8] = resp_bytes.as_slice();
        let resp: GetBlocksByHeightBinResponse = from_bytes(&mut reader)
            .map_err(|e| RpcError::InvalidNode(format!("epee decode: {e}")))?;
        Ok(resp)
    }

    fn get_blocks_bin(
        &self,
        start_height: u64,
        count: u64,
        prune: bool,
    ) -> Result<GetBlocksBinResponse, RpcError> {
        let req = GetBlocksBinRequest {
            start_height,
            count,
            prune,
        };
        let body = to_bytes(req)
            .map(|b| b.to_vec())
            .map_err(|e| RpcError::InvalidNode(format!("epee encode: {e}")))?;
        let resp_bytes = self.post_bin("get_blocks.bin", body)?;
        let mut reader: &[u8] = resp_bytes.as_slice();
        let resp: GetBlocksBinResponse = from_bytes(&mut reader)
            .map_err(|e| RpcError::InvalidNode(format!("epee decode: {e}")))?;
        Ok(resp)
    }

    fn get_blocks_fast_bin(
        &self,
        block_ids: Vec<[u8; 32]>,
        start_height: u64,
        prune: bool,
    ) -> Result<GetBlocksFastBinResponse, RpcError> {
        // Match COMMAND_RPC_GET_BLOCKS_FAST::request_t defaults:
        // requested_info defaults to 0 (BLOCKS_ONLY),
        // no_miner_tx defaults to false,
        // pool_info_since defaults to 0,
        // max_block_count defaults to 0.
        //
        // IMPORTANT: `block_ids` must be encoded as KV_SERIALIZE_CONTAINER_POD_AS_BLOB(block_ids),
        // i.e. as a single packed blob of 32-byte hashes.
        let mut block_ids_blob: Vec<u8> = Vec::with_capacity(block_ids.len().saturating_mul(32));
        for h in &block_ids {
            block_ids_blob.extend_from_slice(h);
        }

        // Make the request more explicit in debug mode to encourage daemons to return block entries
        // rather than a packed hash-list variant in `blocks`.
        let (requested_info, max_block_count) = if bulk_bin_debug_enabled() {
            // Empirical: try a "stronger" requested_info and a non-zero max_block_count.
            // We can iterate on requested_info values based on daemon behavior.
            (1u8, block_ids.len() as u64)
        } else {
            (0u8, 0u64)
        };

        if bulk_bin_debug_enabled() {
            println!(
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
            .map_err(|e| RpcError::InvalidNode(format!("epee encode: {e}")))?;
        // Wallet2-style endpoint (non-underscored variant) to avoid colliding with the range-based
        // `/get_blocks.bin` request shape (start_height/count/prune).
        let resp_bytes = self.post_bin("getblocks.bin", body)?;
        let mut reader: &[u8] = resp_bytes.as_slice();
        let resp: GetBlocksFastBinResponse = from_bytes(&mut reader)
            .map_err(|e| RpcError::InvalidNode(format!("epee decode: {e}")))?;
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
                let detail = match &err {
                    ureq::Error::Status(code, resp) => {
                        format!("HTTP {code} {}", resp.status_text())
                    }
                    ureq::Error::Transport(transport) => transport.to_string(),
                };
                (-15, format!("json_rpc {method}: {detail}"))
            })?;
        let value: serde_json::Value = response
            .into_json()
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

impl Rpc for BlockingRpcTransport {
    fn post(
        &self,
        route: &str,
        body: Vec<u8>,
    ) -> impl Future<Output = Result<Vec<u8>, RpcError>> + Send {
        let client = self.clone();
        let route_string = route.to_string();
        async move { client.post_bytes(&route_string, body) }
    }
}
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

fn map_rpc_error(err: RpcError) -> c_int {
    match err {
        RpcError::ConnectionError(_) => -15,
        RpcError::InternalError(_) => -16,
        RpcError::InvalidNode(_) => -16,
        RpcError::TransactionsNotFound(_) => -16,
        RpcError::InvalidTransaction(_) => -16,
        _ => -16,
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
        let b_point = ED25519_BASEPOINT_POINT * keys.view_scalar_dalek;
        let mut data = Vec::with_capacity(8 + 32 + 4 + 4);
        data.extend_from_slice(b"SubAddr\0");
        data.extend_from_slice(keys.entropy.as_ref());
        data.extend_from_slice(&account_index.to_le_bytes());
        data.extend_from_slice(&subaddress_index.to_le_bytes());
        let m_scalar: curve25519_dalek::Scalar = EdScalar::hash(&data).into();
        let d_dalek = b_point + (ED25519_BASEPOINT_POINT * m_scalar);
        let c_dalek = d_dalek * keys.spend_scalar;

        let d_point = EdPoint::from(d_dalek);
        let c_point = EdPoint::from(c_dalek);
        MoneroAddress::new(network, MoneroAddressType::Subaddress, d_point, c_point).to_string()
    }
}

#[no_mangle]
pub extern "C" fn walletcore_version() -> *mut c_char {
    CString::new("walletcore 0.1.0").unwrap().into_raw()
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
    amount: u64,
    block_height: u64,
    additional_timelock: Timelock,
    is_coinbase: bool,
    subaddress_major: u32,
    subaddress_minor: u32,
    spent: bool,
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
struct ObservedOutput {
    tx_hash: String,
    index_in_tx: u64,
    amount: u64,
    block_height: u64,
    subaddress_major: u32,
    subaddress_minor: u32,
    is_coinbase: bool,
    spent: bool,
    confirmations: u64,
    timelock: ObservedTimelock,
    unlock_height: u64,
    unlocked: bool,
    unlock_time: Option<u64>,
}

#[derive(Clone, Debug, Serialize)]
struct ObservedOutputsEnvelope {
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
struct ObservedTransfer {
    txid: String,
    direction: String, // "in" | "out" | "self"
    amount: u64,       // piconero (positive; interpret via direction)
    fee: Option<u64>,  // piconero (outgoing)
    height: Option<u64>,
    timestamp: Option<u64>,
    confirmations: u64,
    is_pending: bool,
    // MVP choice (A): we do not attribute transfers to a specific subaddress because a tx can touch multiple.
    subaddress_major: Option<u32>,
    subaddress_minor: Option<u32>,
}

/// Persisted ledger entry used to build stable transfer history.
///
/// - Incoming ("in"): `amount` is the total received in that tx to this wallet (sum of outputs).
/// - Outgoing ("out"): `amount` is the recipient amount (what the user intended to send), fee stored separately.
/// - Coinbase receives are included (as "in") with `is_coinbase = true`.
///
/// We keep this separate from `TrackedOutput` so history remains stable even after outputs are spent.
#[derive(Clone, Debug, Serialize, Deserialize)]
struct LedgerEntry {
    txid: String,
    direction: String, // "in" | "out" | "self"
    amount: u64,       // piconero (positive; interpret via direction)
    fee: Option<u64>,  // piconero (outgoing)
    height: Option<u64>,
    timestamp: Option<u64>,
    is_pending: bool,
    is_coinbase: bool,
}

fn confirmations_for_height(chain_height: u64, tx_height: u64) -> u64 {
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
    fn from_tracked(output: &TrackedOutput, chain_height: u64, chain_time: u64) -> Self {
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
            timelock,
            unlock_height,
            unlocked,
            unlock_time,
        }
    }
}

#[derive(Clone)]
struct StoredWallet {
    mnemonic: String,
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

    // Wallet2-style bounded recent block-hash history used to build `block_ids` (short chain history)
    // for `/getblocks.bin` fast sync. This is intentionally bounded to keep cache size small.
    //
    // - `recent_block_hashes_start_height` is the height of the first hash in `recent_block_hashes`.
    // - `recent_block_hashes[i]` corresponds to height `recent_block_hashes_start_height + i`.
    recent_block_hashes_start_height: u64,
    recent_block_hashes: Vec<[u8; 32]>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum PersistedTimelock {
    None,
    Block(u64),
    Time(u64),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedOutput {
    tx_hash: [u8; 32],
    index_in_tx: u64,
    amount: u64,
    block_height: u64,
    timelock: PersistedTimelock,
    is_coinbase: bool,
    subaddress_major: u32,
    subaddress_minor: u32,
    spent: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
enum PersistedNetwork {
    Mainnet,
    Stagenet,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PersistedWallet {
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

    // Bounded recent block-hash history (see `StoredWallet` for details).
    // Marked `serde(default)` so older cache blobs (which don't have these fields yet)
    // can still be deserialized safely.
    #[serde(default)]
    recent_block_hashes_start_height: u64,
    #[serde(default)]
    recent_block_hashes: Vec<[u8; 32]>,
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
            amount: output.amount,
            block_height: output.block_height,
            timelock: PersistedTimelock::from(&output.additional_timelock),
            is_coinbase: output.is_coinbase,
            subaddress_major: output.subaddress_major,
            subaddress_minor: output.subaddress_minor,
            spent: output.spent,
        }
    }
}

impl From<PersistedOutput> for TrackedOutput {
    fn from(output: PersistedOutput) -> Self {
        Self {
            tx_hash: output.tx_hash,
            index_in_tx: output.index_in_tx,
            amount: output.amount,
            block_height: output.block_height,
            additional_timelock: output.timelock.into(),
            is_coinbase: output.is_coinbase,
            subaddress_major: output.subaddress_major,
            subaddress_minor: output.subaddress_minor,
            spent: output.spent,
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

            recent_block_hashes_start_height: wallet.recent_block_hashes_start_height,
            recent_block_hashes: wallet.recent_block_hashes.clone(),
        }
    }
}

impl PersistedWallet {
    fn apply_to_state(self, state: &mut StoredWallet) {
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

        // Bounded recent block-hash history (wallet2-style chain history).
        state.recent_block_hashes_start_height = self.recent_block_hashes_start_height;
        state.recent_block_hashes = self.recent_block_hashes;

        // Defensive: older caches or older runtime state may not have initialized the ledger.
        // Ensure it exists so transfer history can be built deterministically.
        if state.tx_ledger.is_empty() {
            state.tx_ledger = HashMap::new();
        }

        // Invariant enforcement:
        // Cache blobs may have been exported mid-refresh (or from older versions), which can result in
        // tracked outputs/ledger being present while total/unlocked are stale (e.g., 0).
        // Recompute balances from the imported tracked outputs using the imported chain height/time.
        let mut total: u64 = 0;
        let mut unlocked: u64 = 0;
        for o in state.tracked_outputs.iter() {
            total = total.saturating_add(o.amount);
            if o.is_unlocked(state.chain_height, state.chain_time) {
                unlocked = unlocked.saturating_add(o.amount);
            }
        }
        state.total = total;
        state.unlocked = unlocked;
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

    // Basic validation: attempt to parse mnemonic (English) so obviously bad inputs fail fast
    if MoneroSeed::from_string(
        MoneroSeedLanguage::English,
        Zeroizing::new(mnemonic.to_string()),
    )
    .is_err()
    {
        return -10;
    }

    let network = if is_mainnet != 0 {
        MoneroNetwork::Mainnet
    } else {
        MoneroNetwork::Stagenet
    };

    let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
    match map.entry(id.to_string()) {
        Entry::Occupied(mut slot) => {
            let state = slot.get_mut();
            state.mnemonic = mnemonic.to_string();
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
                mnemonic: mnemonic.to_string(),
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

                // Start empty; will be populated during refresh.
                recent_block_hashes_start_height: restore_height,
                recent_block_hashes: Vec::new(),
            });
        }
    }
    0
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
}

#[no_mangle]
pub extern "C" fn wallet_refresh(
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

    // If cancellation was requested before we even start, abort immediately.
    if refresh_cancelled_for_wallet(id) {
        return record_error(-30, "wallet_refresh: cancelled");
    }

    // Clear any stale cancellation request once we have decided to start.
    // This ensures a prior cancel doesn't accidentally cancel a new refresh later.
    set_refresh_cancel_for_wallet(id, false);

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

    // Refresh entry stamp: proves which core build is actually running.
    // This is intentionally one-line and stable so you can grep for it in device logs.
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
        .unwrap_or_else(|| "(default=wallet2)".to_string());
    let env_bulk_fetch_batch = std::env::var("WALLETCORE_BULK_FETCH_BATCH")
        .ok()
        .unwrap_or_else(|| "(default=200)".to_string());

    print!(
        "🧩 walletcore refresh entry: version={} build={} wallet_id={} node_url={} env{{scan_par={} scan_batch={} bulk_fetch={} bulk_mode={} bulk_fetch_batch={}}}\n",
        WALLETCORE_LOG_VERSION,
        build_stamp(),
        id,
        base_url,
        env_par,
        env_batch,
        env_bulk_fetch,
        env_bulk_mode,
        env_bulk_fetch_batch
    );

    let rpc_client = match BlockingRpcTransport::new(&base_url) {
        Ok(client) => client,
        Err(code) => {
            return record_error(
                code,
                format!("wallet_refresh: invalid daemon url '{base_url}'"),
            );
        }
    };
    let daemon = match fetch_daemon_status(&rpc_client) {
        Ok(status) => status,
        Err((code, message)) => {
            return record_error(
                code,
                format!("wallet_refresh: failed to query daemon '{base_url}': {message}"),
            );
        }
    };

    let snapshot = {
        let map = WALLET_STORE.lock().expect("wallet store poisoned");
        match map.get(id) {
            Some(state) => state.clone(),
            None => {
                return record_error(-13, format!("wallet_refresh: wallet '{id}' not registered"))
            }
        }
    };

    let master = match master_keys_from_mnemonic_str(&snapshot.mnemonic) {
        Ok(keys) => keys,
        Err(code) => {
            return record_error(
                code,
                format!("wallet_refresh: unable to parse mnemonic ({code})"),
            )
        }
    };
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
    // Major account lookahead: default 1 (account 0 only); configurable via WALLETCORE_ACCOUNT_GAP
    let account_gap: u32 = std::env::var("WALLETCORE_ACCOUNT_GAP")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .map(|v| v.max(1))
        .unwrap_or(1);

    // Register subaddresses across accounts and subaddresses:
    // major: [0, account_gap), minor: [0, gap_limit]
    for major in 0..account_gap {
        if let Some(idx0) = SubaddressIndex::new(major, 0) {
            scanner.register_subaddress(idx0);
        }
        for minor in 1..=gap_limit {
            if let Some(idx) = SubaddressIndex::new(major, minor) {
                scanner.register_subaddress(idx);
            }
        }
    }

    let mut working_outputs = snapshot.tracked_outputs.clone();
    let mut seen_outpoints = snapshot.seen_outpoints.clone();
    let mut scan_cursor = snapshot.last_scanned.max(snapshot.restore_height);
    update_scan_progress(
        id,
        scan_cursor.min(daemon.height),
        daemon.height,
        daemon.top_block_timestamp,
        snapshot.restore_height,
    );

    // Optional performance logging controls
    let log_perf: bool = std::env::var("WALLETCORE_SCAN_LOG")
        .ok()
        .map(|s| s != "0")
        .unwrap_or(false);
    let overall_start: Option<std::time::Instant> = if log_perf {
        Some(std::time::Instant::now())
    } else {
        None
    };
    let initial_outputs: usize = working_outputs.len();

    // Optional parallel scan controls
    let par: usize = std::env::var("WALLETCORE_SCAN_PAR")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(0);
    let batch: usize = std::env::var("WALLETCORE_SCAN_BATCH")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(200);
    // Bulk mode: allow each worker to scan a small span of consecutive heights
    //
    // Default: ON (1) to reduce per-block RPC overhead (faster on LAN / responsive nodes).
    // Set WALLETCORE_BULK_RPC=0 to disable and force per-block fetch behavior.
    let bulk: bool = std::env::var("WALLETCORE_BULK_RPC")
        .ok()
        .map(|s| s != "0")
        .unwrap_or(true);

    // Binary bulk fetch mode: batch fetch blocks via monerod *.bin endpoints.
    // Default: ON for clearnet. Turn off with WALLETCORE_BULK_FETCH=0.
    //
    // NOTE: We default-enable the mode here, but will only take the bin path when scanning over
    // clearnet (i.e., when node_url is provided by caller). For I2P scans, we keep per-block fetch
    // due to higher latency and stricter proxy behavior.
    let bulk_fetch_mode: BulkFetchMode = bulk_fetch_mode_from_env();
    let bulk_fetch_batch: usize = bulk_fetch_batch_from_env();

    // Log the resolved bulk mode once per refresh (before any worker gating).
    // This disambiguates "env says bulk=1" from "effective mode got forced to per-block due to policy".
    print!(
        "🧱 bulk-fetch mode resolved: requested={} batch={} (pre-clearnet-gating)\n",
        bulk_mode_str(bulk_fetch_mode),
        bulk_fetch_batch
    );

    // Bulk worker span (how many consecutive heights a worker scans in one go when bulk is enabled).
    // Default: 200 blocks. Increase for fewer RPC calls; decrease for more granular progress/cancellation.
    let worker_blocks: usize = std::env::var("WALLETCORE_WORKER_BLOCKS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(200);
    // (moved above) WALLETCORE_WORKER_BLOCKS is now configured alongside WALLETCORE_BULK_RPC.

    if scan_cursor < daemon.height {
        if par > 1 && batch > 1 {
            // Parallel, batched scanning. Each worker uses its own Scanner cloned from the same view_pair.
            //
            // Bulk fetch is default-enabled but clearnet-only (node_url must be provided). For I2P scans we
            // force per-block due to higher latency/proxy behavior.
            let clearnet_scan: bool = !node_url.is_null();
            let effective_bulk_fetch: BulkFetchMode = if clearnet_scan {
                bulk_fetch_mode
            } else {
                BulkFetchMode::PerBlock
            };

            // One-line logging for bulk enable/fallback (per refresh)
            let mut bulk_fetch_logged: bool = false;
            let mut bulk_fetch_fallback_logged: bool = false;

            while scan_cursor < daemon.height {
                // Cancellation check (per-wallet)
                if refresh_cancelled_for_wallet(id) {
                    return record_error(-30, "wallet_refresh: cancelled");
                }

                let end_exclusive = {
                    let end = scan_cursor.saturating_add(batch as u64);
                    if end > daemon.height {
                        daemon.height
                    } else {
                        end
                    }
                };
                // Plan work as disjoint spans so workers don't duplicate fetching/scanning.
                // Each span is at most `bulk_fetch_batch` heights.
                let mut spans: Vec<(u64, u64)> = Vec::new();
                let mut s = scan_cursor;
                while s < end_exclusive {
                    let e = end_exclusive.min(s.saturating_add(bulk_fetch_batch as u64));
                    spans.push((s, e));
                    s = e;
                }

                let (tx, rx) =
                    std::sync::mpsc::channel::<Result<Vec<TrackedOutput>, (c_int, String)>>();

                // One-time enable log
                if effective_bulk_fetch != BulkFetchMode::PerBlock && !bulk_fetch_logged {
                    let mode_str = match effective_bulk_fetch {
                        BulkFetchMode::Wallet2FastBlocks => "getblocks(wallet2)",
                        BulkFetchMode::RangeBlocks => "get_blocks(range)",
                        BulkFetchMode::PerBlock => "per_block",
                    };
                    print!(
                        "🧱 bulk-fetch(bin:{})=on batch={} clearnet={}\n",
                        mode_str, bulk_fetch_batch, clearnet_scan
                    );
                    bulk_fetch_logged = true;
                }

                // Launch workers in chunks of `par`
                for chunk in spans.chunks(par) {
                    for &(start_h, end_h_exclusive) in chunk {
                        // Cancellation check (per-wallet) before spawning more work
                        if refresh_cancelled_for_wallet(id) {
                            return record_error(-30, "wallet_refresh: cancelled");
                        }

                        let txc = tx.clone();
                        let client = rpc_client.clone();
                        let vp = view_pair.clone();
                        let local_gap = gap_limit;
                        let id_owned_for_worker = id.to_string();
                        let worker_effective_bulk_fetch = effective_bulk_fetch;

                        std::thread::spawn(move || {
                            // Early exit if cancelled before worker begins
                            if refresh_cancelled_for_wallet(&id_owned_for_worker) {
                                let _ =
                                    txc.send(Err((-30, "wallet_refresh: cancelled".to_string())));
                                return;
                            }

                            // Local scanner per worker
                            let mut local_scanner = Scanner::new(vp);
                            if let Some(i0) = SubaddressIndex::new(0, 0) {
                                local_scanner.register_subaddress(i0);
                            }
                            for minor in 1..=local_gap {
                                if let Some(idx) = SubaddressIndex::new(0, minor) {
                                    local_scanner.register_subaddress(idx);
                                }
                            }

                            let mut collected: Vec<TrackedOutput> = Vec::new();

                            match worker_effective_bulk_fetch {
                                BulkFetchMode::Wallet2FastBlocks => {
                                    let count = end_h_exclusive.saturating_sub(start_h);
                                    if count == 0 {
                                        let _ = txc.send(Ok(collected));
                                        return;
                                    }

                                    // Build short chain history (block_ids) from the persisted bounded hash window.
                                    // If empty, seed it via on_get_block_hash and retry.
                                    let mut block_ids = {
                                        let mut ids: Vec<[u8; 32]> = Vec::new();
                                        if let Ok(map) = WALLET_STORE.lock() {
                                            if let Some(state) = map.get(&id_owned_for_worker) {
                                                ids = build_short_chain_history(state);
                                            }
                                        }
                                        ids
                                    };

                                    if block_ids.is_empty() {
                                        match client.seed_recent_block_hashes_for_wallet2(
                                            &id_owned_for_worker,
                                            start_h,
                                        ) {
                                            Ok(()) => {
                                                if let Ok(map) = WALLET_STORE.lock() {
                                                    if let Some(state) =
                                                        map.get(&id_owned_for_worker)
                                                    {
                                                        block_ids =
                                                            build_short_chain_history(state);
                                                    }
                                                }
                                            }
                                            Err((code, msg)) => {
                                                let _ = txc.send(Err((
                                                    code,
                                                    format!(
                                                        "wallet_refresh: wallet2 bulk seed failed at start_h {}: {}",
                                                        start_h, msg
                                                    ),
                                                )));
                                                return;
                                            }
                                        }
                                    }

                                    if block_ids.is_empty() {
                                        let _ = txc.send(Err((
                                            -16,
                                            "wallet_refresh: wallet2 bulk mode has no chain history yet (block_ids empty after seeding)".to_string(),
                                        )));
                                        return;
                                    }

                                    // Call wallet2-style getblocks.bin (blocks + output_indices).
                                    let resp = match client
                                        .get_blocks_fast_bin(block_ids, start_h, true)
                                    {
                                        Ok(r) => r,
                                        Err(err) => {
                                            let _ = txc.send(Err((
                                                -16,
                                                format!(
                                                    "wallet_refresh: bulk getblocks.bin failed at heights {}..{}: {}",
                                                    start_h,
                                                    end_h_exclusive.saturating_sub(1),
                                                    err
                                                ),
                                            )));
                                            return;
                                        }
                                    };

                                    if resp.blocks.is_empty() {
                                        let _ = txc.send(Err((
                                            -16,
                                            format!(
                                                "wallet_refresh: bulk getblocks.bin returned 0 blocks for heights {}..{}",
                                                start_h,
                                                end_h_exclusive.saturating_sub(1)
                                            ),
                                        )));
                                        return;
                                    }

                                    if resp.blocks.len() != resp.output_indices.len() {
                                        let _ = txc.send(Err((
                                            -16,
                                            format!(
                                                "wallet_refresh: getblocks.bin mismatched blocks ({}) and output_indices ({}) sizes",
                                                resp.blocks.len(),
                                                resp.output_indices.len()
                                            ),
                                        )));
                                        return;
                                    }

                                    // Scan each returned block entry in order. We assign heights sequentially starting from start_h.
                                    let mut th = start_h;
                                    for (entry, boi) in
                                        resp.blocks.into_iter().zip(resp.output_indices.into_iter())
                                    {
                                        if refresh_cancelled_for_wallet(&id_owned_for_worker) {
                                            let _ = txc.send(Err((
                                                -30,
                                                "wallet_refresh: cancelled".to_string(),
                                            )));
                                            return;
                                        }

                                        // If tx blobs are missing for this entry, fall back to per-block for just that height.
                                        if entry.txs.is_empty() {
                                            let block_number = match usize::try_from(th) {
                                                Ok(v) => v,
                                                Err(_) => {
                                                    let _ = txc.send(Err((
                                                        -16,
                                                        "wallet_refresh: block number conversion overflow"
                                                            .to_string(),
                                                    )));
                                                    return;
                                                }
                                            };

                                            let scannable = match block_on(
                                                client.get_scannable_block_by_number(block_number),
                                            ) {
                                                Ok(block) => block,
                                                Err(err) => {
                                                    let _ = txc.send(Err((
                                                        -16,
                                                        format!(
                                                            "wallet_refresh: per-block fallback RPC block fetch failed at height {}: {}",
                                                            th, err
                                                        ),
                                                    )));
                                                    return;
                                                }
                                            };

                                            // Record hash
                                            {
                                                let block_hash = scannable.block.hash();
                                                if let Ok(mut map) = WALLET_STORE.lock() {
                                                    if let Some(state) =
                                                        map.get_mut(&id_owned_for_worker)
                                                    {
                                                        push_recent_block_hash(
                                                            state, th, block_hash,
                                                        );
                                                    }
                                                }
                                            }

                                            let miner_hash =
                                                scannable.block.miner_transaction().hash();
                                            let outputs = match local_scanner.scan(scannable) {
                                                Ok(result) => result.ignore_additional_timelock(),
                                                Err(_) => {
                                                    let _ = txc.send(Err((
                                                        -16,
                                                        format!("wallet_refresh: scanner failed at height {}", th),
                                                    )));
                                                    return;
                                                }
                                            };

                                            for output in outputs {
                                                let (major, minor) = output
                                                    .subaddress()
                                                    .map(|idx| (idx.account(), idx.address()))
                                                    .unwrap_or((0, 0));
                                                collected.push(TrackedOutput {
                                                    tx_hash: output.transaction(),
                                                    index_in_tx: output.index_in_transaction(),
                                                    amount: output.commitment().amount,
                                                    block_height: th,
                                                    additional_timelock: output
                                                        .additional_timelock(),
                                                    is_coinbase: output.transaction() == miner_hash,
                                                    subaddress_major: major,
                                                    subaddress_minor: minor,
                                                    spent: false,
                                                });
                                            }

                                            th = th.saturating_add(1);
                                            continue;
                                        }

                                        // Parse block blob
                                        let mut bb = entry.block.as_slice();
                                        let parsed_block = match Block::read(&mut bb) {
                                            Ok(b) => b,
                                            Err(_) => {
                                                let _ = txc.send(Err((
                                                    -16,
                                                    format!(
                                                        "wallet_refresh: block parse failed at height {}",
                                                        th
                                                    ),
                                                )));
                                                return;
                                            }
                                        };

                                        // Parse tx blobs (pruned)
                                        let mut parsed_txs: Vec<Transaction<Pruned>> =
                                            Vec::with_capacity(entry.txs.len());
                                        for tx_blob in entry.txs {
                                            let mut tb = tx_blob.as_slice();
                                            match Transaction::<Pruned>::read(&mut tb) {
                                                Ok(t) => parsed_txs.push(t),
                                                Err(_) => {
                                                    let _ = txc.send(Err((
                                                        -16,
                                                        format!(
                                                            "wallet_refresh: tx parse failed at height {}",
                                                            th
                                                        ),
                                                    )));
                                                    return;
                                                }
                                            }
                                        }

                                        // Record hash from the parsed block (works without extra RPC)
                                        {
                                            let block_hash = parsed_block.hash();
                                            if let Ok(mut map) = WALLET_STORE.lock() {
                                                if let Some(state) =
                                                    map.get_mut(&id_owned_for_worker)
                                                {
                                                    push_recent_block_hash(state, th, block_hash);
                                                }
                                            }
                                        }

                                        // Compute output_index_for_first_ringct_output from output_indices (wallet2-style),
                                        // avoiding get_o_indexes.bin.
                                        let mut output_index_for_first_ringct_output: Option<u64> =
                                            None;
                                        for txoi in boi.indices.iter() {
                                            if let Some(first) = txoi.indices.first() {
                                                output_index_for_first_ringct_output = Some(*first);
                                                break;
                                            }
                                        }

                                        let scannable = ScannableBlock {
                                            block: parsed_block,
                                            transactions: parsed_txs,
                                            output_index_for_first_ringct_output,
                                        };

                                        let miner_hash = scannable.block.miner_transaction().hash();
                                        let outputs = match local_scanner.scan(scannable) {
                                            Ok(result) => result.ignore_additional_timelock(),
                                            Err(_) => {
                                                let _ = txc.send(Err((
                                                    -16,
                                                    format!(
                                                        "wallet_refresh: scanner failed at height {}",
                                                        th
                                                    ),
                                                )));
                                                return;
                                            }
                                        };

                                        for output in outputs {
                                            let (major, minor) = output
                                                .subaddress()
                                                .map(|idx| (idx.account(), idx.address()))
                                                .unwrap_or((0, 0));
                                            collected.push(TrackedOutput {
                                                tx_hash: output.transaction(),
                                                index_in_tx: output.index_in_transaction(),
                                                amount: output.commitment().amount,
                                                block_height: th,
                                                additional_timelock: output.additional_timelock(),
                                                is_coinbase: output.transaction() == miner_hash,
                                                subaddress_major: major,
                                                subaddress_minor: minor,
                                                spent: false,
                                            });
                                        }

                                        th = th.saturating_add(1);
                                    }

                                    let _ = txc.send(Ok(collected));
                                }

                                BulkFetchMode::RangeBlocks => {
                                    let count = end_h_exclusive.saturating_sub(start_h);
                                    if count == 0 {
                                        let _ = txc.send(Ok(collected));
                                        return;
                                    }

                                    let resp = match client.get_blocks_bin(start_h, count, false) {
                                        Ok(r) => r,
                                        Err(err) => {
                                            let _ = txc.send(Err((
                                                -16,
                                                format!(
                                                    "wallet_refresh: bulk get_blocks.bin failed at heights {}..{}: {}",
                                                    start_h,
                                                    end_h_exclusive.saturating_sub(1),
                                                    err
                                                ),
                                            )));
                                            return;
                                        }
                                    };

                                    if resp.blocks.is_empty() {
                                        let _ = txc.send(Err((
                                            -16,
                                            format!(
                                                "wallet_refresh: bulk get_blocks.bin returned 0 blocks for heights {}..{}",
                                                start_h,
                                                end_h_exclusive.saturating_sub(1)
                                            ),
                                        )));
                                        return;
                                    }

                                    let mut th = start_h;
                                    for entry in resp.blocks {
                                        if refresh_cancelled_for_wallet(&id_owned_for_worker) {
                                            let _ = txc.send(Err((
                                                -30,
                                                "wallet_refresh: cancelled".to_string(),
                                            )));
                                            return;
                                        }

                                        if entry.txs.is_empty() {
                                            let block_number = match usize::try_from(th) {
                                                Ok(v) => v,
                                                Err(_) => {
                                                    let _ = txc.send(Err((
                                                        -16,
                                                        "wallet_refresh: block number conversion overflow"
                                                            .to_string(),
                                                    )));
                                                    return;
                                                }
                                            };

                                            let scannable = match block_on(
                                                client.get_scannable_block_by_number(block_number),
                                            ) {
                                                Ok(block) => block,
                                                Err(err) => {
                                                    let _ = txc.send(Err((
                                                        -16,
                                                        format!(
                                                            "wallet_refresh: per-block fallback RPC block fetch failed at height {}: {}",
                                                            th, err
                                                        ),
                                                    )));
                                                    return;
                                                }
                                            };

                                            // Record block hash into wallet2-style recent hash history
                                            // (used to build short chain history for `/getblocks.bin`).
                                            {
                                                let block_hash = scannable.block.hash();
                                                if let Ok(mut map) = WALLET_STORE.lock() {
                                                    if let Some(state) =
                                                        map.get_mut(&id_owned_for_worker)
                                                    {
                                                        push_recent_block_hash(
                                                            state, th, block_hash,
                                                        );
                                                    }
                                                }
                                            }

                                            let miner_hash =
                                                scannable.block.miner_transaction().hash();
                                            let outputs = match local_scanner.scan(scannable) {
                                                Ok(result) => result.ignore_additional_timelock(),
                                                Err(_) => {
                                                    let _ = txc.send(Err((
                                                        -16,
                                                        format!(
                                                            "wallet_refresh: scanner failed at height {}",
                                                            th
                                                        ),
                                                    )));
                                                    return;
                                                }
                                            };

                                            for output in outputs {
                                                let (major, minor) = output
                                                    .subaddress()
                                                    .map(|idx| (idx.account(), idx.address()))
                                                    .unwrap_or((0, 0));
                                                collected.push(TrackedOutput {
                                                    tx_hash: output.transaction(),
                                                    index_in_tx: output.index_in_transaction(),
                                                    amount: output.commitment().amount,
                                                    block_height: th,
                                                    additional_timelock: output
                                                        .additional_timelock(),
                                                    is_coinbase: output.transaction() == miner_hash,
                                                    subaddress_major: major,
                                                    subaddress_minor: minor,
                                                    spent: false,
                                                });
                                            }

                                            th = th.saturating_add(1);
                                            continue;
                                        }

                                        let mut bb = entry.block.as_slice();
                                        let parsed_block = match Block::read(&mut bb) {
                                            Ok(b) => b,
                                            Err(_) => {
                                                let _ = txc.send(Err((
                                                    -16,
                                                    format!(
                                                        "wallet_refresh: block parse failed at height {}",
                                                        th
                                                    ),
                                                )));
                                                return;
                                            }
                                        };

                                        let mut parsed_txs: Vec<Transaction<Pruned>> =
                                            Vec::with_capacity(entry.txs.len());
                                        for tx_blob in entry.txs {
                                            let mut tb = tx_blob.as_slice();
                                            match Transaction::<Pruned>::read(&mut tb) {
                                                Ok(t) => parsed_txs.push(t),
                                                Err(_) => {
                                                    let _ = txc.send(Err((
                                                        -16,
                                                        format!(
                                                            "wallet_refresh: tx parse failed at height {}",
                                                            th
                                                        ),
                                                    )));
                                                    return;
                                                }
                                            }
                                        }

                                        let mut output_index_for_first_ringct_output: Option<u64> =
                                            None;
                                        let miner_tx_hash = parsed_block.miner_transaction().hash();
                                        let miner_tx = Transaction::<Pruned>::from(
                                            parsed_block.miner_transaction().clone(),
                                        );

                                        for (hash, tx) in
                                            core::iter::once((&miner_tx_hash, &miner_tx)).chain(
                                                parsed_block.transactions.iter().zip(&parsed_txs),
                                            )
                                        {
                                            if (!matches!(tx, Transaction::V2 { .. }))
                                                || tx.prefix().outputs.is_empty()
                                            {
                                                continue;
                                            }

                                            let idxs = match get_o_indexes_limited(&client, *hash) {
                                                Ok(v) => v,
                                                Err(err3) => {
                                                    let _ = txc.send(Err((
                                                        -16,
                                                        format!(
                                                            "wallet_refresh: get_o_indexes failed at height {}: {}",
                                                            th, err3
                                                        ),
                                                    )));
                                                    return;
                                                }
                                            };
                                            if let Some(first) = idxs.first() {
                                                output_index_for_first_ringct_output = Some(*first);
                                            }
                                            break;
                                        }

                                        let scannable = ScannableBlock {
                                            block: parsed_block,
                                            transactions: parsed_txs,
                                            output_index_for_first_ringct_output,
                                        };

                                        let miner_hash = scannable.block.miner_transaction().hash();
                                        let outputs = match local_scanner.scan(scannable) {
                                            Ok(result) => result.ignore_additional_timelock(),
                                            Err(_) => {
                                                let _ = txc.send(Err((
                                                    -16,
                                                    format!(
                                                        "wallet_refresh: scanner failed at height {}",
                                                        th
                                                    ),
                                                )));
                                                return;
                                            }
                                        };

                                        for output in outputs {
                                            let (major, minor) = output
                                                .subaddress()
                                                .map(|idx| (idx.account(), idx.address()))
                                                .unwrap_or((0, 0));
                                            collected.push(TrackedOutput {
                                                tx_hash: output.transaction(),
                                                index_in_tx: output.index_in_transaction(),
                                                amount: output.commitment().amount,
                                                block_height: th,
                                                additional_timelock: output.additional_timelock(),
                                                is_coinbase: output.transaction() == miner_hash,
                                                subaddress_major: major,
                                                subaddress_minor: minor,
                                                spent: false,
                                            });
                                        }

                                        th = th.saturating_add(1);
                                    }

                                    let _ = txc.send(Ok(collected));
                                }

                                BulkFetchMode::PerBlock => {
                                    // Original per-block scan for this span.
                                    for th in start_h..end_h_exclusive {
                                        if refresh_cancelled_for_wallet(&id_owned_for_worker) {
                                            let _ = txc.send(Err((
                                                -30,
                                                "wallet_refresh: cancelled".to_string(),
                                            )));
                                            return;
                                        }

                                        let block_number = match usize::try_from(th) {
                                            Ok(v) => v,
                                            Err(_) => {
                                                let _ = txc.send(Err((
                                                    -16,
                                                    "wallet_refresh: block number conversion overflow"
                                                        .to_string(),
                                                )));
                                                return;
                                            }
                                        };

                                        let scannable = match block_on(
                                            client.get_scannable_block_by_number(block_number),
                                        ) {
                                            Ok(block) => block,
                                            Err(err) => {
                                                let code = map_rpc_error(err);
                                                let _ = txc.send(Err((
                                                    code,
                                                    format!(
                                                        "wallet_refresh: RPC block fetch failed at height {}",
                                                        th
                                                    ),
                                                )));
                                                return;
                                            }
                                        };

                                        let miner_hash = scannable.block.miner_transaction().hash();
                                        let outputs = match local_scanner.scan(scannable) {
                                            Ok(result) => result.ignore_additional_timelock(),
                                            Err(_) => {
                                                let _ = txc.send(Err((
                                                    -16,
                                                    format!(
                                                        "wallet_refresh: scanner failed at height {}",
                                                        th
                                                    ),
                                                )));
                                                return;
                                            }
                                        };

                                        for output in outputs {
                                            let (major, minor) = output
                                                .subaddress()
                                                .map(|idx| (idx.account(), idx.address()))
                                                .unwrap_or((0, 0));
                                            collected.push(TrackedOutput {
                                                tx_hash: output.transaction(),
                                                index_in_tx: output.index_in_transaction(),
                                                amount: output.commitment().amount,
                                                block_height: th,
                                                additional_timelock: output.additional_timelock(),
                                                is_coinbase: output.transaction() == miner_hash,
                                                subaddress_major: major,
                                                subaddress_minor: minor,
                                                spent: false,
                                            });
                                        }
                                    }

                                    let _ = txc.send(Ok(collected));
                                }
                            }
                        });
                    }

                    // Drain results for this chunk with timeout to prevent deadlock if a worker stalls
                    let mut received = 0usize;
                    let worker_timeout = std::time::Duration::from_secs(120);
                    while received < chunk.len() {
                        // Cancellation check (per-wallet) while waiting on workers
                        if refresh_cancelled_for_wallet(id) {
                            return record_error(-30, "wallet_refresh: cancelled");
                        }

                        match rx.recv_timeout(worker_timeout) {
                            Ok(Ok(vec_outputs)) => {
                                // Cancellation check before applying results
                                if refresh_cancelled_for_wallet(id) {
                                    return record_error(-30, "wallet_refresh: cancelled");
                                }

                                for t in vec_outputs {
                                    let key = (t.tx_hash, t.index_in_tx);
                                    if !seen_outpoints.insert(key) {
                                        continue;
                                    }
                                    working_outputs.push(t);
                                }
                                received += 1;
                            }
                            Ok(Err((code, msg))) => {
                                // If bulk fetch failed inside a worker, log once and fall back to per-block
                                // on the next outer iterations (best-effort).
                                if effective_bulk_fetch != BulkFetchMode::PerBlock
                                    && !bulk_fetch_fallback_logged
                                {
                                    print!(
                                        "🧱 bulk-fetch(bin) failed; falling back to per-block: {}\n",
                                        msg
                                    );
                                    bulk_fetch_fallback_logged = true;
                                }
                                // Abort on first error (including cancellation)
                                return record_error(code, msg);
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                                return record_error(
                                    -16,
                                    format!(
                                        "wallet_refresh: parallel worker stalled (no result within {}s) while scanning heights {}..{}",
                                        worker_timeout.as_secs(),
                                        scan_cursor,
                                        end_exclusive.saturating_sub(1)
                                    ),
                                );
                            }
                            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => {
                                return record_error(
                                    -16,
                                    "wallet_refresh: parallel worker channel closed unexpectedly",
                                );
                            }
                        }
                    }

                    // Update progress after draining this chunk.
                    //
                    // NOTE: In the span-based scheduler, `chunk` items are (start_h, end_h_exclusive) tuples.
                    // We advance scan_cursor to the end of the last span in this chunk.
                    if let Some(&(_span_start, span_end_exclusive)) = chunk.last() {
                        scan_cursor = span_end_exclusive.min(daemon.height);
                        update_scan_progress(
                            id,
                            scan_cursor.min(daemon.height),
                            daemon.height,
                            daemon.top_block_timestamp,
                            snapshot.restore_height,
                        );
                    }
                }

                // Advance cursor to end of this batch
                scan_cursor = end_exclusive;
                update_scan_progress(
                    id,
                    scan_cursor.min(daemon.height),
                    daemon.height,
                    daemon.top_block_timestamp,
                    snapshot.restore_height,
                );
            }
            // Ensure we align with daemon height after finishing batches
            scan_cursor = daemon.height;
        } else {
            // Sequential scan with optional bulk *.bin fetch.
            //
            // Bulk fetch is default-enabled but clearnet-only (node_url must be provided),
            // and may be disabled via WALLETCORE_BULK_FETCH=0.
            let clearnet_scan: bool = !node_url.is_null();
            let effective_bulk_fetch: BulkFetchMode = if clearnet_scan {
                bulk_fetch_mode
            } else {
                BulkFetchMode::PerBlock
            };

            // One-line logging for bulk enable/fallback (per refresh)
            let mut bulk_fetch_logged: bool = false;
            let mut bulk_fetch_fallback_logged: bool = false;

            while scan_cursor < daemon.height {
                // Cancellation check (per-wallet)
                if refresh_cancelled_for_wallet(id) {
                    return record_error(-30, "wallet_refresh: cancelled");
                }

                match effective_bulk_fetch {
                    BulkFetchMode::Wallet2FastBlocks | BulkFetchMode::RangeBlocks => {
                        if !bulk_fetch_logged {
                            let mode_str = match effective_bulk_fetch {
                                BulkFetchMode::Wallet2FastBlocks => "getblocks(wallet2)",
                                BulkFetchMode::RangeBlocks => "get_blocks(range)",
                                BulkFetchMode::PerBlock => "per_block",
                            };
                            print!(
                                "🧱 bulk-fetch(bin:{})=on batch={} clearnet={}\n",
                                mode_str, bulk_fetch_batch, clearnet_scan
                            );
                            bulk_fetch_logged = true;
                        }

                        // Fetch contiguous range via get_blocks.bin (preferred for full tx blobs)
                        let end_exclusive = daemon
                            .height
                            .min(scan_cursor.saturating_add(bulk_fetch_batch as u64));
                        let count = end_exclusive.saturating_sub(scan_cursor);

                        let resp = match rpc_client.get_blocks_bin(scan_cursor, count, false) {
                            Ok(r) => r,
                            Err(err) => {
                                if !bulk_fetch_fallback_logged {
                                    print!(
                                        "🧱 bulk-fetch(bin:get_blocks) failed; falling back to per-block: {}\n",
                                        err
                                    );
                                    bulk_fetch_fallback_logged = true;
                                }
                                // Process current height via per-block, then continue (we'll keep falling back)
                                let block_number = match usize::try_from(scan_cursor) {
                                    Ok(v) => v,
                                    Err(_) => {
                                        return record_error(
                                            -16,
                                            "wallet_refresh: block number conversion overflow",
                                        )
                                    }
                                };
                                let scannable = match block_on(
                                    rpc_client.get_scannable_block_by_number(block_number),
                                ) {
                                    Ok(block) => block,
                                    Err(err2) => {
                                        let code = map_rpc_error(err2);
                                        return record_error(
                                            code,
                                            format!(
                                                "wallet_refresh: RPC block fetch failed at height {}",
                                                scan_cursor
                                            ),
                                        );
                                    }
                                };
                                let miner_hash = scannable.block.miner_transaction().hash();
                                let outputs = match scanner.scan(scannable) {
                                    Ok(result) => result.ignore_additional_timelock(),
                                    Err(_) => {
                                        return record_error(
                                            -16,
                                            format!(
                                                "wallet_refresh: scanner failed at height {}",
                                                scan_cursor
                                            ),
                                        );
                                    }
                                };
                                for output in outputs {
                                    let key = (output.transaction(), output.index_in_transaction());
                                    if !seen_outpoints.insert(key) {
                                        continue;
                                    }
                                    let (major, minor) = output
                                        .subaddress()
                                        .map(|idx| (idx.account(), idx.address()))
                                        .unwrap_or((0, 0));
                                    working_outputs.push(TrackedOutput {
                                        tx_hash: output.transaction(),
                                        index_in_tx: output.index_in_transaction(),
                                        amount: output.commitment().amount,
                                        block_height: scan_cursor,
                                        additional_timelock: output.additional_timelock(),
                                        is_coinbase: output.transaction() == miner_hash,
                                        subaddress_major: major,
                                        subaddress_minor: minor,
                                        spent: false,
                                    });
                                }
                                scan_cursor += 1;
                                update_scan_progress(
                                    id,
                                    scan_cursor.min(daemon.height),
                                    daemon.height,
                                    daemon.top_block_timestamp,
                                    snapshot.restore_height,
                                );
                                continue;
                            }
                        };

                        // Process returned entries sequentially (assumed 1-per-height starting at scan_cursor).
                        // If any specific entry is missing tx blobs, fall back to the existing per-block logic
                        // for just that height instead of aborting the entire batch.
                        let mut th = scan_cursor;
                        for entry in resp.blocks {
                            if refresh_cancelled_for_wallet(id) {
                                return record_error(-30, "wallet_refresh: cancelled");
                            }

                            // If this entry omitted tx blobs, scan this single height via per-block RPC and continue.
                            if entry.txs.is_empty() {
                                if !bulk_fetch_fallback_logged {
                                    print!(
                                        "🧱 bulk-fetch(bin:get_blocks) partial fallback: missing tx blobs for some heights; using per-block for those\n"
                                    );
                                    bulk_fetch_fallback_logged = true;
                                }

                                let block_number = match usize::try_from(th) {
                                    Ok(v) => v,
                                    Err(_) => {
                                        if !bulk_fetch_fallback_logged {
                                            print!(
                                                "🧱 bulk-fetch(bin:get_blocks) failed; falling back to per-block: block number conversion overflow\n"
                                            );
                                            bulk_fetch_fallback_logged = true;
                                        }
                                        break;
                                    }
                                };

                                let scannable = match block_on(
                                    rpc_client.get_scannable_block_by_number(block_number),
                                ) {
                                    Ok(block) => block,
                                    Err(_) => {
                                        if !bulk_fetch_fallback_logged {
                                            print!(
                                                "🧱 bulk-fetch(bin:get_blocks) failed; falling back to per-block: RPC block fetch failed\n"
                                            );
                                            bulk_fetch_fallback_logged = true;
                                        }
                                        break;
                                    }
                                };

                                // Record block hash into wallet2-style recent hash history
                                // (used to build short chain history for `/getblocks.bin`).
                                {
                                    let block_hash = scannable.block.hash();
                                    if let Ok(mut map) = WALLET_STORE.lock() {
                                        if let Some(state) = map.get_mut(id) {
                                            push_recent_block_hash(state, th, block_hash);
                                        }
                                    }
                                }

                                let miner_hash = scannable.block.miner_transaction().hash();
                                let outputs = match scanner.scan(scannable) {
                                    Ok(result) => result.ignore_additional_timelock(),
                                    Err(_) => {
                                        if !bulk_fetch_fallback_logged {
                                            print!(
                                                "🧱 bulk-fetch(bin:get_blocks) failed; falling back to per-block: scanner failed\n"
                                            );
                                            bulk_fetch_fallback_logged = true;
                                        }
                                        break;
                                    }
                                };

                                for output in outputs {
                                    let (major, minor) = output
                                        .subaddress()
                                        .map(|idx| (idx.account(), idx.address()))
                                        .unwrap_or((0, 0));
                                    working_outputs.push(TrackedOutput {
                                        tx_hash: output.transaction(),
                                        index_in_tx: output.index_in_transaction(),
                                        amount: output.commitment().amount,
                                        block_height: th,
                                        additional_timelock: output.additional_timelock(),
                                        is_coinbase: output.transaction() == miner_hash,
                                        subaddress_major: major,
                                        subaddress_minor: minor,
                                        spent: false,
                                    });
                                }

                                th = th.saturating_add(1);
                                scan_cursor = th;
                                update_scan_progress(
                                    id,
                                    scan_cursor.min(daemon.height),
                                    daemon.height,
                                    daemon.top_block_timestamp,
                                    snapshot.restore_height,
                                );
                                continue;
                            }

                            // Parse block blob
                            let mut bb = entry.block.as_slice();
                            let parsed_block = match Block::read(&mut bb) {
                                Ok(b) => b,
                                Err(_) => {
                                    if !bulk_fetch_fallback_logged {
                                        print!(
                                            "🧱 bulk-fetch(bin:get_blocks) failed; falling back to per-block: block parse failed\n"
                                        );
                                        bulk_fetch_fallback_logged = true;
                                    }
                                    break;
                                }
                            };

                            // Parse tx blobs (pruned)
                            let mut parsed_txs: Vec<Transaction<Pruned>> =
                                Vec::with_capacity(entry.txs.len());
                            let mut tx_parse_failed = false;
                            for tx_blob in entry.txs {
                                let mut tb = tx_blob.as_slice();
                                match Transaction::<Pruned>::read(&mut tb) {
                                    Ok(t) => parsed_txs.push(t),
                                    Err(_) => {
                                        tx_parse_failed = true;
                                        break;
                                    }
                                }
                            }
                            if tx_parse_failed {
                                if !bulk_fetch_fallback_logged {
                                    print!(
                                        "🧱 bulk-fetch(bin:get_blocks) failed; falling back to per-block: tx parse failed\n"
                                    );
                                    bulk_fetch_fallback_logged = true;
                                }
                                break;
                            }

                            // Compute output_index_for_first_ringct_output (A1) using get_o_indexes.bin.
                            let mut output_index_for_first_ringct_output: Option<u64> = None;
                            let miner_tx_hash = parsed_block.miner_transaction().hash();
                            let miner_tx = Transaction::<Pruned>::from(
                                parsed_block.miner_transaction().clone(),
                            );
                            for (hash, tx) in core::iter::once((&miner_tx_hash, &miner_tx))
                                .chain(parsed_block.transactions.iter().zip(&parsed_txs))
                            {
                                if (!matches!(tx, Transaction::V2 { .. }))
                                    || tx.prefix().outputs.is_empty()
                                {
                                    continue;
                                }
                                let idxs = match get_o_indexes_limited(&rpc_client, *hash) {
                                    Ok(v) => v,
                                    Err(err) => {
                                        if !bulk_fetch_fallback_logged {
                                            print!(
                                                "🧱 bulk-fetch(bin:get_blocks) failed; falling back to per-block: get_o_indexes failed ({})\n",
                                                err
                                            );
                                            bulk_fetch_fallback_logged = true;
                                        }
                                        break;
                                    }
                                };
                                if let Some(first) = idxs.first() {
                                    output_index_for_first_ringct_output = Some(*first);
                                }
                                break;
                            }

                            let scannable = ScannableBlock {
                                block: parsed_block,
                                transactions: parsed_txs,
                                output_index_for_first_ringct_output,
                            };

                            let miner_hash = scannable.block.miner_transaction().hash();
                            let outputs = match scanner.scan(scannable) {
                                Ok(result) => result.ignore_additional_timelock(),
                                Err(_) => {
                                    return record_error(
                                        -16,
                                        format!(
                                            "wallet_refresh: scanner failed at height {}",
                                            scan_cursor
                                        ),
                                    );
                                }
                            };

                            for output in outputs {
                                let key = (output.transaction(), output.index_in_transaction());
                                if !seen_outpoints.insert(key) {
                                    continue;
                                }

                                let (major, minor) = output
                                    .subaddress()
                                    .map(|idx| (idx.account(), idx.address()))
                                    .unwrap_or((0, 0));

                                working_outputs.push(TrackedOutput {
                                    tx_hash: output.transaction(),
                                    index_in_tx: output.index_in_transaction(),
                                    amount: output.commitment().amount,
                                    block_height: scan_cursor,
                                    additional_timelock: output.additional_timelock(),
                                    is_coinbase: output.transaction() == miner_hash,
                                    subaddress_major: major,
                                    subaddress_minor: minor,
                                    spent: false,
                                });
                            }

                            scan_cursor += 1;
                            update_scan_progress(
                                id,
                                scan_cursor.min(daemon.height),
                                daemon.height,
                                daemon.top_block_timestamp,
                                snapshot.restore_height,
                            );
                        }

                        if bulk_fetch_fallback_logged {
                            continue;
                        }
                    }

                    BulkFetchMode::PerBlock => {
                        let block_number = match usize::try_from(scan_cursor) {
                            Ok(value) => value,
                            Err(_) => {
                                return record_error(
                                    -16,
                                    "wallet_refresh: block number conversion overflow",
                                )
                            }
                        };
                        let scannable = match block_on(
                            rpc_client.get_scannable_block_by_number(block_number),
                        ) {
                            Ok(block) => block,
                            Err(err) => {
                                let code = map_rpc_error(err);
                                return record_error(
                                    code,
                                    format!(
                                        "wallet_refresh: RPC block fetch failed at height {}",
                                        scan_cursor
                                    ),
                                );
                            }
                        };
                        let miner_hash = scannable.block.miner_transaction().hash();
                        let outputs = match scanner.scan(scannable) {
                            Ok(result) => result.ignore_additional_timelock(),
                            Err(_) => {
                                return record_error(
                                    -16,
                                    format!(
                                        "wallet_refresh: scanner failed at height {}",
                                        scan_cursor
                                    ),
                                );
                            }
                        };

                        for output in outputs {
                            let key = (output.transaction(), output.index_in_transaction());
                            if !seen_outpoints.insert(key) {
                                continue;
                            }

                            let (major, minor) = output
                                .subaddress()
                                .map(|idx| (idx.account(), idx.address()))
                                .unwrap_or((0, 0));

                            working_outputs.push(TrackedOutput {
                                tx_hash: output.transaction(),
                                index_in_tx: output.index_in_transaction(),
                                amount: output.commitment().amount,
                                block_height: scan_cursor,
                                additional_timelock: output.additional_timelock(),
                                is_coinbase: output.transaction() == miner_hash,
                                subaddress_major: major,
                                subaddress_minor: minor,
                                spent: false,
                            });
                        }

                        scan_cursor += 1;
                        update_scan_progress(
                            id,
                            scan_cursor.min(daemon.height),
                            daemon.height,
                            daemon.top_block_timestamp,
                            snapshot.restore_height,
                        );
                    }
                }
            }
            scan_cursor = daemon.height;
        }
    }

    working_outputs.retain(|output| !output.spent);

    // Overall performance log for this refresh
    if log_perf {
        let blocks_scanned =
            scan_cursor.saturating_sub(snapshot.last_scanned.max(snapshot.restore_height));
        let new_outputs = working_outputs.len().saturating_sub(initial_outputs);
        if let Some(start) = overall_start {
            let secs = start.elapsed().as_secs_f64();
            eprintln!(
                "wallet_refresh: scanned {} blocks; new_outputs={}; elapsed={:.3}s",
                blocks_scanned, new_outputs, secs
            );
        }
    }

    // Update stable transfer ledger based on observed outputs.
    //
    // - We keep history stable even after outputs are spent by persisting an aggregate per txid.
    // - Incoming ("in"): sum all outputs seen for that txid (including coinbase).
    // - Confirm pending outgoing ("out"):
    //   1) heuristic: if we ever see an on-chain output with that txid (typically change), mark confirmed
    //   2) fallback: query the daemon for tx existence by hash via json_rpc_call("get_transactions")
    let mut computed_ledger: HashMap<String, LedgerEntry> = snapshot.tx_ledger.clone();
    for o in &working_outputs {
        let txid = hex_lowercase(&o.tx_hash);

        // If this txid exists as pending outgoing, seeing it on-chain is enough to confirm it (common case: change).
        if let Some(entry) = computed_ledger.get_mut(&txid) {
            if entry.direction == "out" && entry.is_pending {
                entry.is_pending = false;
                if entry.height.is_none() || entry.height == Some(0) {
                    entry.height = if o.block_height == 0 {
                        None
                    } else {
                        Some(o.block_height)
                    };
                }
                if entry.timestamp.is_none() && daemon.top_block_timestamp > 0 {
                    entry.timestamp = Some(daemon.top_block_timestamp);
                }
            }
        }

        // Aggregate incoming amounts (coinbase included) irrespective of spent status.
        // If an outgoing record exists, we do NOT overwrite direction; we only allow "in" creation for unknown txids.
        match computed_ledger.get_mut(&txid) {
            Some(entry) => {
                if entry.direction == "in" {
                    entry.amount = entry.amount.saturating_add(o.amount);
                    entry.is_coinbase = entry.is_coinbase || o.is_coinbase;
                    if entry.height.is_none() || entry.height == Some(0) {
                        entry.height = if o.block_height == 0 {
                            None
                        } else {
                            Some(o.block_height)
                        };
                    } else if let Some(h) = entry.height {
                        if o.block_height != 0 && o.block_height < h {
                            entry.height = Some(o.block_height);
                        }
                    }
                    if entry.timestamp.is_none() && daemon.top_block_timestamp > 0 {
                        entry.timestamp = Some(daemon.top_block_timestamp);
                    }
                }
            }
            None => {
                computed_ledger.insert(
                    txid.clone(),
                    LedgerEntry {
                        txid,
                        direction: "in".to_string(),
                        amount: o.amount,
                        fee: None,
                        height: if o.block_height == 0 {
                            None
                        } else {
                            Some(o.block_height)
                        },
                        timestamp: if daemon.top_block_timestamp > 0 {
                            Some(daemon.top_block_timestamp)
                        } else {
                            None
                        },
                        is_pending: false,
                        is_coinbase: o.is_coinbase,
                    },
                );
            }
        }
    }

    // Fallback confirmation: ask the daemon whether remaining pending outgoing txids exist.
    // This is bounded by the number of pending outgoing entries (typically small).
    {
        // Collect pending txids still marked pending in the ledger.
        let mut txs_hashes: Vec<String> = Vec::new();
        for p in snapshot.pending_outgoing.iter() {
            if let Some(entry) = computed_ledger.get(&p.txid) {
                if entry.direction == "out" && entry.is_pending {
                    txs_hashes.push(p.txid.clone());
                }
            }
        }

        if !txs_hashes.is_empty() {
            // Call daemon get_transactions and parse enough fields to distinguish:
            // - in_pool == true  => still pending
            // - in_pool == false => mined (set height if available)
            //
            // This avoids incorrectly marking mempool txs as confirmed.
            match rpc_client.json_rpc_call(
                "get_transactions",
                serde_json::json!({ "txs_hashes": txs_hashes }),
            ) {
                Ok(value) => {
                    if let Some(result) = value.get("result") {
                        // missed_tx is returned as an array of hex strings for unknown txs
                        let missed: std::collections::HashSet<String> = result
                            .get("missed_tx")
                            .and_then(|v| v.as_array())
                            .map(|arr| {
                                arr.iter()
                                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();

                        // Parse returned tx records (each should correspond to a requested tx hash unless missed).
                        if let Some(txs) = result.get("txs").and_then(|v| v.as_array()) {
                            for tx in txs {
                                let txid = match tx.get("tx_hash").and_then(|h| h.as_str()) {
                                    Some(s) => s.to_string(),
                                    None => continue,
                                };

                                // If daemon doesn't know the tx, skip.
                                if missed.contains(&txid) {
                                    continue;
                                }

                                // Default behavior: if we can't parse in_pool, be conservative and keep pending.
                                let in_pool = tx.get("in_pool").and_then(|v| v.as_bool());
                                let block_height = tx.get("block_height").and_then(|v| v.as_u64());

                                if let Some(entry) = computed_ledger.get_mut(&txid) {
                                    if entry.direction == "out" {
                                        match in_pool {
                                            Some(true) => {
                                                // Still in mempool; keep pending.
                                                entry.is_pending = true;
                                                // Do not set height.
                                            }
                                            Some(false) => {
                                                // Mined.
                                                entry.is_pending = false;

                                                // Record mined height (if available)
                                                if entry.height.is_none() || entry.height == Some(0)
                                                {
                                                    entry.height = block_height.filter(|h| *h > 0);
                                                }

                                                // Fetch mined block timestamp via get_block_header_by_height.
                                                // If this fails, fall back to daemon top timestamp.
                                                if entry.timestamp.is_none() {
                                                    if let Some(h) = entry.height {
                                                        let header_res = rpc_client.json_rpc_call(
                                                            "get_block_header_by_height",
                                                            serde_json::json!({ "height": h }),
                                                        );
                                                        if let Ok(v) = header_res {
                                                            if let Some(ts) = v
                                                                .get("result")
                                                                .and_then(|r| r.get("block_header"))
                                                                .and_then(|bh| bh.get("timestamp"))
                                                                .and_then(|t| t.as_u64())
                                                            {
                                                                entry.timestamp = Some(ts);
                                                            }
                                                        }
                                                    }

                                                    if entry.timestamp.is_none()
                                                        && daemon.top_block_timestamp > 0
                                                    {
                                                        entry.timestamp =
                                                            Some(daemon.top_block_timestamp);
                                                    }
                                                }
                                            }
                                            None => {
                                                // Unknown; keep pending to avoid mislabeling mempool txs as confirmed.
                                                entry.is_pending = true;
                                            }
                                        }
                                    }
                                }
                            }
                        }

                        // Defensive fallback: if a requested tx is not missed and we have no txs array details,
                        // do NOT mark it confirmed (to avoid treating mempool as confirmed). We only ever clear
                        // pending status here when we can observe in_pool == false or we confirm via output scanning.
                        //
                        // (No-op by design.)
                        let _ = missed;
                    }
                }
                Err((_code, _msg)) => {
                    // Ignore: node may not support the method or may be temporarily unavailable.
                    // Pending entries will still confirm via the on-chain output heuristic when possible.
                }
            }
        }
    }

    // Drop pending_outgoing entries that are now confirmed in the ledger.
    let mut pending_outgoing = snapshot.pending_outgoing.clone();
    pending_outgoing.retain(|p| {
        if let Some(entry) = computed_ledger.get(&p.txid) {
            entry.direction == "out" && entry.is_pending
        } else {
            true
        }
    });

    let mut total = 0u64;
    let mut unlocked = 0u64;
    for output in &working_outputs {
        total = total.saturating_add(output.amount);
        if output.is_unlocked(daemon.height, daemon.top_block_timestamp) {
            unlocked = unlocked.saturating_add(output.amount);
        }
    }

    {
        let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
        let Some(state) = map.get_mut(id) else {
            return -13;
        };
        state.last_scanned = scan_cursor.max(state.restore_height);
        state.total = total;
        state.unlocked = unlocked;
        state.chain_height = daemon.height;
        state.chain_time = daemon.top_block_timestamp;
        if daemon.top_block_timestamp > 0 {
            state.last_refresh_timestamp = daemon.top_block_timestamp;
        }
        state.tracked_outputs = working_outputs;
        state.seen_outpoints = seen_outpoints;
        state.tx_ledger = computed_ledger;
        state.pending_outgoing = pending_outgoing;
    }

    if !out_last_scanned.is_null() {
        unsafe {
            *out_last_scanned = scan_cursor.max(snapshot.restore_height);
        }
    }
    clear_last_error();
    0
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

    // If cancellation was requested before we even start, abort immediately.
    if refresh_cancelled_for_wallet(id_str) {
        return record_error(-30, "wallet_refresh_async: cancelled");
    }

    // Clear any stale cancellation request once we have decided to start.
    set_refresh_cancel_for_wallet(id_str, false);

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

    std::thread::spawn(move || {
        if let Ok(wallet_cstr) = CString::new(id_owned) {
            let node_cstr = node_owned.and_then(|url| CString::new(url).ok());
            let mut last_scanned: u64 = 0;
            let node_ptr = node_cstr
                .as_ref()
                .map(|c| c.as_ptr())
                .unwrap_or(std::ptr::null::<c_char>());
            let _ = wallet_refresh(
                wallet_cstr.as_ptr(),
                node_ptr,
                &mut last_scanned as *mut u64,
            );
        }
    });

    0
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
        // Total/unlocked balances should consider all outputs (including spent if core keeps them),
        // but tracked_outputs is typically pruned of spent outputs during refresh. Either way, we
        // preserve existing semantics and only sum what exists in tracked_outputs.
        if let Some(f) = &filter {
            if let Some(minor) = f.subaddress_minor {
                // Account 0 only for now
                if !(o.subaddress_major == 0 && o.subaddress_minor == minor) {
                    continue;
                }
            }
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

            // Drop tracked outputs and seen outpoints to force a clean rescan
            state.tracked_outputs.clear();
            state.seen_outpoints.clear();

            clear_last_error();
            0
        }
        None => record_error(
            -13,
            format!("wallet_force_rescan_from_height: wallet '{id}' not opened"),
        ),
    }
}

#[no_mangle]
pub extern "C" fn wallet_import_cache(
    wallet_id: *const c_char,
    cache_ptr: *const u8,
    cache_len: usize,
) -> c_int {
    clear_last_error();
    if wallet_id.is_null() || cache_ptr.is_null() || cache_len == 0 {
        return record_error(-11, "wallet_import_cache: invalid arguments");
    }
    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return record_error(-10, "wallet_import_cache: invalid wallet_id utf8"),
    };
    let data = unsafe { slice::from_raw_parts(cache_ptr, cache_len) };
    let persisted: PersistedWallet = match bincode::deserialize(data) {
        Ok(p) => p,
        Err(err) => {
            return record_error(
                -16,
                format!("wallet_import_cache: deserialize failed ({err})"),
            )
        }
    };
    let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
    match map.get_mut(id) {
        Some(state) => {
            persisted.apply_to_state(state);
            clear_last_error();
            0
        }
        None => record_error(
            -13,
            format!("wallet_import_cache: wallet '{id}' not opened"),
        ),
    }
}

#[no_mangle]
pub extern "C" fn wallet_export_cache(
    wallet_id: *const c_char,
    out_buf: *mut u8,
    out_buf_len: usize,
    out_written: *mut usize,
) -> c_int {
    clear_last_error();
    if wallet_id.is_null() {
        if !out_written.is_null() {
            unsafe { *out_written = 0 };
        }
        return record_error(-11, "wallet_export_cache: invalid wallet_id");
    }
    if out_buf.is_null() && out_buf_len > 0 {
        if !out_written.is_null() {
            unsafe { *out_written = 0 };
        }
        return record_error(
            -11,
            "wallet_export_cache: null output buffer with non-zero length",
        );
    }
    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => return record_error(-10, "wallet_export_cache: invalid wallet_id utf8"),
    };
    let map = WALLET_STORE.lock().expect("wallet store poisoned");
    let state = match map.get(id) {
        Some(state) => state,
        None => {
            return record_error(
                -13,
                format!("wallet_export_cache: wallet '{id}' not opened"),
            )
        }
    };
    let persisted = PersistedWallet::from(state);
    let bytes = match bincode::serialize(&persisted) {
        Ok(b) => b,
        Err(err) => {
            return record_error(
                -16,
                format!("wallet_export_cache: serialize failed ({err})"),
            )
        }
    };
    if out_buf.is_null() {
        if !out_written.is_null() {
            unsafe { *out_written = bytes.len() };
        }
        return -12;
    }
    if bytes.len() > out_buf_len {
        if !out_written.is_null() {
            unsafe { *out_written = bytes.len() };
        }
        return record_error(
            -12,
            format!(
                "wallet_export_cache: buffer too small (need {}, have {})",
                bytes.len(),
                out_buf_len
            ),
        );
    }
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), out_buf, bytes.len());
        if !out_written.is_null() {
            *out_written = bytes.len();
        }
    }
    clear_last_error();
    0
}

#[no_mangle]
pub extern "C" fn wallet_export_outputs_json(wallet_id: *const c_char) -> *mut c_char {
    clear_last_error();
    if wallet_id.is_null() {
        record_error(-11, "wallet_export_outputs_json: invalid wallet_id");
        return ptr::null_mut();
    }
    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(-10, "wallet_export_outputs_json: invalid wallet_id utf8");
            return ptr::null_mut();
        }
    };
    let envelope = {
        let map = WALLET_STORE.lock().expect("wallet store poisoned");
        let Some(state) = map.get(id) else {
            record_error(
                -13,
                format!("wallet_export_outputs_json: wallet '{id}' not opened"),
            );
            return ptr::null_mut();
        };
        let outputs = state
            .tracked_outputs
            .iter()
            .map(|o| ObservedOutput::from_tracked(o, state.chain_height, state.chain_time))
            .collect();
        ObservedOutputsEnvelope {
            wallet_id: id.to_string(),
            restore_height: state.restore_height,
            last_scanned_height: state.last_scanned,
            chain_height: state.chain_height,
            chain_time: state.chain_time,
            outputs,
        }
    };
    let json = match serde_json::to_string(&envelope) {
        Ok(json) => json,
        Err(err) => {
            record_error(
                -16,
                format!("wallet_export_outputs_json: serialization failed ({err})"),
            );
            return ptr::null_mut();
        }
    };
    match CString::new(json) {
        Ok(cstr) => {
            clear_last_error();
            cstr.into_raw()
        }
        Err(_) => {
            record_error(
                -16,
                "wallet_export_outputs_json: JSON contained interior null bytes",
            );
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn wallet_list_transfers_json(wallet_id: *const c_char) -> *mut c_char {
    clear_last_error();

    if wallet_id.is_null() {
        record_error(-11, "wallet_list_transfers_json: invalid wallet_id");
        return ptr::null_mut();
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(-10, "wallet_list_transfers_json: invalid wallet_id utf8");
            return ptr::null_mut();
        }
    };

    let transfers: Vec<ObservedTransfer> = {
        let map = WALLET_STORE.lock().expect("wallet store poisoned");
        let Some(state) = map.get(id) else {
            record_error(
                -13,
                format!("wallet_list_transfers_json: wallet '{id}' not opened"),
            );
            return ptr::null_mut();
        };

        // Build rows from the persisted transfer ledger so history remains stable even after outputs are spent.
        let mut rows: Vec<ObservedTransfer> = Vec::new();

        for entry in state.tx_ledger.values() {
            let height = entry.height.unwrap_or(0);
            let confirmations = if entry.is_pending {
                0
            } else {
                confirmations_for_height(state.chain_height, height)
            };

            rows.push(ObservedTransfer {
                txid: entry.txid.clone(),
                direction: entry.direction.clone(),
                amount: entry.amount,
                fee: entry.fee,
                height: entry.height,
                timestamp: entry.timestamp,
                confirmations,
                is_pending: entry.is_pending,
                subaddress_major: None,
                subaddress_minor: None,
            });
        }

        // Sort: pending first (newest first), then confirmed by height desc.
        rows.sort_by(|a, b| match (a.is_pending, b.is_pending) {
            (true, false) => std::cmp::Ordering::Less,
            (false, true) => std::cmp::Ordering::Greater,
            _ => {
                let ah = a.height.unwrap_or(0);
                let bh = b.height.unwrap_or(0);
                bh.cmp(&ah)
                    .then_with(|| b.timestamp.unwrap_or(0).cmp(&a.timestamp.unwrap_or(0)))
            }
        });

        rows
    };

    let json = match serde_json::to_string(&transfers) {
        Ok(s) => s,
        Err(err) => {
            record_error(
                -16,
                format!("wallet_list_transfers_json: serialization failed ({err})"),
            );
            return ptr::null_mut();
        }
    };

    match CString::new(json) {
        Ok(cstr) => {
            clear_last_error();
            cstr.into_raw()
        }
        Err(_) => {
            record_error(
                -16,
                "wallet_list_transfers_json: JSON contained interior null bytes",
            );
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn wallet_preview_sweep(
    wallet_id: *const c_char,
    node_url: *const c_char,
    to_address: *const c_char,
    ring_len: u8,
) -> *mut c_char {
    clear_last_error();

    if wallet_id.is_null() || to_address.is_null() {
        record_error(-11, "wallet_preview_sweep: null argument(s)");
        return ptr::null_mut();
    }

    // No filter (whole wallet)
    wallet_preview_sweep_with_filter(wallet_id, node_url, to_address, ptr::null(), ring_len)
}

#[no_mangle]
pub extern "C" fn wallet_sweep(
    wallet_id: *const c_char,
    node_url: *const c_char,
    to_address: *const c_char,
    ring_len: u8,
) -> *mut c_char {
    clear_last_error();

    if wallet_id.is_null() || to_address.is_null() {
        record_error(-11, "wallet_sweep: null argument(s)");
        return ptr::null_mut();
    }

    // No filter (whole wallet)
    wallet_sweep_with_filter(wallet_id, node_url, to_address, ptr::null(), ring_len)
}

#[no_mangle]
pub extern "C" fn wallet_send(
    wallet_id: *const c_char,
    node_url: *const c_char,
    to_address: *const c_char,
    amount_piconero: u64,
    ring_len: u8,
) -> *mut c_char {
    clear_last_error();

    if wallet_id.is_null() || to_address.is_null() {
        record_error(-11, "wallet_send: null argument(s)");
        return ptr::null_mut();
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(-10, "wallet_send: wallet_id contained invalid UTF-8");
            return ptr::null_mut();
        }
    };

    let recipient_str = match unsafe { CStr::from_ptr(to_address) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(-10, "wallet_send: to_address contained invalid UTF-8");
            return ptr::null_mut();
        }
    };

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

    // Lookup wallet snapshot
    let snapshot = {
        let map = WALLET_STORE.lock().expect("wallet store poisoned");
        match map.get(id) {
            Some(state) => state.clone(),
            None => {
                record_error(-13, format!("wallet_send: wallet '{id}' not registered"));
                return ptr::null_mut();
            }
        }
    };

    // Parse recipient address on the same network
    let recipient_address = match MoneroAddress::from_str(snapshot.network, recipient_str) {
        Ok(addr) => addr,
        Err(_) => {
            record_error(
                -10,
                "wallet_send: invalid recipient address for wallet network",
            );
            return ptr::null_mut();
        }
    };

    // Build RPC client and fetch daemon status
    let rpc_client = match BlockingRpcTransport::new(&base_url) {
        Ok(client) => client,
        Err(code) => {
            record_error(
                code,
                format!("wallet_send: invalid daemon url '{base_url}'"),
            );
            return ptr::null_mut();
        }
    };
    let daemon = match fetch_daemon_status(&rpc_client) {
        Ok(status) => status,
        Err((code, message)) => {
            record_error(
                code,
                format!("wallet_send: failed to query daemon '{base_url}': {message}"),
            );
            return ptr::null_mut();
        }
    };

    // Construct master keys and view pair
    let master = match master_keys_from_mnemonic_str(&snapshot.mnemonic) {
        Ok(keys) => keys,
        Err(code) => {
            record_error(code, "wallet_send: unable to parse mnemonic");
            return ptr::null_mut();
        }
    };
    let view_pair = match master.to_view_pair() {
        Ok(pair) => pair,
        Err(code) => {
            record_error(code, "wallet_send: failed to construct view pair");
            return ptr::null_mut();
        }
    };

    // Prepare scanner with registered subaddresses up to gap_limit
    let mut scanner = Scanner::new(view_pair.clone());
    let gap_limit = snapshot.gap_limit.max(1);
    if let Some(i0) = SubaddressIndex::new(0, 0) {
        scanner.register_subaddress(i0);
    }
    for minor in 1..=gap_limit {
        if let Some(index) = SubaddressIndex::new(0, minor) {
            scanner.register_subaddress(index);
        }
    }

    // Choose spendable outputs (unspent and unlocked)
    let mut spendable = snapshot
        .tracked_outputs
        .iter()
        .cloned()
        .filter(|o| !o.spent && o.is_unlocked(daemon.height, daemon.top_block_timestamp))
        .collect::<Vec<_>>();
    // Sort by amount ascending to minimize change fragmentation
    spendable.sort_by_key(|o| o.amount);

    // We must select enough to cover (amount + fee). Fee depends on input count, so iterate.
    let mut rng = OsRng;
    let ring_len_eff: u8 = if ring_len < 2 { 16 } else { ring_len };

    // Fetch fee rate once
    let fee_rate = match block_on(rpc_client.get_fee_rate(monero_wallet::rpc::FeePriority::Normal))
    {
        Ok(fr) => fr,
        Err(err) => {
            let code = map_rpc_error(err);
            record_error(code, "wallet_send: get_fee_rate failed");
            return ptr::null_mut();
        }
    };

    // Change to primary account (no explicit subaddress)
    let change = monero_wallet::send::Change::new(view_pair.clone(), None);

    let mut selected_tracked: Vec<TrackedOutput> = Vec::new();
    let mut selected_sum: u64 = 0;

    let max_selection_rounds: usize = 24;

    for _round in 0..max_selection_rounds {
        if selected_tracked.is_empty() {
            for o in &spendable {
                selected_tracked.push(o.clone());
                selected_sum = selected_sum.saturating_add(o.amount);
                if selected_sum >= amount_piconero {
                    break;
                }
            }

            if selected_sum < amount_piconero {
                record_error(
                    -18,
                    format!(
                        "wallet_send: insufficient unlocked funds (have {}, need {})",
                        selected_sum, amount_piconero
                    ),
                );
                return ptr::null_mut();
            }
        }

        // Reconstruct WalletOutput for each selected TrackedOutput by rescanning its block
        let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();
        for t in &selected_tracked {
            let block_number = match usize::try_from(t.block_height) {
                Ok(value) => value,
                Err(_) => {
                    record_error(-16, "wallet_send: block number conversion overflow");
                    return ptr::null_mut();
                }
            };
            let scannable = match block_on(rpc_client.get_scannable_block_by_number(block_number)) {
                Ok(block) => block,
                Err(err) => {
                    let code = map_rpc_error(err);
                    record_error(
                        code,
                        format!(
                            "wallet_send: RPC block fetch failed at height {}",
                            t.block_height
                        ),
                    );
                    return ptr::null_mut();
                }
            };

            let outputs = match scanner.scan(scannable) {
                Ok(result) => result.ignore_additional_timelock(),
                Err(_) => {
                    record_error(
                        -16,
                        format!("wallet_send: scanner failed at height {}", t.block_height),
                    );
                    return ptr::null_mut();
                }
            };

            // Find the exact WalletOutput matching (tx_hash, index)
            let maybe_out = outputs.into_iter().find(|wo| {
                wo.transaction() == t.tx_hash && wo.index_in_transaction() == t.index_in_tx
            });

            let wallet_out = match maybe_out {
                Some(wo) => wo,
                None => {
                    record_error(
                        -16,
                        "wallet_send: failed to reconstruct selected output (not found after scan)",
                    );
                    return ptr::null_mut();
                }
            };

            let with_decoys = match block_on(monero_wallet::OutputWithDecoys::new(
                &mut rng,
                &rpc_client,
                ring_len_eff,
                usize::try_from(daemon.height).unwrap_or(daemon.height as usize),
                wallet_out,
            )) {
                Ok(i) => i,
                Err(err) => {
                    let code = map_rpc_error(err);
                    record_error(code, "wallet_send: decoy selection failed");
                    return ptr::null_mut();
                }
            };

            inputs.push(with_decoys);
        }

        // Outgoing view key seed for RNGs
        let mut ovk = [0u8; 32];
        rng.fill_bytes(&mut ovk);

        // Build signable transaction
        let intent = match monero_wallet::send::SignableTransaction::new(
            monero_wallet::ringct::RctType::ClsagBulletproofPlus,
            Zeroizing::new(ovk),
            inputs,
            vec![(recipient_address, amount_piconero)],
            change.clone(),
            Vec::new(),
            fee_rate,
        ) {
            Ok(tx) => tx,
            Err(e) => {
                record_error(
                    -16,
                    format!("wallet_send: transaction construction failed ({e})"),
                );
                return ptr::null_mut();
            }
        };
        let fee_piconero = intent.necessary_fee();
        let needed_total = amount_piconero.saturating_add(fee_piconero);

        if selected_sum >= needed_total {
            // We have enough inputs to cover amount + fee; proceed with signing/broadcast below.
            // (fee_piconero is used later in the function)
            break;
        }

        // Otherwise, select more inputs and retry (fee may increase with more inputs).
        let mut added_any = false;
        for o in &spendable {
            if selected_tracked
                .iter()
                .any(|s| s.tx_hash == o.tx_hash && s.index_in_tx == o.index_in_tx)
            {
                continue;
            }
            selected_tracked.push(o.clone());
            selected_sum = selected_sum.saturating_add(o.amount);
            added_any = true;
            if selected_sum >= needed_total {
                break;
            }
        }

        if !added_any {
            record_error(
                -18,
                format!(
                    "wallet_send: insufficient unlocked funds for amount+fee (have {}, need {})",
                    selected_sum, needed_total
                ),
            );
            return ptr::null_mut();
        }
    }

    // Rebuild intent one last time using final selection so `intent` and `fee_piconero` are in-scope
    // and match the actual transaction we sign/broadcast.
    let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();
    for t in &selected_tracked {
        let block_number = match usize::try_from(t.block_height) {
            Ok(value) => value,
            Err(_) => {
                record_error(-16, "wallet_send: block number conversion overflow");
                return ptr::null_mut();
            }
        };
        let scannable = match block_on(rpc_client.get_scannable_block_by_number(block_number)) {
            Ok(block) => block,
            Err(err) => {
                let code = map_rpc_error(err);
                record_error(
                    code,
                    format!(
                        "wallet_send: RPC block fetch failed at height {}",
                        t.block_height
                    ),
                );
                return ptr::null_mut();
            }
        };

        let outputs = match scanner.scan(scannable) {
            Ok(result) => result.ignore_additional_timelock(),
            Err(_) => {
                record_error(
                    -16,
                    format!("wallet_send: scanner failed at height {}", t.block_height),
                );
                return ptr::null_mut();
            }
        };

        let maybe_out = outputs
            .into_iter()
            .find(|wo| wo.transaction() == t.tx_hash && wo.index_in_transaction() == t.index_in_tx);

        let wallet_out = match maybe_out {
            Some(wo) => wo,
            None => {
                record_error(
                    -16,
                    "wallet_send: failed to reconstruct selected output (not found after scan)",
                );
                return ptr::null_mut();
            }
        };

        let with_decoys = match block_on(monero_wallet::OutputWithDecoys::new(
            &mut rng,
            &rpc_client,
            ring_len_eff,
            usize::try_from(daemon.height).unwrap_or(daemon.height as usize),
            wallet_out,
        )) {
            Ok(i) => i,
            Err(err) => {
                let code = map_rpc_error(err);
                record_error(code, "wallet_send: decoy selection failed");
                return ptr::null_mut();
            }
        };

        inputs.push(with_decoys);
    }

    // Outgoing view key seed for RNGs
    let mut ovk = [0u8; 32];
    rng.fill_bytes(&mut ovk);

    let intent = match monero_wallet::send::SignableTransaction::new(
        monero_wallet::ringct::RctType::ClsagBulletproofPlus,
        Zeroizing::new(ovk),
        inputs,
        vec![(recipient_address, amount_piconero)],
        change,
        Vec::new(),
        fee_rate,
    ) {
        Ok(tx) => tx,
        Err(e) => {
            record_error(
                -16,
                format!("wallet_send: transaction construction failed ({e})"),
            );
            return ptr::null_mut();
        }
    };
    let fee_piconero = intent.necessary_fee();

    // Sign
    let spend_key = Zeroizing::new(monero_wallet::ed25519::Scalar::from(master.spend_scalar));
    let mut signer_rng = OsRng;
    let tx = match intent.sign(&mut signer_rng, &spend_key) {
        Ok(tx) => tx,
        Err(e) => {
            record_error(-16, format!("wallet_send: signing failed ({e})"));
            return ptr::null_mut();
        }
    };

    // Broadcast
    if let Err(err) = block_on(rpc_client.publish_transaction(&tx)) {
        let code = map_rpc_error(err);
        record_error(code, "wallet_send: publish_transaction failed");
        return ptr::null_mut();
    }

    // Update in-memory wallet store: mark selected outputs as spent and reduce cached totals
    {
        let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
        if let Some(state) = map.get_mut(id) {
            let spent_sum: u64 = selected_tracked.iter().map(|t| t.amount).sum();
            for t in &selected_tracked {
                if let Some(o) = state
                    .tracked_outputs
                    .iter_mut()
                    .find(|o| o.tx_hash == t.tx_hash && o.index_in_tx == t.index_in_tx)
                {
                    o.spent = true;
                }
            }
            // Adjust cached totals; a subsequent refresh will reconcile precisely
            state.total = state.total.saturating_sub(spent_sum);
            state.unlocked = state.unlocked.saturating_sub(spent_sum);
        }
    }

    // Return result JSON with txid and fee
    let tx_hash = tx.hash();
    let hex = hex_lowercase(&tx_hash);

    // Record a pending outgoing tx for UI history.
    {
        let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
        if let Some(state) = map.get_mut(id) {
            state.pending_outgoing.push(PendingOutgoingTx {
                txid: hex.clone(),
                amount: amount_piconero,
                fee: fee_piconero,
                created_at: state.chain_time,
            });

            // Update stable transfer ledger (outgoing is pending until confirmed by refresh).
            state.tx_ledger.insert(
                hex.clone(),
                LedgerEntry {
                    txid: hex.clone(),
                    direction: "out".to_string(),
                    amount: amount_piconero,
                    fee: Some(fee_piconero),
                    height: None,
                    timestamp: Some(state.chain_time),
                    is_pending: true,
                    is_coinbase: false,
                },
            );
        }
    }

    let result_json = match serde_json::to_string(&serde_json::json!({
        "txid": hex,
        "fee": fee_piconero
    })) {
        Ok(s) => s,
        Err(err) => {
            record_error(
                -16,
                format!("wallet_send: result JSON serialization failed ({err})"),
            );
            return ptr::null_mut();
        }
    };
    match CString::new(result_json) {
        Ok(cstr) => {
            clear_last_error();
            cstr.into_raw()
        }
        Err(_) => {
            record_error(
                -16,
                "wallet_send: result JSON contained interior null bytes",
            );
            ptr::null_mut()
        }
    }
}
#[no_mangle]
pub extern "C" fn wallet_preview_fee(
    wallet_id: *const c_char,
    node_url: *const c_char,
    destinations_json: *const c_char,
    ring_len: u8,
) -> *mut c_char {
    clear_last_error();

    if wallet_id.is_null() || destinations_json.is_null() {
        record_error(-11, "wallet_preview_fee: null argument(s)");
        return ptr::null_mut();
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(-10, "wallet_preview_fee: wallet_id contained invalid UTF-8");
            return ptr::null_mut();
        }
    };

    let dests_str = match unsafe { CStr::from_ptr(destinations_json) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(-10, "wallet_preview_fee: destinations_json invalid UTF-8");
            return ptr::null_mut();
        }
    };

    #[derive(Deserialize)]
    struct Pay {
        address: String,
        amount: u64,
    }

    let pays: Vec<Pay> = match serde_json::from_str(dests_str) {
        Ok(v) => v,
        Err(err) => {
            record_error(
                -11,
                format!("wallet_preview_fee: invalid destinations JSON ({err})"),
            );
            return ptr::null_mut();
        }
    };
    if pays.is_empty() {
        record_error(-11, "wallet_preview_fee: empty destinations");
        return ptr::null_mut();
    }

    let snapshot = {
        let map = WALLET_STORE.lock().expect("wallet store poisoned");
        match map.get(id) {
            Some(state) => state.clone(),
            None => {
                record_error(
                    -13,
                    format!("wallet_preview_fee: wallet '{id}' not registered"),
                );
                return ptr::null_mut();
            }
        }
    };

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

    let rpc_client = match BlockingRpcTransport::new(&base_url) {
        Ok(client) => client,
        Err(code) => {
            record_error(
                code,
                format!("wallet_preview_fee: invalid daemon url '{base_url}'"),
            );
            return ptr::null_mut();
        }
    };
    let daemon = match fetch_daemon_status(&rpc_client) {
        Ok(status) => status,
        Err((code, message)) => {
            record_error(
                code,
                format!("wallet_preview_fee: failed to query daemon '{base_url}': {message}"),
            );
            return ptr::null_mut();
        }
    };

    let master = match master_keys_from_mnemonic_str(&snapshot.mnemonic) {
        Ok(keys) => keys,
        Err(code) => {
            record_error(code, "wallet_preview_fee: unable to parse mnemonic");
            return ptr::null_mut();
        }
    };
    let view_pair = match master.to_view_pair() {
        Ok(pair) => pair,
        Err(code) => {
            record_error(code, "wallet_preview_fee: failed to construct view pair");
            return ptr::null_mut();
        }
    };

    let mut scanner = Scanner::new(view_pair.clone());
    let gap_limit = snapshot.gap_limit.max(1);
    if let Some(i0) = SubaddressIndex::new(0, 0) {
        scanner.register_subaddress(i0);
    }
    for minor in 1..=gap_limit {
        if let Some(index) = SubaddressIndex::new(0, minor) {
            scanner.register_subaddress(index);
        }
    }

    // Parse destinations into monero addresses
    let mut destinations: Vec<(monero_address::MoneroAddress, u64)> =
        Vec::with_capacity(pays.len());
    let mut total_needed: u64 = 0;
    for p in &pays {
        let addr = match MoneroAddress::from_str(snapshot.network, &p.address) {
            Ok(a) => a,
            Err(_) => {
                record_error(-10, "wallet_preview_fee: invalid destination address");
                return ptr::null_mut();
            }
        };
        total_needed = total_needed.saturating_add(p.amount);
        destinations.push((addr, p.amount));
    }

    // Gather unlocked, unspent outputs.
    // IMPORTANT: we must select enough inputs to cover (destinations + fee).
    // Fee depends on input count/size, so selection is iterative until it stabilizes.
    let mut spendable = snapshot
        .tracked_outputs
        .iter()
        .cloned()
        .filter(|o| !o.spent && o.is_unlocked(daemon.height, daemon.top_block_timestamp))
        .collect::<Vec<_>>();
    spendable.sort_by_key(|o| o.amount);

    // Build inputs with decoys
    let mut rng = OsRng;
    let ring_len_eff: u8 = if ring_len < 2 { 16 } else { ring_len };

    // Fetch fee rate once (depends on daemon policy/height, not our selection)
    let fee_rate = match block_on(rpc_client.get_fee_rate(monero_wallet::rpc::FeePriority::Normal))
    {
        Ok(fr) => fr,
        Err(err) => {
            let code = map_rpc_error(err);
            record_error(code, "wallet_preview_fee: get_fee_rate failed");
            return ptr::null_mut();
        }
    };

    let change = monero_wallet::send::Change::new(view_pair.clone(), None);

    // Iteratively select inputs until we can construct a tx that covers amount + fee.
    let mut selected: Vec<TrackedOutput> = Vec::new();
    let mut selected_sum: u64 = 0;

    // Prevent pathological looping; input selection should converge quickly.
    let max_selection_rounds: usize = 24;

    // Track last needed value to avoid infinite loops on non-monotonic fee changes.
    let mut last_needed_total: Option<u64> = None;

    for round in 0..max_selection_rounds {
        // Ensure we have at least enough selected for the destination totals on first pass.
        if selected.is_empty() {
            for o in &spendable {
                selected.push(o.clone());
                selected_sum = selected_sum.saturating_add(o.amount);
                if selected_sum >= total_needed {
                    break;
                }
            }
            if selected_sum < total_needed {
                record_error(
                    -18,
                    format!(
                        "wallet_preview_fee: insufficient unlocked funds (have {}, need {})",
                        selected_sum, total_needed
                    ),
                );
                return ptr::null_mut();
            }
        }

        // Rebuild inputs for current selection (needed to estimate fee accurately)
        let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();
        for t in &selected {
            let block_number = match usize::try_from(t.block_height) {
                Ok(value) => value,
                Err(_) => {
                    record_error(-16, "wallet_preview_fee: block number conversion overflow");
                    return ptr::null_mut();
                }
            };
            let scannable = match block_on(rpc_client.get_scannable_block_by_number(block_number)) {
                Ok(block) => block,
                Err(err) => {
                    let code = map_rpc_error(err);
                    record_error(
                        code,
                        format!(
                            "wallet_preview_fee: RPC block fetch failed at height {}",
                            t.block_height
                        ),
                    );
                    return ptr::null_mut();
                }
            };
            let outputs = match scanner.scan(scannable) {
                Ok(result) => result.ignore_additional_timelock(),
                Err(_) => {
                    record_error(
                        -16,
                        format!(
                            "wallet_preview_fee: scanner failed at height {}",
                            t.block_height
                        ),
                    );
                    return ptr::null_mut();
                }
            };
            let maybe_out = outputs.into_iter().find(|wo| {
                wo.transaction() == t.tx_hash && wo.index_in_transaction() == t.index_in_tx
            });
            let wallet_out = match maybe_out {
                Some(wo) => wo,
                None => {
                    record_error(
                        -16,
                        "wallet_preview_fee: failed to reconstruct selected output",
                    );
                    return ptr::null_mut();
                }
            };
            let with_decoys = match block_on(monero_wallet::OutputWithDecoys::new(
                &mut rng,
                &rpc_client,
                ring_len_eff,
                usize::try_from(daemon.height).unwrap_or(daemon.height as usize),
                wallet_out,
            )) {
                Ok(i) => i,
                Err(err) => {
                    let code = map_rpc_error(err);
                    record_error(code, "wallet_preview_fee: decoy selection failed");
                    return ptr::null_mut();
                }
            };
            inputs.push(with_decoys);
        }

        // New OVK each attempt; it should not affect fee, but keep it fresh.
        let mut ovk = [0u8; 32];
        rng.fill_bytes(&mut ovk);

        let intent = match monero_wallet::send::SignableTransaction::new(
            monero_wallet::ringct::RctType::ClsagBulletproofPlus,
            Zeroizing::new(ovk),
            inputs,
            destinations.clone(),
            change.clone(),
            Vec::new(),
            fee_rate,
        ) {
            Ok(tx) => tx,
            Err(e) => {
                // If we fail due to not enough funds, we can try selecting more.
                // For other construction errors, surface the error.
                record_error(
                    -16,
                    format!("wallet_preview_fee: transaction construction failed ({e})"),
                );
                return ptr::null_mut();
            }
        };

        let fee = intent.necessary_fee();
        let needed_total = total_needed.saturating_add(fee);

        // If we already cover amount+fee, we're done: return fee.
        if selected_sum >= needed_total {
            let json = match serde_json::to_string(&serde_json::json!({ "fee": fee })) {
                Ok(s) => s,
                Err(err) => {
                    record_error(
                        -16,
                        format!("wallet_preview_fee: result JSON serialization failed ({err})"),
                    );
                    return ptr::null_mut();
                }
            };
            match CString::new(json) {
                Ok(cstr) => {
                    clear_last_error();
                    return cstr.into_raw();
                }
                Err(_) => {
                    record_error(
                        -16,
                        "wallet_preview_fee: result JSON contained interior null bytes",
                    );
                    return ptr::null_mut();
                }
            }
        }

        // Guard against non-converging needed_total.
        if let Some(last) = last_needed_total {
            if needed_total <= last && round > 0 {
                // We didn't make progress but still don't cover; select more.
            }
        }
        last_needed_total = Some(needed_total);

        // Select more inputs (one-by-one) until we cover the newly estimated required total,
        // then loop to recompute fee with the expanded input set.
        let mut added_any = false;
        for o in &spendable {
            // Skip already selected (linear scan is fine; selection sizes are small)
            if selected
                .iter()
                .any(|s| s.tx_hash == o.tx_hash && s.index_in_tx == o.index_in_tx)
            {
                continue;
            }
            selected.push(o.clone());
            selected_sum = selected_sum.saturating_add(o.amount);
            added_any = true;
            if selected_sum >= needed_total {
                break;
            }
        }

        if !added_any {
            record_error(
                -18,
                format!(
                    "wallet_preview_fee: insufficient unlocked funds for amount+fee (have {}, need {})",
                    selected_sum, needed_total
                ),
            );
            return ptr::null_mut();
        }
    }

    record_error(
        -16,
        "wallet_preview_fee: fee estimation did not converge (too many selection rounds)",
    );
    return ptr::null_mut();
}

#[no_mangle]
pub extern "C" fn wallet_send_with_filter(
    wallet_id: *const c_char,
    node_url: *const c_char,
    destinations_json: *const c_char,
    filter_json: *const c_char,
    ring_len: u8,
) -> *mut c_char {
    clear_last_error();

    if wallet_id.is_null() || destinations_json.is_null() {
        record_error(-11, "wallet_send_with_filter: null argument(s)");
        return ptr::null_mut();
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(
                -10,
                "wallet_send_with_filter: wallet_id contained invalid UTF-8",
            );
            return ptr::null_mut();
        }
    };

    let dests_str = match unsafe { CStr::from_ptr(destinations_json) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(
                -10,
                "wallet_send_with_filter: destinations_json invalid UTF-8",
            );
            return ptr::null_mut();
        }
    };

    let filt_str_opt = if !filter_json.is_null() {
        unsafe { CStr::from_ptr(filter_json) }.to_str().ok()
    } else {
        None
    };

    #[derive(Deserialize)]
    struct Pay {
        address: String,
        amount: u64,
    }
    #[derive(Deserialize)]
    struct InputFilter {
        subaddress_minor: Option<u32>,
    }

    let pays: Vec<Pay> = match serde_json::from_str(dests_str) {
        Ok(v) => v,
        Err(err) => {
            record_error(
                -11,
                format!("wallet_send_with_filter: invalid destinations JSON ({err})"),
            );
            return ptr::null_mut();
        }
    };
    if pays.is_empty() {
        record_error(-11, "wallet_send_with_filter: empty destinations");
        return ptr::null_mut();
    }
    let filter: Option<InputFilter> = match filt_str_opt {
        Some(s) if !s.is_empty() => match serde_json::from_str(s) {
            Ok(f) => Some(f),
            Err(err) => {
                record_error(
                    -11,
                    format!("wallet_send_with_filter: invalid filter JSON ({err})"),
                );
                return ptr::null_mut();
            }
        },
        _ => None,
    };

    let snapshot = {
        let map = WALLET_STORE.lock().expect("wallet store poisoned");
        match map.get(id) {
            Some(state) => state.clone(),
            None => {
                record_error(
                    -13,
                    format!("wallet_send_with_filter: wallet '{id}' not registered"),
                );
                return ptr::null_mut();
            }
        }
    };

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

    let rpc_client = match BlockingRpcTransport::new(&base_url) {
        Ok(client) => client,
        Err(code) => {
            record_error(
                code,
                format!("wallet_send_with_filter: invalid daemon url '{base_url}'"),
            );
            return ptr::null_mut();
        }
    };
    let daemon = match fetch_daemon_status(&rpc_client) {
        Ok(status) => status,
        Err((code, message)) => {
            record_error(
                code,
                format!("wallet_send_with_filter: failed to query daemon '{base_url}': {message}"),
            );
            return ptr::null_mut();
        }
    };

    let master = match master_keys_from_mnemonic_str(&snapshot.mnemonic) {
        Ok(keys) => keys,
        Err(code) => {
            record_error(code, "wallet_send_with_filter: unable to parse mnemonic");
            return ptr::null_mut();
        }
    };
    let view_pair = match master.to_view_pair() {
        Ok(pair) => pair,
        Err(code) => {
            record_error(
                code,
                "wallet_send_with_filter: failed to construct view pair",
            );
            return ptr::null_mut();
        }
    };

    let mut scanner = Scanner::new(view_pair.clone());
    let gap_limit = snapshot.gap_limit.max(1);
    if let Some(i0) = SubaddressIndex::new(0, 0) {
        scanner.register_subaddress(i0);
    }
    for minor in 1..=gap_limit {
        if let Some(index) = SubaddressIndex::new(0, minor) {
            scanner.register_subaddress(index);
        }
    }

    let mut destinations: Vec<(monero_address::MoneroAddress, u64)> =
        Vec::with_capacity(pays.len());
    let mut total_needed: u64 = 0;
    for p in &pays {
        let addr = match MoneroAddress::from_str(snapshot.network, &p.address) {
            Ok(a) => a,
            Err(_) => {
                record_error(-10, "wallet_send_with_filter: invalid destination address");
                return ptr::null_mut();
            }
        };
        total_needed = total_needed.saturating_add(p.amount);
        destinations.push((addr, p.amount));
    }

    // Filter spendable outputs
    let mut spendable: Vec<TrackedOutput> = snapshot
        .tracked_outputs
        .iter()
        .cloned()
        .filter(|o| !o.spent && o.is_unlocked(daemon.height, daemon.top_block_timestamp))
        .collect();

    if let Some(f) = &filter {
        if let Some(minor) = f.subaddress_minor {
            spendable.retain(|o| o.subaddress_major == 0 && o.subaddress_minor == minor);
        }
    }
    spendable.sort_by_key(|o| o.amount);

    // IMPORTANT: select enough inputs to cover (destinations + fee).
    // Fee depends on input count, so selection is iterative until it stabilizes.
    let mut rng = OsRng;
    let ring_len_eff: u8 = if ring_len < 2 { 16 } else { ring_len };

    // Fetch fee rate once (depends on daemon policy/height, not our selection)
    let fee_rate = match block_on(rpc_client.get_fee_rate(monero_wallet::rpc::FeePriority::Normal))
    {
        Ok(fr) => fr,
        Err(err) => {
            let code = map_rpc_error(err);
            record_error(code, "wallet_send_with_filter: get_fee_rate failed");
            return ptr::null_mut();
        }
    };

    let change = monero_wallet::send::Change::new(view_pair.clone(), None);

    let mut selected: Vec<TrackedOutput> = Vec::new();
    let mut selected_sum: u64 = 0;

    let max_selection_rounds: usize = 24;

    for _round in 0..max_selection_rounds {
        // Ensure at least enough to cover destination totals on first pass.
        if selected.is_empty() {
            for o in &spendable {
                selected.push(o.clone());
                selected_sum = selected_sum.saturating_add(o.amount);
                if selected_sum >= total_needed {
                    break;
                }
            }

            if selected_sum < total_needed {
                record_error(
                    -18,
                    format!(
                        "wallet_send_with_filter: insufficient unlocked funds (have {}, need {})",
                        selected_sum, total_needed
                    ),
                );
                return ptr::null_mut();
            }
        }

        // Build inputs with decoys for current selection
        let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();
        for t in &selected {
            let block_number = match usize::try_from(t.block_height) {
                Ok(value) => value,
                Err(_) => {
                    record_error(
                        -16,
                        "wallet_send_with_filter: block number conversion overflow",
                    );
                    return ptr::null_mut();
                }
            };
            let scannable = match block_on(rpc_client.get_scannable_block_by_number(block_number)) {
                Ok(block) => block,
                Err(err) => {
                    let code = map_rpc_error(err);
                    record_error(
                        code,
                        format!(
                            "wallet_send_with_filter: RPC block fetch failed at height {}",
                            t.block_height
                        ),
                    );
                    return ptr::null_mut();
                }
            };
            let outputs = match scanner.scan(scannable) {
                Ok(result) => result.ignore_additional_timelock(),
                Err(_) => {
                    record_error(
                        -16,
                        format!(
                            "wallet_send_with_filter: scanner failed at height {}",
                            t.block_height
                        ),
                    );
                    return ptr::null_mut();
                }
            };
            let maybe_out = outputs.into_iter().find(|wo| {
                wo.transaction() == t.tx_hash && wo.index_in_transaction() == t.index_in_tx
            });
            let wallet_out = match maybe_out {
                Some(wo) => wo,
                None => {
                    record_error(
                        -16,
                        "wallet_send_with_filter: failed to reconstruct selected output",
                    );
                    return ptr::null_mut();
                }
            };
            let with_decoys = match block_on(monero_wallet::OutputWithDecoys::new(
                &mut rng,
                &rpc_client,
                ring_len_eff,
                usize::try_from(daemon.height).unwrap_or(daemon.height as usize),
                wallet_out,
            )) {
                Ok(i) => i,
                Err(err) => {
                    let code = map_rpc_error(err);
                    record_error(code, "wallet_send_with_filter: decoy selection failed");
                    return ptr::null_mut();
                }
            };
            inputs.push(with_decoys);
        }

        // New OVK each attempt; it should not affect fee, but keep it fresh.
        let mut ovk = [0u8; 32];
        rng.fill_bytes(&mut ovk);

        let intent = match monero_wallet::send::SignableTransaction::new(
            monero_wallet::ringct::RctType::ClsagBulletproofPlus,
            Zeroizing::new(ovk),
            inputs,
            destinations.clone(),
            change.clone(),
            Vec::new(),
            fee_rate,
        ) {
            Ok(tx) => tx,
            Err(e) => {
                record_error(
                    -16,
                    format!("wallet_send_with_filter: transaction construction failed ({e})"),
                );
                return ptr::null_mut();
            }
        };
        let fee_piconero = intent.necessary_fee();
        let needed_total = total_needed.saturating_add(fee_piconero);

        if selected_sum >= needed_total {
            // Enough to cover amount + fee; proceed with signing/broadcast below.
            break;
        }

        // Select more inputs and retry (fee may increase with more inputs).
        let mut added_any = false;
        for o in &spendable {
            if selected
                .iter()
                .any(|s| s.tx_hash == o.tx_hash && s.index_in_tx == o.index_in_tx)
            {
                continue;
            }
            selected.push(o.clone());
            selected_sum = selected_sum.saturating_add(o.amount);
            added_any = true;
            if selected_sum >= needed_total {
                break;
            }
        }

        if !added_any {
            record_error(
                -18,
                format!(
                    "wallet_send_with_filter: insufficient unlocked funds for amount+fee (have {}, need {})",
                    selected_sum, needed_total
                ),
            );
            return ptr::null_mut();
        }
    }

    // Rebuild intent one last time using final selection so `fee_piconero` below matches actual tx.
    let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();
    for t in &selected {
        let block_number = match usize::try_from(t.block_height) {
            Ok(value) => value,
            Err(_) => {
                record_error(
                    -16,
                    "wallet_send_with_filter: block number conversion overflow",
                );
                return ptr::null_mut();
            }
        };
        let scannable = match block_on(rpc_client.get_scannable_block_by_number(block_number)) {
            Ok(block) => block,
            Err(err) => {
                let code = map_rpc_error(err);
                record_error(
                    code,
                    format!(
                        "wallet_send_with_filter: RPC block fetch failed at height {}",
                        t.block_height
                    ),
                );
                return ptr::null_mut();
            }
        };
        let outputs = match scanner.scan(scannable) {
            Ok(result) => result.ignore_additional_timelock(),
            Err(_) => {
                record_error(
                    -16,
                    format!(
                        "wallet_send_with_filter: scanner failed at height {}",
                        t.block_height
                    ),
                );
                return ptr::null_mut();
            }
        };
        let maybe_out = outputs
            .into_iter()
            .find(|wo| wo.transaction() == t.tx_hash && wo.index_in_transaction() == t.index_in_tx);
        let wallet_out = match maybe_out {
            Some(wo) => wo,
            None => {
                record_error(
                    -16,
                    "wallet_send_with_filter: failed to reconstruct selected output",
                );
                return ptr::null_mut();
            }
        };
        let with_decoys = match block_on(monero_wallet::OutputWithDecoys::new(
            &mut rng,
            &rpc_client,
            ring_len_eff,
            usize::try_from(daemon.height).unwrap_or(daemon.height as usize),
            wallet_out,
        )) {
            Ok(i) => i,
            Err(err) => {
                let code = map_rpc_error(err);
                record_error(code, "wallet_send_with_filter: decoy selection failed");
                return ptr::null_mut();
            }
        };
        inputs.push(with_decoys);
    }

    let mut ovk = [0u8; 32];
    rng.fill_bytes(&mut ovk);

    let intent = match monero_wallet::send::SignableTransaction::new(
        monero_wallet::ringct::RctType::ClsagBulletproofPlus,
        Zeroizing::new(ovk),
        inputs,
        destinations,
        change,
        Vec::new(),
        fee_rate,
    ) {
        Ok(tx) => tx,
        Err(e) => {
            record_error(
                -16,
                format!("wallet_send_with_filter: transaction construction failed ({e})"),
            );
            return ptr::null_mut();
        }
    };
    let fee_piconero = intent.necessary_fee();

    let spend_key = Zeroizing::new(monero_wallet::ed25519::Scalar::from(master.spend_scalar));
    let mut signer_rng = OsRng;
    let tx = match intent.sign(&mut signer_rng, &spend_key) {
        Ok(tx) => tx,
        Err(e) => {
            record_error(
                -16,
                format!("wallet_send_with_filter: signing failed ({e})"),
            );
            return ptr::null_mut();
        }
    };

    if let Err(err) = block_on(rpc_client.publish_transaction(&tx)) {
        let code = map_rpc_error(err);
        record_error(code, "wallet_send_with_filter: publish_transaction failed");
        return ptr::null_mut();
    }

    {
        let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
        if let Some(state) = map.get_mut(id) {
            let spent_sum: u64 = selected.iter().map(|t| t.amount).sum();
            for t in &selected {
                if let Some(o) = state
                    .tracked_outputs
                    .iter_mut()
                    .find(|o| o.tx_hash == t.tx_hash && o.index_in_tx == t.index_in_tx)
                {
                    o.spent = true;
                }
            }
            state.total = state.total.saturating_sub(spent_sum);
            state.unlocked = state.unlocked.saturating_sub(spent_sum);
        }
    }

    let tx_hash = tx.hash();
    let hex = hex_lowercase(&tx_hash);
    let result_json = match serde_json::to_string(&serde_json::json!({
        "txid": hex,
        "fee": fee_piconero
    })) {
        Ok(s) => s,
        Err(err) => {
            record_error(
                -16,
                format!("wallet_send_with_filter: result JSON serialization failed ({err})"),
            );
            return ptr::null_mut();
        }
    };
    match CString::new(result_json) {
        Ok(cstr) => {
            clear_last_error();
            cstr.into_raw()
        }
        Err(_) => {
            record_error(
                -16,
                "wallet_send_with_filter: result JSON contained interior null bytes",
            );
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn wallet_preview_sweep_with_filter(
    wallet_id: *const c_char,
    node_url: *const c_char,
    to_address: *const c_char,
    filter_json: *const c_char,
    ring_len: u8,
) -> *mut c_char {
    clear_last_error();

    if wallet_id.is_null() || to_address.is_null() {
        record_error(-11, "wallet_preview_sweep_with_filter: null argument(s)");
        return ptr::null_mut();
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(
                -10,
                "wallet_preview_sweep_with_filter: wallet_id contained invalid UTF-8",
            );
            return ptr::null_mut();
        }
    };

    let addr_str = match unsafe { CStr::from_ptr(to_address) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(
                -10,
                "wallet_preview_sweep_with_filter: to_address contained invalid UTF-8",
            );
            return ptr::null_mut();
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
                record_error(
                    -11,
                    format!("wallet_preview_sweep_with_filter: invalid filter JSON ({err})"),
                );
                return ptr::null_mut();
            }
        },
        _ => None,
    };

    let snapshot = {
        let map = WALLET_STORE.lock().expect("wallet store poisoned");
        match map.get(id) {
            Some(state) => state.clone(),
            None => {
                record_error(
                    -13,
                    format!("wallet_preview_sweep_with_filter: wallet '{id}' not registered"),
                );
                return ptr::null_mut();
            }
        }
    };

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

    let rpc_client = match BlockingRpcTransport::new(&base_url) {
        Ok(client) => client,
        Err(code) => {
            record_error(
                code,
                format!("wallet_preview_sweep_with_filter: invalid daemon url '{base_url}'"),
            );
            return ptr::null_mut();
        }
    };
    let daemon = match fetch_daemon_status(&rpc_client) {
        Ok(status) => status,
        Err((code, message)) => {
            record_error(
                code,
                format!(
                    "wallet_preview_sweep_with_filter: failed to query daemon '{base_url}': {message}"
                ),
            );
            return ptr::null_mut();
        }
    };

    let master = match master_keys_from_mnemonic_str(&snapshot.mnemonic) {
        Ok(keys) => keys,
        Err(code) => {
            record_error(
                code,
                "wallet_preview_sweep_with_filter: unable to parse mnemonic",
            );
            return ptr::null_mut();
        }
    };
    let view_pair = match master.to_view_pair() {
        Ok(pair) => pair,
        Err(code) => {
            record_error(
                code,
                "wallet_preview_sweep_with_filter: failed to construct view pair",
            );
            return ptr::null_mut();
        }
    };

    // Validate destination address early
    let recipient_address = match MoneroAddress::from_str(snapshot.network, addr_str) {
        Ok(a) => a,
        Err(_) => {
            record_error(
                -10,
                "wallet_preview_sweep_with_filter: invalid destination address",
            );
            return ptr::null_mut();
        }
    };

    let mut scanner = Scanner::new(view_pair.clone());
    let gap_limit = snapshot.gap_limit.max(1);
    if let Some(i0) = SubaddressIndex::new(0, 0) {
        scanner.register_subaddress(i0);
    }
    for minor in 1..=gap_limit {
        if let Some(index) = SubaddressIndex::new(0, minor) {
            scanner.register_subaddress(index);
        }
    }

    // Spendable == unlocked & unspent only (sweep uses unlocked-only)
    let mut spendable: Vec<TrackedOutput> = snapshot
        .tracked_outputs
        .iter()
        .cloned()
        .filter(|o| !o.spent && o.is_unlocked(daemon.height, daemon.top_block_timestamp))
        .collect();

    if let Some(f) = &filter {
        if let Some(minor) = f.subaddress_minor {
            spendable.retain(|o| o.subaddress_major == 0 && o.subaddress_minor == minor);
        }
    }

    if spendable.is_empty() {
        record_error(
            -18,
            "wallet_preview_sweep_with_filter: no unlocked funds to sweep",
        );
        return ptr::null_mut();
    }

    // Prefer fewer/larger inputs for sweeps to reduce fees.
    spendable.sort_by_key(|o| std::cmp::Reverse(o.amount));

    let mut rng = OsRng;
    let ring_len_eff: u8 = if ring_len < 2 { 16 } else { ring_len };

    // Fee rate once
    let fee_rate = match block_on(rpc_client.get_fee_rate(monero_wallet::rpc::FeePriority::Normal))
    {
        Ok(fr) => fr,
        Err(err) => {
            let code = map_rpc_error(err);
            record_error(
                code,
                "wallet_preview_sweep_with_filter: get_fee_rate failed",
            );
            return ptr::null_mut();
        }
    };

    let change = monero_wallet::send::Change::new(view_pair.clone(), None);

    // Iteratively decide how many inputs to sweep, and compute amount = sum(inputs) - fee.
    let mut selected: Vec<TrackedOutput> = Vec::new();
    let mut selected_sum: u64 = 0;

    let max_selection_rounds: usize = 24;
    let mut last_amount: Option<u64> = None;

    for _round in 0..max_selection_rounds {
        // Add one more input each round until it stops increasing the computed sendable amount.
        if selected.len() < spendable.len() {
            let next = spendable[selected.len()].clone();
            selected_sum = selected_sum.saturating_add(next.amount);
            selected.push(next);
        } else if selected.is_empty() {
            record_error(
                -18,
                "wallet_preview_sweep_with_filter: no unlocked funds to sweep",
            );
            return ptr::null_mut();
        }

        // Build inputs with decoys
        let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();
        for t in &selected {
            let block_number = match usize::try_from(t.block_height) {
                Ok(value) => value,
                Err(_) => {
                    record_error(
                        -16,
                        "wallet_preview_sweep_with_filter: block number conversion overflow",
                    );
                    return ptr::null_mut();
                }
            };
            let scannable = match block_on(rpc_client.get_scannable_block_by_number(block_number)) {
                Ok(block) => block,
                Err(err) => {
                    let code = map_rpc_error(err);
                    record_error(
                        code,
                        format!(
                            "wallet_preview_sweep_with_filter: RPC block fetch failed at height {}",
                            t.block_height
                        ),
                    );
                    return ptr::null_mut();
                }
            };
            let outputs = match scanner.scan(scannable) {
                Ok(result) => result.ignore_additional_timelock(),
                Err(_) => {
                    record_error(
                        -16,
                        format!(
                            "wallet_preview_sweep_with_filter: scanner failed at height {}",
                            t.block_height
                        ),
                    );
                    return ptr::null_mut();
                }
            };
            let maybe_out = outputs.into_iter().find(|wo| {
                wo.transaction() == t.tx_hash && wo.index_in_transaction() == t.index_in_tx
            });
            let wallet_out = match maybe_out {
                Some(wo) => wo,
                None => {
                    record_error(
                        -16,
                        "wallet_preview_sweep_with_filter: failed to reconstruct selected output",
                    );
                    return ptr::null_mut();
                }
            };
            let with_decoys = match block_on(monero_wallet::OutputWithDecoys::new(
                &mut rng,
                &rpc_client,
                ring_len_eff,
                usize::try_from(daemon.height).unwrap_or(daemon.height as usize),
                wallet_out,
            )) {
                Ok(i) => i,
                Err(err) => {
                    let code = map_rpc_error(err);
                    record_error(
                        code,
                        "wallet_preview_sweep_with_filter: decoy selection failed",
                    );
                    return ptr::null_mut();
                }
            };
            inputs.push(with_decoys);
        }

        // Compute a consistent sweep amount via fixed-point iteration:
        // amount = selected_sum - fee(amount), because fee depends on tx weight which depends on amount encoding.
        // This prevents constructing impossible txs where outputs ~= inputs with no room for fee.
        let mut amount_guess: u64 = selected_sum;
        let mut fee: u64 = 0;

        // Small bound; this should converge quickly because fee changes are small and monotonic-ish with size.
        let max_amount_iters: usize = 12;

        for _ in 0..max_amount_iters {
            let mut ovk = [0u8; 32];
            rng.fill_bytes(&mut ovk);

            // If fee >= selected_sum, sweep is impossible with this selection.
            // Clamp to zero to force failure handling below.
            let candidate_amount = selected_sum.saturating_sub(fee);

            let intent = match monero_wallet::send::SignableTransaction::new(
                monero_wallet::ringct::RctType::ClsagBulletproofPlus,
                Zeroizing::new(ovk),
                inputs.clone(),
                vec![(recipient_address, candidate_amount)],
                change.clone(),
                Vec::new(),
                fee_rate,
            ) {
                Ok(tx) => tx,
                Err(e) => {
                    record_error(
                        -16,
                        format!(
                            "wallet_preview_sweep_with_filter: transaction construction failed ({e})"
                        ),
                    );
                    return ptr::null_mut();
                }
            };

            let new_fee = intent.necessary_fee();
            let new_amount = selected_sum.saturating_sub(new_fee);

            // Converged: amount consistent with fee
            if new_amount == amount_guess && new_fee == fee {
                fee = new_fee;
                amount_guess = new_amount;
                break;
            }

            fee = new_fee;
            amount_guess = new_amount;
        }

        if fee >= selected_sum || amount_guess == 0 {
            // This selection can't pay its own fee; try adding more inputs, otherwise fail.
            if selected.len() >= spendable.len() {
                record_error(
                    -18,
                    format!(
                        "wallet_preview_sweep_with_filter: insufficient unlocked funds to pay fee (inputs {}, necessary_fee {})",
                        selected_sum, fee
                    ),
                );
                return ptr::null_mut();
            }
            continue;
        }

        let amount = amount_guess;

        // Stop when amount stops improving (adding more inputs would mostly increase fee).
        if let Some(prev) = last_amount {
            if amount <= prev {
                // Use previous best result
                let json = match serde_json::to_string(
                    &serde_json::json!({ "amount": prev, "fee": selected_sum.saturating_sub(prev) }),
                ) {
                    Ok(s) => s,
                    Err(err) => {
                        record_error(
                            -16,
                            format!("wallet_preview_sweep_with_filter: result JSON serialization failed ({err})"),
                        );
                        return ptr::null_mut();
                    }
                };
                match CString::new(json) {
                    Ok(cstr) => {
                        clear_last_error();
                        return cstr.into_raw();
                    }
                    Err(_) => {
                        record_error(
                            -16,
                            "wallet_preview_sweep_with_filter: result JSON contained interior null bytes",
                        );
                        return ptr::null_mut();
                    }
                }
            }
        }

        last_amount = Some(amount);

        // If we've already swept all unlocked outputs, return best.
        if selected.len() >= spendable.len() {
            let json = match serde_json::to_string(
                &serde_json::json!({ "amount": amount, "fee": fee }),
            ) {
                Ok(s) => s,
                Err(err) => {
                    record_error(
                        -16,
                        format!("wallet_preview_sweep_with_filter: result JSON serialization failed ({err})"),
                    );
                    return ptr::null_mut();
                }
            };
            match CString::new(json) {
                Ok(cstr) => {
                    clear_last_error();
                    return cstr.into_raw();
                }
                Err(_) => {
                    record_error(
                        -16,
                        "wallet_preview_sweep_with_filter: result JSON contained interior null bytes",
                    );
                    return ptr::null_mut();
                }
            }
        }
    }

    record_error(
        -16,
        "wallet_preview_sweep_with_filter: fee estimation did not converge (too many selection rounds)",
    );
    ptr::null_mut()
}

#[no_mangle]
pub extern "C" fn wallet_sweep_with_filter(
    wallet_id: *const c_char,
    node_url: *const c_char,
    to_address: *const c_char,
    filter_json: *const c_char,
    ring_len: u8,
) -> *mut c_char {
    clear_last_error();

    if wallet_id.is_null() || to_address.is_null() {
        record_error(-11, "wallet_sweep_with_filter: null argument(s)");
        return ptr::null_mut();
    }

    // First, preview to get computed amount+fee (unlocked-only).
    let preview_ptr =
        wallet_preview_sweep_with_filter(wallet_id, node_url, to_address, filter_json, ring_len);
    if preview_ptr.is_null() {
        // wallet_preview_sweep_with_filter already recorded last_error
        return ptr::null_mut();
    }
    let preview_str = unsafe { CStr::from_ptr(preview_ptr) }
        .to_string_lossy()
        .to_string();
    let _ = walletcore_free_cstr(preview_ptr);

    #[derive(Deserialize)]
    struct SweepPreviewResult {
        amount: u64,
    }

    let preview: SweepPreviewResult = match serde_json::from_str(&preview_str) {
        Ok(v) => v,
        Err(err) => {
            record_error(
                -16,
                format!("wallet_sweep_with_filter: failed to decode preview result ({err})"),
            );
            return ptr::null_mut();
        }
    };

    if preview.amount == 0 {
        record_error(
            -18,
            "wallet_sweep_with_filter: computed sweep amount is zero",
        );
        return ptr::null_mut();
    }

    // Use existing send_with_filter by constructing destinations JSON.
    let dest_json = match serde_json::to_string(&vec![serde_json::json!({
        "address": unsafe { CStr::from_ptr(to_address) }.to_string_lossy().to_string(),
        "amount": preview.amount
    })]) {
        Ok(s) => s,
        Err(err) => {
            record_error(
                -16,
                format!("wallet_sweep_with_filter: destinations JSON serialization failed ({err})"),
            );
            return ptr::null_mut();
        }
    };

    let send_ptr = CString::new(dest_json).ok();
    let send_cstr = match send_ptr {
        Some(c) => c,
        None => {
            record_error(
                -16,
                "wallet_sweep_with_filter: destinations JSON contained interior null bytes",
            );
            return ptr::null_mut();
        }
    };

    let raw = wallet_send_with_filter(
        wallet_id,
        node_url,
        send_cstr.as_ptr(),
        filter_json,
        ring_len,
    );
    if raw.is_null() {
        return ptr::null_mut();
    }

    let send_str = unsafe { CStr::from_ptr(raw) }.to_string_lossy().to_string();
    let _ = walletcore_free_cstr(raw);

    #[derive(Deserialize)]
    struct SendResult {
        txid: String,
        fee: u64,
    }
    let send_res: SendResult = match serde_json::from_str(&send_str) {
        Ok(v) => v,
        Err(err) => {
            record_error(
                -16,
                format!("wallet_sweep_with_filter: failed to decode send result ({err})"),
            );
            return ptr::null_mut();
        }
    };

    // Note: `fee` is used below; keep it as part of the decoded struct to avoid relying on string parsing.

    // Record a pending outgoing tx for UI history.
    {
        let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
        // wallet_send_with_filter already used `wallet_id`, so we can reuse it here.
        let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
            Ok(s) => s.trim(),
            Err(_) => "",
        };
        if !id.is_empty() {
            if let Some(state) = map.get_mut(id) {
                state.pending_outgoing.push(PendingOutgoingTx {
                    txid: send_res.txid.clone(),
                    amount: preview.amount,
                    fee: send_res.fee,
                    created_at: state.chain_time,
                });

                // Update stable transfer ledger (outgoing is pending until confirmed by refresh).
                state.tx_ledger.insert(
                    send_res.txid.clone(),
                    LedgerEntry {
                        txid: send_res.txid.clone(),
                        direction: "out".to_string(),
                        amount: preview.amount,
                        fee: Some(send_res.fee),
                        height: None,
                        timestamp: Some(state.chain_time),
                        is_pending: true,
                        is_coinbase: false,
                    },
                );
            }
        }
    }
    let result_json = match serde_json::to_string(&serde_json::json!({
        "txid": send_res.txid,
        "amount": preview.amount,
        "fee": send_res.fee
    })) {
        Ok(s) => s,
        Err(err) => {
            record_error(
                -16,
                format!("wallet_sweep_with_filter: result JSON serialization failed ({err})"),
            );
            return ptr::null_mut();
        }
    };

    match CString::new(result_json) {
        Ok(cstr) => {
            clear_last_error();
            cstr.into_raw()
        }
        Err(_) => {
            record_error(
                -16,
                "wallet_sweep_with_filter: result JSON contained interior null bytes",
            );
            ptr::null_mut()
        }
    }
}

#[no_mangle]
pub extern "C" fn wallet_preview_fee_with_filter(
    wallet_id: *const c_char,
    node_url: *const c_char,
    destinations_json: *const c_char,
    filter_json: *const c_char,
    ring_len: u8,
) -> *mut c_char {
    clear_last_error();

    if wallet_id.is_null() || destinations_json.is_null() {
        record_error(-11, "wallet_preview_fee_with_filter: null argument(s)");
        return ptr::null_mut();
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(
                -10,
                "wallet_preview_fee_with_filter: wallet_id contained invalid UTF-8",
            );
            return ptr::null_mut();
        }
    };

    let dests_str = match unsafe { CStr::from_ptr(destinations_json) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(
                -10,
                "wallet_preview_fee_with_filter: destinations_json invalid UTF-8",
            );
            return ptr::null_mut();
        }
    };

    let filt_str_opt = if !filter_json.is_null() {
        unsafe { CStr::from_ptr(filter_json) }.to_str().ok()
    } else {
        None
    };

    #[derive(Deserialize)]
    struct Pay {
        address: String,
        amount: u64,
    }
    #[derive(Deserialize)]
    struct InputFilter {
        subaddress_minor: Option<u32>,
    }

    let pays: Vec<Pay> = match serde_json::from_str(dests_str) {
        Ok(v) => v,
        Err(err) => {
            record_error(
                -11,
                format!("wallet_preview_fee_with_filter: invalid destinations JSON ({err})"),
            );
            return ptr::null_mut();
        }
    };
    if pays.is_empty() {
        record_error(-11, "wallet_preview_fee_with_filter: empty destinations");
        return ptr::null_mut();
    }
    let filter: Option<InputFilter> = match filt_str_opt {
        Some(s) if !s.is_empty() => match serde_json::from_str(s) {
            Ok(f) => Some(f),
            Err(err) => {
                record_error(
                    -11,
                    format!("wallet_preview_fee_with_filter: invalid filter JSON ({err})"),
                );
                return ptr::null_mut();
            }
        },
        _ => None,
    };

    let snapshot = {
        let map = WALLET_STORE.lock().expect("wallet store poisoned");
        match map.get(id) {
            Some(state) => state.clone(),
            None => {
                record_error(
                    -13,
                    format!("wallet_preview_fee_with_filter: wallet '{id}' not registered"),
                );
                return ptr::null_mut();
            }
        }
    };

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

    let rpc_client = match BlockingRpcTransport::new(&base_url) {
        Ok(client) => client,
        Err(code) => {
            record_error(
                code,
                format!("wallet_preview_fee_with_filter: invalid daemon url '{base_url}'"),
            );
            return ptr::null_mut();
        }
    };
    let daemon = match fetch_daemon_status(&rpc_client) {
        Ok(status) => status,
        Err((code, message)) => {
            record_error(
                code,
                format!(
                "wallet_preview_fee_with_filter: failed to query daemon '{base_url}': {message}"
            ),
            );
            return ptr::null_mut();
        }
    };

    let master = match master_keys_from_mnemonic_str(&snapshot.mnemonic) {
        Ok(keys) => keys,
        Err(code) => {
            record_error(
                code,
                "wallet_preview_fee_with_filter: unable to parse mnemonic",
            );
            return ptr::null_mut();
        }
    };
    let view_pair = match master.to_view_pair() {
        Ok(pair) => pair,
        Err(code) => {
            record_error(
                code,
                "wallet_preview_fee_with_filter: failed to construct view pair",
            );
            return ptr::null_mut();
        }
    };

    let mut scanner = Scanner::new(view_pair.clone());
    let gap_limit = snapshot.gap_limit.max(1);
    if let Some(i0) = SubaddressIndex::new(0, 0) {
        scanner.register_subaddress(i0);
    }
    for minor in 1..=gap_limit {
        if let Some(index) = SubaddressIndex::new(0, minor) {
            scanner.register_subaddress(index);
        }
    }

    // Parse destinations
    let mut destinations: Vec<(monero_address::MoneroAddress, u64)> =
        Vec::with_capacity(pays.len());
    let mut total_needed: u64 = 0;
    for p in &pays {
        let addr = match MoneroAddress::from_str(snapshot.network, &p.address) {
            Ok(a) => a,
            Err(_) => {
                record_error(
                    -10,
                    "wallet_preview_fee_with_filter: invalid destination address",
                );
                return ptr::null_mut();
            }
        };
        total_needed = total_needed.saturating_add(p.amount);
        destinations.push((addr, p.amount));
    }

    // Filter and collect spendable outputs
    let mut spendable: Vec<TrackedOutput> = snapshot
        .tracked_outputs
        .iter()
        .cloned()
        .filter(|o| !o.spent && o.is_unlocked(daemon.height, daemon.top_block_timestamp))
        .collect();
    if let Some(f) = &filter {
        if let Some(minor) = f.subaddress_minor {
            spendable.retain(|o| o.subaddress_major == 0 && o.subaddress_minor == minor);
        }
    }
    spendable.sort_by_key(|o| o.amount);

    // IMPORTANT: select enough inputs to cover (destinations + fee).
    // Fee depends on input count/size, so selection is iterative until it stabilizes.
    let mut rng = OsRng;
    let ring_len_eff: u8 = if ring_len < 2 { 16 } else { ring_len };

    // Fetch fee rate once (depends on daemon policy/height, not our selection)
    let fee_rate = match block_on(rpc_client.get_fee_rate(monero_wallet::rpc::FeePriority::Normal))
    {
        Ok(fr) => fr,
        Err(err) => {
            let code = map_rpc_error(err);
            record_error(code, "wallet_preview_fee_with_filter: get_fee_rate failed");
            return ptr::null_mut();
        }
    };

    let change = monero_wallet::send::Change::new(view_pair.clone(), None);

    // Iteratively select inputs until we can construct a tx that covers amount + fee.
    let mut selected: Vec<TrackedOutput> = Vec::new();
    let mut selected_sum: u64 = 0;

    // Prevent pathological looping; input selection should converge quickly.
    let max_selection_rounds: usize = 24;

    for _round in 0..max_selection_rounds {
        // Ensure we have at least enough selected for the destination totals on first pass.
        if selected.is_empty() {
            for o in &spendable {
                selected.push(o.clone());
                selected_sum = selected_sum.saturating_add(o.amount);
                if selected_sum >= total_needed {
                    break;
                }
            }
            if selected_sum < total_needed {
                record_error(
                    -18,
                    format!(
                        "wallet_preview_fee_with_filter: insufficient unlocked funds (have {}, need {})",
                        selected_sum, total_needed
                    ),
                );
                return ptr::null_mut();
            }
        }

        // Build decoy-selected inputs for the current selection (needed to estimate fee accurately)
        let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();
        for t in &selected {
            let block_number = match usize::try_from(t.block_height) {
                Ok(value) => value,
                Err(_) => {
                    record_error(
                        -16,
                        "wallet_preview_fee_with_filter: block number conversion overflow",
                    );
                    return ptr::null_mut();
                }
            };
            let scannable = match block_on(rpc_client.get_scannable_block_by_number(block_number)) {
                Ok(block) => block,
                Err(err) => {
                    let code = map_rpc_error(err);
                    record_error(
                        code,
                        format!(
                            "wallet_preview_fee_with_filter: RPC block fetch failed at height {}",
                            t.block_height
                        ),
                    );
                    return ptr::null_mut();
                }
            };
            let outputs = match scanner.scan(scannable) {
                Ok(result) => result.ignore_additional_timelock(),
                Err(_) => {
                    record_error(
                        -16,
                        format!(
                            "wallet_preview_fee_with_filter: scanner failed at height {}",
                            t.block_height
                        ),
                    );
                    return ptr::null_mut();
                }
            };
            let maybe_out = outputs.into_iter().find(|wo| {
                wo.transaction() == t.tx_hash && wo.index_in_transaction() == t.index_in_tx
            });
            let wallet_out = match maybe_out {
                Some(wo) => wo,
                None => {
                    record_error(
                        -16,
                        "wallet_preview_fee_with_filter: failed to reconstruct selected output",
                    );
                    return ptr::null_mut();
                }
            };
            let with_decoys = match block_on(monero_wallet::OutputWithDecoys::new(
                &mut rng,
                &rpc_client,
                ring_len_eff,
                usize::try_from(daemon.height).unwrap_or(daemon.height as usize),
                wallet_out,
            )) {
                Ok(i) => i,
                Err(err) => {
                    let code = map_rpc_error(err);
                    record_error(
                        code,
                        "wallet_preview_fee_with_filter: decoy selection failed",
                    );
                    return ptr::null_mut();
                }
            };
            inputs.push(with_decoys);
        }

        // New OVK each attempt; it should not affect fee, but keep it fresh.
        let mut ovk = [0u8; 32];
        rng.fill_bytes(&mut ovk);

        let intent = match monero_wallet::send::SignableTransaction::new(
            monero_wallet::ringct::RctType::ClsagBulletproofPlus,
            Zeroizing::new(ovk),
            inputs,
            destinations.clone(),
            change.clone(),
            Vec::new(),
            fee_rate,
        ) {
            Ok(tx) => tx,
            Err(e) => {
                record_error(
                    -16,
                    format!(
                        "wallet_preview_fee_with_filter: transaction construction failed ({e})"
                    ),
                );
                return ptr::null_mut();
            }
        };

        let fee = intent.necessary_fee();
        let needed_total = total_needed.saturating_add(fee);

        // If we already cover amount+fee, we're done: return fee.
        if selected_sum >= needed_total {
            let json = match serde_json::to_string(&serde_json::json!({ "fee": fee })) {
                Ok(s) => s,
                Err(err) => {
                    record_error(
                        -16,
                        format!("wallet_preview_fee_with_filter: result JSON serialization failed ({err})"),
                    );
                    return ptr::null_mut();
                }
            };
            match CString::new(json) {
                Ok(cstr) => {
                    clear_last_error();
                    return cstr.into_raw();
                }
                Err(_) => {
                    record_error(
                        -16,
                        "wallet_preview_fee_with_filter: result JSON contained interior null bytes",
                    );
                    return ptr::null_mut();
                }
            }
        }

        // Otherwise, select more inputs and retry (fee may increase with more inputs).
        let mut added_any = false;
        for o in &spendable {
            // Skip already selected
            if selected
                .iter()
                .any(|s| s.tx_hash == o.tx_hash && s.index_in_tx == o.index_in_tx)
            {
                continue;
            }
            selected.push(o.clone());
            selected_sum = selected_sum.saturating_add(o.amount);
            added_any = true;
            if selected_sum >= needed_total {
                break;
            }
        }

        if !added_any {
            record_error(
                -18,
                format!(
                    "wallet_preview_fee_with_filter: insufficient unlocked funds for amount+fee (have {}, need {})",
                    selected_sum, needed_total
                ),
            );
            return ptr::null_mut();
        }
    }

    record_error(
        -16,
        "wallet_preview_fee_with_filter: fee estimation did not converge (too many selection rounds)",
    );
    return ptr::null_mut();
}
