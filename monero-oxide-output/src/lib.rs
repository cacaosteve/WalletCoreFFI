use std::{
    collections::{hash_map::Entry, HashMap, HashSet},
    convert::TryInto,
    ffi::{CStr, CString},
    future::Future,
    io::Read,
    os::raw::{c_char, c_int},
    ptr, slice,
    sync::{Arc, Mutex},
    time::Duration,
};

use std::sync::atomic::{AtomicBool, Ordering};

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
    rpc::{Rpc, RpcError},
    transaction::Timelock,
    Scanner, ViewPair,
};

use serde::{Deserialize, Serialize};
// Keccak256 is used via EdScalar::hash(), no direct import needed
use once_cell::sync::Lazy;
use rand::{rngs::OsRng, RngCore};

use ureq::serde_json;
use zeroize::Zeroizing;
#[cfg(not(any(target_os = "ios", target_os = "tvos", target_os = "watchos")))]
use zmq;

const DEFAULT_LOCK_WINDOW: u64 = 10;
const COINBASE_LOCK_WINDOW: u64 = 60;

static LAST_ERROR_MESSAGE: Lazy<Mutex<Option<String>>> = Lazy::new(|| Mutex::new(None));

/// Per-wallet cancellation flags for `wallet_refresh` / `wallet_refresh_async`.
/// This is best-effort: the refresh loop checks it frequently and aborts promptly.
///
/// Keyed by `wallet_id` string.
static REFRESH_CANCEL_FLAGS: Lazy<Mutex<HashMap<String, Arc<AtomicBool>>>> =
    Lazy::new(|| Mutex::new(HashMap::new()));

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
    let bulk: bool = std::env::var("WALLETCORE_BULK_RPC")
        .ok()
        .map(|s| s != "0")
        .unwrap_or(false);
    let worker_blocks: usize = std::env::var("WALLETCORE_WORKER_BLOCKS")
        .ok()
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(8);

    if scan_cursor < daemon.height {
        if par > 1 && batch > 1 {
            // Parallel, batched scanning. Each worker uses its own Scanner cloned from the same view_pair.
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
                let heights: Vec<u64> = if bulk {
                    (scan_cursor..end_exclusive)
                        .step_by(worker_blocks.max(1))
                        .collect()
                } else {
                    (scan_cursor..end_exclusive).collect()
                };
                let _count = heights.len();

                let (tx, rx) =
                    std::sync::mpsc::channel::<Result<Vec<TrackedOutput>, (c_int, String)>>();

                // Launch workers in chunks of `par`
                for chunk in heights.chunks(par) {
                    for &h in chunk {
                        // Cancellation check (per-wallet) before spawning more work
                        if refresh_cancelled_for_wallet(id) {
                            return record_error(-30, "wallet_refresh: cancelled");
                        }

                        let txc = tx.clone();
                        let client = rpc_client.clone();
                        let vp = view_pair.clone();
                        let local_gap = gap_limit;
                        // Capture bulk parameters for this worker
                        let end_ex = end_exclusive;
                        let bulk_mode = bulk;
                        let worker_span = worker_blocks as u64;
                        let id_owned_for_worker = id.to_string();
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

                            // Determine span for this worker
                            let start_height = h;
                            let end_height_exclusive = if bulk_mode {
                                start_height.saturating_add(worker_span).min(end_ex)
                            } else {
                                start_height.saturating_add(1)
                            };

                            let mut collected: Vec<TrackedOutput> = Vec::new();
                            for th in start_height..end_height_exclusive {
                                // Cancellation check (per-wallet) inside worker loop
                                if refresh_cancelled_for_wallet(&id_owned_for_worker) {
                                    let _ = txc
                                        .send(Err((-30, "wallet_refresh: cancelled".to_string())));
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

                    // Update progress after draining this chunk to reduce perceived stalls
                    if let Some(&chunk_last_height) = chunk.last() {
                        let next_cursor = chunk_last_height.saturating_add(1).min(daemon.height);
                        scan_cursor = next_cursor;
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
            // Sequential scan (original path)
            while scan_cursor < daemon.height {
                // Cancellation check (per-wallet)
                if refresh_cancelled_for_wallet(id) {
                    return record_error(-30, "wallet_refresh: cancelled");
                }

                let block_number = match usize::try_from(scan_cursor) {
                    Ok(value) => value,
                    Err(_) => {
                        return record_error(
                            -16,
                            "wallet_refresh: block number conversion overflow",
                        )
                    }
                };
                let scannable =
                    match block_on(rpc_client.get_scannable_block_by_number(block_number)) {
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
                            format!("wallet_refresh: scanner failed at height {}", scan_cursor),
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
