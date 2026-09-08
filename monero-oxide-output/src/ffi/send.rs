//! Send-related FFI surface extracted from the historical mega-`lib.rs`.
//!
//! This module intentionally keeps behavior identical to the inlined implementation,
//! while relying on `crate::support` for a small, stable set of re-exports.

#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_return)]

use crate::support::*;
use crate::StoredWallet;

use core::ffi::c_char;
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use serde_json;
use std::{
    collections::HashSet,
    ffi::{CStr, CString},
    ptr,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

// External types used by the send path.
use monero_address::MoneroAddress;
use monero_interface::{FeeError, FeeRate};
use monero_wallet::{
    transaction::{Input, NotPruned, Transaction},
    Scanner,
};

/// Hold the refresh job registry lock for the complete send/prepare/relay operation. This closes
/// both races: an operation cannot snapshot wallet outputs while a scanner is running, and a new
/// scanner cannot start until the operation has finished updating local spent state.
fn run_while_refresh_stopped(
    wallet_id: *const c_char,
    context: &str,
    operation: impl FnOnce() -> *mut c_char,
) -> *mut c_char {
    clear_last_error();
    if wallet_id.is_null() {
        record_error(-11, format!("{context}: wallet_id pointer was null"));
        return ptr::null_mut();
    }
    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(value) if !value.trim().is_empty() => value.trim(),
        Ok(_) => {
            record_error(-14, format!("{context}: wallet_id was empty"));
            return ptr::null_mut();
        }
        Err(_) => {
            record_error(-10, format!("{context}: wallet_id contained invalid UTF-8"));
            return ptr::null_mut();
        }
    };

    match crate::ffi::refresh::with_refresh_stopped(id, operation) {
        Ok(result) => result,
        Err(()) => {
            record_error(
                -31,
                format!("{context}: refresh already running for wallet '{id}'"),
            );
            ptr::null_mut()
        }
    }
}

// Treat any broadcast failure tagged as `double_spend` as requiring spent-evidence before we
// quarantine a candidate output.
fn is_double_spend_tagged_broadcast_error(s: &str) -> bool {
    // We tag failures as: `broadcast failed (double_spend): ...`
    s.contains("broadcast failed (double_spend):")
}

/// Derive key image bytes using the *exact* signer semantics from `monero-oxide`
/// (`SignableTransaction::sign`):
///
/// - input_secret = a + key_offset
/// - key_image = input_secret * Hp(P)
///
/// This intentionally ignores any subaddress `m` term; the signer does not include it.
// NOTE: signer-aligned key image derivation is provided by shared support (`derive_key_image_bytes`)
// and should not be duplicated in this module.

/// Query daemon for key image spent status via *non-JSON* RPC route (`/is_key_image_spent`).
///
/// Returns a vector aligned with `key_images` where:
/// - `0` means unspent
/// - `1` means spent in blockchain
/// - `2` means spent in pool
///
/// If the daemon doesn't support this endpoint or the response shape is unexpected, returns an
/// error string.
///
/// Note: this is **not** a JSON-RPC method. It must be called via the regular RPC route, not
/// `/json_rpc`.
fn rpc_is_key_image_spent(
    rpc_client: &RpcClient,
    key_images: &[[u8; 32]],
) -> Result<Vec<u8>, String> {
    #[derive(Debug, Deserialize)]
    struct KiResp {
        // monerod returns `spent_status` as an array of integers (0/1/2), aligned with request order.
        spent_status: Vec<u8>,
        // `status` is usually "OK" on success; keep it optional to be tolerant of proxies.
        status: Option<String>,
    }

    if key_images.is_empty() {
        return Ok(Vec::new());
    }

    // Build params JSON in the shape monerod expects for the *route* call:
    // { "key_images": ["<hex>", ...] }
    //
    // We build this manually to avoid introducing new serialization dependencies here.
    let mut kis = String::new();
    for (i, ki) in key_images.iter().enumerate() {
        if i != 0 {
            kis.push(',');
        }
        kis.push('"');
        kis.push_str(&hex_dump_prefix(ki, 32).replace(' ', ""));
        kis.push('"');
    }
    let params = format!(r#"{{"key_images":[{kis}]}}"#);

    // Call the non-JSON RPC route and parse the returned JSON.
    let raw = TOKIO_RUNTIME
        .block_on(rpc_client.rpc_call("is_key_image_spent", Some(params), 0))
        .map_err(|e| format!("is_key_image_spent rpc failed: {e}"))?;

    let resp: KiResp =
        serde_json::from_str(&raw).map_err(|e| format!("is_key_image_spent parse failed: {e}"))?;

    if resp.spent_status.len() != key_images.len() {
        return Err(format!(
            "is_key_image_spent returned {} entries, expected {}",
            resp.spent_status.len(),
            key_images.len()
        ));
    }

    if let Some(status) = resp.status.as_deref() {
        if status != "OK" {
            return Err(format!("is_key_image_spent returned status={}", status));
        }
    }

    Ok(resp.spent_status)
}

/// Auto-retry configuration for the send path.
///
/// Default: retry up to 2 times when we *actually* quarantine a newly-discovered toxic input.
/// This is deliberately bounded to avoid long UI stalls.
///
/// Override with:
/// - `WALLETCORE_SEND_RETRY_MAX` (integer, default 2)
/// - `WALLETCORE_SEND_AUTORETRY=0` to disable
fn walletcore_send_retry_max() -> usize {
    if std::env::var("WALLETCORE_SEND_AUTORETRY")
        .ok()
        .is_some_and(|v| v == "0")
    {
        return 0;
    }

    std::env::var("WALLETCORE_SEND_RETRY_MAX")
        .ok()
        .and_then(|v| v.trim().parse::<usize>().ok())
        .unwrap_or(2)
}

#[derive(Deserialize)]
struct PreparedSendPayload {
    txid: String,
    amount: u64,
    fee: u64,
    signed_tx_hex: String,
    #[serde(default)]
    wallet_binding: Option<String>,
}

fn validate_prepared_binding(
    prepared: &PreparedSendPayload,
    wallet: &StoredWallet,
) -> Result<(), &'static str> {
    match prepared.wallet_binding.as_deref() {
        Some(binding) if binding == wallet_cache_binding(wallet) => Ok(()),
        Some(_) => Err("pending transaction belongs to another wallet or network; recovery data retained"),
        None => Err("legacy pending transaction lacks wallet identity; explicit recovery is required; recovery data retained"),
    }
}

fn decode_hex(value: &str) -> Result<Vec<u8>, String> {
    let value = value.trim();
    if value.is_empty() || value.len() % 2 != 0 {
        return Err("signed transaction hex must be non-empty and even-length".to_string());
    }
    if value.len() > 4 * 1024 * 1024 {
        return Err("signed transaction hex exceeds the 2 MiB binary limit".to_string());
    }

    fn nibble(byte: u8) -> Option<u8> {
        match byte {
            b'0'..=b'9' => Some(byte - b'0'),
            b'a'..=b'f' => Some(byte - b'a' + 10),
            b'A'..=b'F' => Some(byte - b'A' + 10),
            _ => None,
        }
    }

    let bytes = value.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len() / 2);
    for pair in bytes.chunks_exact(2) {
        let high = nibble(pair[0])
            .ok_or_else(|| "signed transaction contains non-hex data".to_string())?;
        let low = nibble(pair[1])
            .ok_or_else(|| "signed transaction contains non-hex data".to_string())?;
        decoded.push((high << 4) | low);
    }
    Ok(decoded)
}

fn daemon_knows_tx(base_url: &str, txid: &str) -> Result<bool, String> {
    #[derive(Deserialize)]
    struct TxInfo {
        tx_hash: String,
    }

    #[derive(Deserialize)]
    struct GetTransactionsResponse {
        #[serde(default)]
        txs: Vec<TxInfo>,
    }

    let rpc_client: RpcClient = TOKIO_RUNTIME
        .block_on(monero_simple_request_rpc::SimpleRequestTransport::new(
            base_url.to_string(),
        ))
        .map_err(|error| format!("failed to connect daemon '{base_url}': {error}"))?;
    let params = serde_json::json!({
        "txs_hashes": [txid],
        "decode_as_json": false,
        "prune": true
    })
    .to_string();
    let raw = TOKIO_RUNTIME
        .block_on(rpc_client.rpc_call("get_transactions", Some(params), 2 * 1024 * 1024))
        .map_err(|error| format!("get_transactions failed: {error}"))?;
    let response: GetTransactionsResponse = serde_json::from_str(&raw)
        .map_err(|error| format!("get_transactions response was invalid: {error}"))?;
    Ok(response
        .txs
        .iter()
        .any(|transaction| transaction.tx_hash.eq_ignore_ascii_case(txid)))
}

fn relay_result_json(txid: &str, status: &str) -> *mut c_char {
    let result = serde_json::json!({ "txid": txid, "status": status }).to_string();
    match CString::new(result) {
        Ok(value) => {
            clear_last_error();
            value.into_raw()
        }
        Err(_) => {
            record_error(
                -16,
                "wallet_relay_prepared: result contained interior null bytes",
            );
            ptr::null_mut()
        }
    }
}

/// Relay a previously prepared transaction. Repeating this call is idempotent because the signed
/// blob and therefore its transaction hash are immutable.
#[no_mangle]
pub extern "C" fn wallet_relay_prepared(
    wallet_id: *const c_char,
    node_url: *const c_char,
    prepared_json: *const c_char,
) -> *mut c_char {
    run_while_refresh_stopped(wallet_id, "wallet_relay_prepared", || {
        wallet_relay_prepared_impl(wallet_id, node_url, prepared_json)
    })
}

fn wallet_relay_prepared_impl(
    wallet_id: *const c_char,
    node_url: *const c_char,
    prepared_json: *const c_char,
) -> *mut c_char {
    clear_last_error();
    if wallet_id.is_null() || prepared_json.is_null() {
        record_error(-11, "wallet_relay_prepared: null argument(s)");
        return ptr::null_mut();
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(value) if !value.trim().is_empty() => value.trim(),
        _ => {
            record_error(-10, "wallet_relay_prepared: invalid wallet id");
            return ptr::null_mut();
        }
    };
    let payload_text = match unsafe { CStr::from_ptr(prepared_json) }.to_str() {
        Ok(value) => value,
        Err(_) => {
            record_error(-10, "wallet_relay_prepared: prepared payload was not UTF-8");
            return ptr::null_mut();
        }
    };
    let prepared: PreparedSendPayload = match serde_json::from_str(payload_text) {
        Ok(value) => value,
        Err(error) => {
            record_error(
                -10,
                format!("wallet_relay_prepared: invalid payload ({error})"),
            );
            return ptr::null_mut();
        }
    };
    // This runs before blob decoding or ANY RPC. The refresh registry lock also excludes
    // wallet replacement for the entire relay, so validation and local application agree.
    let binding_result = {
        let store = WALLET_STORE.lock().expect("wallet store poisoned");
        store
            .get(id)
            .ok_or("wallet not opened")
            .and_then(|wallet| validate_prepared_binding(&prepared, wallet))
    };
    if let Err(error) = binding_result {
        record_error(-10, format!("wallet_relay_prepared: {error}"));
        return ptr::null_mut();
    }
    let tx_bytes = match decode_hex(&prepared.signed_tx_hex) {
        Ok(value) => value,
        Err(error) => {
            record_error(-10, format!("wallet_relay_prepared: {error}"));
            return ptr::null_mut();
        }
    };
    let mut reader = tx_bytes.as_slice();
    let transaction = match Transaction::<NotPruned>::read(&mut reader) {
        Ok(value) if reader.is_empty() => value,
        Ok(_) => {
            record_error(
                -10,
                "wallet_relay_prepared: signed blob contained trailing bytes",
            );
            return ptr::null_mut();
        }
        Err(error) => {
            record_error(
                -10,
                format!("wallet_relay_prepared: invalid transaction ({error})"),
            );
            return ptr::null_mut();
        }
    };
    let actual_txid = hex_lowercase(&transaction.hash());
    if !actual_txid.eq_ignore_ascii_case(prepared.txid.trim()) {
        record_error(
            -10,
            "wallet_relay_prepared: payload txid does not match signed blob",
        );
        return ptr::null_mut();
    }

    let base_url = if node_url.is_null() {
        None
    } else {
        unsafe { CStr::from_ptr(node_url) }
            .to_str()
            .ok()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(str::to_string)
    }
    .or_else(|| std::env::var("MONERO_URL").ok())
    .unwrap_or_else(|| "http://127.0.0.1:18081".to_string());

    if daemon_knows_tx(&base_url, &actual_txid).unwrap_or(false) {
        apply_relayed_tx_local_state(id, &transaction, &prepared, &actual_txid);
        return relay_result_json(&actual_txid, "already_known");
    }

    if let Err(error) = TOKIO_RUNTIME.block_on(broadcast_send_raw_transaction(&base_url, &tx_bytes))
    {
        if daemon_knows_tx(&base_url, &actual_txid).unwrap_or(false) {
            apply_relayed_tx_local_state(id, &transaction, &prepared, &actual_txid);
            return relay_result_json(&actual_txid, "already_known");
        }
        record_error(
            map_rpc_error(error.clone()),
            format!("wallet_relay_prepared: send_raw_transaction failed ({error})"),
        );
        return ptr::null_mut();
    }

    if !apply_relayed_tx_local_state(id, &transaction, &prepared, &actual_txid) {
        record_error(
            -13,
            format!("wallet_relay_prepared: wallet '{id}' not registered"),
        );
        return ptr::null_mut();
    }
    relay_result_json(&actual_txid, "accepted")
}

fn apply_relayed_tx_local_state(
    id: &str,
    transaction: &Transaction<NotPruned>,
    prepared: &PreparedSendPayload,
    actual_txid: &str,
) -> bool {
    let mut store = WALLET_STORE.lock().expect("wallet store poisoned");
    let Some(state) = store.get_mut(id) else {
        return false;
    };

    let mut spent_sum = 0u64;
    for input in transaction.prefix().inputs.iter() {
        let Input::ToKey { key_image, .. } = input else {
            continue;
        };
        if let Some(output) = state
            .tracked_outputs
            .iter_mut()
            .find(|output| output.key_image == key_image.to_bytes())
        {
            if !output.spent {
                mark_tracked_output_spent(output, parse_hex_32(actual_txid));
                spent_sum = spent_sum.saturating_add(output.amount);
            }
        }
    }
    state.total = state.total.saturating_sub(spent_sum);
    state.unlocked = state.unlocked.saturating_sub(spent_sum);

    if !state
        .pending_outgoing
        .iter()
        .any(|entry| entry.txid == actual_txid)
    {
        state.pending_outgoing.push(PendingOutgoingTx {
            txid: actual_txid.to_string(),
            amount: prepared.amount,
            fee: prepared.fee,
            created_at: state.chain_time,
        });
    }
    state
        .tx_ledger
        .entry(actual_txid.to_string())
        .or_insert_with(|| LedgerEntry {
            txid: actual_txid.to_string(),
            direction: "out".to_string(),
            amount: outgoing_ledger_amount(prepared.amount, prepared.fee),
            fee: Some(prepared.fee),
            height: None,
            timestamp: Some(state.chain_time),
            is_pending: true,
            is_coinbase: false,
        });
    true
}

/// Single-destination convenience send (legacy API).
#[no_mangle]
pub extern "C" fn wallet_send(
    wallet_id: *const c_char,
    node_url: *const c_char,
    to_address: *const c_char,
    amount_piconero: u64,
    ring_len: u8,
) -> *mut c_char {
    run_while_refresh_stopped(wallet_id, "wallet_send", || {
        wallet_send_impl(
            wallet_id,
            node_url,
            to_address,
            amount_piconero,
            ring_len,
            false,
        )
    })
}

/// Build and sign a single-destination transaction without broadcasting it.
#[no_mangle]
pub extern "C" fn wallet_prepare_send(
    wallet_id: *const c_char,
    node_url: *const c_char,
    to_address: *const c_char,
    amount_piconero: u64,
    ring_len: u8,
) -> *mut c_char {
    run_while_refresh_stopped(wallet_id, "wallet_prepare_send", || {
        wallet_send_impl(
            wallet_id,
            node_url,
            to_address,
            amount_piconero,
            ring_len,
            true,
        )
    })
}

fn wallet_send_impl(
    wallet_id: *const c_char,
    node_url: *const c_char,
    to_address: *const c_char,
    amount_piconero: u64,
    ring_len: u8,
    prepare_only: bool,
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
    let mut snapshot = {
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

    // Build daemon RPC client (upstream)
    let rpc_client: RpcClient = match TOKIO_RUNTIME.block_on(
        monero_simple_request_rpc::SimpleRequestTransport::new(base_url.clone()),
    ) {
        Ok(d) => d,
        Err(e) => {
            record_error(
                -16,
                format!("wallet_send: failed to connect daemon '{base_url}': {e}"),
            );
            return ptr::null_mut();
        }
    };

    // Daemon height (0-based latest_block_number + 1)
    let daemon_height = match TOKIO_RUNTIME.block_on(rpc_client.latest_block_number()) {
        Ok(n) => n.saturating_add(1) as u64,
        Err(e) => {
            record_error(
                -16,
                format!("wallet_send: failed to query daemon height '{base_url}': {e}"),
            );
            return ptr::null_mut();
        }
    };

    let daemon = DaemonStatus {
        height: daemon_height,
        top_block_timestamp: resolve_daemon_tip_timestamp(&base_url),
    };

    // Construct master keys and view pair
    let master = snapshot.keys.clone();
    let view_pair = match master.to_view_pair() {
        Ok(pair) => pair,
        Err(code) => {
            record_error(code, "wallet_send: failed to construct view pair");
            return ptr::null_mut();
        }
    };

    // Prepare scanner with registered subaddresses.
    //
    // IMPORTANT: For sends we must be able to reconstruct the spend key offset for *any* selected
    // output. Limiting registration to just `gap_limit` can cause us to fail to derive outputs
    // received on higher minor indices (e.g. 0:21), which can manifest as daemon `invalid_input`
    // on broadcast due to an incorrect key image.
    let mut scanner = Scanner::new(view_pair.clone());
    let gap_limit = snapshot.gap_limit.max(1);

    // Register up to the max minor index we actually have outputs for (plus a small cushion),
    // and also respect gap_limit (whichever is larger).
    let max_minor_in_wallet = snapshot
        .tracked_outputs
        .iter()
        .map(|o| o.subaddress_minor)
        .max()
        .unwrap_or(0);
    let register_up_to = gap_limit.max(max_minor_in_wallet.saturating_add(5));

    for minor in 0..=register_up_to {
        if let Some(index) = SubaddressIndex::new(0, minor) {
            scanner.register_subaddress(index);
        }
    }

    // Fee rate (once)
    let max_per_weight = fee_rate_max_per_weight_cap();
    let fee_priority = walletcore_fee_priority();
    let fee_rate: FeeRate =
        match TOKIO_RUNTIME.block_on(rpc_client.fee_rate(fee_priority, max_per_weight)) {
            Ok(fr) => fr,
            Err(e) => {
                let code = match e {
                    FeeError::InterfaceError(inner) => map_rpc_error(inner),
                    _ => -16,
                };
                record_error(code, "wallet_send: fee_rate failed");
                return ptr::null_mut();
            }
        };

    // Change to primary account
    let change = monero_wallet::send::Change::new(view_pair.clone(), None);

    // Ring length normalization (default to 16 when caller passes nonsense)
    let mut rng = OsRng;
    let ring_len_eff: u8 = if ring_len < 2 { 16 } else { ring_len };

    // Bounded auto-retry: only retries when we *actually* quarantine a newly discovered toxic input.
    let max_retries = walletcore_send_retry_max();
    let mut quarantined_this_call: usize = 0;

    for attempt in 0..=max_retries {
        // Always re-pull snapshot after a quarantine so spendable universe changes.
        if attempt > 0 {
            snapshot = {
                let map = WALLET_STORE.lock().expect("wallet store poisoned");
                match map.get(id) {
                    Some(state) => state.clone(),
                    None => {
                        record_error(-13, format!("wallet_send: wallet '{id}' not registered"));
                        return ptr::null_mut();
                    }
                }
            };

            walletcore_log_line(
                id,
                snapshot.network,
                &format!(
                    "🔁 wallet_send auto-retry attempt={} max_retries={} quarantined_this_call={} wallet_id={}",
                    attempt,
                    max_retries,
                    quarantined_this_call,
                    id
                ),
            );
        }

        // Choose spendable outputs (unspent and unlocked), excluding quarantined outpoints.
        let mut spendable = snapshot
            .tracked_outputs
            .iter()
            .cloned()
            .filter(|o| !o.spent && o.is_unlocked(daemon.height, daemon.top_block_timestamp))
            .filter(|o| {
                !snapshot
                    .invalid_input_quarantine
                    .contains(&(o.tx_hash, o.index_in_tx))
            })
            .collect::<Vec<_>>();

        // Preflight: ask daemon whether these key images are already spent (chain or pool).
        //
        // If spend detection is lagging or cache is stale, this prevents constructing/broadcasting
        // a tx which the daemon rejects with `invalid_input`.
        if !spendable.is_empty() {
            let key_images: Vec<[u8; 32]> = spendable.iter().map(|o| o.key_image).collect();
            match rpc_is_key_image_spent(&rpc_client, &key_images) {
                Ok(statuses) => {
                    // quarantine spent ones and exclude them from spendable
                    let mut newly_quarantined: usize = 0;
                    for (o, st) in spendable.iter().zip(statuses.iter()) {
                        if *st != 0 {
                            newly_quarantined += 1;
                            let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
                            if let Some(state) = map.get_mut(id) {
                                state
                                    .invalid_input_quarantine
                                    .insert((o.tx_hash, o.index_in_tx));
                            }
                        }
                    }

                    if newly_quarantined > 0 {
                        // Log which outputs were quarantined by preflight so we can correlate with
                        // later `invalid_input` failures.
                        if walletcore_decoy_probe_enabled() {
                            for (o, st) in spendable.iter().zip(statuses.iter()) {
                                if *st != 0 {
                                    walletcore_log_line(
                                        id,
                                        snapshot.network,
                                        &format!(
                                            "🧪 preflight is_key_image_spent: quarantining wallet_id={} out={} key_image={} spent_status={}",
                                            id,
                                            format!(
                                                "{}:{}",
                                                hex_dump_prefix(&o.tx_hash, 32),
                                                o.index_in_tx
                                            ),
                                            hex_dump_prefix(&o.key_image, 32),
                                            st
                                        ),
                                    );
                                }
                            }
                        }

                        quarantined_this_call =
                            quarantined_this_call.saturating_add(newly_quarantined);
                        // Re-pull snapshot so we use the updated quarantine set, then rebuild spendable list.
                        snapshot = {
                            let map = WALLET_STORE.lock().expect("wallet store poisoned");
                            match map.get(id) {
                                Some(state) => state.clone(),
                                None => {
                                    record_error(
                                        -13,
                                        format!("wallet_send: wallet '{id}' not registered"),
                                    );
                                    return ptr::null_mut();
                                }
                            }
                        };
                        spendable = snapshot
                            .tracked_outputs
                            .iter()
                            .cloned()
                            .filter(|o| {
                                !o.spent && o.is_unlocked(daemon.height, daemon.top_block_timestamp)
                            })
                            .filter(|o| {
                                !snapshot
                                    .invalid_input_quarantine
                                    .contains(&(o.tx_hash, o.index_in_tx))
                            })
                            .collect::<Vec<_>>();
                    }
                }
                Err(e) => {
                    // Don't hard-fail send if daemon doesn't support it; just log for debugging.
                    walletcore_log_line(
                        id,
                        snapshot.network,
                        &format!("🧪 preflight is_key_image_spent unavailable/failed: wallet_id={} err={}", id, e),
                    );
                }
            }
        }

        // Input selection order
        match walletcore_input_select_mode() {
            InputSelectMode::SmallestFirst => spendable.sort_by_key(|o| o.amount),
            InputSelectMode::LargestFirst => spendable.sort_by(|a, b| b.amount.cmp(&a.amount)),
        }

        // Iterative input selection until amount+fee is covered
        let mut selected_tracked: Vec<TrackedOutput> = Vec::new();
        let mut selected_sum: u64 = 0;
        let max_selection_rounds: usize = 24;

        // If we quarantine due to key-image mismatch, we must restart the *outer attempt loop*
        // so we rebuild `snapshot`/`spendable` with the updated quarantine set.
        let mut restart_outer_attempt = false;

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

            // Reconstruct wallet outputs + decoys for current selection
            let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();
            let mut restart_attempt = false;

            // Diagnostics: capture wallet_out-derived KIs for this attempt, aligned to the signer formula.
            // This is used to compare:
            // - tracked KI (from refresh)
            // - reconstructed-output-derived KI (our helper)
            // - signer-aligned KI computed from the reconstructed output
            //
            // NOTE: This must live across selection rounds so it can be logged later even if we rebuild
            // inputs/decoys multiple times before broadcasting.
            let mut diag_reconstructed_signer_kis: Vec<([u8; 32], u64, [u8; 32], [u8; 32])> =
                Vec::new();

            for t in &selected_tracked {
                let block_number = match usize::try_from(t.block_height) {
                    Ok(value) => value,
                    Err(_) => {
                        record_error(-16, "wallet_send: block number conversion overflow");
                        return ptr::null_mut();
                    }
                };
                let scannable = match TOKIO_RUNTIME
                    .block_on(rpc_client.scannable_block_by_number(block_number))
                {
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

                let wallet_out = match outputs.into_iter().find(|wo| {
                    wo.transaction() == t.tx_hash && wo.index_in_transaction() == t.index_in_tx
                }) {
                    Some(wo) => wo,
                    None => {
                        record_error(
                            -16,
                            "wallet_send: failed to reconstruct selected output (not found after scan)",
                        );
                        return ptr::null_mut();
                    }
                };

                // Key image consistency check: ensure the reconstructed output corresponds to the same
                // key image we tracked during refresh. If not, this output is not safely spendable
                // with our current snapshot (reorg/stale cache/subaddress mismatch/etc.).
                //
                // The shared helper is signer-aligned; compute once and compare to tracked.
                let signer_ki = derive_key_image_bytes(
                    &wallet_out,
                    master.spend_scalar,
                    master.view_scalar_ed,
                    t.subaddress_major,
                    t.subaddress_minor,
                );

                // Record for later correlation.
                diag_reconstructed_signer_kis.push((
                    t.tx_hash,
                    t.index_in_tx,
                    signer_ki,
                    signer_ki,
                ));

                if signer_ki != t.key_image {
                    // Real invariant violation: the signer would produce a different key image than what we tracked.
                    // Gated: dumps full key image hex.
                    if walletcore_debug_input_dump_enabled() {
                        walletcore_log_line(
                            id,
                            snapshot.network,
                            &format!(
                                "🧪 key_image_mismatch: quarantining wallet_id={} out={}:{} subaddr={}:{} tracked_key_image={} signer_key_image={}",
                                id,
                                hex_dump_prefix(&t.tx_hash, 32),
                                t.index_in_tx,
                                t.subaddress_major,
                                t.subaddress_minor,
                                hex_dump_prefix(&t.key_image, 32),
                                hex_dump_prefix(&signer_ki, 32)
                            ),
                        );
                    }

                    // Quarantine this outpoint and restart selection so we don't attempt to spend it.
                    {
                        let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
                        if let Some(state) = map.get_mut(id) {
                            state
                                .invalid_input_quarantine
                                .insert((t.tx_hash, t.index_in_tx));
                        }
                    }

                    quarantined_this_call = quarantined_this_call.saturating_add(1);
                    inputs.clear();
                    restart_attempt = true;
                    restart_outer_attempt = true;
                    break;
                }

                let with_decoys = if walletcore_decoy_mode_bin16() {
                    let ring_len_eff: u8 = 16;
                    let daemon_iface = match TOKIO_RUNTIME
                        .block_on(make_bin_decoy_daemon(&base_url))
                    {
                        Ok(d) => d,
                        Err(e) => {
                            let code = map_rpc_error(e.clone());
                            record_error(
                                code,
                                format!(
                                    "wallet_send: failed to construct bin16 decoy daemon for '{base_url}': {e}"
                                ),
                            );
                            return ptr::null_mut();
                        }
                    };

                    match TOKIO_RUNTIME.block_on(monero_wallet::OutputWithDecoys::new(
                        &mut rng,
                        &daemon_iface,
                        ring_len_eff,
                        usize::try_from(daemon.height.saturating_sub(1))
                            .unwrap_or(daemon.height.saturating_sub(1) as usize),
                        wallet_out,
                    )) {
                        Ok(i) => i,
                        Err(err) => {
                            let code = match &err {
                                monero_interface::TransactionsError::InterfaceError(inner) => {
                                    map_rpc_error(inner.clone())
                                }
                                monero_interface::TransactionsError::TransactionNotFound => -16,
                                monero_interface::TransactionsError::PrunedTransaction => -16,
                            };
                            record_error(
                                code,
                                format!("wallet_send: decoy selection failed ({err:?})"),
                            );
                            return ptr::null_mut();
                        }
                    }
                } else {
                    match TOKIO_RUNTIME.block_on(monero_wallet::OutputWithDecoys::new(
                        &mut rng,
                        &rpc_client,
                        ring_len_eff,
                        usize::try_from(daemon.height.saturating_sub(1))
                            .unwrap_or(daemon.height.saturating_sub(1) as usize),
                        wallet_out,
                    )) {
                        Ok(i) => i,
                        Err(err) => {
                            let code = match &err {
                                monero_interface::TransactionsError::InterfaceError(inner) => {
                                    map_rpc_error(inner.clone())
                                }
                                monero_interface::TransactionsError::TransactionNotFound => -16,
                                monero_interface::TransactionsError::PrunedTransaction => -16,
                            };
                            record_error(
                                code,
                                format!("wallet_send: decoy selection failed ({err:?})"),
                            );
                            return ptr::null_mut();
                        }
                    }
                };

                inputs.push(with_decoys);
            }

            if restart_attempt {
                // A key-image mismatch was detected and quarantined.
                // Break out of selection rounds and restart the *outer attempt loop* so we rebuild
                // `snapshot` and `spendable` with the updated quarantine set.
                break;
            }

            // New OVK seed each attempt
            let mut ovk = [0u8; 32];
            rng.fill_bytes(&mut ovk);

            // Build signable tx
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
                    let msg = e.to_string();
                    if msg.contains("not enough funds") {
                        // Add one more input and retry
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
                            break;
                        }
                        if !added_any {
                            record_error(
                                -18,
                                format!(
                                    "wallet_send: insufficient unlocked funds for amount+fee (have {}, need at least {})",
                                    selected_sum, amount_piconero
                                ),
                            );
                            return ptr::null_mut();
                        }
                        continue;
                    }

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
                break;
            }

            // Add more inputs until we cover needed_total, then retry
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

        if restart_outer_attempt {
            // Restart the outer attempt loop. This ensures we re-pull the snapshot and rebuild
            // `spendable` after the quarantine mutation.
            continue;
        }

        // Rebuild inputs one last time for final tx
        //
        // NOTE: Reset signer KI diagnostics for the final build of inputs so the later log block
        // uses values corresponding to the actual attempted broadcast.
        let diag_reconstructed_signer_kis: Vec<([u8; 32], u64, [u8; 32], [u8; 32])> = Vec::new();
        let mut diag_reconstructed_signer_kis = diag_reconstructed_signer_kis;

        let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();
        for t in &selected_tracked {
            let block_number = match usize::try_from(t.block_height) {
                Ok(value) => value,
                Err(_) => {
                    record_error(-16, "wallet_send: block number conversion overflow");
                    return ptr::null_mut();
                }
            };
            let scannable =
                match TOKIO_RUNTIME.block_on(rpc_client.scannable_block_by_number(block_number)) {
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

            let wallet_out = match outputs.into_iter().find(|wo| {
                wo.transaction() == t.tx_hash && wo.index_in_transaction() == t.index_in_tx
            }) {
                Some(wo) => wo,
                None => {
                    record_error(
                        -16,
                        "wallet_send: failed to reconstruct selected output (not found after scan)",
                    );
                    return ptr::null_mut();
                }
            };

            // Populate signer-aligned KI diagnostics for the final broadcast attempt.
            // This allows the later `🧪 ki_diag ...` log block to compare tracked vs derived vs signer KIs
            // for the exact reconstructed outputs used to build inputs/decoys.
            {
                let signer_ki = derive_key_image_bytes(
                    &wallet_out,
                    master.spend_scalar,
                    master.view_scalar_ed,
                    t.subaddress_major,
                    t.subaddress_minor,
                );
                // Store in both slots for compatibility with existing diagnostic consumers.
                diag_reconstructed_signer_kis.push((
                    t.tx_hash,
                    t.index_in_tx,
                    signer_ki,
                    signer_ki,
                ));
            }

            let with_decoys = if walletcore_decoy_mode_bin16() {
                let ring_len_eff: u8 = 16;
                let daemon_iface = match TOKIO_RUNTIME.block_on(make_bin_decoy_daemon(&base_url)) {
                    Ok(d) => d,
                    Err(e) => {
                        let code = map_rpc_error(e.clone());
                        record_error(
                            code,
                            format!(
                                "wallet_send: failed to construct bin16 decoy daemon for '{base_url}': {e}"
                            ),
                        );
                        return ptr::null_mut();
                    }
                };

                match TOKIO_RUNTIME.block_on(monero_wallet::OutputWithDecoys::new(
                    &mut rng,
                    &daemon_iface,
                    ring_len_eff,
                    usize::try_from(daemon.height.saturating_sub(1))
                        .unwrap_or(daemon.height.saturating_sub(1) as usize),
                    wallet_out,
                )) {
                    Ok(i) => i,
                    Err(err) => {
                        let code = match &err {
                            monero_interface::TransactionsError::InterfaceError(inner) => {
                                map_rpc_error(inner.clone())
                            }
                            monero_interface::TransactionsError::TransactionNotFound => -16,
                            monero_interface::TransactionsError::PrunedTransaction => -16,
                        };
                        record_error(
                            code,
                            format!("wallet_send: decoy selection failed ({err:?})"),
                        );
                        return ptr::null_mut();
                    }
                }
            } else {
                match TOKIO_RUNTIME.block_on(monero_wallet::OutputWithDecoys::new(
                    &mut rng,
                    &rpc_client,
                    ring_len_eff,
                    usize::try_from(daemon.height.saturating_sub(1))
                        .unwrap_or(daemon.height.saturating_sub(1) as usize),
                    wallet_out,
                )) {
                    Ok(i) => i,
                    Err(err) => {
                        let code = match &err {
                            monero_interface::TransactionsError::InterfaceError(inner) => {
                                map_rpc_error(inner.clone())
                            }
                            monero_interface::TransactionsError::TransactionNotFound => -16,
                            monero_interface::TransactionsError::PrunedTransaction => -16,
                        };
                        record_error(
                            code,
                            format!("wallet_send: decoy selection failed ({err:?})"),
                        );
                        return ptr::null_mut();
                    }
                }
            };

            inputs.push(with_decoys);
        }

        // New OVK seed
        let mut ovk = [0u8; 32];
        rng.fill_bytes(&mut ovk);

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

        if prepare_only {
            let tx_blob = tx.serialize();
            let txid = hex_lowercase(&tx.hash());
            let result_json = match serde_json::to_string(&serde_json::json!({
                "txid": txid,
                "amount": amount_piconero,
                "fee": fee_piconero,
                "wallet_binding": wallet_cache_binding(&snapshot),
                "signed_tx_hex": hex_lowercase(&tx_blob)
            })) {
                Ok(s) => s,
                Err(err) => {
                    record_error(
                        -16,
                        format!("wallet_prepare_send: result JSON serialization failed ({err})"),
                    );
                    return ptr::null_mut();
                }
            };

            return match CString::new(result_json) {
                Ok(cstr) => {
                    clear_last_error();
                    cstr.into_raw()
                }
                Err(_) => {
                    record_error(
                        -16,
                        "wallet_prepare_send: result JSON contained interior null bytes",
                    );
                    ptr::null_mut()
                }
            };
        }

        // Broadcast via /send_raw_transaction
        let tx_blob = tx.serialize();
        if let Err(err) =
            TOKIO_RUNTIME.block_on(broadcast_send_raw_transaction(&base_url, &tx_blob))
        {
            let code = map_rpc_error(err.clone());
            let msg = format!("wallet_send: send_raw_transaction failed ({err})");
            let err_text = format!("{err}");

            // If the daemon reports invalid_input or double_spend, dump ring/key-image invariants
            // to help diagnose issues like duplicate key images, duplicate ring members, or malformed rings.
            if walletcore_decoy_probe_enabled()
                && (is_invalid_input_send_raw_tx_error(&err_text)
                    || crate::is_double_spend_send_raw_tx_error(&err_text))
            {
                // Extract key images from tx prefix inputs
                let mut key_images_hex: Vec<String> = Vec::new();
                let mut key_images_set: HashSet<String> = HashSet::new();
                let mut dup_key_images: Vec<String> = Vec::new();

                // Note: `tx.prefix().inputs` contains `Input::ToKey { key_offsets, key_image, .. }`
                // where `key_offsets` are relative offsets (Monero encoding).
                for input in tx.prefix().inputs.iter() {
                    if let monero_wallet::transaction::Input::ToKey {
                        key_offsets,
                        key_image,
                        ..
                    } = input
                    {
                        let ki_hex = hex_dump_prefix(&key_image.to_bytes(), 32).replace(' ', "");
                        if !key_images_set.insert(ki_hex.clone()) {
                            dup_key_images.push(ki_hex.clone());
                        }
                        key_images_hex.push(ki_hex.clone());

                        // Check for duplicate absolute ring members (after converting relative offsets)
                        let mut abs: Vec<u64> = Vec::with_capacity(key_offsets.len());
                        let mut cur: u64 = 0;
                        for off in key_offsets {
                            cur = cur.saturating_add(*off);
                            abs.push(cur);
                        }
                        let mut seen: HashSet<u64> = HashSet::new();
                        let mut dup_members: Vec<u64> = Vec::new();
                        for a in &abs {
                            if !seen.insert(*a) {
                                dup_members.push(*a);
                            }
                        }

                        if !dup_members.is_empty() {
                            walletcore_log_line(
                                id,
                                snapshot.network,
                                &format!(
                                    "🧪 ring_sanity: duplicate ring members detected wallet_id={} key_image={} dup_members={:?} ring_len={} first_members={:?}",
                                    id,
                                    ki_hex,
                                    dup_members,
                                    abs.len(),
                                    abs.iter().take(8).copied().collect::<Vec<u64>>()
                                ),
                            );
                        }
                    }
                }

                if !dup_key_images.is_empty() {
                    walletcore_log_line(
                        id,
                        snapshot.network,
                        &format!(
                            "🧪 ring_sanity: duplicate key images detected wallet_id={} dup_key_images={:?}",
                            id,
                            dup_key_images
                        ),
                    );
                }

                walletcore_log_line(
                    id,
                    snapshot.network,
                    &format!(
                        "🧪 ring_sanity: tx_inputs={} key_images_count={} (hex, no-spaces) key_images_prefix={}",
                        tx.prefix().inputs.len(),
                        key_images_hex.len(),
                        key_images_hex.iter().take(8).cloned().collect::<Vec<_>>().join(",")
                    ),
                );
            }

            // Log selected inputs for correlation.
            // Gated: dumps per-output txids + amounts.
            if walletcore_debug_input_dump_enabled() {
                walletcore_log_line(
                    id,
                    snapshot.network,
                    &format!(
                        "🧾 send selected_inputs wallet_id={} selected_count={} selected_sum={} inputs={}",
                        id,
                        selected_tracked.len(),
                        selected_sum,
                        selected_tracked
                            .iter()
                            .map(|o| {
                                format!(
                                    "{}:{}@{}:{}",
                                    hex_lowercase(&o.tx_hash),
                                    o.index_in_tx,
                                    o.block_height,
                                    o.amount
                                )
                            })
                            .collect::<Vec<String>>()
                            .join(",")
                    ),
                );
            }

            // Signer-aligned KI diagnostics: for each selected input, show
            // - tracked KI (refresh)
            // - derived KI (our helper from reconstructed output)
            // - signer KI (computed from reconstructed output exactly like monero-oxide signer)
            //
            // This helps determine whether the mismatch is:
            // - refresh tracking (tracked != signer),
            // - reconstruction/derivation (derived != signer),
            // - or something deeper (none match).
            if walletcore_decoy_probe_enabled() {
                for t in &selected_tracked {
                    let tracked = t.key_image;
                    let mut derived_opt: Option<[u8; 32]> = None;
                    let mut signer_opt: Option<[u8; 32]> = None;

                    for (txh, idx, derived, signer) in diag_reconstructed_signer_kis.iter() {
                        if *txh == t.tx_hash && *idx == t.index_in_tx {
                            derived_opt = Some(*derived);
                            signer_opt = Some(*signer);
                            break;
                        }
                    }

                    walletcore_log_line(
                        id,
                        snapshot.network,
                        &format!(
                            "🧪 ki_diag wallet_id={} out={}:{} tracked_key_image={} derived_key_image={} signer_key_image={}",
                            id,
                            hex_dump_prefix(&t.tx_hash, 32),
                            t.index_in_tx,
                            hex_dump_prefix(&tracked, 32),
                            match derived_opt {
                                Some(v) => hex_dump_prefix(&v, 32),
                                None => "(none)".to_string(),
                            },
                            match signer_opt {
                                Some(v) => hex_dump_prefix(&v, 32),
                                None => "(none)".to_string(),
                            },
                        ),
                    );
                }
            }

            walletcore_debug_dump_tracked_outputs(
                id,
                snapshot.network,
                "send selected_input_dump",
                &selected_tracked,
                daemon.height,
                daemon.top_block_timestamp,
            );

            // If the daemon reports a double spend, proactively check the daemon's view of the
            // tx key images and quarantine any matching *selected inputs* whose key images are
            // spent in chain or pool.
            //
            // IMPORTANT: only quarantine when we have spent evidence (`spent_status` 1/2). If the
            // daemon reports double-spend but `is_key_image_spent` returns all unspent, we should
            // not quarantine random outputs.
            if crate::is_double_spend_send_raw_tx_error(&err_text) {
                // Extract all key images from the signed tx.
                let mut tx_key_images: Vec<[u8; 32]> = Vec::new();
                for input in tx.prefix().inputs.iter() {
                    if let monero_wallet::transaction::Input::ToKey { key_image, .. } = input {
                        tx_key_images.push(key_image.to_bytes());
                    }
                }

                match rpc_is_key_image_spent(&rpc_client, &tx_key_images) {
                    Ok(statuses) => {
                        let mut newly_quarantined: usize = 0;

                        // For each spent key image in the tx, quarantine the matching selected output.
                        for (ki, st) in tx_key_images.iter().zip(statuses.iter()) {
                            if *st == 0 {
                                continue;
                            }

                            for o in selected_tracked.iter() {
                                if &o.key_image != ki {
                                    continue;
                                }

                                newly_quarantined += 1;

                                // Quarantine the outpoint.
                                {
                                    let mut map =
                                        WALLET_STORE.lock().expect("wallet store poisoned");
                                    if let Some(state) = map.get_mut(id) {
                                        state
                                            .invalid_input_quarantine
                                            .insert((o.tx_hash, o.index_in_tx));
                                        // Also mark as spent if the daemon says it's spent in blockchain.
                                        if *st == 1 {
                                            if let Some(out) =
                                                state.tracked_outputs.iter_mut().find(|x| {
                                                    x.tx_hash == o.tx_hash
                                                        && x.index_in_tx == o.index_in_tx
                                                })
                                            {
                                                out.spent = true;
                                            }
                                        }
                                    }
                                }

                                if walletcore_decoy_probe_enabled() {
                                    walletcore_log_line(
                                        id,
                                        snapshot.network,
                                        &format!(
                                            "🧪 double_spend sweep: quarantining wallet_id={} out={}:{} key_image={} spent_status={}",
                                            id,
                                            hex_dump_prefix(&o.tx_hash, 32),
                                            o.index_in_tx,
                                            hex_dump_prefix(&o.key_image, 32),
                                            st
                                        ),
                                    );
                                }
                            }
                        }

                        if newly_quarantined > 0 {
                            quarantined_this_call =
                                quarantined_this_call.saturating_add(newly_quarantined);
                        } else {
                            // Important diagnostic: if we observed spent key images for this tx but none
                            // matched our selected inputs, we cannot quarantine and will likely loop.
                            // Log this even when probe is off, since it's a correctness signal.
                            let any_spent = statuses.iter().any(|st| *st != 0);
                            if any_spent {
                                walletcore_log_line(
                                    id,
                                    snapshot.network,
                                    &format!(
                                        "🧪 double_spend sweep: spent key images had no match in selected_tracked (selected_inputs={} tx_inputs={}) wallet_id={}",
                                        selected_tracked.len(),
                                        tx_key_images.len(),
                                        id
                                    ),
                                );
                            } else if walletcore_decoy_probe_enabled() {
                                walletcore_log_line(
                                    id,
                                    snapshot.network,
                                    &format!(
                                        "🧪 double_spend sweep: daemon reported double_spend but is_key_image_spent returned all unspent (tx_inputs={}) wallet_id={}",
                                        tx_key_images.len(),
                                        id
                                    ),
                                );
                            }
                        }
                    }
                    Err(e) => {
                        if walletcore_decoy_probe_enabled() {
                            walletcore_log_line(
                                id,
                                snapshot.network,
                                &format!(
                                    "🧪 double_spend sweep is_key_image_spent failed: wallet_id={} err={}",
                                    id, e
                                ),
                            );
                        }
                    }
                }
            }

            // Optional: bisect/quarantine when the daemon signals either:
            // - invalid_input=true
            // - double_spend=true
            //
            // We explicitly do NOT bisect on generic `status=Failed` as it can quarantine good inputs.
            //
            // IMPORTANT:
            // - Bisect is now *opt-in only* via `WALLETCORE_SEND_BISECT=1`.
            // - If we already quarantined any selected inputs based on direct spent evidence (wallet2-like),
            //   do NOT run bisect in the same failure path. Bisect can otherwise "hunt" and quarantine
            //   unrelated good outputs, making state worse.
            //
            // NOTE: Classify based on the daemon error text itself (`err_text`), not the wrapper `msg`.
            let should_bisect = walletcore_send_bisect_enabled()
                && std::env::var("WALLETCORE_SEND_BISECT")
                    .ok()
                    .map(|s| s == "1" || s.eq_ignore_ascii_case("true"))
                    .unwrap_or(false)
                && quarantined_this_call == 0
                && !crate::is_http_client_failed_error(&err_text)
                && (is_invalid_input_send_raw_tx_error(&err_text)
                    || crate::is_double_spend_send_raw_tx_error(&err_text));

            // If we're not bisecting (or can't quarantine), just return the error.
            if !should_bisect {
                record_error(code, msg);
                return ptr::null_mut();
            }

            let start = Instant::now();
            let budget = Duration::from_secs(20);

            let mut all = selected_tracked.clone();
            all.sort_by(|a, b| b.amount.cmp(&a.amount));

            let mut try_subset = |subset: &[TrackedOutput]| -> Result<(), String> {
                let mut rng = OsRng;
                let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();

                for t in subset {
                    let block_number = usize::try_from(t.block_height)
                        .map_err(|_| "block number conversion overflow".to_string())?;
                    let scannable = TOKIO_RUNTIME
                        .block_on(rpc_client.scannable_block_by_number(block_number))
                        .map_err(|e| {
                            format!(
                                "RPC block fetch failed at height {} ({})",
                                t.block_height, e
                            )
                        })?;
                    let outputs = scanner
                        .scan(scannable)
                        .map_err(|_| format!("scanner failed at height {}", t.block_height))?
                        .ignore_additional_timelock();
                    let wallet_out = outputs
                        .into_iter()
                        .find(|wo| {
                            wo.transaction() == t.tx_hash
                                && wo.index_in_transaction() == t.index_in_tx
                        })
                        .ok_or_else(|| "failed to reconstruct selected output".to_string())?;

                    let with_decoys = if walletcore_decoy_mode_bin16() {
                        let ring_len_eff: u8 = 16;
                        let daemon_iface = TOKIO_RUNTIME
                            .block_on(make_bin_decoy_daemon(&base_url))
                            .map_err(|e| {
                                format!("failed to construct bin16 decoy daemon ({})", e)
                            })?;
                        TOKIO_RUNTIME
                            .block_on(monero_wallet::OutputWithDecoys::new(
                                &mut rng,
                                &daemon_iface,
                                ring_len_eff,
                                usize::try_from(daemon.height.saturating_sub(1))
                                    .unwrap_or(daemon.height.saturating_sub(1) as usize),
                                wallet_out,
                            ))
                            .map_err(|e| format!("decoy selection failed ({:?})", e))?
                    } else {
                        TOKIO_RUNTIME
                            .block_on(monero_wallet::OutputWithDecoys::new(
                                &mut rng,
                                &rpc_client,
                                ring_len_eff,
                                usize::try_from(daemon.height.saturating_sub(1))
                                    .unwrap_or(daemon.height.saturating_sub(1) as usize),
                                wallet_out,
                            ))
                            .map_err(|e| format!("decoy selection failed ({:?})", e))?
                    };

                    inputs.push(with_decoys);
                }

                let mut ovk = [0u8; 32];
                rng.fill_bytes(&mut ovk);

                let intent = monero_wallet::send::SignableTransaction::new(
                    monero_wallet::ringct::RctType::ClsagBulletproofPlus,
                    Zeroizing::new(ovk),
                    inputs,
                    vec![(recipient_address, amount_piconero)],
                    change.clone(),
                    Vec::new(),
                    fee_rate,
                )
                .map_err(|e| format!("construct failed ({e})"))?;

                let spend_key =
                    Zeroizing::new(monero_wallet::ed25519::Scalar::from(master.spend_scalar));
                let mut signer_rng = OsRng;
                let tx = intent
                    .sign(&mut signer_rng, &spend_key)
                    .map_err(|e| format!("sign failed ({e})"))?;

                let tx_blob = tx.serialize();
                match TOKIO_RUNTIME.block_on(broadcast_send_raw_transaction(&base_url, &tx_blob)) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        let e_text = format!("{e}");
                        let tag = if is_invalid_input_send_raw_tx_error(&e_text) {
                            "invalid_input"
                        } else if crate::is_double_spend_send_raw_tx_error(&e_text) {
                            "double_spend"
                        } else {
                            "other"
                        };

                        // On double-spend, sweep *all tx input key images* and report what the daemon says.
                        // If any are spent (chain=1 or pool=2), quarantine the *matching selected outputs*.
                        //
                        // IMPORTANT (wallet2-like behavior):
                        // - Always do this sweep on double-spend (not gated on probe mode).
                        // - Treat spent-in-chain (1) and spent-in-pool (2) the same for input selection:
                        //   both must not be selected again.
                        if crate::is_double_spend_send_raw_tx_error(&e_text) {
                            let mut tx_key_images: Vec<[u8; 32]> = Vec::new();
                            for input in tx.prefix().inputs.iter() {
                                if let monero_wallet::transaction::Input::ToKey {
                                    key_image, ..
                                } = input
                                {
                                    tx_key_images.push(key_image.to_bytes());
                                }
                            }

                            match rpc_is_key_image_spent(&rpc_client, &tx_key_images) {
                                Ok(statuses) => {
                                    let mut any_spent = false;

                                    for (ki, st) in tx_key_images.iter().zip(statuses.iter()) {
                                        if *st == 0 {
                                            continue;
                                        }
                                        any_spent = true;

                                        walletcore_log_line(
                                            id,
                                            snapshot.network,
                                            &format!(
                                                "🧪 try_subset double_spend sweep: key_image={} spent_status={}",
                                                hex_dump_prefix(ki, 32),
                                                st
                                            ),
                                        );

                                        // Quarantine matching outputs in the *current selection* (the attempted tx inputs),
                                        // not just the bisect subset.
                                        //
                                        // Rationale: bisect subsets are a debugging tool and may not include all
                                        // inputs of the failing tx in later rounds; we still must quarantine the
                                        // actually-spent inputs to converge.
                                        let mut matched_any = false;
                                        for o in selected_tracked.iter() {
                                            if &o.key_image != ki {
                                                continue;
                                            }
                                            matched_any = true;

                                            let mut map =
                                                WALLET_STORE.lock().expect("wallet store poisoned");
                                            if let Some(state) = map.get_mut(id) {
                                                state
                                                    .invalid_input_quarantine
                                                    .insert((o.tx_hash, o.index_in_tx));

                                                // If daemon confirms spent-in-chain, also mark as spent so refresh/spend-detect
                                                // state converges quickly.
                                                if *st == 1 {
                                                    if let Some(out) =
                                                        state.tracked_outputs.iter_mut().find(|x| {
                                                            x.tx_hash == o.tx_hash
                                                                && x.index_in_tx == o.index_in_tx
                                                        })
                                                    {
                                                        out.spent = true;
                                                    }
                                                }
                                            }

                                            walletcore_log_line(
                                                id,
                                                snapshot.network,
                                                &format!(
                                                    "🧪 try_subset double_spend sweep: quarantined_out wallet_id={} out={}:{} key_image={} spent_status={}",
                                                    id,
                                                    hex_dump_prefix(&o.tx_hash, 32),
                                                    o.index_in_tx,
                                                    hex_dump_prefix(&o.key_image, 32),
                                                    st
                                                ),
                                            );
                                        }

                                        if !matched_any {
                                            walletcore_log_line(
                                                id,
                                                snapshot.network,
                                                &format!(
                                                    "🧪 try_subset double_spend sweep: spent key_image had no match in selected_tracked set (selected_inputs={}) key_image={} spent_status={}",
                                                    selected_tracked.len(),
                                                    hex_dump_prefix(ki, 32),
                                                    st
                                                ),
                                            );
                                        }
                                    }

                                    if !any_spent {
                                        walletcore_log_line(
                                            id,
                                            snapshot.network,
                                            &format!(
                                                "🧪 try_subset double_spend sweep: daemon reported double_spend but is_key_image_spent returned all unspent (tx_inputs={})",
                                                tx_key_images.len()
                                            ),
                                        );
                                    }
                                }
                                Err(err) => {
                                    walletcore_log_line(
                                        id,
                                        snapshot.network,
                                        &format!(
                                            "🧪 try_subset double_spend sweep is_key_image_spent failed: err={}",
                                            err
                                        ),
                                    );
                                }
                            }
                        }

                        Err(format!("broadcast failed ({}): {}", tag, e))
                    }
                }
            };

            let mut lo = 0usize;
            let mut hi = all.len();
            let mut last_err: Option<String> = None;

            while start.elapsed() < budget && lo + 1 < hi {
                let mid = (lo + hi) / 2;
                let subset = &all[..mid];
                match try_subset(subset) {
                    Ok(()) => {
                        lo = mid.max(lo + 1);
                    }
                    Err(e) => {
                        let is_signal = e.contains("broadcast failed (invalid_input):")
                            || e.contains("broadcast failed (double_spend):");
                        if is_signal {
                            last_err = Some(e);
                            hi = mid.max(lo + 1);
                        } else {
                            lo = mid.max(lo + 1);
                        }
                    }
                }
            }

            let mut newly_inserted = false;
            let mut quarantined_out: Option<(String, u32)> = None;

            if hi <= all.len() && hi > 0 {
                let bad = &all[hi - 1];
                walletcore_log_line(
                    id,
                    snapshot.network,
                    &format!(
                        "🧨 send_bisect: candidate invalid_input output wallet_id={} txid={} index_in_tx={} height={} amount_piconero={} key_image={} err={}",
                        id,
                        hex_dump_prefix(&bad.tx_hash, 32),
                        bad.index_in_tx,
                        bad.block_height,
                        bad.amount,
                        hex_dump_prefix(&bad.key_image, 32),
                        last_err.clone().unwrap_or_else(|| "(none)".to_string())
                    ),
                );

                // Extra probe: check the daemon's view of this candidate key image before quarantining.
                // This helps distinguish "actually spent/in-pool" from "reconstruction mismatch".
                //
                // For double_spend, avoid quarantining unless we have spent evidence (status 1/2).
                let mut candidate_spent_status: Option<u8> = None;
                if walletcore_decoy_probe_enabled() {
                    match rpc_is_key_image_spent(&rpc_client, &[bad.key_image]) {
                        Ok(statuses) => {
                            let st = statuses.get(0).copied().unwrap_or(255);
                            candidate_spent_status = Some(st);
                            walletcore_log_line(
                                id,
                                snapshot.network,
                                &format!(
                                    "🧪 bisect candidate is_key_image_spent: wallet_id={} out={}:{} key_image={} spent_status={}",
                                    id,
                                    hex_dump_prefix(&bad.tx_hash, 32),
                                    bad.index_in_tx,
                                    hex_dump_prefix(&bad.key_image, 32),
                                    st
                                ),
                            );
                        }
                        Err(e) => {
                            walletcore_log_line(
                                id,
                                snapshot.network,
                                &format!(
                                    "🧪 bisect candidate is_key_image_spent failed: wallet_id={} out={}:{} key_image={} err={}",
                                    id,
                                    hex_dump_prefix(&bad.tx_hash, 32),
                                    bad.index_in_tx,
                                    hex_dump_prefix(&bad.key_image, 32),
                                    e
                                ),
                            );
                        }
                    }
                }

                // Gate quarantine for double_spend: only quarantine when the daemon also reports
                // the candidate key image as spent (in chain or pool). Otherwise, we risk
                // quarantining valid inputs due to inconsistent daemon views.
                //
                // NOTE: Some errors may be tagged `invalid_input` yet still include `double_spend=true`.
                // Treat any double-spend tag as requiring spent evidence.
                let last_err_is_double_spend = last_err.as_deref().is_some_and(|e| {
                    is_double_spend_tagged_broadcast_error(e)
                        || crate::is_double_spend_send_raw_tx_error(e)
                });
                let allow_quarantine = if last_err_is_double_spend {
                    matches!(candidate_spent_status, Some(1) | Some(2))
                } else {
                    true
                };

                if allow_quarantine {
                    if let Ok(mut map) = WALLET_STORE.lock() {
                        if let Some(state) = map.get_mut(id) {
                            let key = (bad.tx_hash, bad.index_in_tx);
                            newly_inserted = state.invalid_input_quarantine.insert(key);
                            quarantined_out =
                                Some((hex_lowercase(&bad.tx_hash), bad.index_in_tx as u32));
                        }
                    }
                } else if walletcore_decoy_probe_enabled() {
                    walletcore_log_line(
                        id,
                        snapshot.network,
                        &format!(
                            "🧪 double_spend bisect: not quarantining candidate (no spent evidence) wallet_id={} out={}:{} key_image={} spent_status={:?} err={}",
                            id,
                            hex_dump_prefix(&bad.tx_hash, 32),
                            bad.index_in_tx,
                            hex_dump_prefix(&bad.key_image, 32),
                            candidate_spent_status,
                            last_err.clone().unwrap_or_else(|| "(none)".to_string())
                        ),
                    );
                }

                // Keep quarantine logging inside the allow_quarantine branch so it doesn't reference
                // `state` out of scope and doesn't run when we chose not to quarantine.
                if allow_quarantine {
                    if let Ok(map) = WALLET_STORE.lock() {
                        if let Some(state) = map.get(id) {
                            walletcore_log_line(
                                id,
                                snapshot.network,
                                &format!(
                                    "🧾 invalid_input_quarantine {} wallet_id={} out={} quarantine_size={}",
                                    if newly_inserted {
                                        "added"
                                    } else {
                                        "already_present"
                                    },
                                    id,
                                    format!("{}:{}", hex_lowercase(&bad.tx_hash), bad.index_in_tx),
                                    state.invalid_input_quarantine.len()
                                ),
                            );
                        }
                    }
                }
            }

            if newly_inserted && attempt < max_retries {
                quarantined_this_call = quarantined_this_call.saturating_add(1);
                if let Some((txid_hex, idx)) = quarantined_out {
                    walletcore_log_line(
                        id,
                        snapshot.network,
                        &format!(
                            "🔁 wallet_send auto-retry scheduling next attempt wallet_id={} quarantined_out={}:{} attempt={} max_retries={}",
                            id,
                            txid_hex,
                            idx,
                            attempt,
                            max_retries
                        ),
                    );
                }
                continue;
            }

            // No quarantine happened, or retries exhausted -> return the original broadcast error.
            if newly_inserted && attempt >= max_retries {
                record_error(
                    code,
                    format!(
                        "wallet_send: send_raw_transaction failed; quarantined {}; retries exhausted ({}/{}) ({})",
                        quarantined_this_call,
                        attempt,
                        max_retries,
                        err
                    ),
                );
                return ptr::null_mut();
            }

            record_error(code, msg);
            return ptr::null_mut();
        }

        // Broadcast succeeded -> update store and return success.
        let tx_hash = tx.hash();
        let hex = hex_lowercase(&tx_hash);
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
                        mark_tracked_output_spent(o, Some(tx_hash));
                    }
                }
                state.total = state.total.saturating_sub(spent_sum);
                state.unlocked = state.unlocked.saturating_sub(spent_sum);
            }
        }

        {
            let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
            if let Some(state) = map.get_mut(id) {
                state.pending_outgoing.push(PendingOutgoingTx {
                    txid: hex.clone(),
                    amount: amount_piconero,
                    fee: fee_piconero,
                    created_at: state.chain_time,
                });

                if walletcore_debug_input_dump_enabled() {
                    walletcore_log_line(
                        id,
                        snapshot.network,
                        &format!(
                            "🧾 pending_outgoing recorded wallet_id={} txid={} amount_piconero={} fee_piconero={} created_at={} pending_outgoing_count={}",
                            id,
                            hex,
                            amount_piconero,
                            fee_piconero,
                            state.chain_time,
                            state.pending_outgoing.len()
                        ),
                    );
                }

                state.tx_ledger.insert(
                    hex.clone(),
                    LedgerEntry {
                        txid: hex.clone(),
                        direction: "out".to_string(),
                        amount: outgoing_ledger_amount(amount_piconero, fee_piconero),
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

        return match CString::new(result_json) {
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
        };
    }

    record_error(
        -16,
        format!(
            "wallet_send: failed after retries (max_retries={})",
            walletcore_send_retry_max()
        ),
    );
    ptr::null_mut()
}

/// Multi-destination send with optional input filtering.
#[no_mangle]
pub extern "C" fn wallet_send_with_filter(
    wallet_id: *const c_char,
    node_url: *const c_char,
    destinations_json: *const c_char,
    filter_json: *const c_char,
    ring_len: u8,
) -> *mut c_char {
    run_while_refresh_stopped(wallet_id, "wallet_send_with_filter", || {
        wallet_send_with_filter_impl(
            wallet_id,
            node_url,
            destinations_json,
            filter_json,
            ring_len,
            false,
        )
    })
}

/// Build and sign a filtered multi-destination transaction without broadcasting it.
/// Returns the same prepare payload shape as `wallet_prepare_send`.
#[no_mangle]
pub extern "C" fn wallet_prepare_send_with_filter(
    wallet_id: *const c_char,
    node_url: *const c_char,
    destinations_json: *const c_char,
    filter_json: *const c_char,
    ring_len: u8,
) -> *mut c_char {
    run_while_refresh_stopped(wallet_id, "wallet_prepare_send_with_filter", || {
        wallet_send_with_filter_impl(
            wallet_id,
            node_url,
            destinations_json,
            filter_json,
            ring_len,
            true,
        )
    })
}

fn wallet_send_with_filter_impl(
    wallet_id: *const c_char,
    node_url: *const c_char,
    destinations_json: *const c_char,
    filter_json: *const c_char,
    ring_len: u8,
    prepare_only: bool,
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

    let rpc_client: RpcClient = match TOKIO_RUNTIME.block_on(
        monero_simple_request_rpc::SimpleRequestTransport::new(base_url.clone()),
    ) {
        Ok(d) => d,
        Err(e) => {
            record_error(
                -16,
                format!("wallet_send_with_filter: failed to connect daemon '{base_url}': {e}"),
            );
            return ptr::null_mut();
        }
    };

    let daemon_height = match TOKIO_RUNTIME.block_on(rpc_client.latest_block_number()) {
        Ok(n) => n.saturating_add(1) as u64,
        Err(e) => {
            record_error(
                -16,
                format!("wallet_send_with_filter: failed to query daemon height '{base_url}': {e}"),
            );
            return ptr::null_mut();
        }
    };

    let daemon = DaemonStatus {
        height: daemon_height,
        top_block_timestamp: resolve_daemon_tip_timestamp(&base_url),
    };

    let master = snapshot.keys.clone();
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

    // Prepare scanner with registered subaddresses.
    //
    // Same rationale as `wallet_send`: we must be able to reconstruct any selected output
    // even if it was received on a higher subaddress minor index than `gap_limit`.
    let mut scanner = Scanner::new(view_pair.clone());
    let gap_limit = snapshot.gap_limit.max(1);

    let max_minor_in_wallet = snapshot
        .tracked_outputs
        .iter()
        .map(|o| o.subaddress_minor)
        .max()
        .unwrap_or(0);
    let register_up_to = gap_limit.max(max_minor_in_wallet.saturating_add(5));

    for minor in 0..=register_up_to {
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
        .filter(|o| {
            !snapshot
                .invalid_input_quarantine
                .contains(&(o.tx_hash, o.index_in_tx))
        })
        .collect();

    if let Some(f) = &filter {
        if let Some(minor) = f.subaddress_minor {
            spendable.retain(|o| o.subaddress_major == 0 && o.subaddress_minor == minor);
        }
    }

    match walletcore_input_select_mode() {
        InputSelectMode::SmallestFirst => spendable.sort_by_key(|o| o.amount),
        InputSelectMode::LargestFirst => spendable.sort_by(|a, b| b.amount.cmp(&a.amount)),
    }

    // Fee rate once
    let max_per_weight = fee_rate_max_per_weight_cap();
    let fee_priority = walletcore_fee_priority();
    let fee_rate: FeeRate =
        match TOKIO_RUNTIME.block_on(rpc_client.fee_rate(fee_priority, max_per_weight)) {
            Ok(fr) => fr,
            Err(e) => {
                let code = match e {
                    FeeError::InterfaceError(inner) => map_rpc_error(inner),
                    _ => -16,
                };
                record_error(code, "wallet_send_with_filter: fee_rate failed");
                return ptr::null_mut();
            }
        };

    let change = monero_wallet::send::Change::new(view_pair.clone(), None);

    let mut rng = OsRng;
    let ring_len_eff: u8 = if ring_len < 2 { 16 } else { ring_len };

    let mut selected: Vec<TrackedOutput> = Vec::new();
    let mut selected_sum: u64 = 0;

    let max_selection_rounds: usize = 24;

    for _round in 0..max_selection_rounds {
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

        let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();
        let mut restart_round = false;
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
            let scannable =
                match TOKIO_RUNTIME.block_on(rpc_client.scannable_block_by_number(block_number)) {
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
            let wallet_out = match outputs.into_iter().find(|wo| {
                wo.transaction() == t.tx_hash && wo.index_in_transaction() == t.index_in_tx
            }) {
                Some(wo) => wo,
                None => {
                    record_error(-16, "wallet_send: failed to reconstruct selected output");
                    return ptr::null_mut();
                }
            };

            // Key image consistency check: ensure the reconstructed output corresponds to the same
            // key image we tracked during refresh. If not, this output is not safely spendable
            // with our current snapshot (reorg/stale cache/subaddress mismatch/etc.).
            //
            // IMPORTANT:
            // Use the shared, signer-aligned key image helper and compare it directly against the tracked KI.
            let signer_ki = derive_key_image_bytes(
                &wallet_out,
                master.spend_scalar,
                master.view_scalar_ed,
                t.subaddress_major,
                t.subaddress_minor,
            );
            if signer_ki != t.key_image {
                // Diagnostic line for this invariant violation.
                // Gated: dumps full key image hex.
                if walletcore_debug_input_dump_enabled() {
                    walletcore_log_line(
                        id,
                        snapshot.network,
                        &format!(
                            "🧪 key_image_mismatch: quarantining wallet_id={} out={}:{} subaddr={}:{} tracked_key_image={} signer_key_image={}",
                            id,
                            hex_dump_prefix(&t.tx_hash, 32),
                            t.index_in_tx,
                            t.subaddress_major,
                            t.subaddress_minor,
                            hex_dump_prefix(&t.key_image, 32),
                            hex_dump_prefix(&signer_ki, 32)
                        ),
                    );
                }

                // Quarantine this outpoint and restart selection so we don't attempt to spend it.
                {
                    let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
                    if let Some(state) = map.get_mut(id) {
                        state
                            .invalid_input_quarantine
                            .insert((t.tx_hash, t.index_in_tx));
                    }
                }

                // Restart selection rounds in this send_with_filter attempt.
                // We cannot mutate `selected` while iterating it, so set a flag and break.
                inputs.clear();
                restart_round = true;
                break;
            }

            let with_decoys = if walletcore_decoy_mode_bin16() {
                let ring_len_eff: u8 = 16;
                let daemon_iface = match TOKIO_RUNTIME.block_on(make_bin_decoy_daemon(&base_url)) {
                    Ok(d) => d,
                    Err(e) => {
                        let code = map_rpc_error(e.clone());
                        record_error(
                            code,
                            format!(
                                "wallet_send_with_filter: failed to construct bin16 decoy daemon for '{base_url}': {e}"
                            ),
                        );
                        return ptr::null_mut();
                    }
                };

                match TOKIO_RUNTIME.block_on(monero_wallet::OutputWithDecoys::new(
                    &mut rng,
                    &daemon_iface,
                    ring_len_eff,
                    usize::try_from(daemon.height.saturating_sub(1))
                        .unwrap_or(daemon.height.saturating_sub(1) as usize),
                    wallet_out,
                )) {
                    Ok(i) => i,
                    Err(err) => {
                        let code = match &err {
                            monero_interface::TransactionsError::InterfaceError(inner) => {
                                map_rpc_error(inner.clone())
                            }
                            monero_interface::TransactionsError::TransactionNotFound => -16,
                            monero_interface::TransactionsError::PrunedTransaction => -16,
                        };
                        record_error(
                            code,
                            format!("wallet_send_with_filter: decoy selection failed ({err:?})"),
                        );
                        return ptr::null_mut();
                    }
                }
            } else {
                match TOKIO_RUNTIME.block_on(monero_wallet::OutputWithDecoys::new(
                    &mut rng,
                    &rpc_client,
                    ring_len_eff,
                    usize::try_from(daemon.height.saturating_sub(1))
                        .unwrap_or(daemon.height.saturating_sub(1) as usize),
                    wallet_out,
                )) {
                    Ok(i) => i,
                    Err(err) => {
                        let code = match &err {
                            monero_interface::TransactionsError::InterfaceError(inner) => {
                                map_rpc_error(inner.clone())
                            }
                            monero_interface::TransactionsError::TransactionNotFound => -16,
                            monero_interface::TransactionsError::PrunedTransaction => -16,
                        };
                        record_error(
                            code,
                            format!("wallet_send_with_filter: decoy selection failed ({err:?})"),
                        );
                        return ptr::null_mut();
                    }
                }
            };

            inputs.push(with_decoys);
        }

        if restart_round {
            selected.clear();
            selected_sum = 0;
            continue;
        }

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
                let msg = e.to_string();
                if msg.contains("not enough funds") {
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
                        break;
                    }

                    if !added_any {
                        record_error(
                            -18,
                            format!(
                                "wallet_send_with_filter: insufficient unlocked funds for amount+fee (have {}, need at least {})",
                                selected_sum, total_needed
                            ),
                        );
                        return ptr::null_mut();
                    }

                    continue;
                }

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
            break;
        }

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

    // Rebuild final tx for signing/broadcast
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
        let scannable =
            match TOKIO_RUNTIME.block_on(rpc_client.scannable_block_by_number(block_number)) {
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
        let wallet_out = match outputs
            .into_iter()
            .find(|wo| wo.transaction() == t.tx_hash && wo.index_in_transaction() == t.index_in_tx)
        {
            Some(wo) => wo,
            None => {
                record_error(
                    -16,
                    "wallet_send_with_filter: failed to reconstruct selected output",
                );
                return ptr::null_mut();
            }
        };

        let with_decoys = if walletcore_decoy_mode_bin16() {
            let ring_len_eff: u8 = 16;
            let daemon_iface = match TOKIO_RUNTIME.block_on(make_bin_decoy_daemon(&base_url)) {
                Ok(d) => d,
                Err(e) => {
                    let code = map_rpc_error(e.clone());
                    record_error(
                        code,
                        format!(
                            "wallet_send_with_filter: failed to construct bin16 decoy daemon for '{base_url}': {e}"
                        ),
                    );
                    return ptr::null_mut();
                }
            };

            match TOKIO_RUNTIME.block_on(monero_wallet::OutputWithDecoys::new(
                &mut rng,
                &daemon_iface,
                ring_len_eff,
                usize::try_from(daemon.height).unwrap_or(daemon.height as usize),
                wallet_out,
            )) {
                Ok(i) => i,
                Err(err) => {
                    let code = match &err {
                        monero_interface::TransactionsError::InterfaceError(inner) => {
                            map_rpc_error(inner.clone())
                        }
                        monero_interface::TransactionsError::TransactionNotFound => -16,
                        monero_interface::TransactionsError::PrunedTransaction => -16,
                    };
                    record_error(
                        code,
                        format!("wallet_send_with_filter: decoy selection failed ({err:?})"),
                    );
                    return ptr::null_mut();
                }
            }
        } else {
            match TOKIO_RUNTIME.block_on(monero_wallet::OutputWithDecoys::new(
                &mut rng,
                &rpc_client,
                ring_len_eff,
                usize::try_from(daemon.height).unwrap_or(daemon.height as usize),
                wallet_out,
            )) {
                Ok(i) => i,
                Err(err) => {
                    let code = match &err {
                        monero_interface::TransactionsError::InterfaceError(inner) => {
                            map_rpc_error(inner.clone())
                        }
                        monero_interface::TransactionsError::TransactionNotFound => -16,
                        monero_interface::TransactionsError::PrunedTransaction => -16,
                    };
                    record_error(
                        code,
                        format!("wallet_send_with_filter: decoy selection failed ({err:?})"),
                    );
                    return ptr::null_mut();
                }
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

    if prepare_only {
        let tx_blob = tx.serialize();
        let txid = hex_lowercase(&tx.hash());
        let result_json = match serde_json::to_string(&serde_json::json!({
            "txid": txid,
            "amount": total_needed,
            "fee": fee_piconero,
            "wallet_binding": wallet_cache_binding(&snapshot),
            "signed_tx_hex": hex_lowercase(&tx_blob)
        })) {
            Ok(s) => s,
            Err(err) => {
                record_error(
                    -16,
                    format!(
                        "wallet_prepare_send_with_filter: result JSON serialization failed ({err})"
                    ),
                );
                return ptr::null_mut();
            }
        };

        return match CString::new(result_json) {
            Ok(cstr) => {
                clear_last_error();
                cstr.into_raw()
            }
            Err(_) => {
                record_error(
                    -16,
                    "wallet_prepare_send_with_filter: result JSON contained interior null bytes",
                );
                ptr::null_mut()
            }
        };
    }

    let tx_blob = tx.serialize();
    if let Err(err) = TOKIO_RUNTIME.block_on(broadcast_send_raw_transaction(&base_url, &tx_blob)) {
        let code = map_rpc_error(err.clone());
        let msg = format!("wallet_send_with_filter: send_raw_transaction failed ({err})");

        // Optional bisect (legacy: only on invalid_input)
        if walletcore_send_bisect_enabled() && is_invalid_input_send_raw_tx_error(&msg) {
            let start = Instant::now();
            let budget = Duration::from_secs(20);

            let mut all = selected.clone();
            all.sort_by(|a, b| b.amount.cmp(&a.amount));

            let mut try_subset = |subset: &[TrackedOutput]| -> Result<(), String> {
                let mut rng = OsRng;
                let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();

                for t in subset {
                    let block_number = usize::try_from(t.block_height)
                        .map_err(|_| "block number conversion overflow".to_string())?;
                    let scannable = TOKIO_RUNTIME
                        .block_on(rpc_client.scannable_block_by_number(block_number))
                        .map_err(|e| {
                            format!(
                                "RPC block fetch failed at height {} ({})",
                                t.block_height, e
                            )
                        })?;
                    let outputs = scanner
                        .scan(scannable)
                        .map_err(|_| format!("scanner failed at height {}", t.block_height))?
                        .ignore_additional_timelock();
                    let wallet_out = outputs
                        .into_iter()
                        .find(|wo| {
                            wo.transaction() == t.tx_hash
                                && wo.index_in_transaction() == t.index_in_tx
                        })
                        .ok_or_else(|| "failed to reconstruct selected output".to_string())?;

                    let with_decoys = if walletcore_decoy_mode_bin16() {
                        let ring_len_eff: u8 = 16;
                        let daemon_iface = TOKIO_RUNTIME
                            .block_on(make_bin_decoy_daemon(&base_url))
                            .map_err(|e| {
                                format!("failed to construct bin16 decoy daemon ({})", e)
                            })?;
                        TOKIO_RUNTIME
                            .block_on(monero_wallet::OutputWithDecoys::new(
                                &mut rng,
                                &daemon_iface,
                                ring_len_eff,
                                usize::try_from(daemon.height).unwrap_or(daemon.height as usize),
                                wallet_out,
                            ))
                            .map_err(|e| format!("decoy selection failed ({:?})", e))?
                    } else {
                        TOKIO_RUNTIME
                            .block_on(monero_wallet::OutputWithDecoys::new(
                                &mut rng,
                                &rpc_client,
                                ring_len_eff,
                                usize::try_from(daemon.height).unwrap_or(daemon.height as usize),
                                wallet_out,
                            ))
                            .map_err(|e| format!("decoy selection failed ({:?})", e))?
                    };

                    inputs.push(with_decoys);
                }

                let mut ovk = [0u8; 32];
                rng.fill_bytes(&mut ovk);

                let intent = monero_wallet::send::SignableTransaction::new(
                    monero_wallet::ringct::RctType::ClsagBulletproofPlus,
                    Zeroizing::new(ovk),
                    inputs,
                    destinations.clone(),
                    change.clone(),
                    Vec::new(),
                    fee_rate,
                )
                .map_err(|e| format!("construct failed ({e})"))?;

                let spend_key =
                    Zeroizing::new(monero_wallet::ed25519::Scalar::from(master.spend_scalar));
                let mut signer_rng = OsRng;
                let tx = intent
                    .sign(&mut signer_rng, &spend_key)
                    .map_err(|e| format!("sign failed ({e})"))?;

                let tx_blob = tx.serialize();
                match TOKIO_RUNTIME.block_on(broadcast_send_raw_transaction(&base_url, &tx_blob)) {
                    Ok(()) => Ok(()),
                    Err(e) => Err(format!(
                        "broadcast failed ({}): {}",
                        if is_invalid_input_send_raw_tx_error(&format!("{e}")) {
                            "invalid_input"
                        } else {
                            "other"
                        },
                        e
                    )),
                }
            };

            let mut lo = 0usize;
            let mut hi = all.len();
            let mut last_err: Option<String> = None;

            while lo < hi && start.elapsed() <= budget {
                let mid = (lo + hi) / 2;
                let test: Vec<TrackedOutput> = all[lo..mid.max(lo + 1)].to_vec();

                match try_subset(&test) {
                    Ok(()) => {
                        lo = mid.max(lo + 1);
                    }
                    Err(e) => {
                        if e.contains("broadcast failed (invalid_input):") {
                            last_err = Some(e);
                            hi = mid.max(lo + 1);
                        } else {
                            lo = mid.max(lo + 1);
                        }
                    }
                }

                if hi.saturating_sub(lo) == 1 {
                    let bad = &all[lo];
                    walletcore_log_line(
                        id,
                        snapshot.network,
                        &format!(
                            "🧨 send_bisect: candidate invalid_input output wallet_id={} txid={} index_in_tx={} height={} amount_piconero={} err={}",
                            id,
                            hex_dump_prefix(&bad.tx_hash, 32),
                            bad.index_in_tx,
                            bad.block_height,
                            bad.amount,
                            last_err.clone().unwrap_or_else(|| "(none)".to_string())
                        ),
                    );
                    break;
                }
            }
        }

        record_error(code, msg);
        return ptr::null_mut();
    }

    // Mark spent + adjust totals
    let tx_hash = tx.hash();
    let hex = hex_lowercase(&tx_hash);
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
                    mark_tracked_output_spent(o, Some(tx_hash));
                }
            }
            state.total = state.total.saturating_sub(spent_sum);
            state.unlocked = state.unlocked.saturating_sub(spent_sum);
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

#[cfg(test)]
mod tests {
    use super::decode_hex;

    #[test]
    fn pending_send_binding_rejects_legacy_foreign_and_network_replacement() {
        use super::*;
        let id = CString::new("prepared-binding-fixture").unwrap();
        let seed = CString::new("ability pockets lordship tomorrow gypsy match neutral uncle avatar betting bicycle junk unzip pyramid lynx mammal edgy empty uneven knowledge juvenile wiring paradise psychic betting").unwrap();
        assert_eq!(
            crate::wallet_open_from_mnemonic(id.as_ptr(), seed.as_ptr(), 100, 1),
            0
        );
        let mut store = WALLET_STORE.lock().unwrap();
        let wallet = store.get_mut("prepared-binding-fixture").unwrap();
        let mut prepared = PreparedSendPayload {
            txid: "fixture".into(),
            amount: 1,
            fee: 1,
            signed_tx_hex: "00".into(),
            wallet_binding: Some(wallet_cache_binding(wallet)),
        };
        assert!(validate_prepared_binding(&prepared, wallet).is_ok());
        let binding = prepared.wallet_binding.clone();
        prepared.wallet_binding = None;
        assert!(validate_prepared_binding(&prepared, wallet).is_err());
        prepared.wallet_binding = Some("another wallet".into());
        assert!(validate_prepared_binding(&prepared, wallet).is_err());
        prepared.wallet_binding = binding;
        wallet.network = crate::MoneroNetwork::Stagenet;
        assert!(validate_prepared_binding(&prepared, wallet).is_err());
        store.remove("prepared-binding-fixture");
    }

    #[test]
    fn native_relay_rejects_unbound_journals_before_blob_or_network_work() {
        use super::*;
        let id = CString::new("prepared-binding-native-fixture").unwrap();
        let seed = CString::new("ability pockets lordship tomorrow gypsy match neutral uncle avatar betting bicycle junk unzip pyramid lynx mammal edgy empty uneven knowledge juvenile wiring paradise psychic betting").unwrap();
        assert_eq!(
            crate::wallet_open_from_mnemonic(id.as_ptr(), seed.as_ptr(), 100, 1),
            0
        );
        let node = CString::new("not-a-node-url").unwrap();
        for (binding, expected) in [
            (None, "lacks wallet identity"),
            (Some("foreign"), "another wallet or network"),
        ] {
            let mut payload = serde_json::json!({"txid":"fixture", "amount":1, "fee":1, "signed_tx_hex":"not-hex"});
            if let Some(value) = binding {
                payload["wallet_binding"] = value.into();
            }
            let payload = CString::new(payload.to_string()).unwrap();
            assert!(wallet_relay_prepared(id.as_ptr(), node.as_ptr(), payload.as_ptr()).is_null());
            // Neither malformed signed bytes nor an invalid endpoint may be consulted first.
            assert!(crate::last_error_clone().unwrap().contains(expected));
        }
        WALLET_STORE
            .lock()
            .unwrap()
            .remove("prepared-binding-native-fixture");
    }

    #[test]
    fn decode_hex_accepts_mixed_case() {
        assert_eq!(decode_hex("00aBfF").unwrap(), vec![0, 0xab, 0xff]);
    }

    #[test]
    fn decode_hex_rejects_empty_odd_and_non_hex_values() {
        assert!(decode_hex("").is_err());
        assert!(decode_hex("abc").is_err());
        assert!(decode_hex("zz").is_err());
    }

    #[test]
    fn decode_hex_enforces_binary_size_limit() {
        let oversized = "00".repeat((2 * 1024 * 1024) + 1);
        assert!(decode_hex(&oversized).is_err());
    }
}
