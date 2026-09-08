//! Sweep-related FFI surface extracted from the historical mega-`lib.rs`.
//!
//! This module keeps behavior identical to the inlined implementation, while relying on
//! `crate::support` for a stable, small set of re-exports.
//!
//! Exposes:
//! - `wallet_preview_sweep`
//! - `wallet_sweep`
//! - `wallet_preview_sweep_with_filter`
//! - `wallet_sweep_with_filter`

#![allow(clippy::too_many_arguments)]
#![allow(clippy::needless_return)]

use crate::support::*;

use core::ffi::c_char;
use rand::{rngs::OsRng, RngCore};
use serde::Deserialize;
use std::{
    collections::HashSet,
    ffi::{CStr, CString},
    ptr,
    time::{Duration, Instant},
};
use zeroize::Zeroizing;

// External types used by the sweep path.
use monero_address::MoneroAddress;
use monero_interface::{FeeError, FeeRate};
use monero_wallet::Scanner;

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
    run_while_refresh_stopped(wallet_id, "wallet_sweep", || {
        wallet_sweep_with_filter_impl(
            wallet_id,
            node_url,
            to_address,
            ptr::null(),
            ring_len,
            false,
        )
    })
}

/// Build and sign a full-wallet sweep without broadcasting it.
#[no_mangle]
pub extern "C" fn wallet_prepare_sweep(
    wallet_id: *const c_char,
    node_url: *const c_char,
    to_address: *const c_char,
    ring_len: u8,
) -> *mut c_char {
    clear_last_error();

    if wallet_id.is_null() || to_address.is_null() {
        record_error(-11, "wallet_prepare_sweep: null argument(s)");
        return ptr::null_mut();
    }

    run_while_refresh_stopped(wallet_id, "wallet_prepare_sweep", || {
        wallet_sweep_with_filter_impl(wallet_id, node_url, to_address, ptr::null(), ring_len, true)
    })
}

#[no_mangle]
pub extern "C" fn wallet_preview_sweep_with_filter(
    wallet_id: *const c_char,
    node_url: *const c_char,
    to_address: *const c_char,
    filter_json: *const c_char,
    ring_len: u8,
) -> *mut c_char {
    run_while_refresh_stopped(wallet_id, "wallet_preview_sweep_with_filter", || {
        wallet_preview_sweep_with_filter_impl(
            wallet_id,
            node_url,
            to_address,
            filter_json,
            ring_len,
        )
    })
}

fn wallet_preview_sweep_with_filter_impl(
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

    // Keep the original rich debug log (helps correlate node vs wallet behavior).
    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🔎 sweep_preview context wallet_id={} base_url={} ring_len={} gap_limit={} filter_subaddr_minor={}",
            id,
            base_url,
            ring_len,
            snapshot.gap_limit,
            match filter.as_ref().and_then(|f| f.subaddress_minor) {
                Some(v) => v.to_string(),
                None => "(none)".to_string(),
            }
        ),
    );

    let rpc_client: RpcClient = match TOKIO_RUNTIME.block_on(
        monero_simple_request_rpc::SimpleRequestTransport::new(base_url.clone()),
    ) {
        Ok(d) => d,
        Err(e) => {
            record_error(
                -16,
                format!(
                    "wallet_preview_sweep_with_filter: failed to connect daemon '{base_url}': {e}"
                ),
            );
            return ptr::null_mut();
        }
    };

    let daemon_height = match TOKIO_RUNTIME.block_on(rpc_client.latest_block_number()) {
        Ok(n) => n.saturating_add(1) as u64,
        Err(e) => {
            record_error(
                -16,
                format!(
                    "wallet_preview_sweep_with_filter: failed to query daemon height '{base_url}': {e}"
                ),
            );
            return ptr::null_mut();
        }
    };

    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🔎 sweep_preview daemon_height wallet_id={} base_url={} daemon_height={}",
            id, base_url, daemon_height
        ),
    );

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
                "wallet_preview_sweep_with_filter: failed to construct view pair",
            );
            return ptr::null_mut();
        }
    };

    // Validate destination address early.
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

    // Exclude outputs originating from pending outgoing txids (change outputs).
    let pending_txids: HashSet<String> = snapshot
        .pending_outgoing
        .iter()
        .map(|p| p.txid.trim().to_ascii_lowercase())
        .collect();

    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧹 sweep_preview pending_outgoing context wallet_id={} pending_txids_count={} pending_txids_sample={}",
            id,
            pending_txids.len(),
            pending_txids
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<String>>()
                .join(",")
        ),
    );

    let mut spendable: Vec<TrackedOutput> = snapshot
        .tracked_outputs
        .iter()
        .cloned()
        .filter(|o| !o.spent && o.is_unlocked(daemon.height, daemon.top_block_timestamp))
        .filter(|o| {
            if pending_txids.is_empty() {
                return true;
            }
            let txid = hex_lowercase(&o.tx_hash);
            !pending_txids.contains(&txid)
        })
        .collect();

    // Always log exclusion summary (even when zero).
    let excluded_pending = snapshot
        .tracked_outputs
        .iter()
        .filter(|o| !o.spent && o.is_unlocked(daemon.height, daemon.top_block_timestamp))
        .filter(|o| pending_txids.contains(&hex_lowercase(&o.tx_hash)))
        .count();

    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧹 sweep_preview pending_outgoing exclusion wallet_id={} excluded_count={} pending_txids_count={}",
            id,
            excluded_pending,
            pending_txids.len()
        ),
    );

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

    // Prefer fewer/larger inputs for sweeps.
    spendable.sort_by_key(|o| core::cmp::Reverse(o.amount));

    let mut rng = OsRng;
    let ring_len_eff: u8 = if ring_len < 2 { 16 } else { ring_len };

    // Fee rate once.
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
                record_error(code, "wallet_preview_sweep_with_filter: fee_rate failed");
                return ptr::null_mut();
            }
        };

    // Keep original fee-rate log style.
    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "💸 fee_rate wallet_id={} base_url={} priority={:?} max_per_weight={} fee_rate={:?}",
            id, base_url, fee_priority, max_per_weight, fee_rate
        ),
    );

    let change = monero_wallet::send::Change::new(view_pair.clone(), None);

    // Sweep preview selection:
    // - select all spendable, but filter out dust below min_input.
    let min_input = walletcore_sweep_min_input_piconero();
    let selected: Vec<TrackedOutput> = spendable
        .iter()
        .cloned()
        .filter(|o| o.amount >= min_input)
        .collect();

    let skipped_count = spendable.len().saturating_sub(selected.len());
    let skipped_sum: u64 = spendable
        .iter()
        .filter(|o| o.amount < min_input)
        .map(|o| o.amount)
        .sum();

    let selected_sum: u64 = selected.iter().map(|o| o.amount).sum();

    if selected.is_empty() {
        record_error(
            -18,
            format!(
                "wallet_preview_sweep_with_filter: no unlocked funds to sweep (all outputs below min_input_piconero={} skipped_count={} skipped_sum={})",
                min_input, skipped_count, skipped_sum
            ),
        );
        return ptr::null_mut();
    }

    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧹 sweep_preview dust filter wallet_id={} min_input_piconero={} selected_count={} selected_sum={} skipped_count={} skipped_sum={}",
            id,
            min_input,
            selected.len(),
            selected_sum,
            skipped_count,
            skipped_sum
        ),
    );

    // Debug toggle: allow sweep preview without decoys.
    if walletcore_disable_decoys() {
        walletcore_log_line(
            id,
            snapshot.network,
            &format!(
                "🧪 WALLETCORE_DISABLE_DECOYS=1: sweep_preview returning placeholder (amount, fee) without decoy selection wallet_id={} base_url={}",
                id, base_url
            ),
        );

        let placeholder_fee: u64 = 30_700_000;
        let amount = selected_sum.saturating_sub(placeholder_fee);

        let json = match serde_json::to_string(&serde_json::json!({
            "amount": amount,
            "fee": placeholder_fee
        })) {
            Ok(s) => s,
            Err(err) => {
                record_error(
                    -16,
                    format!(
                        "wallet_preview_sweep_with_filter: result JSON serialization failed ({err})"
                    ),
                );
                return ptr::null_mut();
            }
        };

        return match CString::new(json) {
            Ok(cstr) => {
                clear_last_error();
                cstr.into_raw()
            }
            Err(_) => {
                record_error(
                    -16,
                    "wallet_preview_sweep_with_filter: result JSON contained interior null bytes",
                );
                ptr::null_mut()
            }
        };
    }

    // Decoy probe log (kept for debug parity).
    if walletcore_decoy_probe_enabled() {
        walletcore_log_line(
            id,
            snapshot.network,
            &format!(
                "🧪 WALLETCORE_DECOY_PROBE=1: running decoy probe wallet_id={} base_url={} ring_len_eff={} selected_inputs={}",
                id, base_url, ring_len_eff, selected.len()
            ),
        );
    }

    if walletcore_decoy_mode_bin16() {
        walletcore_log_line(
            id,
            snapshot.network,
            &format!(
                "🧪 WALLETCORE_DECOY_MODE=bin16 enabled: sweep_preview will use monero-daemon-rpc (bin_rpc) decoy provider wallet_id={} base_url={}",
                id, base_url
            ),
        );
    }

    let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();
    for t in &selected {
        if walletcore_debug_input_dump_enabled() {
            walletcore_log_line(
                id,
                snapshot.network,
                &format!(
                    "🔎 sweep_preview selecting_input wallet_id={} base_url={} real_out_height={} real_out_txid={} real_out_index_in_tx={} real_out_amount_piconero={} daemon_height={}",
                    id,
                    base_url,
                    t.block_height,
                    hex_dump_prefix(&t.tx_hash, 32),
                    t.index_in_tx,
                    t.amount,
                    daemon.height
                ),
            );
        }

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

        let scannable =
            match TOKIO_RUNTIME.block_on(rpc_client.scannable_block_by_number(block_number)) {
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

        let wallet_out = match outputs
            .into_iter()
            .find(|wo| wo.transaction() == t.tx_hash && wo.index_in_transaction() == t.index_in_tx)
        {
            Some(wo) => wo,
            None => {
                record_error(
                    -16,
                    "wallet_preview_sweep_with_filter: failed to reconstruct selected output",
                );
                return ptr::null_mut();
            }
        };

        let with_decoys = if walletcore_decoy_mode_bin16() {
            let daemon_iface = match TOKIO_RUNTIME.block_on(make_bin_decoy_daemon(&base_url)) {
                Ok(d) => d,
                Err(e) => {
                    let code = map_rpc_error(e.clone());
                    record_error(
                        code,
                        format!(
                            "wallet_preview_sweep_with_filter: failed to construct bin16 decoy daemon for '{base_url}': {e}"
                        ),
                    );
                    return ptr::null_mut();
                }
            };

            match TOKIO_RUNTIME.block_on(monero_wallet::OutputWithDecoys::new(
                &mut rng,
                &daemon_iface,
                16,
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

                    if walletcore_decoy_probe_enabled() {
                        walletcore_log_line(
                            id,
                            snapshot.network,
                            &format!(
                                "🧪 WALLETCORE_DECOY_PROBE=1: decoy selection failed wallet_id={} base_url={} daemon_height={} real_out_height={} real_out_txid={} real_out_index_in_tx={} ring_len_eff={} err={:?}",
                                id,
                                base_url,
                                daemon.height,
                                t.block_height,
                                hex_dump_prefix(&t.tx_hash, 32),
                                t.index_in_tx,
                                16,
                                err
                            ),
                        );
                    }

                    record_error(
                        code,
                        format!(
                            "wallet_preview_sweep_with_filter: decoy selection failed ({err:?})"
                        ),
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

                    if walletcore_decoy_probe_enabled() {
                        walletcore_log_line(
                            id,
                            snapshot.network,
                            &format!(
                                "🧪 WALLETCORE_DECOY_PROBE=1: decoy selection failed wallet_id={} base_url={} daemon_height={} real_out_height={} real_out_txid={} real_out_index_in_tx={} ring_len_eff={} err={:?}",
                                id,
                                base_url,
                                daemon.height,
                                t.block_height,
                                hex_dump_prefix(&t.tx_hash, 32),
                                t.index_in_tx,
                                ring_len_eff,
                                err
                            ),
                        );
                    }

                    record_error(
                        code,
                        format!(
                            "wallet_preview_sweep_with_filter: decoy selection failed ({err:?})"
                        ),
                    );
                    return ptr::null_mut();
                }
            }
        };

        inputs.push(with_decoys);
    }

    // Fixed-point iteration for sweep amount:
    // amount = selected_sum - fee(amount)
    let mut fee_guess: u64 = 0;
    let max_amount_iters: usize = 8;

    for _ in 0..max_amount_iters {
        let mut ovk = [0u8; 32];
        rng.fill_bytes(&mut ovk);

        let candidate_amount = selected_sum.saturating_sub(fee_guess);

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
                let msg = e.to_string();
                if msg.contains("not enough funds") {
                    fee_guess = fee_guess.saturating_add(50_000_000);
                    continue;
                }
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
        if new_fee == fee_guess {
            break;
        }
        fee_guess = new_fee;
    }

    let fee = fee_guess;
    let amount = selected_sum.saturating_sub(fee);

    if fee >= selected_sum || amount == 0 {
        record_error(
            -18,
            format!(
                "wallet_preview_sweep_with_filter: insufficient unlocked funds to pay fee (inputs {}, necessary_fee {})",
                selected_sum, fee
            ),
        );
        return ptr::null_mut();
    }

    let json = match serde_json::to_string(&serde_json::json!({ "amount": amount, "fee": fee })) {
        Ok(s) => s,
        Err(err) => {
            record_error(
                -16,
                format!(
                    "wallet_preview_sweep_with_filter: result JSON serialization failed ({err})"
                ),
            );
            return ptr::null_mut();
        }
    };

    return match CString::new(json) {
        Ok(cstr) => {
            clear_last_error();
            cstr.into_raw()
        }
        Err(_) => {
            record_error(
                -16,
                "wallet_preview_sweep_with_filter: result JSON contained interior null bytes",
            );
            ptr::null_mut()
        }
    };
}

#[no_mangle]
pub extern "C" fn wallet_sweep_with_filter(
    wallet_id: *const c_char,
    node_url: *const c_char,
    to_address: *const c_char,
    filter_json: *const c_char,
    ring_len: u8,
) -> *mut c_char {
    run_while_refresh_stopped(wallet_id, "wallet_sweep_with_filter", || {
        wallet_sweep_with_filter_impl(
            wallet_id,
            node_url,
            to_address,
            filter_json,
            ring_len,
            false,
        )
    })
}

/// Build and sign a filtered sweep without broadcasting it.
#[no_mangle]
pub extern "C" fn wallet_prepare_sweep_with_filter(
    wallet_id: *const c_char,
    node_url: *const c_char,
    to_address: *const c_char,
    filter_json: *const c_char,
    ring_len: u8,
) -> *mut c_char {
    run_while_refresh_stopped(wallet_id, "wallet_prepare_sweep_with_filter", || {
        wallet_sweep_with_filter_impl(wallet_id, node_url, to_address, filter_json, ring_len, true)
    })
}

fn wallet_sweep_with_filter_impl(
    wallet_id: *const c_char,
    node_url: *const c_char,
    to_address: *const c_char,
    filter_json: *const c_char,
    ring_len: u8,
    prepare_only: bool,
) -> *mut c_char {
    clear_last_error();
    if wallet_id.is_null() || to_address.is_null() {
        record_error(-11, "wallet_sweep_with_filter: null argument(s)");
        return ptr::null_mut();
    }

    let id = match unsafe { CStr::from_ptr(wallet_id) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(
                -10,
                "wallet_sweep_with_filter: wallet_id contained invalid UTF-8",
            );
            return ptr::null_mut();
        }
    };

    let to_addr_str = match unsafe { CStr::from_ptr(to_address) }.to_str() {
        Ok(s) => s.trim(),
        Err(_) => {
            record_error(
                -10,
                "wallet_sweep_with_filter: to_address contained invalid UTF-8",
            );
            return ptr::null_mut();
        }
    };

    let snapshot = {
        let map = WALLET_STORE.lock().expect("wallet store poisoned");
        match map.get(id) {
            Some(s) => s.clone(),
            None => {
                record_error(
                    -13,
                    format!("wallet_sweep_with_filter: wallet '{id}' not registered"),
                );
                return ptr::null_mut();
            }
        }
    };

    #[derive(Deserialize)]
    struct InputFilter {
        subaddress_minor: Option<u32>,
    }

    let filter: Option<InputFilter> = if !filter_json.is_null() {
        unsafe { CStr::from_ptr(filter_json) }
            .to_str()
            .ok()
            .and_then(|s| {
                let s = s.trim();
                if s.is_empty() {
                    None
                } else {
                    serde_json::from_str::<InputFilter>(s).ok()
                }
            })
    } else {
        None
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

    let recipient_address = match MoneroAddress::from_str(snapshot.network, to_addr_str) {
        Ok(a) => a,
        Err(_) => {
            record_error(-10, "wallet_sweep_with_filter: invalid destination address");
            return ptr::null_mut();
        }
    };

    let rpc_client: RpcClient = match TOKIO_RUNTIME.block_on(
        monero_simple_request_rpc::SimpleRequestTransport::new(base_url.clone()),
    ) {
        Ok(c) => c,
        Err(e) => {
            record_error(
                -16,
                format!("wallet_sweep_with_filter: failed to connect daemon '{base_url}': {e}"),
            );
            return ptr::null_mut();
        }
    };

    let daemon_height = match TOKIO_RUNTIME.block_on(rpc_client.latest_block_number()) {
        Ok(h) => h.saturating_add(1) as u64,
        Err(e) => {
            record_error(
                -16,
                format!(
                    "wallet_sweep_with_filter: failed to query daemon height '{base_url}': {e}"
                ),
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
                "wallet_sweep_with_filter: failed to construct view pair",
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

    let pending_txids: HashSet<String> = snapshot
        .pending_outgoing
        .iter()
        .map(|p| p.txid.trim().to_ascii_lowercase())
        .collect();

    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧹 sweep pending_outgoing context wallet_id={} pending_txids_count={} pending_txids_sample={}",
            id,
            pending_txids.len(),
            pending_txids
                .iter()
                .take(3)
                .cloned()
                .collect::<Vec<String>>()
                .join(",")
        ),
    );

    let mut spendable: Vec<TrackedOutput> = snapshot
        .tracked_outputs
        .iter()
        .cloned()
        .filter(|o| !o.spent && o.is_unlocked(daemon.height, daemon.top_block_timestamp))
        .filter(|o| {
            if pending_txids.is_empty() {
                return true;
            }
            let txid = hex_lowercase(&o.tx_hash);
            !pending_txids.contains(&txid)
        })
        .collect();

    let excluded_pending = snapshot
        .tracked_outputs
        .iter()
        .filter(|o| !o.spent && o.is_unlocked(daemon.height, daemon.top_block_timestamp))
        .filter(|o| pending_txids.contains(&hex_lowercase(&o.tx_hash)))
        .count();

    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧹 sweep pending_outgoing exclusion wallet_id={} excluded_count={} pending_txids_count={}",
            id,
            excluded_pending,
            pending_txids.len()
        ),
    );

    if let Some(f) = &filter {
        if let Some(minor) = f.subaddress_minor {
            spendable.retain(|o| o.subaddress_major == 0 && o.subaddress_minor == minor);
        }
    }

    // Dust filter.
    let min_input = walletcore_sweep_min_input_piconero();
    let skipped_count = spendable.iter().filter(|o| o.amount < min_input).count();
    let skipped_sum: u64 = spendable
        .iter()
        .filter(|o| o.amount < min_input)
        .map(|o| o.amount)
        .sum();
    spendable.retain(|o| o.amount >= min_input);

    if spendable.is_empty() {
        record_error(
            -18,
            format!(
                "wallet_sweep_with_filter: no unlocked funds to sweep (all outputs below min_input_piconero={} skipped_count={} skipped_sum={})",
                min_input, skipped_count, skipped_sum
            ),
        );
        return ptr::null_mut();
    }

    walletcore_log_line(
        id,
        snapshot.network,
        &format!(
            "🧹 sweep dust filter wallet_id={} min_input_piconero={} selected_count={} selected_sum={} skipped_count={} skipped_sum={}",
            id,
            min_input,
            spendable.len(),
            spendable.iter().map(|o| o.amount).sum::<u64>(),
            skipped_count,
            skipped_sum
        ),
    );

    // Fee rate once.
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
                record_error(code, "wallet_sweep_with_filter: fee_rate failed");
                return ptr::null_mut();
            }
        };

    let ring_len_eff: u8 = if ring_len < 2 { 16 } else { ring_len };
    let change = monero_wallet::send::Change::new(view_pair.clone(), None);

    // Build inputs with decoys for ALL selected outputs.
    let mut rng = OsRng;
    let mut inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();

    for t in &spendable {
        let block_number = match usize::try_from(t.block_height) {
            Ok(value) => value,
            Err(_) => {
                record_error(
                    -16,
                    "wallet_sweep_with_filter: block number conversion overflow",
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
                            "wallet_sweep_with_filter: RPC block fetch failed at height {}",
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
                        "wallet_sweep_with_filter: scanner failed at height {}",
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
                    "wallet_sweep_with_filter: failed to reconstruct selected output",
                );
                return ptr::null_mut();
            }
        };

        let with_decoys = if walletcore_decoy_mode_bin16() {
            let daemon_iface = match TOKIO_RUNTIME.block_on(make_bin_decoy_daemon(&base_url)) {
                Ok(d) => d,
                Err(e) => {
                    let code = map_rpc_error(e.clone());
                    record_error(
                        code,
                        format!(
                            "wallet_sweep_with_filter: failed to construct bin16 decoy daemon for '{base_url}': {e}"
                        ),
                    );
                    return ptr::null_mut();
                }
            };

            match TOKIO_RUNTIME.block_on(monero_wallet::OutputWithDecoys::new(
                &mut rng,
                &daemon_iface,
                16,
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
                        format!("wallet_sweep_with_filter: decoy selection failed ({err:?})"),
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
                        format!("wallet_sweep_with_filter: decoy selection failed ({err:?})"),
                    );
                    return ptr::null_mut();
                }
            }
        };

        inputs.push(with_decoys);
    }

    let inputs_sum: u64 = spendable.iter().map(|t| t.amount).sum();

    // Fixed-point fee convergence at send time.
    let mut fee_guess: u64 = 0;
    let max_iters: usize = 8;

    let mut final_amount: u64 = 0;
    let mut final_fee: u64 = 0;
    let mut final_intent: Option<monero_wallet::send::SignableTransaction> = None;

    for _ in 0..max_iters {
        let mut ovk = [0u8; 32];
        rng.fill_bytes(&mut ovk);

        let candidate_amount = inputs_sum.saturating_sub(fee_guess);

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
                let msg = e.to_string();
                if msg.contains("not enough funds") {
                    fee_guess = fee_guess.saturating_add(50_000_000);
                    continue;
                }
                record_error(
                    -16,
                    format!("wallet_sweep_with_filter: transaction construction failed ({e})"),
                );
                return ptr::null_mut();
            }
        };

        let fee = intent.necessary_fee();
        final_fee = fee;
        final_amount = inputs_sum.saturating_sub(fee);
        final_intent = Some(intent);

        if fee == fee_guess {
            break;
        }
        fee_guess = fee;
    }

    if final_amount == 0 || final_fee >= inputs_sum {
        record_error(
            -18,
            format!(
                "wallet_sweep_with_filter: insufficient unlocked funds to pay fee (inputs {}, necessary_fee {})",
                inputs_sum, final_fee
            ),
        );
        return ptr::null_mut();
    }

    let intent = match final_intent {
        Some(i) => i,
        None => {
            record_error(
                -16,
                "wallet_sweep_with_filter: fee estimation did not converge",
            );
            return ptr::null_mut();
        }
    };

    // Sign and broadcast.
    let spend_key = Zeroizing::new(monero_wallet::ed25519::Scalar::from(master.spend_scalar));
    let mut signer_rng = OsRng;
    let tx = match intent.sign(&mut signer_rng, &spend_key) {
        Ok(tx) => tx,
        Err(e) => {
            record_error(
                -16,
                format!("wallet_sweep_with_filter: signing failed ({e})"),
            );
            return ptr::null_mut();
        }
    };

    if prepare_only {
        let tx_blob = tx.serialize();
        let txid = hex_lowercase(&tx.hash());
        let result_json = match serde_json::to_string(&serde_json::json!({
            "txid": txid,
            "amount": final_amount,
            "fee": final_fee,
            "wallet_binding": wallet_cache_binding(&snapshot),
            "signed_tx_hex": hex_lowercase(&tx_blob)
        })) {
            Ok(s) => s,
            Err(err) => {
                record_error(
                    -16,
                    format!(
                        "wallet_prepare_sweep_with_filter: result JSON serialization failed ({err})"
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
                    "wallet_prepare_sweep_with_filter: result JSON contained interior null bytes",
                );
                ptr::null_mut()
            }
        };
    }

    let tx_blob = tx.serialize();
    if let Err(err) = TOKIO_RUNTIME.block_on(broadcast_send_raw_transaction(&base_url, &tx_blob)) {
        let code = map_rpc_error(err.clone());
        let msg = format!("wallet_sweep_with_filter: send_raw_transaction failed ({err})");

        // Optional bisect for invalid_input in sweep sends.
        if walletcore_sweep_bisect_enabled() && is_invalid_input_send_raw_tx_error(&msg) {
            let start = Instant::now();
            let budget = Duration::from_secs(20);

            let all = spendable.clone();

            let mut try_subset = |subset: &Vec<TrackedOutput>| -> Result<(), String> {
                if subset.is_empty() {
                    return Err("empty subset".to_string());
                }

                let inputs_sum: u64 = subset.iter().map(|t| t.amount).sum();
                let mut local_inputs: Vec<monero_wallet::OutputWithDecoys> = Vec::new();
                let mut local_rng = OsRng;

                for t in subset {
                    if start.elapsed() > budget {
                        return Err("bisect budget exceeded".to_string());
                    }

                    let block_number = usize::try_from(t.block_height)
                        .map_err(|_| "block number overflow".to_string())?;
                    let scannable = TOKIO_RUNTIME
                        .block_on(rpc_client.scannable_block_by_number(block_number))
                        .map_err(|e| format!("block fetch failed: {e}"))?;
                    let outputs = scanner
                        .scan(scannable)
                        .map_err(|_| "scanner failed".to_string())?
                        .ignore_additional_timelock();

                    let wallet_out = outputs
                        .into_iter()
                        .find(|wo| {
                            wo.transaction() == t.tx_hash
                                && wo.index_in_transaction() == t.index_in_tx
                        })
                        .ok_or_else(|| "failed to reconstruct selected output".to_string())?;

                    let with_decoys = if walletcore_decoy_mode_bin16() {
                        let daemon_iface = TOKIO_RUNTIME
                            .block_on(make_bin_decoy_daemon(&base_url))
                            .map_err(|e| format!("failed to construct bin16 decoy daemon: {e}"))?;
                        TOKIO_RUNTIME
                            .block_on(monero_wallet::OutputWithDecoys::new(
                                &mut local_rng,
                                &daemon_iface,
                                16,
                                usize::try_from(daemon.height).unwrap_or(daemon.height as usize),
                                wallet_out,
                            ))
                            .map_err(|e| format!("decoy selection failed: {e:?}"))?
                    } else {
                        TOKIO_RUNTIME
                            .block_on(monero_wallet::OutputWithDecoys::new(
                                &mut local_rng,
                                &rpc_client,
                                ring_len_eff,
                                usize::try_from(daemon.height).unwrap_or(daemon.height as usize),
                                wallet_out,
                            ))
                            .map_err(|e| format!("decoy selection failed: {e:?}"))?
                    };

                    local_inputs.push(with_decoys);
                }

                // Fee convergence (bounded). If subset can't pay fee, treat as non-signal.
                let mut fee_guess: u64 = 0;
                let mut final_intent: Option<monero_wallet::send::SignableTransaction> = None;
                for _ in 0..8 {
                    if start.elapsed() > budget {
                        return Err("bisect budget exceeded".to_string());
                    }

                    let mut ovk = [0u8; 32];
                    local_rng.fill_bytes(&mut ovk);
                    let candidate_amount = inputs_sum.saturating_sub(fee_guess);

                    let intent = match monero_wallet::send::SignableTransaction::new(
                        monero_wallet::ringct::RctType::ClsagBulletproofPlus,
                        Zeroizing::new(ovk),
                        local_inputs.clone(),
                        vec![(recipient_address, candidate_amount)],
                        change.clone(),
                        Vec::new(),
                        fee_rate,
                    ) {
                        Ok(tx) => tx,
                        Err(e) => {
                            let msg = e.to_string();
                            if msg.contains("not enough funds") {
                                return Err(format!("subset cannot pay fee: {msg}"));
                            }
                            return Err(format!("tx construction failed: {msg}"));
                        }
                    };

                    let fee = intent.necessary_fee();
                    final_intent = Some(intent);
                    if fee == fee_guess {
                        break;
                    }
                    fee_guess = fee;
                }

                let intent = final_intent.ok_or_else(|| "fee convergence failed".to_string())?;
                let spend_key =
                    Zeroizing::new(monero_wallet::ed25519::Scalar::from(master.spend_scalar));
                let mut srng = OsRng;
                let tx = intent
                    .sign(&mut srng, &spend_key)
                    .map_err(|e| format!("sign failed: {e}"))?;
                let tx_blob = tx.serialize();

                match TOKIO_RUNTIME.block_on(broadcast_send_raw_transaction(&base_url, &tx_blob)) {
                    Ok(()) => Ok(()),
                    Err(e) => {
                        let emsg = e.to_string();
                        if is_invalid_input_send_raw_tx_error(&emsg) {
                            Err(format!("broadcast failed (invalid_input): {emsg}"))
                        } else {
                            Err(format!("broadcast failed (non-signal): {emsg}"))
                        }
                    }
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
                            "🧨 sweep_bisect: candidate invalid_input output wallet_id={} txid={} index_in_tx={} height={} amount_piconero={} err={}",
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

    // Mark spent outputs in memory, adjust totals (best-effort).
    let tx_hash = tx.hash();
    let hex = hex_lowercase(&tx_hash);
    {
        let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
        if let Some(state) = map.get_mut(id) {
            for t in &spendable {
                if let Some(o) = state
                    .tracked_outputs
                    .iter_mut()
                    .find(|o| o.tx_hash == t.tx_hash && o.index_in_tx == t.index_in_tx)
                {
                    mark_tracked_output_spent(o, Some(tx_hash));
                }
            }
            state.total = state.total.saturating_sub(inputs_sum);
            state.unlocked = state.unlocked.saturating_sub(inputs_sum);
        }
    }

    // Record pending outgoing tx + ledger.

    {
        let mut map = WALLET_STORE.lock().expect("wallet store poisoned");
        if let Some(state) = map.get_mut(id) {
            state.pending_outgoing.push(PendingOutgoingTx {
                txid: hex.clone(),
                amount: final_amount,
                fee: final_fee,
                created_at: state.chain_time,
            });

            state.tx_ledger.insert(
                hex.clone(),
                LedgerEntry {
                    txid: hex.clone(),
                    direction: "out".to_string(),
                    amount: outgoing_ledger_amount(final_amount, final_fee),
                    fee: Some(final_fee),
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
        "amount": final_amount,
        "fee": final_fee
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
