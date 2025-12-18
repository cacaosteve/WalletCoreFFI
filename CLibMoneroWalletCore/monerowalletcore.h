/*
 * monerowalletcore.h
 *
 * C ABI for the MoneroWalletCore Rust library (generated to match Rust cdylib/staticlib).
 * All function signatures are aligned with the Rust declarations (usize -> size_t).
 *
 * Ownership notes:
 * - Functions returning char* allocate a C string on the Rust side. The caller MUST
 *   free it with walletcore_free_cstr(char*).
 * - On error (non-zero return codes), walletcore_last_error_message() may return a
 *   human-readable string that should also be freed with walletcore_free_cstr().
 */

#ifndef MONEROWALLETCORE_H
#define MONEROWALLETCORE_H

#ifdef __cplusplus
#  define WALLETCORE_EXTERN_C_BEGIN extern "C" {
#  define WALLETCORE_EXTERN_C_END   }
#else
#  define WALLETCORE_EXTERN_C_BEGIN
#  define WALLETCORE_EXTERN_C_END
#endif

#include <stddef.h>  /* size_t */
#include <stdint.h>  /* uint8_t, uint32_t, uint64_t, int32_t */

WALLETCORE_EXTERN_C_BEGIN

/* ===== Version / Error utilities ===== */

/* Returns a newly-allocated NUL-terminated version string; free with walletcore_free_cstr. */
char* walletcore_version(void);

/* Returns the last error message as a newly-allocated string, or NULL if none; free with walletcore_free_cstr. */
char* walletcore_last_error_message(void);

/* Frees a C string returned by MoneroWalletCore; returns 0 on success. No-op if ptr is NULL. */
int32_t walletcore_free_cstr(char* ptr);


/* ===== Cache import/export ===== */

/* Import a previously exported cache blob for the given wallet_id (idempotent). */
int32_t wallet_import_cache(
    const char* wallet_id,
    const uint8_t* cache_ptr,
    size_t cache_len
);

/*
 * Export current cache. Two-phase API:
 * 1) Call with out_buf = NULL, out_buf_len = 0 to probe required size (out_written -> required).
 * 2) Allocate a buffer of that size, then call again to fill it (out_written -> actual bytes).
 */
int32_t wallet_export_cache(
    const char* wallet_id,
    uint8_t* out_buf,
    size_t out_buf_len,
    size_t* out_written
);


/* ===== Address derivation ===== */

/*
 * Derive an address from a 32-byte seed (secret spend key).
 * is_mainnet: 1 => mainnet, 0 => stagenet/testnet (implementation-defined).
 * Writes UTF-8 address bytes (NUL-terminated) into out_buf and sets out_written (excluding NUL).
 */
int32_t wallet_derive_address_from_seed(
    const uint8_t* seed_ptr,
    size_t seed_len,
    uint8_t is_mainnet,
    uint32_t account_index,
    uint32_t subaddress_index,
    char* out_buf,
    size_t out_buf_len,
    size_t* out_written
);

/* Derive the primary address (account 0, subaddress 0) from a 32-byte seed. */
int32_t wallet_primary_address_from_seed(
    const uint8_t* seed_ptr,
    size_t seed_len,
    uint8_t is_mainnet,
    char* out_buf,
    size_t out_buf_len,
    size_t* out_written
);

/* Derive the primary address (account 0, subaddress 0) from a 25-word mnemonic (ASCII). */
int32_t wallet_primary_address_from_mnemonic(
    const char* mnemonic,
    uint8_t is_mainnet,
    char* out_buf,
    size_t out_buf_len,
    size_t* out_written
);

/* Derive a subaddress (account_index, subaddress_index) from a 25-word mnemonic (ASCII). */
int32_t wallet_derive_subaddress_from_mnemonic(
    const char* mnemonic,
    uint32_t account_index,
    uint32_t subaddress_index,
    uint8_t is_mainnet,
    char* out_buf,
    size_t out_buf_len,
    size_t* out_written
);


/* ===== Wallet lifecycle / sync / balances ===== */

/*
 * Open/register a wallet from a 25-word mnemonic.
 * restore_height is a chain height hint (0 if unknown).
 * is_mainnet: 1 => mainnet, 0 => stagenet/testnet (implementation-defined).
 */
int32_t wallet_open_from_mnemonic(
    const char* wallet_id,
    const char* mnemonic,
    uint64_t restore_height,
    uint8_t is_mainnet
);

/* Update the registered subaddress gap limit for scanning (minimum 1). */
int32_t wallet_set_gap_limit(
    const char* wallet_id,
    uint32_t gap_limit
);

/* Start a background ZMQ listener for block notifications. */
int32_t wallet_start_zmq_listener(
    const char* endpoint
);

/* Stop the active ZMQ listener, if any. */
int32_t wallet_stop_zmq_listener(void);

/* Read the most recent ZMQ notification sequence height. */
int32_t wallet_zmq_sequence(
    uint64_t* out_sequence
);

/*
 * Refresh the wallet against the daemon (node_url). On success, writes last_scanned height.
 * node_url may be NULL to use a default (env/localhost).
 */
int32_t wallet_refresh(
    const char* wallet_id,
    const char* node_url,
    uint64_t* out_last_scanned
);

int32_t wallet_refresh_async(
    const char* wallet_id,
    const char* node_url
);

/*
 * Request cancellation of the in-flight refresh for a specific wallet.
 *
 * This sets a per-wallet cancel flag that the refresh loop checks frequently.
 * The next check will abort the refresh with a cancellation error.
 *
 * Returns 0 on success.
 */
int32_t wallet_refresh_cancel(const char* wallet_id);

/*
 * Retrieve current sync status for a wallet.
 * Returns chain height/time, last scanned height, and restore height.
 * Any output pointer may be NULL if the caller is not interested in that value.
 */
int32_t wallet_sync_status(
    const char* wallet_id,
    uint64_t* out_chain_height,
    uint64_t* out_chain_time,
    uint64_t* out_last_refresh_timestamp,
    uint64_t* out_last_scanned,
    uint64_t* out_restore_height
);

/* Get total and unlocked balances (piconero) for wallet_id. */
int32_t wallet_get_balance(
    const char* wallet_id,
    uint64_t* out_total_piconero,
    uint64_t* out_unlocked_piconero
);

/*
 * Export observed outputs as a JSON string.
 * Returns a newly-allocated char*; caller must free with walletcore_free_cstr.
 */
char* wallet_export_outputs_json(
    const char* wallet_id
);


/* ===== Transfers: history ===== */

/*
 * List transfers (transaction-level history) as a JSON string.
 * Returns a newly-allocated char*; caller must free with walletcore_free_cstr.
 *
 * Intended schema (subject to evolution):
 * [
 *   {
 *     "txid": "<hex>",
 *     "direction": "in" | "out" | "self",
 *     "amount": <uint64>,          // piconero (net for out may be represented as positive with direction)
 *     "fee": <uint64|null>,        // piconero, present for outgoing
 *     "height": <uint64|null>,     // confirmed height
 *     "timestamp": <uint64|null>,  // seconds since epoch if known
 *     "confirmations": <uint64>,   // 0 if pending
 *     "is_pending": <bool>,
 *     "subaddress_major": <uint32|null>,
 *     "subaddress_minor": <uint32|null>
 *   },
 *   ...
 * ]
 */
char* wallet_list_transfers_json(
    const char* wallet_id
);

/* ===== Balances ===== */

/*
 * Get total and unlocked balances with an optional input filter (e.g., constrain to a subaddress).
 *
 * filter_json is a JSON object (or NULL). Intended for schemas like:
 *   { "subaddress_minor": 12 }
 *
 * Returns 0 on success and writes totals (piconero) to out parameters.
 */
int32_t wallet_get_balance_with_filter(
    const char* wallet_id,
    const char* filter_json,
    uint64_t* out_total,
    uint64_t* out_unlocked
);

/* ===== Transfers: preview/send ===== */

/*
 * Preview fee and max-sendable amount for a sweep ("send all") to a single destination.
 * Semantics:
 *   - The recipient amount is computed by the core (roughly unlocked - fee).
 *   - Returns JSON:
 *       { "amount": <uint64>, "fee": <uint64> }
 *     where `amount` is the amount to send to the recipient in piconero.
 * Notes:
 *   - If unlocked funds are insufficient to pay the fee, returns an error.
 *   - This is designed for "Send Max" UX.
 * Caller must free the returned string with walletcore_free_cstr.
 */
char* wallet_preview_sweep(
    const char* wallet_id,
    const char* node_url,
    const char* to_address,
    uint8_t ring_len
);

/*
 * Sweep ("send all") to a single destination.
 * Semantics:
 *   - The recipient amount is computed by the core (roughly unlocked - fee).
 *   - Returns JSON:
 *       { "txid": "<hex>", "amount": <uint64>, "fee": <uint64> }
 * Caller must free the returned string with walletcore_free_cstr.
 */
char* wallet_sweep(
    const char* wallet_id,
    const char* node_url,
    const char* to_address,
    uint8_t ring_len
);

/*
 * Preview fee and max-sendable amount for a sweep ("send all") with an optional input filter.
 * filter_json is a JSON object (or NULL). Useful for sweeping a specific subaddress.
 * Returns JSON:
 *   { "amount": <uint64>, "fee": <uint64> }
 * Caller must free the returned string with walletcore_free_cstr.
 */
char* wallet_preview_sweep_with_filter(
    const char* wallet_id,
    const char* node_url,
    const char* to_address,
    const char* filter_json,
    uint8_t ring_len
);

/*
 * Sweep ("send all") with an optional input filter (e.g., constrain to a subaddress).
 * Returns JSON:
 *   { "txid": "<hex>", "amount": <uint64>, "fee": <uint64> }
 * Caller must free the returned string with walletcore_free_cstr.
 */
char* wallet_sweep_with_filter(
    const char* wallet_id,
    const char* node_url,
    const char* to_address,
    const char* filter_json,
    uint8_t ring_len
);

/*
 * Send to a single destination. Returns JSON:
 *   { "txid": "<hex>", "fee": <uint64> }
 * Caller must free the returned string with walletcore_free_cstr.
 */
char* wallet_send(
    const char* wallet_id,
    const char* node_url,
    const char* to_address,
    uint64_t amount_piconero,
    uint8_t ring_len
);

/*
 * Preview fee for multi-destination transfer. destinations_json is a JSON array:
 *   [ { "address": "<addr>", "amount": <uint64> }, ... ]
 * Returns a JSON string (e.g., { "fee": <uint64> }); caller must free it.
 */
char* wallet_preview_fee(
    const char* wallet_id,
    const char* node_url,
    const char* destinations_json,
    uint8_t ring_len
);

/*
 * Send with optional input filter (e.g., constrain to a subaddress).
 * filter_json is a JSON object (or NULL). Returns JSON { "txid": "<hex>", "fee": <uint64> }.
 * Caller must free the returned string.
 */
char* wallet_send_with_filter(
    const char* wallet_id,
    const char* node_url,
    const char* destinations_json,
    const char* filter_json,
    uint8_t ring_len
);

/*
 * Preview fee with optional input filter. Returns JSON (e.g., { "fee": <uint64> }).
 * Caller must free the returned string.
 */
char* wallet_preview_fee_with_filter(
    const char* wallet_id,
    const char* node_url,
    const char* destinations_json,
    const char* filter_json,
    uint8_t ring_len
);

/* Force rescan from a given restore height (resets cache/state). */
int32_t wallet_force_rescan_from_height(
    const char* wallet_id,
    uint64_t new_restore_height
);

WALLETCORE_EXTERN_C_END

#endif /* MONEROWALLETCORE_H */