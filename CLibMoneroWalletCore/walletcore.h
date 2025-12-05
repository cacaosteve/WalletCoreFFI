/*
 * walletcore.h
 *
 * C ABI for the WalletCore Rust library (generated to match Rust cdylib/staticlib).
 * All function signatures are aligned with the Rust declarations (usize -> size_t).
 *
 * Ownership notes:
 * - Functions returning char* allocate a C string on the Rust side. The caller MUST
 *   free it with walletcore_free_cstr(char*).
 * - On error (non-zero return codes), walletcore_last_error_message() may return a
 *   human-readable string that should also be freed with walletcore_free_cstr().
 */

#ifndef WALLETCORE_H
#define WALLETCORE_H

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

/* Frees a C string returned by WalletCore; returns 0 on success. No-op if ptr is NULL. */
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

/*
 * Refresh the wallet against the daemon (node_url). On success, writes last_scanned height.
 * node_url may be NULL to use a default (env/localhost).
 */
int32_t wallet_refresh(
    const char* wallet_id,
    const char* node_url,
    uint64_t* out_last_scanned
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


/* ===== Transfers: preview/send ===== */

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

WALLETCORE_EXTERN_C_END

#endif /* WALLETCORE_H */