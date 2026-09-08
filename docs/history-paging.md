# Local transaction-history query API

The additive API is available as C 'wallet_query_transfers_json', Swift 'queryTransfers',
Rust 'api::query_transfers', and Android 'WalletCore.queryTransfersJson'. It requires a native
library built from the same new source; older release XCFrameworks do not have this symbol.

Example first page:

    {"limit":50,"filter":"all","search":"","offset":0}

Response schema 1 contains wallet_id, revision, total_count, matching_count, pending_count,
offset, next_offset, anchor_offset, scan/tip metadata, and transfers using the existing transfer
model. All amounts/fees remain atomic integers. total_count/pending_count are unfiltered.

Continue with identical filters, response revision, and next_offset. Limits are 1..200; clients
use 50 and keep four pages. Offset > 0 requires a revision. Search is a case-insensitive txid
substring (trimmed, <=256 bytes). filter is all/received/sent/pending. from_timestamp and
to_timestamp are inclusive UTC seconds; unknown timestamps don't match a date constraint.

A changed ledger returns stale_history_cursor. Keep loaded rows and let the user reload.
A new first query may include anchor_txid to locate a previously visible transaction within the
new result set. The returned offset is its containing page; anchor_offset is its absolute result
index. Missing anchors return page zero with anchor_offset=null. Clear anchor_txid before normal
continuations. Exact details can be requested with txid and limit=1.

The in-memory index is bound to the wallet's primary-address/network identity. Content equality
covers all current ledger writers (send, refresh, reorg, cache import). It rebuilds/sorts only when
content changes; tip-only advancement keeps the revision and computes confirmations at read time.
An Arc shares the index across refresh snapshots. Filtering and page serialization happen outside
the wallet-store lock. The core still owns the full ledger; paging bounds UI/FFI payloads, not all
core ledger storage. Content comparison/filtering are O(N), index rebuild/sort O(N log N).

No node RPCs or persisted cache-format changes. Old full-history/export APIs remain available.
The ABI owns the returned C string exactly like existing JSON APIs; free it with the normal free
function. Invalid, oversized, wrong-wallet or stale queries fail rather than returning an
authoritative empty result.

Regression coverage lives in src/ffi/history.rs and Tests/MoneroWalletCoreFFITests/HistoryPagingTests.swift.
No real seed/node is required for those tests.
