# Production hardening follow-up — 2026-09-05

## Status

Local implementation and synthetic verification, not a production certification or published
release. No personal wallet, mnemonic, live-node scan, or funded transaction was needed.
No PRs, pushes, tags, app installs, or node/deployment changes were made in this pass.
The earlier uncommitted history/security work and unrelated local edits were preserved.

## Corrections

- Native EPEE unknown-value skipping now rejects nesting deeper than 64 and consumes a bounded
  work budget. A regression uses the 400 KB / 100,000-level input that previously overflowed the
  stack. Declared oversized arrays fail before iteration. Parser errors no longer leak a newly
  allocated string on every malformed response.
- GPUI exact/send-max preparation checks the approved fee ceiling before writing a journal or
  relaying. A higher fee requires a fresh preview. Existing signed-journal recovery remains
  idempotent and does not create another transaction.
- GPUI preview completions are invalidated by form changes and checked against the current
  wallet session, node, source and exact amount. Changes to fiat conversion invalidate approval;
  loss of a usable rate clears fiat amount input instead of reinterpreting it as XMR. Lock hides
  the wallet immediately, including during a stalled preview/send/recovery operation. Reopening,
  replacement and removal wait for native ownership to end; late results stay hidden.
- Newly prepared transaction JSON includes `wallet_binding`, the primary address including its
  network. Native relay checks it against the current wallet before decoding the signed blob or
  making any RPC. Swift and Kotlin preserve this field when a journal is re-encoded.
- Explicit wallet replacement/removal archives active pending-send recovery files instead of
  letting a replacement wallet auto-relay them. Normal refresh/reopen does not discard the journal.
- Modern cache file readers in Swift, Kotlin and GPUI enforce 128 MiB before allocation and while
  reading; journal reads enforce 8 MiB. Native cache import enforces a 128 MiB bincode decode
  budget, rejects oversized FFI input before constructing a slice, and rejects trailing bytes.
  Export checks encoded size before serialization and serializes outside the wallet-store lock.
  Existing valid cache v3 encoding is retained.
- Empty GPUI history date fields no longer copy the wallet address as a fallback.

## Pending-send compatibility

Legacy journals without `wallet_binding` remain readable but native relay deliberately refuses
them. Foreign-wallet/network journals are refused too. Data is retained for explicit recovery,
not silently deleted or assigned a new binding. Do not “repair” these by blindly adding the
current address: that would bypass the safety check. Resolve any real pending journal before
public rollout. An address label is an identity check, not cryptographic authentication against
a malicious actor who can rewrite both the application and its private files.

## Verification

| Check | Result |
| --- | --- |
| WalletCore `cargo test --lib --locked --offline` | 74 passed; 6 opt-in/live-fixture tests ignored |
| Explicit synthetic 100,000-output/cache/history test | Passed separately; no RPC |
| Swift `NexaWalLogic` tests | 64 passed |
| Swift WalletCore wrapper tests with rebuilt local XCFramework | 9 passed |
| Actual iOS TransactionsModel harness with local core | 3 passed |
| Android logic / app unit and Robolectric tests | 68 / 29 passed |
| GPUI tests with `ui-tests` and local WalletCore override | 71 passed |
| Android source-built debug and release APKs | Passed, arm64-v8a and x86_64 native libraries |
| GPUI macOS release build with local WalletCore override | Passed |
| Apple release XCFramework | All seven Rust target builds passed |
| iOS Release app build with local XCFramework | Passed; code signing disabled |
| Catalyst Release app build with local XCFramework | Passed; code signing disabled |

The 100,000-entry fixture exports outputs, imports/rebuilds the ledger, exports the full ledger
snapshot, imports again, then queries first/middle/last pages and verifies balance. Full cache:
27,900,227 bytes. `/usr/bin/time -l` measured 227,786,752 bytes maximum RSS (about 217 MiB) and
zero swaps for the isolated macOS debug test process. This includes intermediate snapshots;
it is not a phone measurement or an end-to-end sync benchmark. UI page caches remain four
50-record pages; WalletCore still stores the whole ledger and index, so total memory is O(N).

Run the synthetic check without setting any mnemonic:

```sh
cd /Users/steve/supermegamartandwalletcore/MoneroWalletCoreFFI/monero-oxide-output
cargo test --lib --locked --offline synthetic_large_wallet_cache_and_paging -- --ignored --nocapture
```

Apple verification used `/tmp/nexawal-hardening-apple.ApsAY7/MoneroWalletCore.xcframework` and
the adjacent local Swift package/workspace. It did not change the production package URL.
Android's dirty submodule source mirrors the native fixes for these local builds. Do not run a
submodule reset/update that discards them before publishing their actual WalletCore commit.

GPUI local test/build command (Cargo will temporarily rewrite its lock entry):

```sh
cd /Users/steve/supermegamartandwalletcore/nexawal-gpui
cargo test --features ui-tests --offline --config 'patch."https://github.com/cacaosteve/MoneroWalletCoreFFI.git".walletcore.path="../MoneroWalletCoreFFI/monero-oxide-output"'
```

Do not commit that temporary path resolution. All published pins remain unchanged until rollout.

## Pre-commit review corrections

- iOS and Android now accept a fresh, verified completed empty history (for example, a reorg
  removing the last receive). History and balance are published together without the old UI
  spinner/interruption marker vetoing the result. Ordinary interrupted/cache reads retain their
  protections. Clean empty wallets no longer trigger repeated empty-history recovery rescans.
- Android final publication changes a session epoch, so older balance/history reads cannot
  overwrite the completed result. Tests exercise the same publisher used by WalletManager.
- GPUI lock now clears presentation immediately while preserving native operation ownership
  and pending-send recovery. Tests exercise Home's actual lock, blocked reopen/removal and late
  completion handlers using a temporary data directory, without a wallet or RPC.
- Follow-up verification: Swift logic 66 passed; Android logic/app tests 69/31 passed; GPUI
  tests 73 passed. Android debug APK, GPUI Release and unsigned iOS/Catalyst Release builds passed
  with the same local WalletCore overrides. These are synthetic/host checks, not device validation.

The original verification table above records the preceding hardening pass; this follow-up
does not republish WalletCore or change consumer pins.

## Dependency gate

`cargo deny check advisories` fetched the advisory database and exited nonzero. It reported
maintenance advisories, not vulnerability-class advisories, for these resolved Rust dependencies:

| Package | Used by | Advisory |
| --- | --- | --- |
| bincode 1.3.3 | WalletCore cache codec | [RUSTSEC-2025-0141](https://rustsec.org/advisories/RUSTSEC-2025-0141) |
| paste 1.0.15 | Cuprate EPEE build macros; also GPUI dependencies | [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436) |
| rustybuzz 0.20.1 | GPUI SVG/font stack | [RUSTSEC-2026-0206](https://rustsec.org/advisories/RUSTSEC-2026-0206) |
| ttf-parser 0.25.1 | GPUI font/SVG stack | [RUSTSEC-2026-0192](https://rustsec.org/advisories/RUSTSEC-2026-0192) |

No advisory suppressions, cache-codec migration, GPUI rebase or fork changes were made merely
to obtain a green check. Choose a maintained migration path or explicitly document a reviewed,
time-bounded exception before distribution. This was a RustSec check, not an exhaustive advisory
assessment of Android/Maven dependencies, Apple frameworks, operating systems or build tooling.

## Remaining release gates

1. Decide the dependency-maintenance disposition above. A cache-codec migration needs separate
   compatibility tests; updating Zed/GPUI transitives needs platform builds and UI checks.
2. Use a disposable test wallet for physical iOS/Android auth cancellation, background/foreground,
   Wi-Fi/LTE change, offline retry, force-quit/reopen and pending-send recovery checks. Large-wallet
   transaction activity is unnecessary. If funded test sends are unavailable, use a controlled
   test harness and clearly leave real-device send/relay validation outstanding.
3. Check small-screen/large-font history, scrolling/filtering, QR/copy/paste, accessibility and
   task-switcher privacy. Platform authentication/idle-lock policy is not yet identical everywhere.
4. Publish one matching WalletCore source/artifact release, update SwiftPM URL/checksum/resolution,
   Android submodule and GPUI Cargo revision/lock together, and rebuild from those exact pins.
5. Validate actual signed distribution artifacts and clean-machine/source reproducibility. The
   unsigned Apple build and local Android builds are not App Store/F-Droid/Wallet Scrutiny approval.

These gates remain open; the source fixes should not be described as a finished production release.
