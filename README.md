# MoneroWalletCoreFFI

`MoneroWalletCoreFFI` is the shared wallet-core repository used by NexaWal and related apps.

- Swift package / product name: `MoneroWalletCoreFFI`
- Repository: `https://github.com/cacaosteve/MoneroWalletCoreFFI`
- **Active consumer branch:** `main` (source-first; Apple release assets are fetched by SwiftPM)
- Rust wallet core: built from [`cacaosteve/monero-oxide`](https://github.com/cacaosteve/monero-oxide) `perf/scanner-hotpath-only` (pinned rev in `monero-oxide-output/Cargo.toml`)
- Consumers: [nexawal](https://github.com/cacaosteve/nexawal) (SPM), [nexawal-android](https://github.com/cacaosteve/nexawal-android) (git submodule)
- License: [MIT](LICENSE)

Platform outputs:
- Apple (iOS device + simulator + macOS): versioned XCFramework release asset (`walletcore-v*`)
- Android: source-built `.so` files under `.build/artifacts/android/{arm64-v8a,x86_64}/` via `Scripts/build_android.sh`
- Linux (Vapor/server): system-installed `libmonerowalletcore.so` via `pkg-config`

This README explains how to consume the package on Apple platforms, how Linux linking works, and how the native artifacts are built.

### Wallet-core behavior (high level)

- Open from mnemonic; refresh/scan against a Monero daemon
- Pruned block ownership scans run concurrently, with results applied and checkpointed in block
  order. The automatic limit is eight workers on desktop and four on iOS/Android; set
  `WALLETCORE_SCAN_PAR=1` for the serial baseline or a positive value to override the worker count.
- Desktop, Catalyst, and server builds default to 500-block range responses with ordered parallel
  response decoding. iOS and Android retain the 75-block, serial-decoding memory profile.
  `WALLETCORE_BULK_FETCH_BATCH`, `WALLETCORE_UPSTREAM_BLOCK_BATCH`, and
  `WALLETCORE_RANGE_DECODE_PAR` remain available as explicit diagnostic overrides.
- Balance, transfers, subaddress derivation, fee preview
- Send / sweep via **prepare → durable local persist → relay** (apps recover pending prepares across relaunch)
- Secret hygiene: in-memory keys (not a long-lived mnemonic string); KI/amount diagnostic dumps are env-gated

### Security defaults

Custom daemon HTTP reads are bounded before JSON/EPEE decoding: 16 MiB for JSON,
64 MiB for binary responses on iOS/Android, and 128 MiB on desktop. Chunked bodies
are bounded too; exceeding the limit returns an error, never a truncated success.

Sensitive core console/file logging is disabled in standard builds. Development
diagnostics require **both** the `diagnostic-logging` Cargo feature and
`WALLETCORE_DIAGNOSTICS=1`. Do not enable this feature in distributed artifacts or
share diagnostic logs from real wallets. Explicit benchmark RPC timing telemetry
remains separate and opt-in.


## Supported platforms

- iOS 16+
- macOS 13+
- Linux (x86_64 and aarch64, tested on Ubuntu runners)


## Add with Swift Package Manager (SPM)

You have two ways to consume this package:

1) Apple (iOS and macOS) — Versioned release xcframework (no Rust required)
- `Package.swift` points to the checked-in release URL and checksum for the current `walletcore-v*` asset.
- When you add the package, SPM downloads and verifies that XCFramework. The binary is not stored in Git.

2) Linux (Vapor) — System library (no Rust required)
- The package declares a `systemLibrary` target `CLibMoneroWalletCore` that links against an installed `libmonerowalletcore.so`.
- At build time, SPM asks `pkg-config` for headers and link flags and links your app against `libmonerowalletcore.so` already installed on the system.


### iOS/macOS (Xcode)

- File > Add Packages… and paste `https://github.com/cacaosteve/MoneroWalletCoreFFI.git`
- Prefer branch **`main`** (or pin a specific revision). This is what NexaWal uses.
- Select the `MoneroWalletCoreFFI` library product.
- That’s it — SPM downloads and verifies the release XCFramework automatically.

Notes:
- Apple artifacts are built as static libraries in the xcframework (device + simulator + macOS), so you don’t need runtime search paths on iOS/macOS.
- No Rust toolchain is needed on client machines.
- Use **File → Packages → Update to Latest Package Versions** to float to the tip of the branch.


### iOS/macOS (Package.swift consumer)

```swift
// Inside your app’s Package.swift
dependencies: [
    .package(
        url: "https://github.com/cacaosteve/MoneroWalletCoreFFI.git",
        branch: "main"
    )
],
targets: [
    .target(
        name: "YourApp",
        dependencies: [
            .product(name: "MoneroWalletCoreFFI", package: "MoneroWalletCoreFFI")
        ]
    )
]
```

### Android (NexaWal pattern)

- Add this repo as a git submodule tracking `main`.
- Copy (or Gradle-sync) `.build/artifacts/android/<abi>/libmonerowalletcore.so` into your module `jniLibs`.
- Rebuild source artifacts after core changes:

```bash
PROFILE=release CARGO_FEATURES=compile-time-generators ./Scripts/build_android.sh
```

The Android `.so` files are generated under `.build/artifacts/android/` and are
not committed. Android consumers may use the matching `MoneroWalletCore-android.zip`
release asset for a fast local build, while F-Droid and Wallet Scrutiny should
use the from-source Gradle path documented by `nexawal-android`.

## Linux (Vapor) setup

SwiftPM on Linux will not download or build the Rust library for you. It expects a system‑installed `libmonerowalletcore.so` and header, found via `pkg-config monerowalletcore`.

You have two convenient options:

A) System install (recommended; simplest with Docker/CI)
- Build the Rust shared library for your target once, then install it onto the system with the helper script.
- Your Vapor app can then add this package, and SPM will link your app against the installed library.

Steps:
1. Build the Rust library for your Linux target:
   ```
   cd MoneroWalletCoreFFI/monero-oxide-output
   cargo build --release --target x86_64-unknown-linux-gnu
   ```
   (Use `aarch64-unknown-linux-gnu` for ARM64 servers.)

2. Install to the system (default prefix `/usr/local`):
   ```
   cd MoneroWalletCoreFFI
   PREFIX=/usr/local TARGET=x86_64-unknown-linux-gnu ./Scripts/install_linux.sh
   sudo ldconfig  # update shared library cache
   ```

3. Verify:
   ```
   pkg-config --libs --cflags monerowalletcore
   # Should print something like: -I/usr/local/include -L/usr/local/lib -lmonerowalletcore
   ```

4. Build your Vapor app that depends on `MoneroWalletCoreFFI`. SwiftPM will find the library via `pkg-config`.

B) Bake into your Docker image
- Run the same install script in your Dockerfile (or copy the .so and header to `/usr/local` and write a minimal `monerowalletcore.pc`).
- Example sketch:
   ```
   FROM swift:5.9-amazonlinux2

   # Install build tools as needed…
   # Build & install libmonerowalletcore.so
   COPY MoneroWalletCoreFFI /opt/MoneroWalletCoreFFI
   RUN cd /opt/MoneroWalletCoreFFI/monero-oxide-output && \
       cargo build --release --target x86_64-unknown-linux-gnu && \
       cd /opt/MoneroWalletCoreFFI && \
       PREFIX=/usr/local TARGET=x86_64-unknown-linux-gnu ./Scripts/install_linux.sh && \
       ldconfig

   # Now build your Vapor app which depends on MoneroWalletCoreFFI…
   ```

After this, any Vapor app that adds `MoneroWalletCoreFFI` via SPM will compile and link automatically on Linux (no vendored `.so` inside the app repo is required).


## Can Linux be “automatic” like mac?

- On Apple, SPM downloads the checksum-pinned XCFramework release asset — seamless.
- On Linux, SPM’s `systemLibrary` requires the `.so` to be present on the build system. SPM does not fetch `.so` binaries the way it does xcframeworks.
- The closest to “automatic” on Linux is to bake `libmonerowalletcore.so` (and `monerowalletcore.pc`) into your Docker base image (or AMI), so builds don’t need extra steps. That’s why we provide `Scripts/install_linux.sh`.

If you really want to ship `libmonerowalletcore.so` alongside your app (without system install), you still need at build time:
- Headers and `pkg-config` metadata (or custom SwiftPM flags) so SPM can find and link to the .so.
- At runtime, you must ensure the loader can find the library (via `LD_LIBRARY_PATH` or `ldconfig` or rpath).
This approach is more fragile; system install (or a base image with the library pre-installed) is cleaner.


## Swift usage examples

Open, refresh, and get balance:
```swift
import MoneroWalletCoreFFI

try WalletCoreFFIClient.openWalletFromMnemonic(
    walletId: "main_hot",
    mnemonic: "<25-word-monero-mnemonic>",
    restoreHeight: 0,
    mainnet: true
)

let lastScanned = try WalletCoreFFIClient.refreshWallet(
    walletId: "main_hot",
    nodeURL: "http://127.0.0.1:18081"
)

let (total, unlocked) = try WalletCoreFFIClient.getBalance(walletId: "main_hot")
// Use totals…
```

Cache import/export:
```swift
// Import existing cache (if present)
if let cached: Data = /* load from DB/file */ nil {
    try WalletCoreFFIClient.importCache(walletId: "main_hot", cacheBlob: cached)
}

// After refresh, export cache and persist
if let exported = try WalletCoreFFIClient.exportCache(walletId: "main_hot") {
    // Save to DB/file
}
```

Preview fee and send (apps typically prepare → persist → relay; `send` remains available as a convenience wrapper):
```swift
let fee = try WalletCoreFFIClient.previewFee(
    walletId: "main_hot",
    destinations: [.init(address: "<dest>", amount: 1_000_000_000_000)],
    ringLen: 16,
    nodeURL: "http://127.0.0.1:18081"
)

let (txid, paidFee) = try WalletCoreFFIClient.send(
    walletId: "main_hot",
    toAddress: "<dest>",
    amountPiconero: 1_000_000_000_000,
    ringLen: 16,
    nodeURL: "http://127.0.0.1:18081"
)
```

Observed outputs:
```swift
let json = try WalletCoreFFIClient.exportOutputsJSON(walletId: "main_hot")
let envelope = try WalletCoreFFIClient.observedOutputs(walletId: "main_hot")
```

Address derivation:
```swift
// From mnemonic
let primary = try WalletCoreFFIClient.derivePrimaryAddressFromMnemonic("<mnemonic>", mainnet: true)

// From raw seed
let address = try WalletCoreFFIClient.deriveAddressFromSeed(
    seedData: seedBytes, accountIndex: 0, subaddressIndex: 12, mainnet: true
)
```


## Scripts in this repo

- `Scripts/build_xcframework.sh`
  - Builds Apple static libs across supported Apple triples and packages `.build/artifacts/MoneroWalletCore.xcframework`.
- `Scripts/build_android.sh`
  - Builds Android `.so` artifacts for `arm64-v8a` and `x86_64` by default and can install them into `nexawal-android`.
- `Scripts/package_release_artifacts.sh`
  - Creates release zips, a build manifest, and SHA-256 checksums for CI/GitHub Releases.
- `Scripts/install_linux.sh`
  - Installs `libmonerowalletcore.so`, `monerowalletcore.h`, and `monerowalletcore.pc` to a prefix (default `/usr/local`), and can be used in Docker/CI.

These scripts let you generate/update artifacts without manual Xcode/Rust setup on consumer machines.


## CI overview

The `native-release.yml` workflow builds Apple and Android native outputs from
source on pinned Rust/NDK toolchains. On a `walletcore-v*` tag it publishes the
XCFramework and Android zip as release assets. Consumers never need to commit
generated native binaries to this repository.

- Continuous build on pushes/PRs (no releases) validates that artifacts build on Apple/Linux and uploads them per commit as workflow artifacts.
- An optional release workflow (triggered on tags) can publish the xcframework zip and Linux tarballs as GitHub Release assets when you’re ready to version the artifacts.


## Troubleshooting

- “pkg-config: monerowalletcore not found” (Linux)
  - Ensure you ran `./Scripts/install_linux.sh` (or installed the library and `monerowalletcore.pc` yourself).
  - Verify: `pkg-config --libs --cflags monerowalletcore`
  - If installing to a nonstandard prefix, set `PKG_CONFIG_PATH=/your/prefix/lib/pkgconfig`.

- “cannot find -lmonerowalletcore” at link time (Linux)
  - Make sure the `.so` was installed to a directory known to the linker (e.g., `/usr/local/lib`) and that `pkg-config` emits `-L` pointing there.

- “error while loading shared libraries: libmonerowalletcore.so” at runtime (Linux)
  - Ensure the runtime loader can find it: `sudo ldconfig`, or set `LD_LIBRARY_PATH=/usr/local/lib` (or your prefix).

- iOS/mac: “No such module MoneroWalletCoreFFI”
  - Make sure the package is added to the target’s dependencies and the project resolves package resources. The xcframework is included in the repo.


## FAQ

Q: Can SPM download the Linux `.so` automatically?
- No. SPM’s binary target mechanism is designed around xcframeworks for Apple platforms. On Linux, the standard pattern is to link against a system library discovered via `pkg-config`.

Q: Can I keep using a “lib/release” folder inside the app repo?
- You can, but you still need headers and `pkg-config` to make SPM aware of include/link flags, and you must ensure the runtime loader finds the `.so`. It’s usually simpler to install the library system‑wide (or bake into a Docker image) and let `pkg-config` do the rest.

Q: Do Apple clients need Rust?
- No. The XCFramework is built by CI and downloaded from the versioned release asset, so iOS/mac apps just add the package and go.

## License

[MIT](LICENSE). Vendored / downstream crates (including `monero-oxide`) keep their own licenses; retain those notices when redistributing binaries.
