# MoneroWalletCoreFFI

A cross‑platform Swift Package that exposes a safe Swift wrapper around a Rust Monero wallet core via a stable C ABI.

- Apple (iOS + macOS): ships a prebuilt `MoneroWalletCore.xcframework` (binary target) so clients do not need Rust.
- Linux (Vapor): links against a system‑installed `libwalletcore.so` (via `pkg-config`), so servers do not need Rust at build time either.

This README explains how to add the package with SwiftPM on Apple platforms and how to set up Linux so Vapor apps “just work.”


## Supported platforms

- iOS 16+
- macOS 13+
- Linux (x86_64 and aarch64, tested on Ubuntu runners)


## Add with Swift Package Manager (SPM)

You have two ways to consume this package:

1) Apple (iOS and macOS) — Prebuilt xcframework (no Rust required)
- The package contains `Artifacts/MoneroWalletCore.xcframework` and declares a binary target pointing to it.
- When you add the package, SPM uses that xcframework directly.

2) Linux (Vapor) — System library (no Rust required)
- The package declares a `systemLibrary` target `CLibMoneroWalletCore` that links against an installed `libwalletcore.so`.
- At build time, SPM asks `pkg-config` for headers and link flags and links your app against `libwalletcore.so` already installed on the system.


### iOS/macOS (Xcode)

- File > Add Packages… and paste the repository URL (branch “main/master” or a specific revision).
- Select the `MoneroWalletCoreFFI` library product.
- That’s it — the xcframework is used automatically by SPM.

Notes:
- Apple artifacts are built as static libraries in the xcframework, so you don’t need to worry about runtime search paths on iOS/macOS.
- No Rust toolchain is needed on client machines.


### iOS/macOS (Package.swift consumer)

```swift
// Inside your app’s Package.swift
dependencies: [
    .package(url: "https://github.com/<you>/<repo>.git", branch: "main")
],
targets: [
    .target(
        name: "YourApp",
        dependencies: [
            .product(name: "MoneroWalletCoreFFI", package: "repo-name")
        ]
    )
]
```

Replace `<you>/<repo>` and `repo-name` with your actual GitHub org/repo and package name.


## Linux (Vapor) setup

SwiftPM on Linux will not download or build the Rust library for you. It expects a system‑installed `libwalletcore.so` and header, found via `pkg-config walletcore`.

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
   pkg-config --libs --cflags walletcore
   # Should print something like: -I/usr/local/include -L/usr/local/lib -lwalletcore
   ```

4. Build your Vapor app that depends on `MoneroWalletCoreFFI`. SwiftPM will find the library via `pkg-config`.

B) Bake into your Docker image
- Run the same install script in your Dockerfile (or copy the .so and header to `/usr/local` and write a minimal `walletcore.pc`).
- Example sketch:
   ```
   FROM swift:5.9-amazonlinux2

   # Install build tools as needed…
   # Build & install libwalletcore.so
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

- On Apple, SPM uses the xcframework committed in this package — seamless.
- On Linux, SPM’s `systemLibrary` requires the `.so` to be present on the build system. SPM does not fetch `.so` binaries the way it does xcframeworks.
- The closest to “automatic” on Linux is to bake `libwalletcore.so` (and `walletcore.pc`) into your Docker base image (or AMI), so builds don’t need extra steps. That’s why we provide `Scripts/install_linux.sh`.

If you really want to ship `libwalletcore.so` alongside your app (without system install), you still need at build time:
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

Preview fee and send:
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
  - Builds Apple static libs across supported Apple triples and packages `Artifacts/MoneroWalletCore.xcframework`.
- `Scripts/install_linux.sh`
  - Installs `libwalletcore.so`, `walletcore.h`, and `walletcore.pc` to a prefix (default `/usr/local`), and can be used in Docker/CI.

These scripts let you generate/update artifacts without manual Xcode/Rust setup on consumer machines.


## CI overview

- Continuous build on pushes/PRs (no releases) validates that artifacts build on Apple/Linux and uploads them per commit as workflow artifacts.
- An optional release workflow (triggered on tags) can publish the xcframework zip and Linux tarballs as GitHub Release assets when you’re ready to version the artifacts.


## Troubleshooting

- “pkg-config: walletcore not found” (Linux)
  - Ensure you ran `./Scripts/install_linux.sh` (or installed the library and `walletcore.pc` yourself).
  - Verify: `pkg-config --libs --cflags walletcore`
  - If installing to a nonstandard prefix, set `PKG_CONFIG_PATH=/your/prefix/lib/pkgconfig`.

- “cannot find -lwalletcore” at link time (Linux)
  - Make sure the `.so` was installed to a directory known to the linker (e.g., `/usr/local/lib`) and that `pkg-config` emits `-L` pointing there.

- “error while loading shared libraries: libwalletcore.so” at runtime (Linux)
  - Ensure the runtime loader can find it: `sudo ldconfig`, or set `LD_LIBRARY_PATH=/usr/local/lib` (or your prefix).

- iOS/mac: “No such module MoneroWalletCoreFFI”
  - Make sure the package is added to the target’s dependencies and the project resolves package resources. The xcframework is included in the repo.


## FAQ

Q: Can SPM download the Linux `.so` automatically?
- No. SPM’s binary target mechanism is designed around xcframeworks for Apple platforms. On Linux, the standard pattern is to link against a system library discovered via `pkg-config`.

Q: Can I keep using a “lib/release” folder inside the app repo?
- You can, but you still need headers and `pkg-config` to make SPM aware of include/link flags, and you must ensure the runtime loader finds the `.so`. It’s usually simpler to install the library system‑wide (or bake into a Docker image) and let `pkg-config` do the rest.

Q: Do Apple clients need Rust?
- No. The xcframework is prebuilt and shipped in this package, so iOS/mac apps just add the package and go.
