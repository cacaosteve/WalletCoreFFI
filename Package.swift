 // swift-tools-version: 5.9
 import PackageDescription

 let package = Package(
     name: "MoneroWalletCoreFFI",
     defaultLocalization: "en",
     platforms: [
         .iOS(.v16),
         .macOS(.v13)
     ],
     products: [
         .library(name: "MoneroWalletCoreFFI", targets: ["MoneroWalletCoreFFI"])
     ],
     targets: [
         // Apple platforms: prebuilt xcframework
         .binaryTarget(
             name: "MoneroWalletCore",
             path: "Artifacts/MoneroWalletCore.xcframework"
         ),

         // Linux: system library target that links against libwalletcore.so via pkg-config "walletcore"
         .systemLibrary(
             name: "CLibMoneroWalletCore",
             path: "CLibMoneroWalletCore",
             pkgConfig: "walletcore"
         ),

         // Thin Swift wrapper that conditionally links to the appropriate low-level target
         .target(
             name: "MoneroWalletCoreFFI",
             dependencies: [
                 .target(name: "MoneroWalletCore", condition: .when(platforms: [.iOS, .macOS])),
                 .target(name: "CLibMoneroWalletCore", condition: .when(platforms: [.linux]))
             ],
             path: "Sources/MoneroWalletCoreFFI",
             swiftSettings: [
                 .define("WALLETCORE_APPLE", .when(platforms: [.iOS, .macOS])),
                 .define("WALLETCORE_LINUX", .when(platforms: [.linux]))
             ],

         ),

         .executableTarget(
             name: "MoneroWalletCoreFFI_Smoke",
             dependencies: ["MoneroWalletCoreFFI"],
             path: "Utilities/Smoke",
             sources: ["main.swift"]
         )
     ]
 )
