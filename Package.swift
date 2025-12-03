 // swift-tools-version: 5.9
 import PackageDescription

 let package = Package(
     name: "WalletCoreFFI",
     defaultLocalization: "en",
     platforms: [
         .iOS(.v16),
         .macOS(.v13)
     ],
     products: [
         .library(name: "WalletCoreFFI", targets: ["WalletCoreFFI"])
     ],
     targets: [
         // Apple platforms: prebuilt xcframework
         .binaryTarget(
             name: "WalletCore",
             path: "Artifacts/WalletCore.xcframework"
         ),

         // Linux: system library target that links against libwalletcore.so (no pkgConfig/providers)
         .systemLibrary(
             name: "CLibWalletCore",
             path: "CLibWalletCore"
         ),

         // Thin Swift wrapper that conditionally links to the appropriate low-level target
         .target(
             name: "WalletCoreFFI",
             dependencies: [
                 .target(name: "WalletCore", condition: .when(platforms: [.iOS, .macOS])),
                 .target(name: "CLibWalletCore", condition: .when(platforms: [.linux]))
             ],
             path: "Sources/WalletCoreFFI",
             swiftSettings: [
                 .define("WALLETCORE_APPLE", .when(platforms: [.iOS, .macOS])),
                 .define("WALLETCORE_LINUX", .when(platforms: [.linux]))
             ],

         ),

         .executableTarget(
             name: "WalletCoreFFI_Smoke",
             dependencies: ["WalletCoreFFI"],
             path: "Utilities/Smoke",
             sources: ["main.swift"]
         )
     ]
 )
