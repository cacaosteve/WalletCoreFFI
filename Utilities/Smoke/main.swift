import Foundation
import MoneroWalletCoreFFI

@main
struct Smoke {
    static func main() {
        let env = ProcessInfo.processInfo.environment

        // Inputs from environment or defaults
        let walletId = env["WALLET_ID"]?.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty ?? "smoke_wallet"
        guard let mnemonic = env["WALLET_MNEMONIC"]?.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty else {
            Smoke.printUsageAndExit("WALLET_MNEMONIC is required")
        }

        let restoreHeight: UInt64 = {
            if let s = env["WALLET_RESTORE_HEIGHT"]?.trimmingCharacters(in: .whitespacesAndNewlines), let v = UInt64(s) {
                return v
            }
            return 0
        }()

        let nodeURL = env["MONERO_URL"]?.trimmingCharacters(in: .whitespacesAndNewlines).nonEmpty

        let mainnet: Bool = {
            let st = env["STAGENET"]?.lowercased()
            switch st {
            case "1", "true", "yes": return false
            default: return true
            }
        }()

        print("==== MoneroWalletCoreFFI Smoke Test ====")
        print("- Version: \(MoneroWalletCoreFFIClient.version())")
        print("- Wallet ID: \(walletId)")
        print("- Network: \(mainnet ? "mainnet" : "stagenet")")
        print("- Restore height: \(restoreHeight)")
        if let nodeURL { print("- Node URL: \(nodeURL)") }

        do {
            // 1) Open/register wallet
            try MoneroWalletCoreFFIClient.openWalletFromMnemonic(
                walletId: walletId,
                mnemonic: mnemonic,
                restoreHeight: restoreHeight,
                mainnet: mainnet
            )
            print("✔ openWalletFromMnemonic: OK")

            // 2) Refresh wallet
            let lastScanned = try MoneroWalletCoreFFIClient.refreshWallet(walletId: walletId, nodeURL: nodeURL)
            print("✔ refreshWallet: OK (lastScanned=\(lastScanned))")

            // 3) Get balances
            let (total, unlocked) = try MoneroWalletCoreFFIClient.getBalance(walletId: walletId)
            print("✔ getBalance: total=\(total) piconero, unlocked=\(unlocked) piconero")

            print("==== Smoke Test Succeeded ====")
            exit(EXIT_SUCCESS)
        } catch {
            print("✖ Smoke Test Failed: \(error.localizedDescription)")
            if let err = error as? MoneroWalletCoreFFIError {
                switch err {
                case .core(let msg): print("Core error: \(msg)")
                case .nullPointer(let msg): print("Null pointer: \(msg)")
                case .decode(let msg): print("Decode error: \(msg)")
                case .invalidArgument(let msg): print("Invalid argument: \(msg)")
                }
            }
            exit(EXIT_FAILURE)
        }
    }

    private static func printUsageAndExit(_ message: String? = nil) -> Never {
        if let message { fputs("Error: \(message)\n", stderr) }
        let usage = """
        Usage (environment variables):
          WALLET_MNEMONIC         25-word mnemonic (required)
          WALLET_ID               Stable id for the wallet (default: "smoke_wallet")
          WALLET_RESTORE_HEIGHT   Starting scan height (default: 0)
          MONERO_URL              Daemon URL, e.g. http://127.0.0.1:18081 (optional)
          STAGENET                If set to 1/true/yes, use stagenet; otherwise mainnet

        Example:
          WALLET_MNEMONIC=\"... 25 words ...\" \\
          WALLET_ID=smoke_wallet \\
          WALLET_RESTORE_HEIGHT=3000000 \\
          MONERO_URL=http://127.0.0.1:38081 \\
          STAGENET=1 \\
          swift run MoneroWalletCoreFFI_Smoke

        """
        fputs(usage + "\n", stderr)
        exit(EXIT_FAILURE)
    }
}

private extension String {
    var nonEmpty: String? { isEmpty ? nil : self }
}
