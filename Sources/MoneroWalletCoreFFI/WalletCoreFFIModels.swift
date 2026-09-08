import Foundation

public extension WalletCoreFFIClient {
    struct Destination: Encodable {
        public let address: String
        public let amount: UInt64

        public init(address: String, amount: UInt64) {
            self.address = address
            self.amount = amount
        }
    }

    struct SendResult: Decodable {
        public let txid: String
        public let fee: UInt64
    }

    struct PreparedSend: Codable, Equatable {
        public let txid: String
        public let amount: UInt64
        public let fee: UInt64
        public let signedTxHex: String
        /// Primary address, including network. Nil legacy journals are never auto-relayed.
        public let walletBinding: String?

        private enum CodingKeys: String, CodingKey {
            case txid
            case amount
            case fee
            case signedTxHex = "signed_tx_hex"
            case walletBinding = "wallet_binding"
        }
    }

    struct RelayResult: Decodable, Equatable {
        public let txid: String
        public let status: String
    }

    struct FeeResult: Decodable {
        public let fee: UInt64
    }

    struct Transfer: Decodable, Equatable, Sendable {
        public let txid: String
        public let direction: String
        public let amount: UInt64
        public let fee: UInt64?
        public let height: UInt64?
        public let timestamp: UInt64?
        public let confirmations: UInt64
        public let isPending: Bool
        public let subaddressMajor: UInt32?
        public let subaddressMinor: UInt32?

        private enum CodingKeys: String, CodingKey {
            case txid
            case direction
            case amount
            case fee
            case height
            case timestamp
            case confirmations
            case isPending = "is_pending"
            case subaddressMajor = "subaddress_major"
            case subaddressMinor = "subaddress_minor"
        }
    }

    /// A transaction-history snapshot returned by WalletCore.
    ///
    /// `schemaVersion == 0` identifies the legacy bare-array payload. Versioned
    /// snapshots include scan metadata so callers can associate rows with the
    /// exact WalletCore checkpoint that produced them.
    struct TransferHistory: Equatable {
        public let schemaVersion: UInt32
        public let walletId: String?
        public let lastScannedHeight: UInt64?
        public let chainHeight: UInt64?
        public let chainTime: UInt64?
        public let transfers: [Transfer]
    }

    struct SweepPreviewResult: Decodable {
        public let amount: UInt64
        public let fee: UInt64
    }

    struct SweepSendResult: Decodable {
        public let txid: String
        public let amount: UInt64
        public let fee: UInt64
    }

    struct SyncStatus: Equatable {
        public let chainHeight: UInt64
        public let chainTime: UInt64
        public let lastRefreshTimestamp: UInt64
        public let lastScanned: UInt64
        public let restoreHeight: UInt64

        public init(chainHeight: UInt64, chainTime: UInt64, lastRefreshTimestamp: UInt64, lastScanned: UInt64, restoreHeight: UInt64) {
            self.chainHeight = chainHeight
            self.chainTime = chainTime
            self.lastRefreshTimestamp = lastRefreshTimestamp
            self.lastScanned = lastScanned
            self.restoreHeight = restoreHeight
        }
    }
}

public struct WalletObservedOutputsEnvelope: Decodable {
    public struct ObservedOutput: Decodable {
        public let txHash: String
        public let indexInTx: UInt64
        public let amount: UInt64
        public let blockHeight: UInt64
        public let subaddressMajor: UInt32
        public let subaddressMinor: UInt32
        public let isCoinbase: Bool
        public let spent: Bool
        public let confirmations: UInt64
        public let keyImageHex: String
        public let timelock: WalletObservedTimelock
        public let unlockHeight: UInt64
        public let unlocked: Bool
        public let unlockTime: UInt64?
    }

    public let walletId: String
    public let restoreHeight: UInt64
    public let lastScannedHeight: UInt64
    public let chainHeight: UInt64
    public let chainTime: UInt64
    public let outputs: [ObservedOutput]

    enum CodingKeys: String, CodingKey {
        case walletId = "wallet_id"
        case restoreHeight = "restore_height"
        case lastScannedHeight = "last_scanned_height"
        case chainHeight = "chain_height"
        case chainTime = "chain_time"
        case outputs
    }
}

public enum WalletObservedTimelock: Decodable {
    case none
    case block(height: UInt64)
    case time(timestamp: UInt64)

    enum CodingKeys: String, CodingKey {
        case kind
        case height
        case timestamp
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        let kind = try container.decode(String.self, forKey: .kind)
        switch kind {
        case "none":
            self = .none
        case "block":
            self = .block(height: try container.decode(UInt64.self, forKey: .height))
        case "time":
            self = .time(timestamp: try container.decode(UInt64.self, forKey: .timestamp))
        default:
            throw DecodingError.dataCorruptedError(
                forKey: .kind,
                in: container,
                debugDescription: "Unknown timelock kind \(kind)"
            )
        }
    }
}

extension WalletObservedOutputsEnvelope.ObservedOutput {
    enum CodingKeys: String, CodingKey {
        case txHash = "tx_hash"
        case indexInTx = "index_in_tx"
        case amount
        case blockHeight = "block_height"
        case subaddressMajor = "subaddress_major"
        case subaddressMinor = "subaddress_minor"
        case isCoinbase = "is_coinbase"
        case spent
        case confirmations
        case keyImageHex = "key_image_hex"
        case timelock
        case unlockHeight = "unlock_height"
        case unlocked
        case unlockTime = "unlock_time"
    }
}
