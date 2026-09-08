import Foundation
#if canImport(MoneroWalletCore)
import MoneroWalletCore
#else
import CLibMoneroWalletCore
#endif

public extension WalletCoreFFIClient {
    struct HistoryQuery: Encodable, Equatable, Sendable {
        public var limit = 50
        public var offset = 0
        public var revision: String?
        public var filter = "all"
        public var search = ""
        public var fromTimestamp: UInt64?
        public var toTimestamp: UInt64?
        public var txid: String?
        public var anchorTxid: String?
        public init(limit: Int = 50, offset: Int = 0, revision: String? = nil,
                    filter: String = "all", search: String = "", fromTimestamp: UInt64? = nil,
                    toTimestamp: UInt64? = nil, txid: String? = nil, anchorTxid: String? = nil) {
            self.limit = limit; self.offset = offset; self.revision = revision
            self.filter = filter; self.search = search; self.fromTimestamp = fromTimestamp
            self.toTimestamp = toTimestamp; self.txid = txid; self.anchorTxid = anchorTxid
        }
        enum CodingKeys: String, CodingKey {
            case limit, offset, revision, filter, search, txid
            case anchorTxid = "anchor_txid"
            case fromTimestamp = "from_timestamp", toTimestamp = "to_timestamp"
        }
    }
    struct HistoryPage: Decodable, Sendable {
        public let schemaVersion: Int
        public let walletId: String
        public let revision: String
        public let totalCount: Int
        public let matchingCount: Int
        public let pendingCount: Int
        public let offset: Int
        public let nextOffset: Int?
        public let anchorOffset: Int?
        public let lastScannedHeight: UInt64
        public let chainHeight: UInt64
        public let chainTime: UInt64
        public let transfers: [Transfer]
        enum CodingKeys: String, CodingKey {
            case revision, offset, transfers
            case schemaVersion = "schema_version", walletId = "wallet_id"
            case totalCount = "total_count", matchingCount = "matching_count", pendingCount = "pending_count"
            case anchorOffset = "anchor_offset"
            case nextOffset = "next_offset", lastScannedHeight = "last_scanned_height"
            case chainHeight = "chain_height", chainTime = "chain_time"
        }
    }
    static func queryTransfers(walletId: String, query: HistoryQuery = .init()) throws -> HistoryPage {
        let json = String(decoding: try JSONEncoder().encode(query), as: UTF8.self)
        let raw = walletId.withCString { id in json.withCString { wallet_query_transfers_json(id, $0) } }
        let result = try WalletCoreFFISupport.takeCString(raw, context: "wallet_query_transfers_json")
        return try decodeHistoryPageJSON(result, expectedWalletId: walletId)
    }
    static func decodeHistoryPageJSON(_ json: String, expectedWalletId: String) throws -> HistoryPage {
        let page = try JSONDecoder().decode(HistoryPage.self, from: Data(json.utf8))
        guard page.schemaVersion == 1, page.walletId == expectedWalletId,
              !page.revision.isEmpty, page.matchingCount >= 0, page.totalCount >= page.matchingCount,
              page.pendingCount >= 0, page.pendingCount <= page.totalCount,
              page.offset >= 0, page.offset <= page.matchingCount,
              page.transfers.count <= min(200, page.matchingCount - page.offset),
              page.nextOffset == nil || (page.nextOffset == page.offset + page.transfers.count && page.nextOffset! < page.matchingCount && !page.transfers.isEmpty),
              page.anchorOffset == nil || (page.anchorOffset! >= page.offset && page.anchorOffset! < page.offset + page.transfers.count),
              page.transfers.count <= max(0, page.matchingCount - page.offset),
              Set(page.transfers.map(\.txid)).count == page.transfers.count,
              page.transfers.allSatisfy({ !$0.txid.isEmpty && ["in", "out", "self"].contains($0.direction) }) else {
            throw WalletCoreFFIError.decode("Invalid or wrong-wallet history page")
        }
        return page
    }
    static func transfer(walletId: String, txid: String) throws -> Transfer? {
        try queryTransfers(walletId: walletId, query: .init(limit: 1, txid: txid)).transfers.first
    }
}
