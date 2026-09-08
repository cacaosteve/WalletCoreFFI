import XCTest
@testable import MoneroWalletCoreFFI

final class HistoryPagingTests: XCTestCase {
    private let row = #"{"txid":"abababababababababababababababababababababababababababababababab","direction":"in","amount":42,"fee":7,"confirmations":10,"is_pending":false}"#
    private var payload: String {
        #"{"schema_version":1,"wallet_id":"fixture","revision":"42","total_count":10000,"matching_count":10000,"pending_count":0,"offset":0,"next_offset":1,"anchor_offset":0,"last_scanned_height":100,"chain_height":110,"chain_time":0,"transfers":["# + row + "]}"
    }
    func testBoundedPageKeepsLedgerCountAndExactAmounts() throws {
        let page = try WalletCoreFFIClient.decodeHistoryPageJSON(payload, expectedWalletId: "fixture")
        XCTAssertEqual(page.totalCount, 10000)
        XCTAssertEqual(page.transfers.count, 1)
        XCTAssertEqual(page.transfers.first?.amount, 42)
        XCTAssertEqual(page.transfers.first?.fee, 7)
        XCTAssertEqual(page.anchorOffset, 0)
    }
    func testMalformedWrongWalletAndDuplicatePagesAreRejected() {
        for bad in [
            payload.replacingOccurrences(of: #""fixture""#, with: #""other""#),
            payload.replacingOccurrences(of: #""schema_version":1"#, with: #""schema_version":2"#),
            payload.replacingOccurrences(of: #""pending_count":0"#, with: #""pending_count":-1"#),
            payload.replacingOccurrences(of: #""revision":"42""#, with: #""revision":"""#),
            payload.replacingOccurrences(of: #""next_offset":1"#, with: #""next_offset":0"#),
            payload.replacingOccurrences(of: #""anchor_offset":0"#, with: #""anchor_offset":100"#),
            payload.replacingOccurrences(of: "[\(row)]", with: "[\(row),\(row)]"),
        ] {
            XCTAssertThrowsError(try WalletCoreFFIClient.decodeHistoryPageJSON(bad, expectedWalletId: "fixture"))
        }
    }
    func testQueryUsesNativeFieldNamesAndNoImplicitCursor() throws {
        let query = WalletCoreFFIClient.HistoryQuery(filter: "pending", anchorTxid: "abc")
        let object = try JSONSerialization.jsonObject(with: JSONEncoder().encode(query)) as! [String: Any]
        XCTAssertEqual(object["anchor_txid"] as? String, "abc")
        XCTAssertEqual(object["limit"] as? Int, 50)
        XCTAssertNil(object["revision"])
    }
}
