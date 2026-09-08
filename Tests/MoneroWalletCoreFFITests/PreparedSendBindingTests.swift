import XCTest
@testable import MoneroWalletCoreFFI

final class PreparedSendBindingTests: XCTestCase {
    func testJournalRoundTripPreservesWalletBinding() throws {
        let json = #"{"txid":"fixture","amount":1,"fee":2,"signed_tx_hex":"00","wallet_binding":"primary-address-with-network"}"#
        let prepared = try JSONDecoder().decode(WalletCoreFFIClient.PreparedSend.self, from: Data(json.utf8))
        XCTAssertEqual(prepared.walletBinding, "primary-address-with-network")
        let encoded = try JSONEncoder().encode(prepared)
        let decoded = try JSONDecoder().decode(WalletCoreFFIClient.PreparedSend.self, from: encoded)
        XCTAssertEqual(decoded, prepared)
        let object = try XCTUnwrap(JSONSerialization.jsonObject(with: encoded) as? [String: Any])
        XCTAssertEqual(object["wallet_binding"] as? String, prepared.walletBinding)
    }

    func testLegacyJournalRemainsReadableForExplicitRecovery() throws {
        let json = #"{"txid":"fixture","amount":1,"fee":2,"signed_tx_hex":"00"}"#
        let prepared = try JSONDecoder().decode(WalletCoreFFIClient.PreparedSend.self, from: Data(json.utf8))
        XCTAssertNil(prepared.walletBinding)
        // Decoding is allowed; the native relay rejects unbound legacy records.
    }
}
