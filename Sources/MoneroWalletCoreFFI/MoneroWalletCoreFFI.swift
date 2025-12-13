import Foundation

#if canImport(MoneroWalletCore)
import MoneroWalletCore
#elseif canImport(CLibMoneroWalletCore)
import CLibMoneroWalletCore
#else
#error("MoneroWalletCoreFFI: Missing C module. Ensure the xcframework (Apple) or system library (Linux) is available.")
#endif

/// Errors thrown by the Swift wrapper when the underlying FFI returns an error code or invalid data.
public enum WalletCoreFFIError: Error, LocalizedError {
    case core(String)                // error reported by the Rust core (via last_error_message)
    case nullPointer(String)         // FFI returned a null pointer unexpectedly
    case decode(String)              // failed to decode JSON payload (send/preview responses)
    case invalidArgument(String)     // validation error in the wrapper before calling FFI

    public var errorDescription: String? {
        switch self {
        case .core(let msg): return msg
        case .nullPointer(let msg): return msg
        case .decode(let msg): return msg
        case .invalidArgument(let msg): return msg
        }
    }
}

/// Minimal Swift wrapper for the WalletCore C FFI.
/// This exposes a small, safe surface area for opening, refreshing, balance querying,
/// fee preview, and sending transactions.
///
/// Notes:
/// - All functions throw WalletCoreFFIError on failure.
/// - Functions that wrap C functions returning char* will free those pointers automatically.
/// - Destinations are encoded as JSON and handed to the core for fee preview and send.
public enum WalletCoreFFIClient {

    // MARK: - Private helpers

    /// Reads the last error message from the core, if any.
    /// This does NOT attempt to free the returned pointer, since implementations may return a static string.
    public static func lastErrorMessage() -> String? {
        guard let cstr = walletcore_last_error_message() else { return nil }
        let s = String(cString: cstr)
        _ = walletcore_free_cstr(cstr)
        return s
    }

    /// Convert a returned C string (char*) into Swift String and free it with walletcore_free_cstr.
    private static func takeCString(_ ptr: UnsafeMutablePointer<CChar>?, context: String) throws -> String {
        guard let p = ptr else {
            let reason = lastErrorMessage() ?? "FFI returned null string (\(context))"
            throw WalletCoreFFIError.nullPointer(reason)
        }
        defer { _ = walletcore_free_cstr(p) }
        return String(cString: p)
    }

    /// Wrapper for an FFI call returning Int32 rc. Throws if rc != 0, using the core's last error message.
    @inline(__always)
    private static func checkRC(_ rc: Int32, context: String) throws {
        guard rc == 0 else {
            let reason = lastErrorMessage() ?? "FFI error in \(context) (rc=\(rc))"
            throw WalletCoreFFIError.core(reason)
        }
    }

    /// JSON helpers
    private static let jsonEncoder: JSONEncoder = {
        let enc = JSONEncoder()
        enc.outputFormatting = [.withoutEscapingSlashes]
        return enc
    }()

    private static let jsonDecoder: JSONDecoder = {
        JSONDecoder()
    }()

    /// Transfer destination schema for FFI JSON calls.
    public struct Destination: Encodable {
        public let address: String
        public let amount: UInt64

        public init(address: String, amount: UInt64) {
            self.address = address
            self.amount = amount
        }
    }

    /// Send result schema returned by FFI JSON calls.
    public struct SendResult: Decodable {
        public let txid: String
        public let fee: UInt64
    }

    /// Fee preview result schema (some builds may return just {"fee": n}).
    public struct FeeResult: Decodable {
        public let fee: UInt64
    }

    /// Sweep preview result schema returned by FFI JSON calls.
    /// JSON: { "amount": <uint64>, "fee": <uint64> }
    public struct SweepPreviewResult: Decodable {
        public let amount: UInt64
        public let fee: UInt64
    }

    /// Sweep send result schema returned by FFI JSON calls.
    /// JSON: { "txid": "<hex>", "amount": <uint64>, "fee": <uint64> }
    public struct SweepSendResult: Decodable {
        public let txid: String
        public let amount: UInt64
        public let fee: UInt64
    }

    public struct SyncStatus: Equatable {
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

    // MARK: - Public API

    /// Returns the linked WalletCore version string.
    public static func version() -> String {
        guard let c = walletcore_version() else { return "unknown" }
        let s = String(cString: c)
        _ = walletcore_free_cstr(c)
        return s
    }

    /// Open/register a wallet from a 25-word mnemonic.
    /// - Parameters:
    ///   - walletId: Stable identifier used by the core to reference the wallet.
    ///   - mnemonic: 25-word mnemonic (ASCII).
    ///   - restoreHeight: Optional starting scan height (0 if unknown).
    ///   - mainnet: True for mainnet, false for stagenet/testnet.
    public static func openWalletFromMnemonic(
        walletId: String,
        mnemonic: String,
        restoreHeight: UInt64 = 0,
        mainnet: Bool = true
    ) throws {
        let rc = walletId.withCString { cId in
            mnemonic.withCString { cMn in
                wallet_open_from_mnemonic(cId, cMn, restoreHeight, mainnet ? 1 : 0)
            }
        }
        try checkRC(rc, context: "wallet_open_from_mnemonic")
    }

    public static func setGapLimit(
        walletId: String,
        gapLimit: UInt32
    ) throws {
#if canImport(CLibMoneroWalletCore)
        let rc = walletId.withCString { cId in
            wallet_set_gap_limit(cId, gapLimit)
        }
        try checkRC(rc, context: "wallet_set_gap_limit")
#else
        _ = walletId
        _ = gapLimit
#endif
    }

    public static func forceRescanFromHeight(
        walletId: String,
        fromHeight: UInt64
    ) throws {
        let rc = walletId.withCString { cId in
            wallet_force_rescan_from_height(cId, fromHeight)
        }
        try checkRC(rc, context: "wallet_force_rescan_from_height")
    }

    public static func startZmqListener(endpoint: String) throws {
#if canImport(CLibMoneroWalletCore)
        let rc = endpoint.withCString { cEndpoint in
            wallet_start_zmq_listener(cEndpoint)
        }
        try checkRC(rc, context: "wallet_start_zmq_listener")
#else
        _ = endpoint
#endif
    }

    public static func stopZmqListener() throws {
#if canImport(CLibMoneroWalletCore)
        let rc = wallet_stop_zmq_listener()
        try checkRC(rc, context: "wallet_stop_zmq_listener")
#endif
    }

    public static func zmqSequence() throws -> UInt64 {
#if canImport(CLibMoneroWalletCore)
        var value: UInt64 = 0
        let rc = wallet_zmq_sequence(&value)
        try checkRC(rc, context: "wallet_zmq_sequence")
        return value
#else
        return 0
#endif
    }

    /// Refresh the wallet against the daemon (nodeURL). Returns the last scanned height.
    public static func refreshWallet(
        walletId: String,
        nodeURL: String? = nil
    ) throws -> UInt64 {
        var lastScanned: UInt64 = 0
        let rc: Int32 = walletId.withCString { cId in
            if let node = nodeURL {
                return node.withCString { cNode in
                    wallet_refresh(cId, cNode, &lastScanned)
                }
            } else {
                return wallet_refresh(cId, nil, &lastScanned)
            }
        }
        try checkRC(rc, context: "wallet_refresh")
        return lastScanned
    }

    /// Kick off a wallet refresh on a background worker without blocking the caller.
    public static func refreshWalletAsync(
        walletId: String,
        nodeURL: String? = nil
    ) throws {
        let rc: Int32 = walletId.withCString { cId in
            if let node = nodeURL {
                return node.withCString { cNode in
                    wallet_refresh_async(cId, cNode)
                }
            } else {
                return wallet_refresh_async(cId, nil)
            }
        }
        try checkRC(rc, context: "wallet_refresh_async")
    }

    /// Retrieve sync status values cached on the core for this wallet.
    public static func syncStatus(
        walletId: String
    ) throws -> SyncStatus {
        var chainHeight: UInt64 = 0
        var chainTime: UInt64 = 0
        var lastRefreshTimestamp: UInt64 = 0
        var lastScanned: UInt64 = 0
        var restoreHeight: UInt64 = 0
        let rc: Int32 = walletId.withCString { cId in
            wallet_sync_status(cId, &chainHeight, &chainTime, &lastRefreshTimestamp, &lastScanned, &restoreHeight)
        }
        try checkRC(rc, context: "wallet_sync_status")
        return SyncStatus(
            chainHeight: chainHeight,
            chainTime: chainTime,
            lastRefreshTimestamp: lastRefreshTimestamp,
            lastScanned: lastScanned,
            restoreHeight: restoreHeight
        )
    }

    /// Get total and unlocked balances (piconero).
    public static func getBalance(
        walletId: String
    ) throws -> (total: UInt64, unlocked: UInt64) {
        var total: UInt64 = 0
        var unlocked: UInt64 = 0
        let rc = walletId.withCString { cId in
            wallet_get_balance(cId, &total, &unlocked)
        }
        try checkRC(rc, context: "wallet_get_balance")
        return (total: total, unlocked: unlocked)
    }

    /// Preview fee for given destinations (multi-output supported).
    /// - Returns: fee in piconero
    public static func previewFee(
        walletId: String,
        destinations: [Destination],
        ringLen: UInt8 = 16,
        nodeURL: String? = nil
    ) throws -> UInt64 {
        let jsonData = try jsonEncoder.encode(destinations)
        guard let jsonStr = String(data: jsonData, encoding: .utf8) else {
            throw WalletCoreFFIError.invalidArgument("Failed to encode destinations as UTF-8 JSON")
        }

        let raw: UnsafeMutablePointer<CChar>? = walletId.withCString { cId in
            if let node = nodeURL {
                return node.withCString { cNode in
                    jsonStr.withCString { cDest in
                        wallet_preview_fee(cId, cNode, cDest, ringLen)
                    }
                }
            } else {
                return jsonStr.withCString { cDest in
                    wallet_preview_fee(cId, nil, cDest, ringLen)
                }
            }
        }

        let s = try takeCString(raw, context: "wallet_preview_fee")
        // Try to decode {"fee": ...}
        if let data = s.data(using: .utf8),
           let res = try? jsonDecoder.decode(FeeResult.self, from: data) {
            return res.fee
        }
        // Fallback: attempt to parse an integer directly if the core returned a bare number.
        if let fee = UInt64(s.trimmingCharacters(in: .whitespacesAndNewlines)) {
            return fee
        }
        throw WalletCoreFFIError.decode("Unexpected preview_fee payload: \(s)")
    }

    /// Preview fee with an input filter (e.g., subaddress constraints).
    /// `filter` is passed as JSON object (e.g., {"subaddress_minor": 12}).
    public static func previewFeeWithFilter(
        walletId: String,
        destinations: [Destination],
        filter: [String: Any]? = nil,
        ringLen: UInt8 = 16,
        nodeURL: String? = nil
    ) throws -> UInt64 {
        let destData = try jsonEncoder.encode(destinations)
        guard let destJSON = String(data: destData, encoding: .utf8) else {
            throw WalletCoreFFIError.invalidArgument("Failed to encode destinations as UTF-8 JSON")
        }

        let filterJSON: String? = {
            guard let filter else { return nil }
            guard JSONSerialization.isValidJSONObject(filter) else { return nil }
            let data = try? JSONSerialization.data(withJSONObject: filter, options: [])
            return data.flatMap { String(data: $0, encoding: .utf8) }
        }()

        let raw: UnsafeMutablePointer<CChar>? = walletId.withCString { cId in
            if let node = nodeURL {
                return node.withCString { cNode in
                    return destJSON.withCString { cDest in
                        if let f = filterJSON {
                            return f.withCString { cFilter in
                                wallet_preview_fee_with_filter(cId, cNode, cDest, cFilter, ringLen)
                            }
                        } else {
                            return wallet_preview_fee_with_filter(cId, cNode, cDest, nil, ringLen)
                        }
                    }
                }
            } else {
                return destJSON.withCString { cDest in
                    if let f = filterJSON {
                        return f.withCString { cFilter in
                            wallet_preview_fee_with_filter(cId, nil, cDest, cFilter, ringLen)
                        }
                    } else {
                        return wallet_preview_fee_with_filter(cId, nil, cDest, nil, ringLen)
                    }
                }
            }
        }

        let s = try takeCString(raw, context: "wallet_preview_fee_with_filter")
        if let data = s.data(using: .utf8),
           let res = try? jsonDecoder.decode(FeeResult.self, from: data) {
            return res.fee
        }
        if let fee = UInt64(s.trimmingCharacters(in: .whitespacesAndNewlines)) {
            return fee
        }
        throw WalletCoreFFIError.decode("Unexpected preview_fee_with_filter payload: \(s)")
    }

    // MARK: - Sweep ("Send Max")

    /// Preview sweep ("Send Max") for a single destination.
    /// - Returns: (amount, fee) in piconero where `amount` is the computed sendable amount (roughly unlocked - fee).
    public static func previewSweep(
        walletId: String,
        toAddress: String,
        ringLen: UInt8 = 16,
        nodeURL: String? = nil
    ) throws -> (amount: UInt64, fee: UInt64) {
        let raw: UnsafeMutablePointer<CChar>? = walletId.withCString { cId in
            if let node = nodeURL {
                return node.withCString { cNode in
                    toAddress.withCString { cAddr in
                        wallet_preview_sweep(cId, cNode, cAddr, ringLen)
                    }
                }
            } else {
                return toAddress.withCString { cAddr in
                    wallet_preview_sweep(cId, nil, cAddr, ringLen)
                }
            }
        }

        let s = try takeCString(raw, context: "wallet_preview_sweep")
        guard let data = s.data(using: .utf8),
              let res = try? jsonDecoder.decode(SweepPreviewResult.self, from: data) else {
            throw WalletCoreFFIError.decode("Unexpected preview_sweep payload: \(s)")
        }
        return (amount: res.amount, fee: res.fee)
    }

    /// Preview sweep ("Send Max") constrained by an input filter (e.g., subaddress minor).
    /// `filter` is passed as JSON object (e.g., {"subaddress_minor": 12}).
    public static func previewSweepWithFilter(
        walletId: String,
        toAddress: String,
        filter: [String: Any]? = nil,
        ringLen: UInt8 = 16,
        nodeURL: String? = nil
    ) throws -> (amount: UInt64, fee: UInt64) {
        let filterJSON: String? = {
            guard let filter else { return nil }
            guard JSONSerialization.isValidJSONObject(filter) else { return nil }
            let data = try? JSONSerialization.data(withJSONObject: filter, options: [])
            return data.flatMap { String(data: $0, encoding: .utf8) }
        }()

        let raw: UnsafeMutablePointer<CChar>? = walletId.withCString { cId in
            if let node = nodeURL {
                return node.withCString { cNode in
                    toAddress.withCString { cAddr in
                        if let f = filterJSON {
                            return f.withCString { cFilter in
                                wallet_preview_sweep_with_filter(cId, cNode, cAddr, cFilter, ringLen)
                            }
                        } else {
                            return wallet_preview_sweep_with_filter(cId, cNode, cAddr, nil, ringLen)
                        }
                    }
                }
            } else {
                return toAddress.withCString { cAddr in
                    if let f = filterJSON {
                        return f.withCString { cFilter in
                            wallet_preview_sweep_with_filter(cId, nil, cAddr, cFilter, ringLen)
                        }
                    } else {
                        return wallet_preview_sweep_with_filter(cId, nil, cAddr, nil, ringLen)
                    }
                }
            }
        }

        let s = try takeCString(raw, context: "wallet_preview_sweep_with_filter")
        guard let data = s.data(using: .utf8),
              let res = try? jsonDecoder.decode(SweepPreviewResult.self, from: data) else {
            throw WalletCoreFFIError.decode("Unexpected preview_sweep_with_filter payload: \(s)")
        }
        return (amount: res.amount, fee: res.fee)
    }

    /// Sweep ("Send Max") to a single destination. Returns (txid, amount, fee).
    public static func sweep(
        walletId: String,
        toAddress: String,
        ringLen: UInt8 = 16,
        nodeURL: String? = nil
    ) throws -> (txid: String, amount: UInt64, fee: UInt64) {
        let raw: UnsafeMutablePointer<CChar>? = walletId.withCString { cId in
            if let node = nodeURL {
                return node.withCString { cNode in
                    toAddress.withCString { cAddr in
                        wallet_sweep(cId, cNode, cAddr, ringLen)
                    }
                }
            } else {
                return toAddress.withCString { cAddr in
                    wallet_sweep(cId, nil, cAddr, ringLen)
                }
            }
        }

        let s = try takeCString(raw, context: "wallet_sweep")
        guard let data = s.data(using: .utf8),
              let res = try? jsonDecoder.decode(SweepSendResult.self, from: data) else {
            throw WalletCoreFFIError.decode("Unexpected sweep payload: \(s)")
        }
        return (txid: res.txid, amount: res.amount, fee: res.fee)
    }

    /// Sweep ("Send Max") constrained by an input filter (e.g., subaddress minor). Returns (txid, amount, fee).
    public static func sweepWithFilter(
        walletId: String,
        toAddress: String,
        filter: [String: Any]? = nil,
        ringLen: UInt8 = 16,
        nodeURL: String? = nil
    ) throws -> (txid: String, amount: UInt64, fee: UInt64) {
        let filterJSON: String? = {
            guard let filter else { return nil }
            guard JSONSerialization.isValidJSONObject(filter) else { return nil }
            let data = try? JSONSerialization.data(withJSONObject: filter, options: [])
            return data.flatMap { String(data: $0, encoding: .utf8) }
        }()

        let raw: UnsafeMutablePointer<CChar>? = walletId.withCString { cId in
            if let node = nodeURL {
                return node.withCString { cNode in
                    toAddress.withCString { cAddr in
                        if let f = filterJSON {
                            return f.withCString { cFilter in
                                wallet_sweep_with_filter(cId, cNode, cAddr, cFilter, ringLen)
                            }
                        } else {
                            return wallet_sweep_with_filter(cId, cNode, cAddr, nil, ringLen)
                        }
                    }
                }
            } else {
                return toAddress.withCString { cAddr in
                    if let f = filterJSON {
                        return f.withCString { cFilter in
                            wallet_sweep_with_filter(cId, nil, cAddr, cFilter, ringLen)
                        }
                    } else {
                        return wallet_sweep_with_filter(cId, nil, cAddr, nil, ringLen)
                    }
                }
            }
        }

        let s = try takeCString(raw, context: "wallet_sweep_with_filter")
        guard let data = s.data(using: .utf8),
              let res = try? jsonDecoder.decode(SweepSendResult.self, from: data) else {
            throw WalletCoreFFIError.decode("Unexpected sweep_with_filter payload: \(s)")
        }
        return (txid: res.txid, amount: res.amount, fee: res.fee)
    }

    /// Send a single-destination transfer. Returns (txid, fee).
    public static func send(
        walletId: String,
        toAddress: String,
        amountPiconero: UInt64,
        ringLen: UInt8 = 16,
        nodeURL: String? = nil
    ) throws -> (txid: String, fee: UInt64) {
        let raw: UnsafeMutablePointer<CChar>? = walletId.withCString { cId in
            if let node = nodeURL {
                return node.withCString { cNode in
                    toAddress.withCString { cAddr in
                        wallet_send(cId, cNode, cAddr, amountPiconero, ringLen)
                    }
                }
            } else {
                return toAddress.withCString { cAddr in
                    wallet_send(cId, nil, cAddr, amountPiconero, ringLen)
                }
            }
        }

        let s = try takeCString(raw, context: "wallet_send")
        guard let data = s.data(using: .utf8),
              let res = try? jsonDecoder.decode(SendResult.self, from: data) else {
            throw WalletCoreFFIError.decode("Unexpected send payload: \(s)")
        }
        return (txid: res.txid, fee: res.fee)
    }

    /// Send with multiple destinations and an optional input filter (e.g., subaddress constraints).
    public static func sendWithFilter(
        walletId: String,
        destinations: [Destination],
        filter: [String: Any]? = nil,
        ringLen: UInt8 = 16,
        nodeURL: String? = nil
    ) throws -> (txid: String, fee: UInt64) {
        let destData = try jsonEncoder.encode(destinations)
        guard let destJSON = String(data: destData, encoding: .utf8) else {
            throw WalletCoreFFIError.invalidArgument("Failed to encode destinations as UTF-8 JSON")
        }

        let filterJSON: String? = {
            guard let filter else { return nil }
            guard JSONSerialization.isValidJSONObject(filter) else { return nil }
            let data = try? JSONSerialization.data(withJSONObject: filter, options: [])
            return data.flatMap { String(data: $0, encoding: .utf8) }
        }()

        let raw: UnsafeMutablePointer<CChar>? = walletId.withCString { cId in
            if let node = nodeURL {
                return node.withCString { cNode in
                    return destJSON.withCString { cDest in
                        if let f = filterJSON {
                            return f.withCString { cFilter in
                                wallet_send_with_filter(cId, cNode, cDest, cFilter, ringLen)
                            }
                        } else {
                            return wallet_send_with_filter(cId, cNode, cDest, nil, ringLen)
                        }
                    }
                }
            } else {
                return destJSON.withCString { cDest in
                    if let f = filterJSON {
                        return f.withCString { cFilter in
                            wallet_send_with_filter(cId, nil, cDest, cFilter, ringLen)
                        }
                    } else {
                        return wallet_send_with_filter(cId, nil, cDest, nil, ringLen)
                    }
                }
            }
        }

        let s = try takeCString(raw, context: "wallet_send_with_filter")
        guard let data = s.data(using: .utf8),
              let res = try? jsonDecoder.decode(SendResult.self, from: data) else {
            throw WalletCoreFFIError.decode("Unexpected send_with_filter payload: \(s)")
        }
        return (txid: res.txid, fee: res.fee)
    }

    // MARK: - Cache import/export

    /// Import a previously exported cache blob for a wallet (idempotent).
    /// Throws if the core rejects the blob or the wallet isn't opened.
    public static func importCache(
        walletId: String,
        cacheBlob: Data
    ) throws {
        let rc: Int32 = cacheBlob.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.bindMemory(to: UInt8.self).baseAddress else {
                return Int32(-11)
            }
            return walletId.withCString { cId in
                wallet_import_cache(cId, base, rawBuf.count)
            }
        }
        try checkRC(rc, context: "wallet_import_cache")
    }

    /// Export the current cache blob for a wallet. Returns nil if empty.
    /// Uses a two-phase API (probe size, then fill buffer).
    public static func exportCache(
        walletId: String
    ) throws -> Data? {
        var required: Int = 0
        let probeRC: Int32 = walletId.withCString { cId in
            wallet_export_cache(cId, nil, 0, &required)
        }
        // Accept either -12 (probe) or 0
        if probeRC != 0 && probeRC != -12 {
            try checkRC(probeRC, context: "wallet_export_cache (probe)")
        }
        guard required > 0 else { return nil }

        var buffer = Data(count: required)
        var written: Int = 0
        let rc: Int32 = buffer.withUnsafeMutableBytes { rawBuf in
            guard let base = rawBuf.bindMemory(to: UInt8.self).baseAddress else {
                return Int32(-11)
            }
            return walletId.withCString { cId in
                wallet_export_cache(cId, base, rawBuf.count, &written)
            }
        }
        try checkRC(rc, context: "wallet_export_cache")
        guard written <= buffer.count else {
            throw WalletCoreFFIError.core("wallet_export_cache reported invalid length (\(written) > \(buffer.count))")
        }
        return buffer.prefix(written)
    }

    // MARK: - Outputs export (JSON) and typed decode

    /// Export observed outputs for a wallet as a JSON string (owned by Swift).
    public static func exportOutputsJSON(walletId: String) throws -> String {
        let raw: UnsafeMutablePointer<CChar>? = walletId.withCString { cId in
            wallet_export_outputs_json(cId)
        }
        return try takeCString(raw, context: "wallet_export_outputs_json")
    }

    /// Convenience: Export and decode observed outputs into a typed envelope.
    public static func observedOutputs(walletId: String) throws -> WalletObservedOutputsEnvelope {
        let json = try exportOutputsJSON(walletId: walletId)
        guard let data = json.data(using: .utf8) else {
            throw WalletCoreFFIError.decode("wallet_export_outputs_json returned non-UTF8")
        }
        do {
            return try jsonDecoder.decode(WalletObservedOutputsEnvelope.self, from: data)
        } catch {
            throw WalletCoreFFIError.decode("Failed to decode observed outputs: \(error.localizedDescription)")
        }
    }

    // MARK: - Address derivation helpers

    /// Derive the primary address (account 0, subaddress 0) from raw seed bytes.
    public static func derivePrimaryAddressFromSeed(seedData: Data, mainnet: Bool = true) throws -> String {
        var buffer = Array<CChar>(repeating: 0, count: 192)
        var written: Int = 0
        let rc: Int32 = seedData.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.bindMemory(to: UInt8.self).baseAddress else { return Int32(-11) }
            return wallet_primary_address_from_seed(
                base,
                rawBuf.count,
                mainnet ? 1 : 0,
                &buffer,
                buffer.count,
                &written
            )
        }
        try checkRC(rc, context: "wallet_primary_address_from_seed")
        buffer[min(written, buffer.count - 1)] = 0
        let addrBytes = buffer.prefix(min(written, buffer.count - 1)).map { UInt8(bitPattern: $0) }
        return String(decoding: addrBytes, as: UTF8.self)
    }

    /// Derive the primary address (account 0, subaddress 0) from hex-encoded seed bytes.
    public static func derivePrimaryAddressFromSeedHex(seedHex: String, mainnet: Bool = true) throws -> String {
        guard let seed = Data(hex: seedHex) else {
            throw WalletCoreFFIError.invalidArgument("Seed hex is invalid")
        }
        return try derivePrimaryAddressFromSeed(seedData: seed, mainnet: mainnet)
    }

    /// Derive the primary address (account 0, subaddress 0) from a 25-word mnemonic.
    public static func derivePrimaryAddressFromMnemonic(_ phrase: String, mainnet: Bool = true) throws -> String {
        var buffer = Array<CChar>(repeating: 0, count: 192)
        var written: Int = 0
        let rc: Int32 = phrase.withCString { cstr in
            wallet_primary_address_from_mnemonic(
                cstr,
                mainnet ? 1 : 0,
                &buffer,
                buffer.count,
                &written
            )
        }
        try checkRC(rc, context: "wallet_primary_address_from_mnemonic")
        buffer[min(written, buffer.count - 1)] = 0
        let addrBytes = buffer.prefix(min(written, buffer.count - 1)).map { UInt8(bitPattern: $0) }
        return String(decoding: addrBytes, as: UTF8.self)
    }

    /// Derive a subaddress (accountIndex, subaddressIndex) from a 25-word mnemonic.
    public static func deriveSubaddressFromMnemonic(
        _ phrase: String,
        accountIndex: UInt32 = 0,
        subaddressIndex: UInt32,
        mainnet: Bool = true
    ) throws -> String {
        var buffer = Array<CChar>(repeating: 0, count: 192)
        var written: Int = 0
        let rc: Int32 = phrase.withCString { cstr in
            wallet_derive_subaddress_from_mnemonic(
                cstr,
                accountIndex,
                subaddressIndex,
                mainnet ? 1 : 0,
                &buffer,
                buffer.count,
                &written
            )
        }
        try checkRC(rc, context: "wallet_derive_subaddress_from_mnemonic")
        buffer[min(written, buffer.count - 1)] = 0
        let addrBytes = buffer.prefix(min(written, buffer.count - 1)).map { UInt8(bitPattern: $0) }
        return String(decoding: addrBytes, as: UTF8.self)
    }

    /// Derive an address from seed bytes for a given (accountIndex, subaddressIndex).
    public static func deriveAddressFromSeed(
        seedData: Data,
        accountIndex: UInt32,
        subaddressIndex: UInt32,
        mainnet: Bool = true
    ) throws -> String {
        var buffer = Array<CChar>(repeating: 0, count: 192)
        var written: Int = 0
        let rc: Int32 = seedData.withUnsafeBytes { rawBuf in
            guard let base = rawBuf.bindMemory(to: UInt8.self).baseAddress else { return Int32(-11) }
            return wallet_derive_address_from_seed(
                base,
                rawBuf.count,
                mainnet ? 1 : 0,
                accountIndex,
                subaddressIndex,
                &buffer,
                buffer.count,
                &written
            )
        }
        try checkRC(rc, context: "wallet_derive_address_from_seed")
        buffer[min(written, buffer.count - 1)] = 0
        let addrBytes = buffer.prefix(min(written, buffer.count - 1)).map { UInt8(bitPattern: $0) }
        return String(decoding: addrBytes, as: UTF8.self)
    }

    /// Derive an address from hex-encoded seed bytes for a given (accountIndex, subaddressIndex).
    public static func deriveAddressFromSeedHex(
        seedHex: String,
        accountIndex: UInt32,
        subaddressIndex: UInt32,
        mainnet: Bool = true
    ) throws -> String {
        guard let seed = Data(hex: seedHex) else {
            throw WalletCoreFFIError.invalidArgument("Seed hex is invalid")
        }
        return try deriveAddressFromSeed(
            seedData: seed,
            accountIndex: accountIndex,
            subaddressIndex: subaddressIndex,
            mainnet: mainnet
        )
    }
}

// MARK: - Observed outputs DTOs (typed decode)

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
        case timelock
        case unlockHeight = "unlock_height"
        case unlocked
        case unlockTime = "unlock_time"
    }
}

// MARK: - Small helpers

private extension Data {
    /// Initialize Data from a hex string (case-insensitive, even-length preferred).
    init?(hex: String) {
        let s = hex.trimmingCharacters(in: .whitespacesAndNewlines)
        let len = s.count
        if len == 0 { return nil }
        var bytes = [UInt8]()
        bytes.reserveCapacity(len / 2)

        var index = s.startIndex
        func val(_ c: Character) -> UInt8? {
            switch c {
            case "0"..."9": return UInt8(c.asciiValue! - Character("0").asciiValue!)
            case "a"..."f": return 10 + UInt8(c.asciiValue! - Character("a").asciiValue!)
            case "A"..."F": return 10 + UInt8(c.asciiValue! - Character("A").asciiValue!)
            default: return nil
            }
        }

        while index < s.endIndex {
            let next = s.index(after: index)
            guard next < s.endIndex else { return nil }
            let c1 = s[index], c2 = s[next]
            guard let v1 = val(c1), let v2 = val(c2) else { return nil }
            bytes.append((v1 << 4) | v2)
            index = s.index(next, offsetBy: 1)
        }
        self.init(bytes)
    }
}
