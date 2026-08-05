import SSLCore
import SSLTLS
import Synchronization

/// A sendable, one-shot owner for TLS 1.3 resumption state.
public final class TLSResumptionState: Sendable {
    private struct Storage: ~Copyable, Sendable {
        var core: TLS13ResumptionState?
    }

    private let storage: Mutex<Storage>
    public let cipherSuite: TLSCipherSuite
    public let issuedAt: VerificationInstant
    public let lifetime: UInt32
    public let ageAdd: UInt32
    public let maximumEarlyDataByteCount: UInt32
    public let applicationProtocol: TLS13ApplicationProtocol?

    init(core: consuming TLS13ResumptionState) {
        cipherSuite = core.cipherSuite
        issuedAt = core.issuedAt
        lifetime = core.lifetime
        ageAdd = core.ageAdd
        maximumEarlyDataByteCount = core.maximumEarlyDataByteCount
        applicationProtocol = core.applicationProtocol
        storage = Mutex(Storage(core: consume core))
    }

    func takeCore() throws(TLSError) -> TLS13ResumptionState {
        let result: Result<TLS13ResumptionState, TLSError> = storage.withLock { state in
            guard let core = state.core.take() else {
                return .failure(.invalidConfiguration(reason: "TLS resumption state was consumed"))
            }
            return .success(consume core)
        }
        return try result.get()
    }

    func copyTicketBytes() throws(TLSError) -> ContiguousArray<UInt8> {
        let result: Result<ContiguousArray<UInt8>, TLSError> = storage.withLock { state in
            guard state.core != nil else {
                return .failure(.invalidConfiguration(reason: "TLS resumption state was consumed"))
            }
            return .success(state.core!.withTicketBytes { bytes in
                var result = ContiguousArray<UInt8>()
                result.reserveCapacity(bytes.count)
                var index = 0
                while index < bytes.count {
                    result.append(bytes[index])
                    index += 1
                }
                return result
            })
        }
        return try result.get()
    }

    func consumePSKBytes() throws(TLSError) -> ContiguousArray<UInt8> {
        let result: Result<ContiguousArray<UInt8>, TLSError> = storage.withLock { state in
            guard var core = state.core.take() else {
                return .failure(.invalidConfiguration(reason: "TLS resumption state was consumed"))
            }
            do {
                let secret = try core.consumePSK()
                let bytes = try secret.withBorrowedBytes { input throws(SecretMemoryError) in
                    var output = ContiguousArray<UInt8>()
                    output.reserveCapacity(input.count)
                    var index = 0
                    while index < input.count {
                        output.append(input[index])
                        index += 1
                    }
                    return output
                }
                state.core = consume core
                return .success(bytes)
            } catch {
                state.core = consume core
                return .failure(.invalidConfiguration(reason: "invalid TLS resumption PSK"))
            }
        }
        return try result.get()
    }
}
