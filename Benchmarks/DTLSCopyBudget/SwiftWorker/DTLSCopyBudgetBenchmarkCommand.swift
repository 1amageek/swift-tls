import TLS

#if canImport(Darwin)
import Darwin
#endif

@main
enum DTLSCopyBudgetBenchmarkCommand {
    private enum Operation: String {
        case receive
        case send
    }

    private enum BenchmarkError: Error {
        case invalidArguments
        case invalidResult
        case measurementUnavailable
    }

    private struct Measurement {
        let nanoseconds: Int64
        let checksum: UInt64
    }

    #if canImport(Darwin)
    private struct AllocationProbe {
        let start: @convention(c) () -> Void
        let stopAndPrint: @convention(c) () -> Void

        init() throws {
            let defaultSearchHandle = UnsafeMutableRawPointer(
                bitPattern: UInt(bitPattern: -2)
            )
            guard
                let startAddress = dlsym(
                    defaultSearchHandle,
                    "swift_tls_allocation_probe_start"
                ),
                let stopAddress = dlsym(
                    defaultSearchHandle,
                    "swift_tls_allocation_probe_stop_and_print"
                )
            else {
                throw BenchmarkError.measurementUnavailable
            }
            start = unsafeBitCast(
                startAddress,
                to: (@convention(c) () -> Void).self
            )
            stopAndPrint = unsafeBitCast(
                stopAddress,
                to: (@convention(c) () -> Void).self
            )
        }
    }
    #endif

    static func main() throws {
        let arguments = CommandLine.arguments
        if arguments.count == 5, arguments[1] == "--memory" {
            guard
                let operation = Operation(rawValue: arguments[2]),
                let payloadByteCount = Int(arguments[3]),
                let iterations = Int(arguments[4]),
                payloadByteCount > 0,
                payloadByteCount <= 16_384,
                iterations > 0
            else {
                throw BenchmarkError.invalidArguments
            }
            try runMemoryMeasurement(
                operation: operation,
                payloadByteCount: payloadByteCount,
                iterations: iterations
            )
            return
        }

        guard
            arguments.count == 5,
            let operation = Operation(rawValue: arguments[1]),
            let payloadByteCount = Int(arguments[2]),
            let iterations = Int(arguments[3]),
            let warmupIterations = Int(arguments[4]),
            payloadByteCount > 0,
            payloadByteCount <= 16_384,
            iterations > 0,
            warmupIterations >= 0
        else {
            throw BenchmarkError.invalidArguments
        }

        let measurement = try timingMeasurement(
            operation: operation,
            payloadByteCount: payloadByteCount,
            iterations: iterations,
            warmupIterations: warmupIterations
        )
        print("RESULT,\(measurement.nanoseconds),\(measurement.checksum)")
    }

    private static func timingMeasurement(
        operation: Operation,
        payloadByteCount: Int,
        iterations: Int,
        warmupIterations: Int
    ) throws -> Measurement {
        let clock = ContinuousClock()
        switch operation {
        case .receive:
            let fixture = try makeReceiveFixture(
                payloadByteCount: payloadByteCount,
                datagramCount: iterations + warmupIterations
            )
            _ = try receive(
                server: fixture.server,
                datagrams: fixture.datagrams,
                range: 0..<warmupIterations,
                payloadByteCount: payloadByteCount
            )
            let start = clock.now
            let checksum = try receive(
                server: fixture.server,
                datagrams: fixture.datagrams,
                range: warmupIterations..<(warmupIterations + iterations),
                payloadByteCount: payloadByteCount
            )
            let elapsed = start.duration(to: clock.now).components
            return Measurement(
                nanoseconds: elapsed.seconds * 1_000_000_000
                    + elapsed.attoseconds / 1_000_000_000,
                checksum: checksum
            )
        case .send:
            let fixture = try makeSendFixture(payloadByteCount: payloadByteCount)
            _ = try send(
                client: fixture.client,
                payload: fixture.payload,
                iterations: warmupIterations
            )
            let start = clock.now
            let checksum = try send(
                client: fixture.client,
                payload: fixture.payload,
                iterations: iterations
            )
            let elapsed = start.duration(to: clock.now).components
            return Measurement(
                nanoseconds: elapsed.seconds * 1_000_000_000
                    + elapsed.attoseconds / 1_000_000_000,
                checksum: checksum
            )
        }
    }

    private static func runMemoryMeasurement(
        operation: Operation,
        payloadByteCount: Int,
        iterations: Int
    ) throws {
        #if canImport(Darwin)
        let probe = try AllocationProbe()
        let checksum: UInt64
        switch operation {
        case .receive:
            let fixture = try makeReceiveFixture(
                payloadByteCount: payloadByteCount,
                datagramCount: iterations + 1
            )
            _ = try receive(
                server: fixture.server,
                datagrams: fixture.datagrams,
                range: 0..<1,
                payloadByteCount: payloadByteCount
            )
            probe.start()
            do {
                checksum = try receive(
                    server: fixture.server,
                    datagrams: fixture.datagrams,
                    range: 1..<(iterations + 1),
                    payloadByteCount: payloadByteCount
                )
            } catch {
                withExtendedLifetime(fixture) {
                    probe.stopAndPrint()
                }
                throw error
            }
            withExtendedLifetime(fixture) {
                probe.stopAndPrint()
            }
        case .send:
            let fixture = try makeSendFixture(payloadByteCount: payloadByteCount)
            _ = try send(client: fixture.client, payload: fixture.payload, iterations: 1)
            probe.start()
            do {
                checksum = try send(
                    client: fixture.client,
                    payload: fixture.payload,
                    iterations: iterations
                )
            } catch {
                withExtendedLifetime(fixture) {
                    probe.stopAndPrint()
                }
                throw error
            }
            withExtendedLifetime(fixture) {
                probe.stopAndPrint()
            }
        }
        print("MEMORY_CHECKSUM,\(checksum)")
        #else
        throw BenchmarkError.measurementUnavailable
        #endif
    }

    private static func makeReceiveFixture(
        payloadByteCount: Int,
        datagramCount: Int
    ) throws -> (server: DTLSServer, datagrams: [[UInt8]]) {
        let identity = p256Identity()
        let configuration = DTLSConfiguration(identity: identity)
        let client = try DTLSClient(configuration: configuration)
        let server = try DTLSServer(configuration: configuration)
        try completeHandshake(client: client, server: server)

        let payload = makePayload(byteCount: payloadByteCount)

        var datagrams: [[UInt8]] = []
        datagrams.reserveCapacity(datagramCount)
        var index = 0
        while index < datagramCount {
            datagrams.append(try client.send(payload.span))
            index += 1
        }
        return (server, datagrams)
    }

    private static func makeSendFixture(
        payloadByteCount: Int
    ) throws -> (client: DTLSClient, payload: ContiguousArray<UInt8>) {
        let identity = p256Identity()
        let configuration = DTLSConfiguration(identity: identity)
        let client = try DTLSClient(configuration: configuration)
        let server = try DTLSServer(configuration: configuration)
        try completeHandshake(client: client, server: server)
        return (client, makePayload(byteCount: payloadByteCount))
    }

    private static func makePayload(byteCount: Int) -> ContiguousArray<UInt8> {
        var payload = ContiguousArray<UInt8>(repeating: 0, count: byteCount)
        var index = 0
        while index < payload.count {
            payload[index] = UInt8(truncatingIfNeeded: index)
            index += 1
        }
        return payload
    }

    @inline(never)
    private static func receive(
        server: DTLSServer,
        datagrams: [[UInt8]],
        range: Range<Int>,
        payloadByteCount: Int
    ) throws -> UInt64 {
        let remoteAddress = ContiguousArray<UInt8>([127, 0, 0, 1, 0x1F, 0x90])
        var checksum: UInt64 = 0
        var index = range.lowerBound
        while index < range.upperBound {
            let datagram = datagrams[index]
            let output = try server.receive(
                datagram.span,
                from: remoteAddress.span
            )
            guard
                output.applicationData.count == payloadByteCount,
                output.datagramsToSend.isEmpty,
                output.anomalies.isEmpty
            else {
                throw BenchmarkError.invalidResult
            }
            checksum &+= UInt64(output.applicationData[0])
            checksum &+= UInt64(output.applicationData[payloadByteCount - 1])
            checksum &+= UInt64(output.applicationData.count)
            index += 1
        }
        return checksum
    }

    @inline(never)
    private static func send(
        client: DTLSClient,
        payload: ContiguousArray<UInt8>,
        iterations: Int
    ) throws -> UInt64 {
        var checksum: UInt64 = 0
        var index = 0
        while index < iterations {
            let datagram = try client.send(payload.span)
            guard
                datagram.count == payload.count + 37,
                datagram.first == 23
            else {
                throw BenchmarkError.invalidResult
            }
            checksum &+= UInt64(datagram.count)
            checksum &+= UInt64(datagram[0])
            index += 1
        }
        return checksum
    }

    private static func completeHandshake(
        client: DTLSClient,
        server: DTLSServer
    ) throws {
        let remoteAddress = ContiguousArray<UInt8>([127, 0, 0, 1, 0x1F, 0x90])
        _ = try server.startHandshake()
        var clientToServer = try client.startHandshake()
        var serverToClient: [[UInt8]] = []
        var iterations = 0
        while !client.isEstablished || !server.isEstablished {
            iterations += 1
            guard iterations < 64 else {
                throw BenchmarkError.invalidResult
            }
            if !clientToServer.isEmpty {
                let datagram = clientToServer.removeFirst()
                let output = try server.receive(
                    datagram.span,
                    from: remoteAddress.span
                )
                serverToClient.append(contentsOf: output.datagramsToSend)
            } else if !serverToClient.isEmpty {
                let datagram = serverToClient.removeFirst()
                let output = try client.receive(datagram.span)
                clientToServer.append(contentsOf: output.datagramsToSend)
            } else {
                throw BenchmarkError.invalidResult
            }
        }
    }

    private static func p256Identity() -> TLSIdentity {
        TLSIdentity(
            privateKey: [UInt8](repeating: 0, count: 31) + [0x01],
            keyType: .ecdsaP256,
            certificateChain: [Certificate(der: p256Certificate())]
        )
    }

    private static func p256Certificate() -> [UInt8] {
        let encoded = "3082016930820110a003020102020107300a06082a8648ce3d04030230223120301e"
            + "06035504030c1773776966742d73736c2d65636473612e6578616d706c65301e170d"
            + "3235303130313030303030305a170d3335303130313030303030305a30223120301e"
            + "06035504030c1773776966742d73736c2d65636473612e6578616d706c6530593013"
            + "06072a8648ce3d020106082a8648ce3d030107034200046b17d1f2e12c4247f8bce6e"
            + "563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f"
            + "9e162bce33576b315ececbb6406837bf51f5a3373035300f0603551d130101ff0405"
            + "30030101ff30220603551d11041b3019821773776966742d73736c2d65636473612e"
            + "6578616d706c65300a06082a8648ce3d040302034700304402207d64b4f0d8d41a49"
            + "720e591dc1844556462cd8beb44558fa9f63156a76f2c6cc022063756eb89655ab0b"
            + "0b04032d184382dd99e0be5ce5cacc66374a36dc83f7ac23"
        var result: [UInt8] = []
        result.reserveCapacity(encoded.count / 2)
        var index = encoded.startIndex
        while index < encoded.endIndex {
            let next = encoded.index(index, offsetBy: 2)
            result.append(UInt8(encoded[index..<next], radix: 16)!)
            index = next
        }
        return result
    }
}
