# swift-tls

Pure Swift implementation of TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) and DTLS 1.2 ([RFC 6347](https://www.rfc-editor.org/rfc/rfc6347)), with a single Tier-1 facade and a cored, Embedded-clean engine underneath.

> **API status.** The facade API documented here (`TLSClient` / `TLSServer` / `DTLSClient` / `DTLSServer`) lives on the **unreleased `embedded` branch** (pending the M8 release). The latest released tag, **`1.3.0`, ships the OLD multi-product API** (`TLSCore` / `TLSRecord` / `DTLSCore` / `DTLSRecord` with `TLSConnection` / `DTLSConnection`) and does NOT contain the facade. Pin to the `embedded` branch to use the API below.

## Cryptographic backend

On host, the unified crypto provider is built on [Swift Crypto](https://github.com/apple/swift-crypto), [Swift Certificates](https://github.com/apple/swift-certificates), and [Swift ASN.1](https://github.com/apple/swift-asn1). **Under Embedded Swift, swift-crypto is dropped** and the provider uses a vendored BoringSSL backend (`p2p-boringssl`, via `EmbeddedDERSignature.swift`) for the DER-ECDSA CertificateVerify signatures — its DER output is byte-identical to the host's. So the package depends on BoringSSL only in the Embedded build; the host build does not.

## Modules

| Product | Import | Visibility | Description |
|---------|--------|------------|-------------|
| **TLS** | `import TLS` | public | Tier-1 facade — the only module a normal user imports. `TLSClient` / `TLSServer` / `DTLSClient` / `DTLSServer`. |
| **TLSWire** | `import TLSWire` | public | Tier-3 pure TLS 1.3 wire codec (target `TLSWireCore`), no crypto, no I/O. |
| **DTLSWire** | `import DTLSWire` | public | Tier-3 pure DTLS 1.2 wire codec (target `DTLSWireCore`). |

The former public products `TLSCore` / `TLSRecord` / `DTLSCore` / `DTLSRecord` have been **demoted to `package`-visibility targets** (host legacy / host strategy bridges). They are no longer importable from outside the package. Use the `TLS` facade instead.

## Public API (Tier-1 facade)

`TLSClient`, `TLSServer`, `DTLSClient`, and `DTLSServer` are each a `final class` and `Sendable`. They wrap a value-type, sans-IO engine behind a lock (the facade is "the caller that locks"). The currency is `[UInt8]` / `Span<UInt8>`; `Data` appears only as a host-only convenience (e.g. WebRTC fingerprint formatting).

```swift
// Construction (typed throws)
init(configuration: TLSConfiguration) throws(TLSError)    // TLSClient / TLSServer
init(configuration: DTLSConfiguration) throws(TLSError)   // DTLSClient / DTLSServer
```

Common methods. **TLS** (`TLSClient` / `TLSServer`) methods are `async`; **DTLS** (`DTLSClient` / `DTLSServer`) methods are synchronous.

| Method | TLS | DTLS |
|--------|-----|------|
| `startHandshake()` | `async throws(TLSError) -> [UInt8]` | `throws(TLSError) -> [[UInt8]]` |
| `receive(_:)` | `async throws(TLSError) -> TLSOutput` | `throws(TLSError) -> DTLSOutput` |
| `send(_:)` | `async throws(TLSError) -> [UInt8]` | `throws(TLSError) -> [UInt8]` |
| `close()` | `async throws(TLSError) -> [UInt8]` | `throws(TLSError) -> [UInt8]` |
| `handleTimeout()` | — | `throws(TLSError) -> [[UInt8]]` (flight retransmission) |

`receive(_:)` takes a `Span<UInt8>`. `DTLSServer.receive(_:from:)` additionally takes `from remoteAddress: Span<UInt8>` for the HelloVerifyRequest cookie binding.

Connection state and peer material:

- `var isEstablished: Bool` — handshake complete.
- TLS: `var negotiatedALPN: String?`, `var peerCertificates: [[UInt8]]?` (DER chain, leaf first), `var peerIdentity: PeerIdentity?` (from the injected validator).
- DTLS: `var isClosed: Bool`, `var remoteCertificateDER: [UInt8]?`, `var remoteFingerprint: String?` (host-only, RFC 8122 / SDP form for WebRTC DTLS-SRTP).

All errors surface as one closed, typed-throws `TLSError` enum (`handshakeNotComplete`, `connectionClosed`, `protocolFailure`, `fatalAlert`, `verificationFailed`, `invalidConfiguration`, `bufferOverflow`, `concurrentReceiveNotAllowed`, `internalError`).

## Features

### TLS 1.3

- Full TLS 1.3 handshake (client and server)
- Cipher suites: `AES-128-GCM-SHA256`, `AES-256-GCM-SHA384`, `ChaCha20-Poly1305-SHA256`
- Key exchange: X25519, P-256, P-384
- HelloRetryRequest
- PSK / session resumption with 0-RTT early data
- Mutual TLS (mTLS)
- The CertificateVerify proof-of-possession signature is **always verified** in the core whenever the peer presents a certificate; the `verifyPeer` configuration flag controls **only** X.509 chain / trust-anchor (or RFC 7250 raw-key) validation, never the handshake signature
- X.509 certificate chain validation (host) and RFC 7250 raw-public-key authentication (host + Embedded)
- Signature schemes: ECDSA P-256 / P-384 and Ed25519 only — RSA is not advertised or verified
- Key Update
- Transport-agnostic, sans-IO design (TCP, QUIC, etc.)
- `Span<UInt8>` input lets adapters feed byte views without pre-materializing `Data`
- Swift 6 strict concurrency (`Sendable`, lock-based facade)

### DTLS 1.2

- Full DTLS 1.2 handshake (client and server)
- Cipher suite: `ECDHE-ECDSA-AES128-GCM-SHA256`
- Mutual authentication: the server requires/verifies a client certificate via `DTLSConfiguration(identity:requireClientCertificate:)`; the client's CertificateVerify proof-of-possession is verified before completion
- Cookie exchange for DoS protection (RFC 6347 §4.2.1); HelloVerifyRequest cookies are bound to the client transport address and minted/verified with a rotating secret (fail-closed)
- Anti-replay protection with 64-bit sliding window (RFC 6347 §4.1.2.6); bad-MAC records are discarded while datagram processing continues
- Non-fatal record anomalies (bad MAC, replay, too-old, malformed) are surfaced via `DTLSOutput.anomalies` instead of being silently swallowed
- Handshake fragment reassembly is bounded to resist memory-exhaustion DoS
- Epoch-based key management; epoch/sequence monotonicity
- Flight retransmission with exponential backoff (driven by `handleTimeout()`)
- Certificate fingerprint verification (WebRTC compatible)

## Requirements

- Swift tools 6.2+
- macOS 26+ / iOS 26+ / tvOS 26+ / watchOS 26+ / visionOS 26+

## Embedded Swift

`--target TLS -c release` compiles under Embedded Swift. The cores (engine / wire / crypto schedule / provider) and the facade are dual-built; under Embedded the facade uses the RFC 7250 raw-public-key strategy (`P2PCoreDER` SPKI extraction, fail-closed) instead of swift-certificates/X.509, and `FacadeLock` replaces `Synchronization.Mutex`.

```bash
P2P_CORE_EMBEDDED=1 P2P_CRYPTO_EMBEDDED=1 swiftly run +6.3.1 \
    swift build --target TLS -c release
```

## Installation

Add to your `Package.swift` (use the `embedded` branch for the facade API — `1.3.0` ships the old API):

```swift
dependencies: [
    .package(url: "https://github.com/1amageek/swift-tls.git", branch: "embedded"),
]
```

Then depend on the facade product:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        .product(name: "TLS", package: "swift-tls"),
        // Opt-in pure wire codecs (only if you need to build/parse records yourself):
        // .product(name: "TLSWire", package: "swift-tls"),
        // .product(name: "DTLSWire", package: "swift-tls"),
    ]
)
```

## Usage

### TCP client (TLS 1.3)

```swift
import TLS

var config = TLSConfiguration.client(serverName: "example.com")
let tls = try TLSClient(configuration: config)

// 1. Start the handshake → send the ClientHello.
let hello = try await tls.startHandshake()
try await tcp.send(hello)

// 2. Feed peer bytes until the handshake completes.
while !tls.isEstablished {
    let received: [UInt8] = try await tcp.receive()
    let output = try await tls.receive(received.span)
    if !output.bytesToSend.isEmpty { try await tcp.send(output.bytesToSend) }
}

// 3. Application data.
let message = Array("Hello".utf8)
let records = try await tls.send(message.span)
try await tcp.send(records)

// 4. Graceful close.
try await tcp.send(try await tls.close())
```

`receive(_:)` / `send(_:)` take a `Span<UInt8>`. Obtain one from the `.span` property of a stable `[UInt8]` (or `Bytes`) binding — the facade copies the span into an internal `[UInt8]` at the boundary, so the borrow only needs to last the call.

### DTLS 1.2 client (UDP)

```swift
import TLS

// ECDSA P-256 identity: DER leaf certificate + raw 32-byte private key.
let identity = TLSIdentity(
    privateKey: rawP256PrivateKey,                 // [UInt8]
    keyType: .ecdsaP256,
    certificateChain: [Certificate(der: leafDER)]
)
let config = DTLSConfiguration(identity: identity, requireClientCertificate: true)
let dtls = try DTLSClient(configuration: config)

// Start the handshake → send the ClientHello datagram(s).
for datagram in try dtls.startHandshake() {
    try await udp.send(datagram)
}

// Process datagrams until the handshake completes.
while !dtls.isEstablished {
    let received: [UInt8] = try await udp.receive()
    let output = try dtls.receive(received.span)
    for datagram in output.datagramsToSend { try await udp.send(datagram) }
    // On a flight timeout, retransmit:
    //   for datagram in try dtls.handleTimeout() { try await udp.send(datagram) }
}

// Application data.
let message = Array("Hello".utf8)
let datagram = try dtls.send(message.span)
try await udp.send(datagram)

// Graceful close.
try await udp.send(try dtls.close())
```

### DTLS 1.2 server (UDP)

```swift
import TLS

let config = DTLSConfiguration(identity: identity, requireClientCertificate: true)
let dtls = try DTLSServer(configuration: config)

// A server has nothing to send until the first ClientHello arrives.
_ = try dtls.startHandshake()

while !dtls.isEstablished {
    let (data, clientAddr): ([UInt8], [UInt8]) = try await udp.receiveFrom()
    // remoteAddress binds the HelloVerifyRequest cookie.
    let output = try dtls.receive(data.span, from: clientAddr.span)
    for datagram in output.datagramsToSend { try await udp.send(datagram, to: clientAddr) }
}
// Now ready for application data.
```

`requireClientCertificate: true` makes the server fail the handshake unless the client presents a certificate and proves possession of its private key via a valid CertificateVerify. Peer-authenticated deployments (WebRTC / libp2p) must set this.

## Architecture

The package is a three-tier stack. Public callers touch only Tier 1.

```
Tier 1  FACADE (public: import TLS)
  TLSClient / TLSServer / DTLSClient / DTLSServer
    final class & Sendable; holds a value-type engine behind FacadeLock
    [UInt8]/Span<UInt8> currency; one TLSError; cert validation + signing injected

Tier 2  ENGINES (package: the cored, sans-IO drivers)
  TLSEngineCore   : TLSClientEngine<C> / TLSServerEngine<C>
  DTLSEngineCore  : DTLSClientEngine<C> / DTLSServerEngine<C>
    value type, caller-locked, sans-IO, generic over C: CryptoProvider
    drives the handshake FSMs (TLSHandshakeCore / DTLSHandshakeCore) through the
    record layer; cert-validation + signing are injected via *EngineConfiguration<C>
    closures (no `any`, no Foundation, no Mutex)
  TLSCryptoCore   : TLS 1.3 key schedule (HKDF, transcript hash)
  TLSCryptoProvider (target) : the unified provider —
    DefaultCryptoProvider for every primitive EXCEPT the two ECDSA signature
    schemes, which are DER-encoded for the CertificateVerify wire (RFC 8446 §4.2.3);
    host = swift-crypto derRepresentation, Embedded = BoringSSL r||s + P2PCoreDER

Tier 3  WIRE CODECS (public: import TLSWire / DTLSWire)
  TLSWireCore / DTLSWireCore : pure encode/decode over ByteReader/ByteWriter,
    no crypto, no I/O

  Host legacy (package, NOT public): TLSCore / TLSRecord / DTLSCore / DTLSRecord
    host TLSConnection / TLS13Handler / DTLSConnection + state machines, and the
    host (swift-certificates / swift-crypto) strategy bridges that fill the engine
    seams under #if !hasFeature(Embedded)
```

## RFC Compliance

### DTLS 1.2 (RFC 6347)

| Section | Feature | Status |
|---------|---------|--------|
| §4.1 | Record layer with epoch/sequence | Yes |
| §4.1 | Epoch mismatch handling | Yes — silent discard |
| §4.1.2.6 | Anti-replay window (64-bit) | Yes |
| §4.1.2.6 | MAC verification before window update | Yes |
| §4.1.2.7 | Invalid record handling | Yes — discarded (datagram continues; surfaced via `anomalies`) |
| §4.2.1 | Cookie exchange (DoS protection) | Yes — cookie bound to client address; rotating secret |
| §4.2.3 | Handshake fragment reassembly | Yes — bounded (per-message + concurrent limits) |
| §4.2.4 | Flight retransmission | Yes — exponential backoff |

### TLS 1.3 (RFC 8446)

| Requirement | Status |
|-------------|--------|
| CertificateVerify proof-of-possession always verified | Yes — in-core, independent of `verifyPeer` (§4.4.3) |
| Fatal alert terminates connection | Yes |
| Data after close_notify ignored | Yes |

## License

MIT
