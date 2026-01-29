# swift-tls

Pure Swift implementation of TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)) and DTLS 1.2 ([RFC 6347](https://www.rfc-editor.org/rfc/rfc6347)).

Built on [Swift Crypto](https://github.com/apple/swift-crypto), [Swift Certificates](https://github.com/apple/swift-certificates), and [Swift ASN.1](https://github.com/apple/swift-asn1) — no dependency on BoringSSL or OpenSSL.

## Modules

| Module | Description |
|--------|-------------|
| **TLSCore** | TLS 1.3 handshake state machine, key schedule, X.509 validation, extensions |
| **TLSRecord** | TLS 1.3 record layer framing, AEAD encryption, `TLSConnection` high-level API |
| **DTLSCore** | DTLS 1.2 handshake handler, flight controller, cookie exchange |
| **DTLSRecord** | DTLS 1.2 record layer, anti-replay protection, `DTLSConnection` high-level API |

## Features

### TLS 1.3

- Full TLS 1.3 handshake (client and server)
- Cipher suites: `AES-128-GCM-SHA256`, `AES-256-GCM-SHA384`, `ChaCha20-Poly1305-SHA256`
- Key exchange: X25519, P-256, P-384
- HelloRetryRequest
- PSK / session resumption with 0-RTT early data
- Mutual TLS (mTLS)
- X.509 certificate chain validation
- Key Update
- Transport-agnostic design (TCP, QUIC, etc.)
- Swift 6 strict concurrency (`Sendable`, `Mutex`)

### DTLS 1.2

- Full DTLS 1.2 handshake (client and server)
- Cipher suite: `ECDHE-ECDSA-AES128-GCM-SHA256`
- Cookie exchange for DoS protection (RFC 6347 §4.2.1)
- Anti-replay protection with 64-bit sliding window (RFC 6347 §4.1.2.6)
- Epoch-based key management
- Flight retransmission with exponential backoff
- Certificate fingerprint verification (WebRTC compatible)

## Requirements

- Swift 6.2+
- macOS 15+ / iOS 18+ / tvOS 18+ / watchOS 11+ / visionOS 2+

## Installation

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/1amageek/swift-tls.git", from: "0.0.1"),
]
```

Then add the targets you need:

```swift
.target(
    name: "YourTarget",
    dependencies: [
        // TLS 1.3
        .product(name: "TLSCore", package: "swift-tls"),
        .product(name: "TLSRecord", package: "swift-tls"),
        // DTLS 1.2
        .product(name: "DTLSCore", package: "swift-tls"),
        .product(name: "DTLSRecord", package: "swift-tls"),
    ]
)
```

## Usage

### TCP Client

```swift
import TLSRecord
import TLSCore

// Configure
var config = TLSConfiguration()
config.serverName = "example.com"

// Create connection
let tls = TLSConnection(configuration: config)

// Start handshake → send ClientHello over TCP
let clientHello = try await tls.startHandshake(isClient: true)
try await tcp.send(clientHello)

// Feed TCP data until handshake completes
while !tls.isConnected {
    let received = try await tcp.receive()
    let output = try await tls.processReceivedData(received)
    if !output.dataToSend.isEmpty {
        try await tcp.send(output.dataToSend)
    }
}

// Send/receive application data
let encrypted = try tls.writeApplicationData(Data("Hello".utf8))
try await tcp.send(encrypted)

// Graceful close
let closeNotify = try tls.close()
try await tcp.send(closeNotify)
```

### TLSCore Only (for custom transports)

Use `TLS13Handler` directly when integrating with a custom transport like QUIC:

```swift
import TLSCore

let handler = TLS13Handler(configuration: config)
let outputs = try await handler.startHandshake(isClient: true)

for output in outputs {
    switch output {
    case .handshakeData(let data, let level):
        // Send data at the given encryption level
        try await transport.send(data, at: level)
    case .keysAvailable(let info):
        // Install keys for the encryption level
        transport.installKeys(info)
    case .handshakeComplete:
        break
    default:
        break
    }
}
```

### DTLS 1.2 Client (UDP)

```swift
import DTLSRecord
import DTLSCore

// Create certificate (for client authentication or self-signed)
let cert = try DTLSCertificate()

// Create connection
let dtls = DTLSConnection(certificate: cert)

// Start handshake → send ClientHello over UDP
let clientHello = try dtls.startHandshake(isClient: true)
for datagram in clientHello {
    try await udp.send(datagram)
}

// Process UDP datagrams until handshake completes
while !dtls.isConnected {
    let received = try await udp.receive()
    let output = try dtls.processReceivedDatagram(received)
    for datagram in output.datagramsToSend {
        try await udp.send(datagram)
    }
}

// Send/receive application data
let encrypted = try dtls.writeApplicationData(Data("Hello".utf8))
try await udp.send(encrypted)

// Handle incoming data
let received = try await udp.receive()
let output = try dtls.processReceivedDatagram(received)
print("Received: \(String(data: output.applicationData, encoding: .utf8)!)")

// Graceful close
let closeNotify = try dtls.close()
try await udp.send(closeNotify)
```

### DTLS 1.2 Server (UDP)

```swift
import DTLSRecord
import DTLSCore

let cert = try DTLSCertificate()
let dtls = DTLSConnection(certificate: cert)

// Server waits for ClientHello
_ = try dtls.startHandshake(isClient: false)

// Process incoming datagrams
while !dtls.isConnected {
    let (data, clientAddr) = try await udp.receiveFrom()
    let output = try dtls.processReceivedDatagram(data, remoteAddress: clientAddr)
    for datagram in output.datagramsToSend {
        try await udp.send(datagram, to: clientAddr)
    }
}

// Now ready for application data
```

## Architecture

```
TLSRecord
├── TLSConnection         High-level API (handshake + record layer)
├── TLSRecordLayer        Record framing + encryption (external key mgmt)
├── TLSRecordCodec        Encode/decode TLS record frames
└── TLSRecordCryptor      AEAD encrypt/decrypt

TLSCore
├── TLS13Handler          Main handler (coordinates state machines)
├── StateMachine/
│   ├── ClientStateMachine
│   └── HandshakeState
├── KeySchedule/
│   ├── TLSKeySchedule    HKDF-based key derivation (RFC 8446 §7)
│   └── TranscriptHash    Running hash of handshake messages
├── Messages/             ClientHello, ServerHello, Finished, etc.
├── Extensions/           SNI, ALPN, KeyShare, PSK, etc.
├── Crypto/               KeyExchange, Signature
├── Session/              PSK resumption, replay protection
└── X509/                 Certificate parsing and chain validation

DTLSRecord
├── DTLSConnection        High-level API (handshake + record layer)
├── DTLSRecordLayer       Record framing + encryption + anti-replay
├── DTLSRecordCodec       Encode/decode DTLS record frames
├── DTLSRecordCryptor     AEAD encrypt/decrypt with explicit nonce
└── AntiReplayWindow      64-bit sliding window (RFC 6347 §4.1.2.6)

DTLSCore
├── DTLSClientHandshakeHandler   Client-side handshake state machine
├── DTLSServerHandshakeHandler   Server-side handshake state machine
├── FlightController             Retransmission with exponential backoff
├── DTLSCertificate              Self-signed cert generation (P-256)
└── CertificateFingerprint       SHA-256 fingerprint for WebRTC SDP
```

## RFC Compliance

### DTLS 1.2 (RFC 6347)

| Section | Feature | Status |
|---------|---------|--------|
| §4.1 | Record layer with epoch/sequence | ✅ |
| §4.1 | Epoch mismatch handling | ✅ Silent discard |
| §4.1.2.6 | Anti-replay window (64-bit) | ✅ |
| §4.1.2.6 | MAC verification before window update | ✅ |
| §4.1.2.7 | Invalid record handling | ✅ Silent discard |
| §4.2.1 | Cookie exchange (DoS protection) | ✅ |
| §4.2.4 | Flight retransmission | ✅ Exponential backoff |

### TLS 1.2 Alert Protocol (RFC 5246 §7.2)

| Requirement | Status |
|-------------|--------|
| Fatal alert terminates connection | ✅ Immediate return |
| Data after close_notify ignored | ✅ Immediate return |

## License

MIT
