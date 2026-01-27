# swift-tls

Pure Swift implementation of TLS 1.3 ([RFC 8446](https://www.rfc-editor.org/rfc/rfc8446)).

Built on [Swift Crypto](https://github.com/apple/swift-crypto), [Swift Certificates](https://github.com/apple/swift-certificates), and [Swift ASN.1](https://github.com/apple/swift-asn1) — no dependency on BoringSSL or OpenSSL.

## Modules

| Module | Description |
|--------|-------------|
| **TLSCore** | Handshake state machine, key schedule, X.509 validation, extensions |
| **TLSRecord** | Record layer framing, AEAD encryption, `TLSConnection` high-level API |

## Features

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
        .product(name: "TLSCore", package: "swift-tls"),
        .product(name: "TLSRecord", package: "swift-tls"),
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
```

## License

MIT
