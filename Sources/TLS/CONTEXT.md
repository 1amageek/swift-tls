# swift-tls-sessions — CONTEXT
Scope/role: the TLS/DTLS 1.3/1.2 session facade (`Sources/TLS`) over the canonical
`swift-ssl` mechanisms; depended on by libp2p, WebRTC, and peer-connectivity for
secure transport.
Last reviewed: 2026-08-04

Invariants and design intent that the code does not state structurally. Read this
before changing the facade (`Sources/TLS`) or the engines. The currency is
`[UInt8]` / `Span<UInt8>`; this is an Embedded-first package — there is no
backward-compatibility obligation to the old `Data` / `TLSConnection` API.

## Target ecosystem boundary

- `swift-tls-sessions` owns the public TLS-family session protocols, role-specific
  configuration, negotiated-session snapshots, typed effects/errors, lifecycle,
  and correlated capability suspension/resumption.
- The intended public profiles are `TLS` for reliable streams, `DTLS` for
  datagrams, and `QUICTLS` for ordered encryption-level-qualified QUIC handshake
  bytes, sharing contracts from `TLSSessionCore`.
- `swift-ssl` is the canonical owner of cryptography, PKI, wire semantics,
  transcript, key schedule, record protection, and TLS/DTLS handshake
  mechanisms. A completed facade transition delegates to `swift-ssl` and never
  maintains a parallel transcript or silently selects an independent backend.
- `swift-tls` performs no socket, UDP, QUIC packet, ICE, SRTP, SCTP, or libp2p
  orchestration. Those responsibilities remain with its consumers.
- The stream and DTLS facades use the canonical `swift-ssl` provider path. This
  package does not own a second TLS/DTLS wire, handshake, replay, or record
  implementation. Unconfigured legacy directories are cleanup material, not a
  supported backend or fallback path.

The workspace source of truth is
[`SECURE_TRANSPORT_ARCHITECTURE.md`](../../../../SECURE_TRANSPORT_ARCHITECTURE.md).

## Three-tier layering (why, not just what)

- **Tier 1 — facade (`import TLS`).** The public stream/DTLS surface a normal caller
  touches: `TLSClient` / `TLSServer` / `DTLSClient` / `DTLSServer`. Non-generic
  (fixed to `TLSCryptoProvider`), one `TLSError`, `[UInt8]`/`Span<UInt8>`. Its job
  is to keep X.509 / Foundation / generics OFF the public surface and to be the
  thing that owns concurrency.
- **Tier 2 — mechanisms (`swift-ssl`).** `SSLTLS`, `SSLDTLS`, and `SSLQUIC` own
  the deterministic protocol drivers, wire/record codecs, key schedules, and
  typed cryptographic seams. The facade only maps caller effects to these engines.
- **Tier 3 — shared wire products (`import TLSWire` / `DTLSWire`).** Pure
  encode/decode, no crypto, no I/O. They are published by `swift-ssl` for callers
  that need a scoped wire view.
- The old `TLSCore` / `TLSRecord` / `DTLSCore` / `DTLSRecord` directories are not
  package targets and are not supported. They must not be restored as a backend
  selection mechanism.

## The engine pattern (the load-bearing contract)

- The engine is a **value type** (`struct`), **caller-locked**, **sans-IO**. It
  takes `mutating` methods, holds NO lock and does NO socket I/O. The facade is
  "the caller that locks": each facade type is a `final class & Sendable` holding
  the engine behind `FacadeLock` and serialising every mutation. Do not add a lock
  inside an engine, and do not make an engine a reference type.
- TLS facade methods are `async` (source compatibility only — the engine never
  suspends, it is lock-bound not I/O-bound, so they complete promptly). DTLS facade
  methods are synchronous. Keep this asymmetry; it is intentional.
- The canonical `swift-ssl` mechanisms are **Embedded-clean** and use typed
  throws. CertificateVerify signing, certificate parsing, trust evaluation,
  record protection, and key derivation all resolve through `SSLCrypto` and
  `SSLX509`; the session façade does not select an external crypto backend.
- A consumer may inject a typed PeerID/application policy callback after the
  cryptographic proof succeeds. That policy callback cannot replace signature
  verification, certificate parsing, or key derivation.

## Security invariants (must hold; tests guard them)

- **CertificateVerify proof-of-possession is ALWAYS verified** in the core whenever
  the peer presents a certificate, **independent of `verifyPeer`** (RFC 8446 §4.4.3,
  stack-wide "S1"). `verifyPeer` gates ONLY the injected `validateCertificate`
  trust step. Never make the signature check conditional on `verifyPeer`.
- The injected `validateCertificate` runs AFTER the in-core possession check and is
  **fail-closed**: a throw aborts the handshake. `peerIdentity` therefore never
  surfaces an unverified peer.
- **DTLS cookie / HelloVerifyRequest is fail-closed.** Cookies are HMAC over a
  per-process random secret, bound to the client transport address; a presented
  cookie that fails verification is rejected by the core. Do not add a path that
  accepts a missing/invalid cookie.
- **Anti-replay window** (RFC 6347 §4.1.2.6): MAC is verified BEFORE the window is
  advanced; replays/too-old/bad-MAC records are discarded but datagram processing
  continues, and the anomaly is surfaced via `DTLSOutput.anomalies` — never silently
  swallowed.
- **Epoch / sequence monotonicity** in the DTLS record layer must be preserved.
- **DER-ECDSA on the wire is byte-identical across targets.** The CertificateVerify
  signature is encoded by the canonical `swift-ssl` DER implementation on Native,
  WASM, and Embedded.
  Any change to one encoder must keep the two outputs identical.

## Embedded constraints handled (do not regress)

- **One facade synchronization contract on every target.** `FacadeLock<Value>` is
  an alias of `Synchronization.Mutex<Value>` on Native, WASM, and Embedded. The
  value engines remain caller-locked; target-specific mutex mechanics belong to
  the linked Swift platform implementation. Never replace Embedded facade state
  with a raw variable, spinlock box, or target-conditioned `Sendable` contract.
- **Certificate strategy is shared by module capability.** Native, WASM, and
  Embedded use the same `SSLX509` parser and trust contract. A target that lacks
  a required platform hook fails with a typed capability error; it never silently
  switches to a raw-public-key or host-only implementation.
- **Every target uses the unified `TLSCryptoProvider` over swift-ssl.** Native,
  WASM, and Embedded resolve the same Pure Swift provider. Target differences are
  limited to platform allocation and synchronization implementations.

## Build

- Host: use the pinned Swift 6.4 development snapshot (platform floor v26).
- Normal WASI facade: use the matching Swift 6.4 WASM SDK with
  `P2P_CORE_WASM=1 swift build --target TLS -c release`.
- Embedded facade: use the matching Swift 6.4 Embedded WASM SDK with
  `P2P_CORE_EMBEDDED=1 swift build --target TLS -c release`.
