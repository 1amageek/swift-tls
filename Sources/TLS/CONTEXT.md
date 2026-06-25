# swift-tls — CONTEXT

Invariants and design intent that the code does not state structurally. Read this
before changing the facade (`Sources/TLS`) or the engines. The currency is
`[UInt8]` / `Span<UInt8>`; this is an Embedded-first package — there is no
backward-compatibility obligation to the old `Data` / `TLSConnection` API.

## Three-tier layering (why, not just what)

- **Tier 1 — facade (`import TLS`).** The ONLY public surface a normal caller
  touches: `TLSClient` / `TLSServer` / `DTLSClient` / `DTLSServer`. Non-generic
  (fixed to `TLSCryptoProvider`), one `TLSError`, `[UInt8]`/`Span<UInt8>`. Its job
  is to keep X.509 / Foundation / generics OFF the public surface and to be the
  thing that owns concurrency.
- **Tier 2 — engines (`package`).** `TLS*Engine<C>` / `DTLS*Engine<C>` in
  `TLSEngineCore` / `DTLSEngineCore`. The actual protocol drivers. Public-but-package.
- **Tier 3 — wire codecs (`import TLSWire` / `DTLSWire`).** Pure encode/decode,
  no crypto, no I/O. Separate opt-in products for callers who build records by hand.
- The old `TLSCore` / `TLSRecord` / `DTLSCore` / `DTLSRecord` are now `package`
  legacy: host `TLSConnection` / `TLS13Handler` / `DTLSConnection` + state machines,
  PLUS the host (swift-certificates / swift-crypto) strategy bridges that fill the
  engine seams on host. Do not re-export them; do not route new callers through them.

## The engine pattern (the load-bearing contract)

- The engine is a **value type** (`struct`), **caller-locked**, **sans-IO**. It
  takes `mutating` methods, holds NO lock and does NO socket I/O. The facade is
  "the caller that locks": each facade type is a `final class & Sendable` holding
  the engine behind `FacadeLock` and serialising every mutation. Do not add a lock
  inside an engine, and do not make an engine a reference type.
- TLS facade methods are `async` (source compatibility only — the engine never
  suspends, it is lock-bound not I/O-bound, so they complete promptly). DTLS facade
  methods are synchronous. Keep this asymmetry; it is intentional.
- The engines are **Embedded-clean**: no Foundation, no `any` existentials, no
  `Mutex`, no `ContinuousClock`, no swift-crypto, no X509. Typed throws
  (`TLSEngineError` / `DTLSEngineError`). A new engine-level error must stay typed —
  a cross-type `catch` must live in a NAMED function, never a closure literal
  (Embedded Swift binds `any Error` inside a closure `catch`).
- The two genuinely host-coupled jobs — CertificateVerify **signing** (a private
  key) and **certificate trust evaluation** (X.509 chain / RFC-7250 raw-key match /
  libp2p PeerID hook) — are INJECTED as `@Sendable` closures via
  `*EngineConfiguration<C>` (`sign`, `validateCertificate`, `resolvePeerKey`,
  and for DTLS `ecdheGenerate`/`ecdheAgree`/`verifyPeerSignature`/`makeCookie`/
  `verifyCookie`). The facade fills them: host bridge under `#if !hasFeature(Embedded)`,
  Embedded RPK strategy under `#if hasFeature(Embedded)`. X.509 never enters an engine.

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
- **DER-ECDSA on the wire is byte-identical host vs Embedded.** The CertificateVerify
  ECDSA signature is DER-encoded (RFC 8446 §4.2.3): host via swift-crypto
  `derRepresentation`, Embedded via BoringSSL raw `r||s` + a `P2PCoreDER` wrapper.
  Any change to one encoder must keep the two outputs identical.

## Embedded constraints handled (do not regress)

- **`FacadeLock`, not `Synchronization.Mutex`.** `Mutex` is unavailable under
  Embedded; `FacadeLock` is `Mutex` on host and an `Atomic<Bool>` spinlock box under
  Embedded. Use `FacadeLock` for any new facade-held state — never `Mutex` directly.
- **Gate on `hasFeature(Embedded)`, NOT `canImport(Foundation)`.** Host vs Embedded
  source selection (host strategy bridges, `remoteFingerprint`, the strategy files)
  all key off `#if hasFeature(Embedded)`. Keep this consistent so the Embedded build
  excludes the swift-crypto / X.509 / Foundation code.
- **Embedded cert strategy = P2PCoreDER SPKI extraction, fail-closed.** Under
  Embedded there is no X.509: peer-key resolution parses the leaf's
  SubjectPublicKeyInfo (RFC 7250 raw public key) via `P2PCoreDER`. A full X.509 leaf
  (not a bare SPKI) is unparseable and yields `nil` / throws, which the core rejects
  fail-closed. The Embedded path therefore serves only the raw-public-key
  (`.rawPublicKey`) deployments (libp2p / WebRTC). Do not add a silent accept.
- **Under Embedded the unified `TLSCryptoProvider` uses a BoringSSL backend**
  (vendored `p2p-boringssl`); swift-crypto is dropped from the Embedded dependency
  set. The "no BoringSSL/OpenSSL" property holds only for the host build.

## Build

- Host: `swift build` (Swift tools 6.2, platform floor v26).
- Embedded facade: `P2P_CORE_EMBEDDED=1 P2P_CRYPTO_EMBEDDED=1 swiftly run +6.3.1
  swift build --target TLS -c release`.
