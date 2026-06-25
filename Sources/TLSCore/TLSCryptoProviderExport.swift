/// Re-exports the unified ``TLSCryptoProvider`` so the host targets that import
/// ``TLSCore`` (``DTLSCore``, ``TLSRecord``, ``DTLSRecord`` and ``TLSCore`` itself)
/// continue to name `TLSCryptoProvider` / `TLSDERP256Signature` /
/// `TLSDERP384Signature` without each file adding an explicit import.
///
/// The provider moved into its own Embedded-clean ``TLSCryptoProvider`` target (the
/// SINGLE `P2PCrypto` importer); this `@_exported import` preserves the previous
/// in-module visibility for the host engine code.
@_exported import TLSCryptoProvider
