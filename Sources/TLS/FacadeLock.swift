/// The facade's value-protecting lock on Native, WASM, and Embedded targets.
///
/// The Tier-1 facade is "the caller that locks": each `TLSClient` / `TLSServer` /
/// `DTLSClient` / `DTLSServer` is a `final class & Sendable` that holds the value-type,
/// sans-IO engine behind this lock, so its public methods are `Sendable`-safe. The
/// engine itself holds no lock; the facade serialises every mutation here.
///
import Synchronization

/// The facade uses one storage and isolation contract on every target. Target-specific
/// mutex mechanics belong to the linked Swift platform implementation, not this layer.
typealias FacadeLock<Value: ~Copyable> = Mutex<Value>
