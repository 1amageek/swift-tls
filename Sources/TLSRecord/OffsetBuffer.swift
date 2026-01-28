/// Offset-based buffer for efficient incremental consumption.
///
/// Standard `Data.removeFirst(_:)` is O(n) because it copies the remaining bytes.
/// This buffer tracks a read offset instead, making consumption O(1) amortized.
/// The underlying storage is compacted when the consumed prefix exceeds a threshold
/// to prevent unbounded memory growth.

import Foundation

struct OffsetBuffer: Sendable {
    private var data: Data = Data()
    private var readOffset: Int = 0

    /// Threshold for compacting: when consumed bytes exceed this, reclaim memory
    private static let compactThreshold: Int = 16384

    /// Number of unconsumed bytes
    var count: Int {
        data.count - readOffset
    }

    /// Whether the buffer has no unconsumed bytes
    var isEmpty: Bool {
        readOffset >= data.count
    }

    /// Append new data to the buffer
    mutating func append(_ newData: Data) {
        data.append(newData)
    }

    /// A view of the unconsumed bytes (zero-copy slice)
    var unconsumed: Data {
        data[data.index(data.startIndex, offsetBy: readOffset)...]
    }

    /// Mark the first `n` bytes as consumed (O(1) amortized)
    mutating func consumeFirst(_ n: Int) {
        readOffset += n
        compactIfNeeded()
    }

    /// Remove all data
    mutating func removeAll() {
        data.removeAll()
        readOffset = 0
    }

    /// Reclaim memory if consumed prefix is large enough
    private mutating func compactIfNeeded() {
        if readOffset >= Self.compactThreshold {
            data = Data(unconsumed)
            readOffset = 0
        }
    }
}
