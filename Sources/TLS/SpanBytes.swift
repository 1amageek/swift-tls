/// Bulk Span<UInt8> -> [UInt8] conversion for the facade boundary.
///
/// One `memcpy`-class copy (`unsafeUninitializedCapacity` + `update(from:)`),
/// never the element-wise `for`-append loop that regressed throughput.
import P2PCoreBytes

extension Span where Element == UInt8 {
    @inline(__always)
    func facadeArray() -> [UInt8] {
        let n = count
        guard n > 0 else { return [] }
        return [UInt8](unsafeUninitializedCapacity: n) { destination, initializedCount in
            withUnsafeBufferPointer { source in
                destination.baseAddress!.update(from: source.baseAddress!, count: n)
            }
            initializedCount = n
        }
    }
}
