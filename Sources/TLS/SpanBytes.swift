/// Bulk `Span<UInt8>` to `[UInt8]` conversion for the facade boundary.
///
/// The facade establishes one owned buffer before a borrowed view crosses its
/// mutex closure. The engine's package-owned entry points consume that same
/// buffer without another packet-sized materialization.
extension Span where Element == UInt8 {
    @inline(__always)
    func facadeArray() -> [UInt8] {
        var result: [UInt8] = []
        result.reserveCapacity(count)
        var index = 0
        while index < count {
            result.append(self[index])
            index += 1
        }
        return result
    }
}
